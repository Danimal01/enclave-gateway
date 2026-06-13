// gateway/onboarding.mjs: the signer-first enclave-born onboarding state machine
// (spec 4.10). Runs ONLY in the gateway's ONBOARDING-mode connection class.
//
// The load-bearing sequencing invariants this enforces (H-5, 5.6):
//   - a current RECOVERY envelope MUST commit to the DB before the first login
//     side effect (auth.sendCode) and before retrying a login after DC/auth-key
//     migration;
//   - the FINAL envelope conditionally upgrades RECOVERY after identity binding;
//   - there is NO ONB_PERSIST_ACK and no web-held blob: the gateway writes both
//     phases through its own gateway-only DB functions;
//   - the TEARDOWN cleanup invariant durably logs out any live authorization
//     before deletion (the three cases below).
//
// All Telegram / KMS / DB / State-Authority effects are injected (`fx`), so the
// transition logic, timeouts, rate caps, and cleanup decisions are unit-tested
// without an enclave. The EIF wires the real effects.

export const STATES = Object.freeze({
  IDLE: "IDLE", PREPARED: "PREPARED", CONNECTING: "CONNECTING", RECOVERY_SEAL: "RECOVERY_SEAL",
  CODE_SENT: "CODE_SENT", SIGNING_IN: "SIGNING_IN", PWD_CHALLENGE: "PWD_CHALLENGE",
  AWAIT_SRP_PROOF: "AWAIT_SRP_PROOF", BINDING: "BINDING", SEALING: "SEALING", DONE: "DONE", TEARDOWN: "TEARDOWN",
});

export const CAPS = Object.freeze({
  PER_STEP_MS: 10 * 60 * 1000,
  TOTAL_MS: 15 * 60 * 1000,
  MAX_CONCURRENT: 50,
  SENDCODE_PER_PHONE_24H: 3,
  STARTS_PER_RATEKEY_24H: 10,
  CODE_GUESSES: 5,
  SRP_GUESSES: 3,
});

export class OnboardingManager {
  // fx (injected effects):
  //   rateCheck({ phone, rateKey })   -> { ok } | throws  (durable atomic, gateway-only)
  //   createLink({ link, state, phone, signersCommit, grantDigest, ownerEmail })
  //   connect()                       -> live onboarding connection (mints auth_key)
  //   sealRecovery({...})             -> commits RECOVERY(1) (BEFORE sendCode)
  //   rotateRecovery({...})           -> RECOVERY(n)->RECOVERY(n+1) (after migration)
  //   sendCode({phone})               -> { phoneCodeHash, isCodeViaApp }
  //   signIn({phone, hash, code})     -> { ok } | throws SESSION_PASSWORD_NEEDED / PHONE_CODE_INVALID
  //   getPassword()                   -> public SRP params
  //   checkPassword({A, M1})          -> { ok } | throws PASSWORD_HASH_INVALID
  //   getMe()                         -> { tgUserId, firstName, username }
  //   finalizeSeal({...})             -> RECOVERY(n)->FINAL(n+1)
  //   logOut()                        -> durable auth.logOut
  //   markTerminal({...}), deleteLink({...})
  //   verifyGrant(...)                -> the OnboardingGrant verifier
  //   now()                           -> epoch ms
  constructor(fx) {
    this._fx = fx;
    this._sessions = new Map(); // onb -> ctx
  }

  get activeCount() { return this._sessions.size; }

  _ctx(onb) {
    const c = this._sessions.get(onb);
    if (!c) throw new Error("unknown onb handle");
    return c;
  }

  // PREPARE: gateway generates candidates; NO DB row, NO State Authority record,
  // NO Telegram contact yet. Emits the ONB_CHALLENGE inputs.
  prepare({ onb, link, state, phone, signerGenesis, nonce, pcr0g, channelKeyHash }) {
    if (this._sessions.size >= CAPS.MAX_CONCURRENT) throw new Error("too many concurrent ceremonies");
    if ([...this._sessions.values()].some((c) => c.phone === phone)) throw new Error("a ceremony is already in flight for this phone");
    const now = this._fx.now();
    this._sessions.set(onb, {
      onb, link, state, phone, signerGenesis, nonce, pcr0g, channelKeyHash,
      status: STATES.PREPARED, startedAt: now, stepAt: now,
      codeGuesses: 0, srpGuesses: 0, recoveryGen: 0, recoveryDigest: null, sealedRecovery: false, signedIn: false,
    });
    return { onb, link, nonce, expiresAt: now + CAPS.TOTAL_MS, pcr0g };
  }

  // C-6 enforcement: every signed candidate field must equal the gateway-held
  // ceremony value (the gateway generated link_id/state; pcr0_g + channel_key_hash
  // are the gateway's own; phone + nonce were sealed in at prepare). signers_commit
  // is separately bound by verifyGrant (== signerGenesis.commit). The nonce is
  // consumed single-use so a captured grant cannot be replayed within the ceremony.
  _bindCandidate(c, candidate) {
    const must = (field, held, got) => {
      if (held === undefined || held === null || String(held) !== String(got)) {
        throw new Error(`grant candidate ${field} does not match the gateway-held ceremony value`);
      }
    };
    must("link_id", c.link, candidate?.link_id);
    must("normalized_phone", c.phone, candidate?.normalized_phone);
    must("gateway_nonce", c.nonce, candidate?.gateway_nonce);
    must("pcr0_g", c.pcr0g, candidate?.pcr0_g);
    must("channel_key_hash", c.channelKeyHash, candidate?.channel_key_hash);
    if (c.nonceConsumed) throw new Error("grant nonce already consumed");
    c.nonceConsumed = true;
  }

  // AUTHORIZE: verify the grant against held candidates, create the link row +
  // signer genesis + State Authority onboarding record, acquire the ceremony
  // lease, then connect() (mints the auth_key). RECOVERY seal happens next,
  // BEFORE any login side effect.
  async authorize({ onb, candidate, authorization, ownerEmail, userId }) {
    const c = this._ctx(onb);
    if (c.status !== STATES.PREPARED) throw new Error("authorize out of order");
    this._checkTimeouts(c);
    // C-6 binding (audit hardening): the SIGNED grant candidate MUST name THIS
    // ceremony's gateway-held values, not browser-chosen ones, and the nonce is
    // single-use. The sealed channel already blocks relay substitution; this is the
    // authoritative enforcement the C-6 claim rests on (no longer transport-only).
    this._bindCandidate(c, candidate);
    // Any failure from here on (rate cap, grant reject, createLink, the Telegram
    // cold-connect, or the recovery seal) MUST tear down this ceremony. Otherwise the
    // in-memory session lingers and prepare() rejects the phone as "already in flight"
    // for every subsequent attempt -- a single failed try wedged the number until an
    // enclave restart. _teardown is idempotent and never throws.
    try {
      const grant = await this._fx.verifyGrant({ candidate, signerGenesis: c.signerGenesis, authorization, nowMs: this._fx.now() });
      if (!grant.ok) throw new Error(`grant rejected: ${grant.reason}`);

      // Rate caps keyed on the gateway-HELD phone (never an attacker-supplied
      // rateKey), AFTER the grant verifies so a failed/invalid signature can't burn a
      // legitimate user's sendCode budget (3/24h) and lock them out.
      await this._fx.rateCheck({ phone: c.phone, rateKey: c.phone });

      await this._fx.createLink({ link: c.link, state: c.state, phone: c.phone, signersCommit: candidate.signers_commit, grantDigest: grant.grantDigest, ownerEmail, userId });
      c.grantDigest = grant.grantDigest;
      c.status = STATES.CONNECTING;
      await this._fx.connect(c);

      // RECOVERY_SEAL: commit RECOVERY(1) BEFORE sendCode.
      c.status = STATES.RECOVERY_SEAL;
      const seal = await this._fx.sealRecovery({ link: c.link, state: c.state, generation: 1, signersCommit: candidate.signers_commit, grantDigest: grant.grantDigest });
      c.recoveryGen = 1;
      c.recoveryDigest = seal.envelopeDigest;
      c.sealedRecovery = true;
      return { onb, status: c.status };
    } catch (e) {
      await this._teardown(onb, `authorize failed: ${e.message}`);
      throw e;
    }
  }

  // After the recovery commit, send the login code. HARD ORDER: this throws if
  // the recovery envelope is not yet durable.
  async startLogin({ onb }) {
    const c = this._ctx(onb);
    if (!c.sealedRecovery) throw new Error("refusing auth.sendCode before the recovery envelope is durable");
    this._checkTimeouts(c);
    // link routes the effect to THIS ceremony's transport (concurrency-safe).
    const res = await this._fx.sendCode({ link: c.link, phone: c.phone });
    c.phoneCodeHash = res.phoneCodeHash;
    c.status = STATES.CODE_SENT;
    c.stepAt = this._fx.now();
    return { isCodeViaApp: res.isCodeViaApp };
  }

  async submitCode({ onb, code }) {
    const c = this._ctx(onb);
    if (c.status !== STATES.CODE_SENT && c.status !== STATES.SIGNING_IN) throw new Error("submitCode out of order");
    this._checkTimeouts(c);
    c.status = STATES.SIGNING_IN;
    try {
      await this._fx.signIn({ link: c.link, phone: c.phone, hash: c.phoneCodeHash, code });
      return await this._bindAndSeal(c);
    } catch (e) {
      if (e.message === "SESSION_PASSWORD_NEEDED") {
        const params = await this._fx.getPassword({ link: c.link });
        c.status = STATES.AWAIT_SRP_PROOF;
        c.stepAt = this._fx.now();
        return { needPassword: true, srpParams: params };
      }
      if (e.message === "PHONE_CODE_INVALID" || e.message === "PHONE_CODE_EXPIRED") {
        c.codeGuesses += 1;
        if (c.codeGuesses >= CAPS.CODE_GUESSES) { await this._teardown(onb, "too many code guesses"); throw new Error("code attempts exhausted"); }
        c.status = STATES.CODE_SENT;
        return { retry: true, reason: e.message };
      }
      await this._teardown(onb, `fatal sign-in: ${e.message}`);
      throw e;
    }
  }

  async submitSrpProof({ onb, A, M1 }) {
    const c = this._ctx(onb);
    if (c.status !== STATES.AWAIT_SRP_PROOF) throw new Error("submitSrpProof out of order");
    this._checkTimeouts(c);
    try {
      await this._fx.checkPassword({ link: c.link, A, M1 });
      return await this._bindAndSeal(c);
    } catch (e) {
      if (e.message === "PASSWORD_HASH_INVALID") {
        c.srpGuesses += 1;
        if (c.srpGuesses >= CAPS.SRP_GUESSES) { await this._teardown(onb, "too many SRP guesses"); throw new Error("SRP attempts exhausted"); }
        // srpId/srp_B are single-use: re-issue fresh params on each retry.
        const params = await this._fx.getPassword({ link: c.link });
        return { retry: true, srpParams: params };
      }
      await this._teardown(onb, `fatal checkPassword: ${e.message}`);
      throw e;
    }
  }

  async _bindAndSeal(c) {
    c.status = STATES.BINDING;
    const me = await this._fx.getMe({ link: c.link });
    c.tgUserId = String(me.tgUserId);
    c.signedIn = true;
    c.status = STATES.SEALING;
    const final = await this._fx.finalizeSeal({
      link: c.link, state: c.state, expectedRecoveryDigest: c.recoveryDigest, expectedGeneration: c.recoveryGen,
      tgUserId: c.tgUserId, firstName: me.firstName, username: me.username,
    });
    c.recoveryGen = c.recoveryGen + 1;
    c.recoveryDigest = final.envelopeDigest;
    c.status = STATES.DONE;
    // Capture the session roster for the "keep" step while the transport is still
    // connected (it is torn down on disconnect below). Best-effort: a failure here
    // never fails the login — the session is already sealed; the user can review
    // from the console after arming. listSessions is read-only (getAuthorizations).
    let sessions = null;
    try { sessions = (await this._fx.listSessions?.({ link: c.link })) ?? null; } catch { sessions = null; }
    await this._fx.disconnect?.(c);
    this._sessions.delete(c.onb);
    return { done: true, tgUserId: c.tgUserId, firstName: me.firstName, username: me.username, sessions };
  }

  abort({ onb }) { return this._teardown(onb, "aborted by user"); }

  _checkTimeouts(c) {
    const now = this._fx.now();
    if (now - c.startedAt > CAPS.TOTAL_MS) { this._teardown(c.onb, "total ceremony cap exceeded"); throw new Error("ceremony expired"); }
    if ((c.status === STATES.CODE_SENT || c.status === STATES.AWAIT_SRP_PROOF) && now - c.stepAt > CAPS.PER_STEP_MS) {
      this._teardown(c.onb, "per-step timeout"); throw new Error("step expired");
    }
  }

  // The cleanup invariant (spec 4.10.4): TEARDOWN must clean up any live
  // Telegram authorization, in three cases keyed by how far the ceremony got.
  async _teardown(onb, reason) {
    const c = this._sessions.get(onb);
    if (!c) return;
    this._sessions.delete(onb);
    try {
      if (!c.sealedRecovery) {
        // Case 1: failed before the recovery commit. Telegram not contacted
        // beyond cold auth-key creation. disconnect + drop is sufficient.
        await this._fx.disconnect?.(c);
        await this._fx.markTerminal({ state: c.state, phase: "ONBOARDING", reason });
        await this._fx.deleteLink?.({ link: c.link, state: c.state });
      } else if (!c.signedIn) {
        // Case 2: recovery committed but sign-in never succeeded. Decrypt
        // recovery, disconnect the unsigned-in connection, terminalize, delete.
        await this._fx.disconnect?.(c);
        await this._fx.markTerminal({ state: c.state, phase: "ONBOARDING", reason });
        await this._fx.deleteLink?.({ link: c.link, state: c.state });
      } else {
        // Case 3: sign-in may have succeeded (incl. crash before final seal).
        // The recovery generation holds a live auth key: durably auth.logOut,
        // THEN terminalize, THEN delete. Logout/terminalize are retried.
        await this._fx.logOut({ link: c.link, state: c.state });
        await this._fx.markTerminal({ state: c.state, phase: "ONBOARDING", reason });
        await this._fx.deleteLink?.({ link: c.link, state: c.state });
      }
    } catch {
      // teardown is durable/retried by the caller's cleanup loop; never throws here
    }
    return { teardown: true, reason };
  }
}
