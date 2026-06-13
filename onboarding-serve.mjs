// gateway/onboarding-serve.mjs: the onboarding EFFECTS wiring (spec 4.10, 5.6).
// Connects the OnboardingManager's injected effects to the real gateway machinery:
// the ONBOARDING-mode transport, the v3 envelope + attested KMS GenerateDataKey,
// the gateway-only seal DB functions (0032), and the State Authority lease/record.
//
// THIS IS THE CREDENTIAL-HANDLING CORE. The single invariant that matters most:
// the plaintext Telegram session exists ONLY inside sealSession(), where it is
// immediately AEAD-sealed under a fresh attested data key (then zeroized) and only
// the CIPHERTEXT is written to the DB. It is never returned, logged, or placed in
// any DB argument. The 2FA password never reaches here at all (the browser computes
// the SRP proof; the transport relays public params out and A/M1 in).
//
// Lease lifecycle (resolved against 4.8/5.5/5.6):
//   - createLink: createOnboardingIfAbsent(state) + acquire the onboarding lease;
//   - DONE (disconnect): release the lease so the SEPARATE arm step re-acquires it;
//   - teardown (markTerminal): terminalize, which atomically clears the lease; the
//     epoch is recovered via a state->link index, or the null-holder path is used
//     after disconnect already released it. Both are valid State Authority CAS paths.
//   - finalize does ONLY the FINAL session seal (status -> connected). Arming
//     (policy genesis + promoteToArmed + adopt) is a separate step.

import { sealEnvelopeV3, envelopeDigest, newContextId, zeroize } from "./kms-envelope-v3.mjs";
import { createHash } from "node:crypto";

// > CAPS.TOTAL_MS (15m) so a single held lease covers the whole ceremony.
const ONB_LEASE_TTL_MS = 16 * 60 * 1000;

export function makeOnboardingEffects({
  db, kms, freshCreds, authorityClient, makeTransport, verifyGrant,
  holder, now = () => Date.now(),
}) {
  if (!db?.rpc || !kms?.generateDataKey || typeof freshCreds !== "function" || !authorityClient
      || typeof makeTransport !== "function" || typeof verifyGrant !== "function" || !holder) {
    throw new Error("onboarding effects: missing dependency");
  }

  const byLink = new Map();      // link -> { state, transport, signersCommit, receiptDigest, leaseEpoch }
  const stateToLink = new Map(); // state -> link (so teardown can recover the lease epoch)
  const slot = (link) => { const s = byLink.get(link); if (!s) throw new Error("onboarding: no live ceremony for this link"); return s; };
  const receiptDigestOf = (signed) => createHash("sha256").update(JSON.stringify(signed)).digest("hex");

  async function dropSlot(link) {
    const s = byLink.get(link);
    if (!s) return;
    byLink.delete(link);
    if (s.state) stateToLink.delete(s.state);
    try { await s.transport?.disconnect(); } catch { /* already down */ }
  }

  // The ONLY place a plaintext session and a data key meet. Seals -> zeroizes ->
  // returns ciphertext + the CAS digest. The session string never leaves here.
  async function sealSession({ link, state, sealPhase, sealGeneration, tgUserId, signersCommit }) {
    const transport = slot(link).transport;
    if (!transport) throw new Error("seal: ceremony has no connected transport");
    const contextId = newContextId();
    const creds = await freshCreds();
    const { plaintextKey, encryptedDataKey } = await kms.generateDataKey({ contextId, creds });
    let env;
    try {
      env = sealEnvelopeV3({
        dataKey: plaintextKey, session: transport.exportSession(),
        sealPhase, sealGeneration, linkId: link, tgUserId, stateId: state,
        kmsContextId: contextId, signersCommit,
      });
    } finally {
      zeroize(plaintextKey);
    }
    const digest = envelopeDigest({ encryptedDataKey, nonce: env.nonce, ciphertext: env.ciphertext, tag: env.tag, kmsContextId: contextId, sealGeneration });
    return { contextId, encryptedDataKey, nonce: env.nonce, ciphertext: env.ciphertext, tag: env.tag, digest };
  }

  return {
    now,
    verifyGrant,

    // Durable atomic rate cap, gateway-only DB fn; RAISEs (rejects) if exceeded.
    rateCheck: async ({ phone, rateKey }) => {
      await db.rpc("onboarding_rate_check", { p_phone: phone, p_rate_key: rateKey ?? "" });
    },

    createLink: async ({ link, state, phone, signersCommit, grantDigest, ownerEmail, userId }) => {
      const rec = await authorityClient.createOnboardingIfAbsent(state);
      const lease = await authorityClient.acquireLease(state, holder, ONB_LEASE_TTL_MS);
      byLink.set(link, { state, transport: null, signersCommit, receiptDigest: receiptDigestOf(rec), leaseEpoch: lease.record.lease_epoch });
      stateToLink.set(state, link);
      await db.rpc("create_onboarding_link", {
        p_link: link, p_state_id: state, p_phone: phone,
        p_signers_commit: signersCommit, p_owner_email: ownerEmail ?? null,
        p_user_id: userId ?? null, // ownership: getOwnedLinkId matches this vs the auth session
      });
    },

    connect: async (c) => {
      const transport = await makeTransport();
      // Store the transport BEFORE connect() so that if the cold handshake throws
      // (or starts an autoReconnect loop), _teardown -> disconnect can find it and
      // stop it. Otherwise a failed connect leaks a reconnecting GramJS sender.
      slot(c.link).transport = transport;
      await transport.connect();        // mints the auth key (cold handshake)
    },

    sealRecovery: async ({ link, state, generation, signersCommit, grantDigest }) => {
      if (generation !== 1) throw new Error("sealRecovery: first generation must be 1");
      const s = await sealSession({ link, state, sealPhase: "RECOVERY", sealGeneration: 1, tgUserId: null, signersCommit });
      await db.rpc("seal_onboarding_recovery", {
        p_link: link, p_state_id: state, p_version: 3, p_seal_generation: 1,
        p_encrypted_data_key: s.encryptedDataKey, p_nonce: s.nonce, p_ciphertext: s.ciphertext, p_tag: s.tag,
        p_context_id: s.contextId, p_signers_commit: signersCommit, p_grant_digest: grantDigest,
        p_state_receipt_digest: slot(link).receiptDigest, p_envelope_digest: s.digest,
      });
      return { envelopeDigest: s.digest };
    },

    rotateRecovery: async ({ link, state, expectedRecoveryDigest, expectedGeneration, signersCommit }) => {
      const sc = signersCommit ?? slot(link).signersCommit;
      const s = await sealSession({ link, state, sealPhase: "RECOVERY", sealGeneration: expectedGeneration + 1, tgUserId: null, signersCommit: sc });
      await db.rpc("rotate_onboarding_recovery", {
        p_link: link, p_state_id: state, p_expected_recovery_digest: expectedRecoveryDigest, p_expected_generation: expectedGeneration,
        p_encrypted_data_key: s.encryptedDataKey, p_nonce: s.nonce, p_ciphertext: s.ciphertext, p_tag: s.tag,
        p_context_id: s.contextId, p_envelope_digest: s.digest,
      });
      return { envelopeDigest: s.digest };
    },

    // Transport-routed effects (per-ceremony via link).
    sendCode: ({ link, phone }) => slot(link).transport.sendCode({ phone }),
    signIn: ({ link, phone, hash, code }) => slot(link).transport.signIn({ phone, hash, code }),
    getPassword: ({ link }) => slot(link).transport.getPassword(),
    checkPassword: ({ link, A, M1 }) => slot(link).transport.checkPassword({ A, M1 }),
    getMe: ({ link }) => slot(link).transport.getMe(),
    listSessions: ({ link }) => slot(link).transport.listSessions(),

    finalizeSeal: async ({ link, state, expectedRecoveryDigest, expectedGeneration, tgUserId, firstName, username }) => {
      const sc = slot(link).signersCommit;
      const s = await sealSession({ link, state, sealPhase: "FINAL", sealGeneration: expectedGeneration + 1, tgUserId, signersCommit: sc });
      await db.rpc("finalize_session_seal", {
        p_link: link, p_state_id: state, p_expected_recovery_digest: expectedRecoveryDigest, p_expected_generation: expectedGeneration,
        p_encrypted_data_key: s.encryptedDataKey, p_nonce: s.nonce, p_ciphertext: s.ciphertext, p_tag: s.tag,
        p_context_id: s.contextId, p_version: 3, p_tg_user_id: tgUserId, p_signers_commit: sc,
        p_envelope_digest: s.digest, p_first_name: firstName ?? null, p_username: username ?? null,
      });
      return { envelopeDigest: s.digest };
    },

    logOut: async ({ link }) => { try { await byLink.get(link)?.transport?.logOut(); } catch { /* dead session = gone */ } },

    markTerminal: async ({ state, phase, reason }) => {
      const link = stateToLink.get(state);
      const epoch = link ? (byLink.get(link)?.leaseEpoch ?? 0) : 0;
      // terminalize atomically clears the lease; holder path if we still hold it,
      // null-holder path if disconnect already released it. Idempotent.
      await authorityClient.markTerminal(state, holder, epoch, phase ?? "ONBOARDING", reason);
    },

    deleteLink: async ({ link, state }) => {
      await db.rpc("delete_onboarding_link", { p_link: link, p_state_id: state });
      await dropSlot(link);
    },

    // DONE path: release the lease so the separate arm step can re-acquire it, then
    // tear down the live transport.
    disconnect: async (c) => {
      const s = byLink.get(c.link);
      if (s) { try { await authorityClient.releaseLease(s.state, holder, s.leaseEpoch); } catch { /* may be released/terminal already */ } }
      await dropSlot(c.link);
    },
  };
}
