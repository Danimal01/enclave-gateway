// gateway/gateway.mjs: the gateway RPC server that composes the audited modules
// into the session-holding open enclave (gateway-brain-architecture.md 4.2).
//
// It owns the ENTIRE session/Telegram/decrypt surface and nothing else:
//   - KMS decrypt of the v3 sealed session (kms-envelope-v3) -> binding-1;
//   - the MTProto sender behind the audited chokepoint (tg-chokepoint +
//     audited-sender) -> binding-2 after connect and every reconnect;
//   - the open policy-authority verifier (policy-verify) -> op enforcement;
//   - the State Authority lease/head client (state-authority) -> self-fence;
//   - the closed-verb-set brain protocol (brain-protocol) -> handle requests.
//
// This module is the orchestration seam. The Telegram transport (the minimal
// MTProto client, 4.2) and the live KMS credentials are injected so the bulk of
// the gateway is unit-testable without an enclave; the EIF wires the real
// implementations. The brain holds none of this: it talks only the closed verb
// set over the admitted channel.

import { MODES } from "./tg-chokepoint.mjs";
import { deriveAuthority, assertOpAllowed, payloadHash } from "./policy-verify.mjs";
import { decodeRequest, encodeResponse, encodeEvent } from "./brain-protocol.mjs";
import { Brain } from "./brain.mjs";

// FLOOD_WAIT detection. GramJS rewrites FloodWaitError's `.message` to a human
// sentence ("A wait of N seconds is required ...") but keeps the wait on
// `.seconds`; the chokepoint may also surface the canonical FLOOD_WAIT_N code.
// Match all three so a rate-limited account backs off for exactly as long as
// Telegram demands instead of hammering and extending the penalty.
function floodWaitSeconds(e) {
  if (!e) return null;
  if (typeof e.seconds === "number" && e.seconds >= 0) return e.seconds;
  const msg = String(e.errorMessage ?? e.message ?? "");
  const m = /FLOOD_WAIT_(\d+)|A wait of (\d+) seconds/i.exec(msg);
  return m ? Number(m[1] ?? m[2]) : null;
}

// Ops that actually touch Telegram (WHO_AM_I answers from cached identity, so it
// is excluded). These are the ops a FLOOD_WAIT backoff must suppress.
const MTPROTO_OPS = new Set(["LIST_SESSIONS", "READ_SECURITY_STATE", "EVICT_SESSION", "DECLINE_RESET", "LOGOUT_SELF", "REFRESH_UPDATES"]);

// L1 self-heal (always-healthy design): an adopted account must complete a real
// Telegram round-trip (a sweep/security read, or the connection's 15s keepalive
// ping) within this window; otherwise its connection is presumed wedged and the
// per-account watchdog rebuilds it surgically (same lease, no enclave restart).
// Must be > the keepalive interval (15s, so a quiet healthy account is proven
// alive ~5x per window) and < the lease TTL (~60s). 75s tolerates ~5 missed pings.
const LIVENESS_STALE_MS = Number(process.env.GW_LIVENESS_STALE_MS || 75000);
// After this many failed surgical reconnects, escalate to selfFence + re-adopt (L2).
const MAX_RECONNECT_ATTEMPTS = 5;

// Stable signature of the LIVE roster. Includes every security-relevant and
// display-identity field (IP, country, device, app, unconfirmed) so a session
// that moves or appears unconfirmed republishes. Only the high-churn timestamps
// (dateActive/dateCreated) are excluded — those advance constantly and would
// defeat the dedup; the dashboard recomputes "X ago" client-side regardless.
function rosterSignature(sessions) {
  if (!Array.isArray(sessions)) return "";
  return sessions
    .map((s) => [
      s.hash, s.current ? 1 : 0, s.unconfirmed ? 1 : 0,
      s.ip ?? "", s.country ?? "", s.region ?? "",
      s.deviceModel ?? "", s.platform ?? "", s.systemVersion ?? "", s.appName ?? "",
    ].join(""))
    .sort()
    .join("|");
}

// Human-readable reason strings for the typed activity-feed events the gateway
// records. Kinds match lib/activity-events.tsx (the dashboard contract).
const EVENT_REASON = {
  login_new: "New Telegram login detected",
  device_evicted: "Removed a session that was not on the signed keep-list",
  session_terminated_elsewhere: "A session was signed out elsewhere",
  session_location_changed: "A session changed location",
  twofa_enabled: "Two-step verification was turned on",
  twofa_disabled: "Two-step verification was turned off",
  reset_requested: "A 2FA-password reset was requested",
  reset_blocked: "A pending 2FA-password reset was declined",
  reset_cancelled: "A pending 2FA-password reset was cancelled",
  recovery_set: "A 2FA recovery email was set",
  login_email_set: "A login email was set",
  account_ttl_changed: "The account self-destruct timer changed",
  session_ttl_changed: "The session auto-terminate timer changed",
  account_frozen: "Telegram froze the account",
  eviction_rate_capped: "Multiple unauthorized sessions are being removed in batches",
  guard_connected: "Your Sessions guard connected",
  guard_disconnected: "Your Sessions guard disconnected and signed out of your account",
};

export class Gateway {
  // deps:
  //   kms              : { generateDataKey, decryptDataKey } (kms-envelope-v3 transport)
  //   openEnvelopeV3   : the v3 open function (binding-1 byte-compares)
  //   authorityClient  : StateAuthorityClient
  //   policyStore      : async (linkId) => ordered policy_envelopes rows
  //   verifierCfg      : { rpId, origins, googleClientId } for signature checks
  //   transportFactory : async ({ mode }) => { sender, connect, disconnect,
  //                       whoAmI, listSessions, readSecurityState, onNewAuth }
  //                       a minimal MTProto client bound to ONE connection
  //   now/monotonic    : injectable clocks
  constructor(deps) {
    this._d = deps;
    this._accts = new Map();   // acctHandle -> live account context (private)
    this._byState = new Map(); // state_id -> acctHandle
  }

  _clock() { return (this._d.now ?? (() => Date.now()))(); }
  // Monotonic clock for liveness/lease deadlines (never walks backward on NTP step).
  _mono() { return (this._d.monotonic ?? (() => Date.now()))(); }

  // Adopt an armed link: acquire the lease, KMS-open the v3 FINAL envelope under
  // the exact context, run binding-1/2, derive authority, and start serving.
  async adopt(row, holder, leaseTtlMs) {
    const { authorityClient, policyStore, verifierCfg } = this._d;

    // 1. State Authority: read -> reject TERMINAL -> acquire the exclusive lease.
    const rec = await authorityClient.read(row.state_id);
    if (rec.phase === "TERMINAL") throw new Error("adopt: account is terminal");
    if (rec.phase !== "ARMED") throw new Error(`adopt: account not ARMED (phase ${rec.phase})`);
    const lease = await authorityClient.acquireLease(row.state_id, holder, leaseTtlMs);
    const gen = lease.record.lease_epoch;

    const handle = `acct-${row.state_id}`;
    let tx = null;
    try {
      // 2-3. KMS-open the FINAL envelope (binding-1) + connect the audited armed
      // transport + binding-2 whoAmI. Shared with recoverAccount (L1) so a rebuild
      // re-opens the sealed session through KMS with identical semantics.
      tx = await this._openAndConnect(handle, row, row.tg_user_id);

      // 4. Derive authority from the signed chain anchored at the State Authority head.
      // A pending signed disconnect sits one past the committed head (the link is
      // 'disconnecting'); we adopt on the SA-anchored armed authority and let
      // reconcileDisconnect re-verify the full chain and finalize the logout.
      // Filtering to the committed head keeps the fail-closed anchor check intact
      // (a Postgres-injected envelope past the head is ignored here, and is only
      // ever trusted after reconcileDisconnect independently re-verifies its
      // signatures) AND lets a restart re-adopt a 'disconnecting' link so the
      // disconnect actually completes.
      const allRows = await policyStore(row.id);
      const rows = (allRows ?? []).filter((r) => r.version <= rec.policy_version);
      const derived = await deriveAuthority(rows, {
        linkId: row.id, tgUserId: row.tg_user_id, signersCommit: row.signers_commit,
        now: this._d.now ?? (() => Date.now()), ...verifierCfg,
      }, { version: rec.policy_version, hash: rec.policy_head_hash });
      if (!derived.ok) throw new Error(`adopt: policy authority rejected: ${derived.reason}`);

      const parsedFreshUntil = row.fresh_until ? Date.parse(row.fresh_until) : NaN;
      const ctx = {
        handle, stateId: row.state_id, linkId: row.id, tgUserId: String(row.tg_user_id),
        gen, holder, leaseDeadline: lease.localDeadline, tx, authority: derived.authority,
        freshUntil: Number.isFinite(parsedFreshUntil) ? parsedFreshUntil : null,
        opChain: Promise.resolve(), // serializes all MTProto work for this account
        floodUntil: null,      // set when Telegram rate-limits; suppresses MTProto until it elapses
        lastPublishSig: null,  // last roster signature published; skips redundant snapshot rewrites
        security: null,        // last published security-notes view (has_2fa, reset_pending, ttls, frozen)
        lastRoster: null,      // previous live roster, for session_terminated_elsewhere / location_changed diff
        massEvictUntil: null,  // per-burst dedup window for eviction_rate_capped
        renewFail: 0,          // consecutive lease-renewal failures (C6: tolerate transients before fencing)
        frozenUntil: null,     // backoff while the account is frozen (account_frozen)
        frozenAlerted: false,  // one-shot guard for the account_frozen event
        // L1 self-heal state:
        row,                   // the sealed (encrypted) descriptor, retained for KMS-reopen on rebuild
        lastRtOkAt: this._mono(), // monotonic ts of the last successful Telegram round-trip (proven-work liveness)
        reconnectAttempts: 0,  // consecutive failed surgical reconnects, escalates to selfFence at MAX
        downSince: null,       // monotonic ts the account first went unhealthy (for honest degraded reporting)
        selfHealing: false,    // re-entrancy guard while recoverAccount is rebuilding this account
        degradedAlerted: false,// one-shot guard for a future guard_degraded event
      };
      this._accts.set(handle, ctx);
      this._byState.set(row.state_id, handle);
      ctx.brain = new Brain({
        gateway: { call: (op, arg) => this._call(handle, op, arg) },
        policyView: async () => this._buildPolicyView(handle),
        now: this._d.now ?? (() => Date.now()),
        log: this._d.logger ?? (() => {}),
      });
      return { handle, gen };
    } catch (e) {
      if (tx) { try { await tx.disconnect(); } catch { /* failed adoption */ } }
      try { await authorityClient.releaseLease(row.state_id, holder, gen); } catch { /* lease expires if release is unavailable */ }
      throw e;
    }
  }

  _ctx(acct, gen) {
    const ctx = this._accts.get(acct);
    if (!ctx) throw new Error("unknown acct handle");
    if (gen !== undefined && gen !== ctx.gen) throw new Error("stale gen: request outside current leased epoch");
    if ((this._d.monotonic ?? (() => 0))() > ctx.leaseDeadline) throw new Error("lease expired: self-fenced");
    return ctx;
  }

  // Handle one decoded brain request. Reads need no token; mutating ops are
  // re-checked against the freshly derived authority (the gateway is the ceiling).
  async handleRequest(frame) {
    const req = decodeRequest(frame);
    try {
      const ctx = this._ctx(req.acct, req.gen);
      const body = await this._dispatch(ctx, req);
      return encodeResponse({ id: req.id, ok: true, body });
    } catch (e) {
      return encodeResponse({ id: req.id, ok: false, code: e.message.slice(0, 80), body: {} });
    }
  }

  async _dispatch(ctx, req) {
    switch (req.op) {
      case "WHO_AM_I":
        return { tgUserId: ctx.tgUserId };
      case "LIST_SESSIONS":
        return { sessions: await ctx.tx.listSessions() };
      case "READ_SECURITY_STATE":
        return await ctx.tx.readSecurityState();
      case "EVICT_SESSION": {
        const freshRoster = await ctx.tx.listSessions();
        const gate = assertOpAllowed(ctx.authority, "EVICT_SESSION", { hash: req.arg.hash, freshRoster });
        if (!gate.ok) throw new Error(`evict refused: ${gate.reason}`);
        // Re-bind the chokepoint's evict gate to THIS exact, policy-approved hash.
        const removed = await ctx.tx.evictSession(req.arg.hash, {
          assertEvictAllowed: (h) => { if (String(h) !== String(req.arg.hash)) throw new Error("evict hash drift"); },
        });
        return { removed };
      }
      case "DECLINE_RESET": {
        const gate = assertOpAllowed(ctx.authority, "DECLINE_RESET");
        if (!gate.ok) throw new Error(`decline refused: ${gate.reason}`);
        return { declined: await ctx.tx.declineReset() };
      }
      case "LOGOUT_SELF": {
        const gate = assertOpAllowed(ctx.authority, "LOGOUT_SELF");
        if (!gate.ok) throw new Error(`logout refused: ${gate.reason}`);
        return { goneOrDead: await ctx.tx.logOutSelf() };
      }
      case "REFRESH_UPDATES":
        // A pure read (updates.getState) that needs no policy gate: it only keeps
        // Telegram's update-delivery window open so new-login pushes arrive in real
        // time (see refreshUpdatesAll). Flood-backoff is applied by _call.
        return { refreshed: await ctx.tx.refreshUpdates() };
      default:
        throw new Error(`unknown op ${req.op}`);
    }
  }

  // ---- in-process detection surface (Option A) --------------------------------
  // The detection engine (brain.mjs) runs inside the gateway and reaches the
  // account ONLY through these. _call is the in-process equivalent of a decoded
  // brain request: it dispatches straight to the same op handler that the chokepoint
  // bounds, so detection can do nothing a remote brain could not.
  async _call(handle, op, arg) {
    const ctx = this._ctx(handle);
    // Flood backoff is enforced HERE, at the single in-process chokepoint every
    // MTProto op crosses — not in the brain (which swallows EVICT/DECLINE errors,
    // so a FLOOD_WAIT from those never reaches a caller) and not in sweepAccount.
    // While rate-limited, refuse MTProto ops without touching Telegram; the brain's
    // per-op try/catch logs and moves on, producing zero traffic during the wait.
    if (MTPROTO_OPS.has(op) && ctx.floodUntil && this._clock() < ctx.floodUntil) {
      throw new Error("flood-backoff");
    }
    try {
      return await this._dispatch(ctx, { op, arg });
    } catch (e) {
      const wait = floodWaitSeconds(e);
      if (wait != null) {
        ctx.floodUntil = this._clock() + wait * 1000;
        this._d.logger?.(`[${handle}] flood-wait ${wait}s — backing off MTProto`);
      }
      throw e;
    }
  }

  // Keep Telegram's update channel WARM so a new login (UpdateNewAuthorization) is
  // PUSHED in ~60ms instead of only surfacing on the ~45s getAuthorizations sweep.
  // Measured behavior (experiments/probe.mjs): Telegram delivers updates to an
  // otherwise-quiet connection only while it keeps receiving a CONTENT request inside
  // a short window (~30s). A transport ping does NOT count, but updates.getState does;
  // re-issuing it every ~12s holds that window open, turning detection from sweep-bound
  // into real-time async push. Routed through _call so it shares each account's
  // FLOOD_WAIT backoff (it cannot hammer during a wait) and the lease/self-fence checks,
  // and a successful refresh also stamps L1 liveness. Best-effort + fire-and-forget: a
  // skipped/failed tick just lets that one channel cool until the next, with the
  // getAuthorizations sweep as the authoritative backstop. Not awaited, so one slow
  // account never starves the others.
  refreshUpdatesAll() {
    for (const handle of this._accts.keys()) {
      const ctx = this._accts.get(handle);
      if (ctx?.floodUntil && this._clock() < ctx.floodUntil) continue; // already backing off
      this._call(handle, "REFRESH_UPDATES").catch(() => { /* the sweep is the backstop */ });
    }
  }

  // The policy view detection plans against, built from the AUTHORITATIVE derived
  // policy (not a separate planning store). Null => watch-only (evict nothing).
  _buildPolicyView(handle) {
    const ctx = this._accts.get(handle);
    if (!ctx?.authority) return null;
    return {
      whitelist: new Set((ctx.authority.whitelist ?? []).map(String)),
      resetProtection: !!ctx.authority.resetProtection,
      freshUntil: ctx.freshUntil ?? null,
      authToken: ctx.authority.headHash ?? "in-process",
    };
  }

  // React to a typed NEW_AUTH event in-process: an immediate protective sweep.
  async _onNewAuth(handle, evt) {
    const ctx = this._accts.get(handle);
    if (!ctx) return; // no account context at all -> nothing to attribute the event to
    // Record a login_new ONLY for a hash that is, right now, a REAL non-current,
    // non-whitelisted session. Telegram reports the guard's OWN session as hash 0, so
    // the push's real hash never matches a present non-current session -- this stops the
    // guard flagging its own onboarding login (or a transient setup authorization) as a
    // scary "new login from an unknown device". A genuine intruder's hash IS present,
    // non-current and unwhitelisted, so it is still recorded instantly. Fail-OPEN if the
    // roster can't be confirmed (flood/transient): record anyway so a real alert is never
    // dropped -- this gates on the ROSTER, not brain-readiness, so the C1 adoption-window
    // push is not lost.
    let shouldRecord = true;
    try {
      const view = this._buildPolicyView(handle);
      const { sessions } = await this._call(handle, "LIST_SESSIONS", {});
      const match = (sessions ?? []).find((s) => String(s.hash) === String(evt.hash));
      shouldRecord = !!match && !match.current && !view?.whitelist?.has(String(evt.hash));
    } catch { /* fail-open: keep shouldRecord = true */ }
    if (shouldRecord) {
      try {
        await this._d.recordEvent?.({
          linkId: ctx.linkId,
          kind: "login_new",
          reason: EVENT_REASON.login_new,
          detail: {
            hash: evt.hash, unconfirmed: !!evt.unconfirmed,
            device: evt.device ?? null, location: evt.location ?? null,
          },
        });
      } catch (e) {
        this._d.logger?.(`event publish failed for ${ctx.linkId}: ${e.message}`);
      }
    }
    // Protective sweep only once the brain is up (detection is best-effort).
    if (ctx.brain) {
      try { await this.sweepAccount(handle); }
      catch { /* the chokepoint bounds the blast radius */ }
    }
  }

  // Serialize all MTProto work for one account onto a single chain so a periodic
  // sweep, a NEW_AUTH-driven sweep, and the reset-protection check never issue
  // concurrent calls on the same connection.
  _runSerial(ctx, fn) {
    const next = ctx.opChain.then(fn, fn);
    ctx.opChain = next.catch(() => {});
    return next;
  }

  // One protective sweep for an adopted account (poll-driven by gateway-main).
  async sweepAccount(handle) {
    const ctx = this._accts.get(handle);
    if (!ctx?.brain) return null;
    const run = async () => {
      // While rate-limited, do not touch MTProto at all (the backoff is set in
      // _call). Hammering during a FLOOD_WAIT only extends the penalty. We also do
      // NOT stamp last_poll here: the dashboard already explains a stale poll during
      // a Telegram freeze as "healing on its own," which is the honest signal.
      if (ctx.floodUntil && this._clock() < ctx.floodUntil) {
        return { listed: 0, proposed: 0, removed: 0, skipped: "flood-backoff", sessions: [], evicted: [] };
      }
      let result;
      try {
        result = await ctx.brain.sweep(handle);
      } catch (e) {
        // _call already recorded the backoff window for a flood; treat it as a skip.
        if (ctx.floodUntil && this._clock() < ctx.floodUntil) {
          return { listed: 0, proposed: 0, removed: 0, skipped: "flood-backoff", sessions: [], evicted: [] };
        }
        throw e;
      }
      // A LIST may have succeeded but an EVICT may have raised FLOOD_WAIT inside
      // Brain.sweep's per-candidate catch. _call records that wait centrally; do
      // not clear it merely because the brain returned a summary.
      if (ctx.floodUntil && this._clock() < ctx.floodUntil) {
        return { ...result, skipped: "flood-backoff" };
      }
      ctx.floodUntil = null; // clear only an expired/stale prior backoff
      // Post-eviction roster = the listed roster minus what we just removed.
      const evictedHashes = new Set((result.evicted ?? []).map((e) => String(e.hash)));
      const sessions = evictedHashes.size > 0
        ? (result.sessions ?? []).filter((s) => !evictedHashes.has(String(s.hash)))
        : (result.sessions ?? []);

      // ── activity events (collected, then recorded OUTSIDE the publish try/catch) ──
      const events = [];

      // Roster diff (C3): the user removing a session elsewhere, or a session moving.
      // Seed on the first sweep (no events for a pre-existing roster); evictions are
      // attributed to device_evicted below, not double-counted as "terminated".
      if (ctx.lastRoster) {
        const curByHash = new Map(sessions.map((s) => [String(s.hash), s]));
        const prevByHash = new Map(ctx.lastRoster.map((s) => [String(s.hash), s]));
        for (const [hash, p] of prevByHash) {
          if (!curByHash.has(hash) && !evictedHashes.has(hash)) {
            events.push({ kind: "session_terminated_elsewhere", hash, deviceModel: p.deviceModel ?? null, country: p.country ?? null, detail: { device: p.deviceModel ?? p.appName ?? null, country: p.country ?? null } });
          }
        }
        for (const [hash, cu] of curByHash) {
          const p = prevByHash.get(hash);
          if (p && (String(cu.country ?? "") !== String(p.country ?? "") || String(cu.region ?? "") !== String(p.region ?? ""))) {
            // Dashboard renders detail.device + detail.country (the NEW location).
            events.push({ kind: "session_location_changed", hash, deviceModel: cu.deviceModel ?? null, country: cu.country ?? null, detail: { device: cu.deviceModel ?? cu.appName ?? null, country: cu.country ?? null, from: p.country ?? null } });
          }
        }
      }
      ctx.lastRoster = sessions;

      // device_evicted (one per removed session).
      for (const row of result.evicted ?? []) {
        events.push({ kind: "device_evicted", hash: String(row.hash), deviceModel: row.deviceModel ?? null, ip: row.ip ?? null, country: row.country ?? null, detail: { device: row.deviceModel ?? row.appName ?? null, country: row.country ?? null } });
      }

      // eviction_rate_capped (H4): the brain capped a mass-eviction; alert once/burst.
      // Only when we ACTUALLY evicted a full batch this sweep AND more remain -- i.e. a
      // genuine flood being whittled down. Without the removed>0 guard this misfired
      // during the 24h fresh window (removed:0 but pending = every detected session), so
      // a single held login rendered a bogus "removing N, 3 at a time" alert.
      if ((result.removed ?? 0) > 0 && (result.pending ?? 0) > 0 && (!ctx.massEvictUntil || this._clock() >= ctx.massEvictUntil)) {
        ctx.massEvictUntil = this._clock() + 3600000;
        events.push({ kind: "eviction_rate_capped", detail: { total: (result.pending ?? 0) + (result.removed ?? 0), perSweep: 3 } });
      } else if ((result.pending ?? 0) === 0) {
        ctx.massEvictUntil = null;
      }

      // Stamp liveness on EVERY successful sweep (dashboard gates PROTECTED on a
      // fresh last_poll). Ship the full roster only when it changed, and ALWAYS
      // include the security notes view so a roster-only publish never clobbers the
      // 2FA/reset/recovery/TTL state the 5-min check maintains.
      const sig = rosterSignature(sessions);
      const rosterChanged = sessions.length > 0 && (result.removed > 0 || sig !== ctx.lastPublishSig);
      try {
        await this._d.publishState?.({ linkId: ctx.linkId, sessions: rosterChanged ? sessions : null, status: "active", notes: { ...(ctx.security ?? {}) } });
        if (rosterChanged) ctx.lastPublishSig = sig;
      } catch (e) {
        this._d.logger?.(`state publish failed for ${ctx.linkId}: ${e.message}`);
      }
      // Record events independently of the publish (H1): a publish failure or one
      // bad event must not swallow the rest of the audit trail.
      for (const ev of events) {
        try {
          await this._d.recordEvent?.({ linkId: ctx.linkId, kind: ev.kind, reason: EVENT_REASON[ev.kind] ?? ev.kind, hash: ev.hash ?? null, deviceModel: ev.deviceModel ?? null, ip: ev.ip ?? null, country: ev.country ?? null, detail: ev.detail ?? {} });
        } catch (e) { this._d.logger?.(`event ${ev.kind} record failed for ${ctx.linkId}: ${e.message}`); }
      }
      return result;
    };
    return this._runSerial(ctx, run);
  }

  // Periodic poll: sweep + reset-protection check across every adopted account.
  async sweepAll() {
    const out = [];
    for (const handle of [...this._accts.keys()]) {
      try { out.push({ handle, sweep: await this.sweepAccount(handle) }); }
      catch (e) { out.push({ handle, error: e.message }); }
    }
    return out;
  }

  // Finalize a user-initiated disconnect (gateway-brain-architecture.md 4.9). The
  // web writes a SIGNED disconnect envelope (head action="disconnect") and flips
  // the link to 'disconnecting'; only the enclave (the auth_key holder) can
  // complete it. For each adopted account whose freshly-read signed chain ends in
  // a disconnect, we: re-verify the chain (the gateway is the ceiling, so a forged
  // Postgres row cannot trigger a logout), sign OURSELVES out of Telegram
  // (auth.LogOut, which removes the guard device from the user's account),
  // terminalize the State Authority (ARMED->TERMINAL, atomically clearing the
  // lease), publish 'disconnected', record the event, and drop the account. Every
  // step is idempotent so a crash or restart mid-way is safely retried next cycle.
  async reconcileDisconnect(handle) {
    const ctx = this._accts.get(handle);
    if (!ctx) return null;
    const { authorityClient, policyStore, verifierCfg } = this._d;

    // Cheap pre-check OUTSIDE the per-account lock: act only when the fresh signed
    // chain's head is a disconnect (the common case is no-op).
    let rows;
    try { rows = await policyStore(ctx.linkId); }
    catch (e) { this._d.logger?.(`disconnect: policy read failed for ${ctx.linkId}: ${e.message}`); return null; }
    const ordered = [...(rows ?? [])].sort((a, b) => a.version - b.version);
    const head = ordered[ordered.length - 1];
    if (!head || String(head.action) !== "disconnect") return null;

    return this._runSerial(ctx, async () => {
      if (!this._accts.has(handle)) return null; // dropped while we waited for the lock

      // If the State Authority is already TERMINAL, the logout/terminalize ran on a
      // prior (interrupted) pass; finish the DB finalize + drop idempotently.
      let rec;
      try { rec = await authorityClient.read(ctx.stateId); }
      catch (e) { this._d.logger?.(`disconnect: SA read failed for ${ctx.linkId}: ${e.message}`); return null; }

      if (rec.phase !== "TERMINAL") {
        // Re-verify the FULL signed chain ends in this disconnect (fail closed): a
        // row injected into Postgres without a valid signature quorum derives to
        // !ok, and we never touch Telegram.
        const derived = await deriveAuthority(rows, {
          linkId: ctx.linkId, tgUserId: ctx.tgUserId, signersCommit: ctx.row.signers_commit,
          now: this._d.now ?? (() => Date.now()), ...verifierCfg,
        }, { version: head.version, hash: payloadHash("disconnect", head.core) });
        if (!derived.ok) { this._d.logger?.(`disconnect REFUSED for ${ctx.linkId}: ${derived.reason}`); return null; }

        // The signed disconnect is now the authority; LOGOUT_SELF becomes permitted.
        ctx.authority = derived.authority;

        // Sign the guard's OWN session out of Telegram (removes the device from the
        // user's account). logOutSelf treats an already-dead session as "gone".
        try { await this._call(handle, "LOGOUT_SELF", {}); }
        catch (e) { this._d.logger?.(`disconnect: logout failed for ${ctx.linkId}: ${e.message}`); return null; }

        // ARMED -> TERMINAL (atomically clears the lease). Best-effort: the session
        // is already gone, so a transient SA error must not block the DB finalize;
        // it retries next cycle (rec stays ARMED) or is reconciled by guard-health.
        try { await authorityClient.markTerminal(ctx.stateId, ctx.holder, ctx.gen, "ARMED", `signed disconnect v${head.version}`, rec.policy_version, rec.policy_head_hash); }
        catch (e) { this._d.logger?.(`disconnect: markTerminal failed for ${ctx.linkId}: ${e.message}`); }
      }

      // Finalize: move the link 'disconnecting' -> 'disconnected' and record the
      // guard_disconnected event, via the enclave-only RPC. (gateway_publish_state
      // writes guard HEALTH, not the link status, and rejects non-live links, so it
      // cannot finalize a disconnect.) Gate the drop on this succeeding: the session
      // is already signed out and the State Authority is TERMINAL, so a transient DB
      // failure must RETRY (keep the account) rather than strand the row in
      // 'disconnecting'. Next cycle re-enters via the TERMINAL branch and only the
      // idempotent finalize remains.
      try { await this._d.finalizeDisconnect?.({ linkId: ctx.linkId, stateId: ctx.stateId }); }
      catch (e) { this._d.logger?.(`disconnect: finalize failed for ${ctx.linkId}: ${e.message}`); return null; }

      // Drop the live account: tear the connection down and forget the context.
      try { await ctx.tx?.disconnect(); } catch { /* already gone */ }
      this._accts.delete(handle);
      this._byState.delete(ctx.stateId);
      this._d.logger?.(`disconnect: finalized ${ctx.linkId} (session signed out, account terminal)`);
      return { disconnected: true };
    });
  }

  // Poll-driven by gateway-main: finalize any adopted account that the user has
  // disconnected. Safe to run every sweep; it is a no-op for non-disconnecting ones.
  async reconcileDisconnectsAll() {
    for (const handle of [...this._accts.keys()]) {
      try { await this.reconcileDisconnect(handle); }
      catch (e) { this._d.logger?.(`disconnect reconcile error: ${e.message}`); }
    }
  }

  async checkSecurityAll() {
    for (const handle of [...this._accts.keys()]) {
      const ctx = this._accts.get(handle);
      if (!ctx?.brain) continue;
      if (ctx.floodUntil && this._clock() < ctx.floodUntil) continue; // respect the active backoff
      // Serialize onto the same per-account chain as sweeps: the 60s/5min timers
      // coincide, and two concurrent MTProto calls on one connection race.
      if (ctx.frozenUntil && this._clock() < ctx.frozenUntil) continue; // skip a frozen account's poll
      await this._runSerial(ctx, async () => {
        let result;
        try { result = await ctx.brain.checkSecurity(handle); }
        catch (e) {
          // account_frozen (C4): Telegram froze the account (FROZEN_METHOD_INVALID).
          // Record once + 1h backoff, distinct from FLOOD_WAIT.
          if (/FROZEN_METHOD_INVALID/i.test(String(e?.message))) {
            ctx.frozenUntil = this._clock() + 3600000;
            if (!ctx.frozenAlerted) {
              ctx.frozenAlerted = true;
              ctx.security = { ...(ctx.security ?? {}), frozen: true };
              try { await this._d.recordEvent?.({ linkId: ctx.linkId, kind: "account_frozen", reason: EVENT_REASON.account_frozen, detail: {} }); } catch { /* best-effort */ }
              try { await this._d.publishState?.({ linkId: ctx.linkId, sessions: null, status: "active", notes: { ...(ctx.security ?? {}) } }); } catch { /* best-effort */ }
            }
            return;
          }
          // _call sets the backoff window on a flood; otherwise it is best-effort.
          if (!(ctx.floodUntil && this._clock() < ctx.floodUntil)) {
            this._d.logger?.(`[${handle}] security check failed: ${e.message}`);
          }
          return;
        }
        ctx.frozenAlerted = false; // a successful read clears any prior frozen flag
        // Update the published security-notes view the dashboard reads.
        const s = result.security;
        ctx.security = {
          has_2fa: s.hasPwd, has_recovery: s.hasRecovery, reset_pending: s.pendingReset,
          account_ttl_days: s.accountTtlDays, session_ttl_days: s.sessionTtlDays, frozen: false,
        };
        // Record the typed change events (twofa/reset/recovery/login-email/ttl).
        for (const ev of result.events ?? []) {
          try { await this._d.recordEvent?.({ linkId: ctx.linkId, kind: ev.kind, reason: EVENT_REASON[ev.kind] ?? ev.kind, detail: ev.detail ?? {} }); }
          catch (e) { this._d.logger?.(`event ${ev.kind} record failed for ${ctx.linkId}: ${e.message}`); }
        }
        // Publish the security state into guard_state.notes (full view, never {}).
        try { await this._d.publishState?.({ linkId: ctx.linkId, sessions: null, status: "active", notes: { ...ctx.security } }); }
        catch (e) { this._d.logger?.(`security publish failed for ${ctx.linkId}: ${e.message}`); }
      }).catch(() => {});
    }
  }

  // The gateway emits only the typed NEW_AUTH event; the raw stream never crosses.
  encodeNewAuth(acct, body) {
    return encodeEvent({ kind: "NEW_AUTH", acct, body: { hash: body.hash, unconfirmed: body.unconfirmed, device: body.device, location: body.location } });
  }

  // Count of currently-served accounts (boot/health observability).
  adoptedCount() { return this._accts.size; }

  // Is this state_id currently adopted/served? Lets the periodic re-adopt loop
  // skip links already guarded and pick up any that aren't (post-restart lease
  // race, a self-fenced account, or a newly-armed link).
  isAdopted(stateId) { return this._byState.has(stateId); }

  // Lease watchdog: renew every adopted account's lease before it expires and
  // refresh its conservative local deadline. A failed renewal self-fences that
  // account (5.5): only one unexpired holder may ever serve.
  async renewAllLeases(ttlMs) {
    for (const [handle, ctx] of [...this._accts]) {
      try {
        const { localDeadline } = await this._d.authorityClient.renewLease(ctx.stateId, ctx.holder, ctx.gen, ttlMs);
        ctx.leaseDeadline = localDeadline;
        ctx.renewFail = 0;
      } catch (e) {
        // C6: tolerate a transient State-Authority blip. Renewal runs every 20s and
        // the local lease deadline (~60s, enforced in _ctx) is the hard self-fence
        // backstop -- so ONE failed renewal must not drop a healthy guard to DOWN
        // (the flapping bug). Fence only after 3 consecutive failures (~60s ≈ TTL).
        ctx.renewFail = (ctx.renewFail ?? 0) + 1;
        if (ctx.renewFail >= 3) await this.selfFence(handle, `lease renewal failed: ${e.message}`);
        else this._d.logger?.(`[${handle}] lease renewal transient failure ${ctx.renewFail}/3: ${e.message}`);
      }
    }
  }

  // Self-fence: stop accepting RPC, drop the live sender, zero session material,
  // on any lease-renewal failure or stale-gen (5.5 H-4).
  async selfFence(acct, reason) {
    const ctx = this._accts.get(acct);
    if (!ctx) return;
    this._accts.delete(acct);
    this._byState.delete(ctx.stateId);
    try { await ctx.tx.disconnect(); } catch { /* already down */ }
    try {
      await this._d.publishState?.({ linkId: ctx.linkId, sessions: null, status: "down", notes: { reason } });
    } catch { /* the off-box heartbeat also detects an unavailable gateway */ }
  }

  // Open the sealed FINAL envelope through KMS (binding-1), build the audited armed
  // transport, connect, and verify binding-2 (whoAmI == expected). Shared by adopt
  // (first connect) and recoverAccount (L1 rebuild) so a rebuild re-opens the sealed
  // session with identical semantics. The plaintext session is zeroed the moment the
  // transport consumes it; the encrypted envelope (ctx.row) is re-decrypted fresh on
  // every rebuild and never cached open.
  async _openAndConnect(handle, row, expectedTgUserId) {
    const dataKey = await this._d.kms.decryptDataKey({
      encryptedDataKey: row.seal_encrypted_data_key, contextId: row.kms_context_id, creds: await this._d.freshCreds(),
    });
    let opened;
    try {
      opened = this._d.openEnvelopeV3({
        dataKey,
        nonce: row.seal_nonce, ciphertext: row.seal_ciphertext, tag: row.seal_tag,
        expected: {
          sealPhase: "FINAL", sealGeneration: row.seal_generation,
          linkId: row.id, tgUserId: row.tg_user_id, stateId: row.state_id,
          kmsContextId: row.kms_context_id, signersCommit: row.signers_commit,
        },
      });
    } finally {
      dataKey.fill(0);
    }
    // onReconnect: catch any login that happened during a GramJS-internal reconnect.
    // onRtOk: stamp proven-work liveness on EVERY successful round-trip (both sweeps
    // and the 15s keepalive ping route through invoke()), so a quiet-but-healthy
    // account stays provably alive and the watchdog never false-trips it.
    const tx = await this._d.transportFactory({
      mode: MODES.ARMED,
      session: opened.session,
      onNewAuth: (evt) => this._onNewAuth(handle, evt),
      onReconnect: () => { this.sweepAccount(handle).catch(() => {}); },
      onRtOk: () => { const c = this._accts.get(handle); if (c) c.lastRtOkAt = this._mono(); },
    });
    opened.session = null;
    await tx.connect();
    const me = await tx.whoAmI();
    if (String(me.tgUserId) !== String(expectedTgUserId)) {
      try { await tx.disconnect(); } catch { /* nothing to clean */ }
      throw new Error("binding-2 identity mismatch");
    }
    return tx;
  }

  // L1: the per-account liveness watchdog. Runs on its OWN timer (gateway-main),
  // entirely OUTSIDE the per-account opChain, so it can notice a chain that is
  // wedged behind a dead promise -- the exact thing that made the 2026-06-14
  // outage invisible. For each account whose last proven round-trip is older than
  // LIVENESS_STALE_MS, trigger a surgical rebuild. Deliberately-quiet accounts
  // (flood/frozen backoff) are stamped, not tripped.
  accountWatchdog() {
    const mono = this._mono();
    for (const [handle, ctx] of [...this._accts]) {
      if (ctx.selfHealing) continue;
      const quiet = (ctx.floodUntil && this._clock() < ctx.floodUntil) || (ctx.frozenUntil && this._clock() < ctx.frozenUntil);
      if (quiet) { ctx.lastRtOkAt = mono; continue; }
      if (mono - ctx.lastRtOkAt > LIVENESS_STALE_MS) {
        this._d.logger?.(`[${handle}] liveness stale ${Math.round((mono - ctx.lastRtOkAt) / 1000)}s -> self-heal`);
        this.recoverAccount(handle).catch(() => {}); // detached: never block the watchdog loop
      }
    }
  }

  // L1: surgically rebuild ONE account's connection with no enclave restart and
  // WITHOUT releasing the lease (we still hold it; renewal never stopped). Abandon
  // the poisoned op chain, re-open the sealed session through KMS, reconnect, re-bind
  // identity, resume sweeping. Escalate to selfFence (L2) after MAX_RECONNECT_ATTEMPTS.
  async recoverAccount(handle) {
    const ctx = this._accts.get(handle);
    if (!ctx || ctx.selfHealing) return;
    ctx.selfHealing = true;
    if (!ctx.downSince) ctx.downSince = this._mono();
    const oldTx = ctx.tx;
    try {
      try { await oldTx?.disconnect(); } catch { /* already down */ }
      ctx.opChain = Promise.resolve(); // abandon the chain wedged behind the dead promise
      let tx;
      try {
        tx = await this._openAndConnect(handle, ctx.row, ctx.tgUserId);
      } catch (e) {
        // A binding-2 identity mismatch is NEVER retryable: do not guard the wrong
        // account. Fence immediately.
        if (/identity mismatch/i.test(String(e?.message))) {
          await this.selfFence(handle, "self-heal identity mismatch");
          return;
        }
        throw e;
      }
      const cur = this._accts.get(handle);
      if (!cur) { try { await tx.disconnect(); } catch { /* fenced mid-rebuild */ } return; }
      cur.tx = tx;
      cur.lastRtOkAt = this._mono();
      cur.reconnectAttempts = 0;
      cur.downSince = null;
      cur.degradedAlerted = false;
      this._d.logger?.(`[${handle}] self-healed: reconnected and re-bound`);
      this.sweepAccount(handle).catch(() => {}); // catch up immediately
    } catch (e) {
      ctx.reconnectAttempts = (ctx.reconnectAttempts ?? 0) + 1;
      this._d.logger?.(`[${handle}] self-heal attempt ${ctx.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} failed: ${e.message}`);
      if (ctx.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        await this.selfFence(handle, `self-heal exhausted: ${e.message}`);
      }
      // else: lastRtOkAt stays stale; the next watchdog tick re-triggers (the timer
      // cadence is the retry backoff).
    } finally {
      const cur = this._accts.get(handle);
      if (cur) cur.selfHealing = false;
    }
  }

  // Honest health: accounts proven alive by a recent round-trip (or deliberately
  // quiet via flood/frozen backoff). Replaces adoptedCount() as the heartbeat's
  // "guarding" signal, so a heartbeat can never read green while sweeps are dead.
  healthyCount() {
    const mono = this._mono();
    let n = 0;
    for (const ctx of this._accts.values()) {
      const quiet = (ctx.floodUntil && this._clock() < ctx.floodUntil) || (ctx.frozenUntil && this._clock() < ctx.frozenUntil);
      if (quiet || (mono - ctx.lastRtOkAt) < LIVENESS_STALE_MS) n++;
    }
    return n;
  }

  // Per-account liveness ages for the GWSTATUS:LIVE beacon the host watchdog reads.
  livenessAges() {
    const mono = this._mono();
    return [...this._accts.values()].map((ctx) => ({ stateId: ctx.stateId, ageMs: mono - ctx.lastRtOkAt, gen: ctx.gen }));
  }

  // Graceful shutdown (SIGTERM): disconnect every account BEFORE releasing its
  // lease, so the outgoing enclave is no longer a Telegram writer when the lease
  // frees. A fresh enclave then re-acquires in seconds (not the ~150s expiry wait)
  // with zero two-writer overlap -- releaseLease CASes on our exact holder+epoch,
  // so it can only ever clear our own lease (single-writer invariant preserved).
  async releaseAllLeases() {
    for (const [handle, ctx] of [...this._accts]) {
      try { await ctx.tx.disconnect(); } catch { /* already down */ }
      try { await this._d.authorityClient.releaseLease(ctx.stateId, ctx.holder, ctx.gen); } catch { /* expires on its own if release fails */ }
      this._accts.delete(handle);
      this._byState.delete(ctx.stateId);
    }
  }
}
