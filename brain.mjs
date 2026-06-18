// gateway/brain.mjs: the in-gateway DETECTION engine (Option A; see
// docs/finish-line-plan.md). Originally specced as a separate CLOSED "brain"
// enclave (architecture doc 4.6); folded INTO the open, attested gateway and run
// IN-PROCESS, because a separate brain requires a separate parent instance and we
// hold cost flat on a single host. It is therefore PUBLISHED and measured into
// PCR0_G like the rest of the gateway, and readable by anyone.
//
// It decides WHICH authorized action to take and WHEN: which non-current,
// non-whitelisted sessions to evict (with fresh-window suppression and a
// MAX_EVICT_PER_SWEEP rate cap), and when to decline a pending 2FA-password
// reset. It owns NO extra authority: it can only call the gateway's existing
// chokepoint verbs, and the gateway independently re-derives the signed policy
// and refuses anything the policy does not permit. The capability ceiling
// (Claim C) is UNCHANGED: detection introduces no new operation.
//
// Honest residual of folding it in: detection now runs inside the session-
// holder's process, so a detection bug is bounded only by the chokepoint (worst
// case a wrong eviction, never a message read or a session leak). If detection
// later becomes worth hiding from attackers, it splits back onto its own host
// with no logic rewrite.

export const DEFAULTS = Object.freeze({
  MAX_EVICT_PER_SWEEP: 3,
  FRESH_WINDOW_MS: 24 * 60 * 60 * 1000,
});

export class Brain {
  // deps:
  //   gateway: async call(op, arg) -> response body. In-process this dispatches
  //            straight to the gateway's op handler; it throws on a refused op.
  //   policyView(acct): async -> { whitelist:Set<string>, resetProtection:bool,
  //            freshUntil:number|null, authToken:string }. Built by the gateway
  //            from the AUTHORITATIVE derived policy (the gateway is the ceiling).
  //   params, now
  constructor({ gateway, policyView, params = {}, now = () => Date.now(), log = () => {} }) {
    this._gw = gateway;
    this._policyView = policyView;
    this._p = { ...DEFAULTS, ...params };
    this._now = now;
    this._log = log;
    // Prior security snapshot for change-detection (twofa/recovery/login-email/
    // reset/ttl). Null until the first read; the first read SEEDS only (no events)
    // so we never emit a spurious "changed" for state that predates the guard.
    this._lastSec = null;
  }

  // One protective sweep for an account handle. Returns a summary of what it
  // proposed and what the gateway did (approved/refused), for observability.
  async sweep(acct) {
    const view = await this._policyView(acct);
    // Non-authoritative early-exit: if there is no verified policy view, watch
    // only (evict nothing). The gateway would refuse anyway, but proposing into
    // a void wastes calls and would misreport "removing N".
    if (!view || !view.whitelist) {
      this._log(`[${acct}] no policy view — watch-only sweep`);
      return { listed: 0, proposed: 0, removed: 0, skipped: "no-policy-view", sessions: [], evicted: [] };
    }

    const { sessions } = await this._gw.call("LIST_SESSIONS", {});
    const fresh = view.freshUntil && this._now() < view.freshUntil;

    // The detection decision: which sessions to act on. The MVP rule is "any
    // session not on the signed whitelist and not the guard's own," ordered
    // most-recent-first so a live intruder is removed first. Richer scoring or
    // anomaly classification plugs in here.
    //
    // COOLDOWN: also skip any hash we already removed within the cooldown window
    // (view.recentlyKilled, supplied by the gateway from the eviction_log). After a
    // successful resetAuthorization Telegram can keep LISTING the terminated session
    // as a ghost for minutes; without this we re-evict + re-log + re-email it every
    // sweep until Telegram GCs it (the eviction-loop incident). Keyed on the Telegram
    // per-session hash, so a real new login (always a NEW hash) is never suppressed —
    // it is not in recentlyKilled and is evicted immediately. A hash whose cooldown
    // has expired drops out of recentlyKilled and falls back into candidates here, so
    // a genuinely persistent session is still re-removed (at most once per window).
    const recentlyKilled = view.recentlyKilled;
    const candidates = sessions
      .filter((s) => !s.current
        && !view.whitelist.has(String(s.hash))
        && !(recentlyKilled && recentlyKilled.has(String(s.hash))))
      .sort((a, b) => Number(b.dateActive ?? 0) - Number(a.dateActive ?? 0));

    if (fresh) {
      this._log(`[${acct}] fresh window active — proposing no evictions`);
      return { listed: sessions.length, proposed: 0, removed: 0, skipped: "fresh-window", pending: candidates.length, sessions, evicted: [] };
    }

    // Rate cap: never fire a thundering mass-eviction in one sweep; whittle a
    // flood down over successive sweeps.
    const batch = candidates.slice(0, this._p.MAX_EVICT_PER_SWEEP);
    let removed = 0;
    const evicted = [];
    for (const s of batch) {
      try {
        const body = await this._gw.call("EVICT_SESSION", { hash: String(s.hash), authorized: view.authToken });
        if (body.removed) {
          removed += 1;
          evicted.push(s);
        }
      } catch (e) {
        // The gateway refused (e.g. the session was on the signed whitelist after
        // all, or became current). The detection proposing is not authority; a
        // refusal is expected and logged, never fatal.
        this._log(`[${acct}] evict ${s.hash} refused by gateway: ${e.message}`);
      }
    }
    return {
      listed: sessions.length, proposed: batch.length, removed,
      pending: Math.max(0, candidates.length - batch.length), sessions, evicted,
    };
  }

  // Reset-protection: while a 2FA-password reset is pending and the signed policy
  // keeps reset-protection on, propose DECLINE_RESET to cancel it.
  async checkSecurity(acct) {
    const view = await this._policyView(acct);
    const sec = await this._gw.call("READ_SECURITY_STATE", {});
    const cur = {
      hasPwd: !!sec.hasPwd, hasRecovery: !!sec.hasRecovery,
      pendingReset: !!sec.pendingReset, pendingResetAt: sec.pendingResetAt ?? null,
      loginEmail: sec.loginEmailPattern ?? null,
      accountTtlDays: sec.accountTtlDays ?? null, sessionTtlDays: sec.sessionTtlDays ?? null,
    };

    // ACTION (authority-bounded): decline a pending reset while protected.
    let declined = false;
    if (cur.pendingReset && view?.resetProtection) {
      try { const body = await this._gw.call("DECLINE_RESET", { authorized: view.authToken }); declined = !!body.declined; }
      catch (e) { this._log(`[${acct}] decline-reset refused: ${e.message}`); }
    }

    // OBSERVABILITY: diff against the prior snapshot and emit typed change events
    // (the gateway records them; the brain holds no DB authority). Seed-only on the
    // first read so we never fire a spurious change for pre-existing state.
    const events = [];
    const prev = this._lastSec;
    if (prev) {
      if (cur.pendingReset && !prev.pendingReset) {
        if (declined) {
          events.push({ kind: "reset_blocked", detail: {} });
        } else {
          // The dashboard renders detail.until (a human string), e.g. "in 7 days".
          const days = cur.pendingResetAt ? Math.max(0, Math.round((cur.pendingResetAt * 1000 - this._now()) / 86400000)) : null;
          events.push({ kind: "reset_requested", detail: days != null ? { until: `in ${days} day${days === 1 ? "" : "s"}` } : {} });
        }
      } else if (!cur.pendingReset && prev.pendingReset) {
        events.push({ kind: "reset_cancelled", detail: {} });
      } else if (declined) {
        events.push({ kind: "reset_blocked", detail: {} });
      }
      if (cur.hasPwd && !prev.hasPwd) events.push({ kind: "twofa_enabled", detail: {} });
      if (!cur.hasPwd && prev.hasPwd) events.push({ kind: "twofa_disabled", detail: {} });
      if (cur.hasRecovery && !prev.hasRecovery) events.push({ kind: "recovery_set", detail: {} });
      if (cur.loginEmail && cur.loginEmail !== prev.loginEmail) events.push({ kind: "login_email_set", detail: { pattern: cur.loginEmail } });
      if (cur.accountTtlDays && prev.accountTtlDays && cur.accountTtlDays !== prev.accountTtlDays) events.push({ kind: "account_ttl_changed", detail: { days: cur.accountTtlDays } });
      if (cur.sessionTtlDays && prev.sessionTtlDays && cur.sessionTtlDays !== prev.sessionTtlDays) events.push({ kind: "session_ttl_changed", detail: { days: cur.sessionTtlDays } });
    } else if (declined) {
      events.push({ kind: "reset_blocked", detail: {} });
    }
    this._lastSec = cur;
    return { declined, pendingReset: cur.pendingReset, events, security: cur };
  }

  // React to the typed NEW_AUTH event the gateway surfaces (four fields, no
  // message content). A new login is the signal to sweep immediately rather than
  // wait for the next poll.
  async onNewAuth(acct, evt) {
    this._log(`[${acct}] NEW_AUTH ${evt.device ?? "?"} @ ${evt.location ?? "?"} — immediate sweep`);
    return this.sweep(acct);
  }

  // Identity readback (binding observability; never authority).
  async whoAmI(acct) {
    return this._gw.call("WHO_AM_I", {});
  }
}
