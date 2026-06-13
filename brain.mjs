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
      return { listed: 0, proposed: 0, removed: 0, skipped: "no-policy-view" };
    }

    const { sessions } = await this._gw.call("LIST_SESSIONS", {});
    const fresh = view.freshUntil && this._now() < view.freshUntil;

    // The detection decision: which sessions to act on. The MVP rule is "any
    // session not on the signed whitelist and not the guard's own," ordered
    // most-recent-first so a live intruder is removed first. Richer scoring or
    // anomaly classification plugs in here.
    const candidates = sessions
      .filter((s) => !s.current && !view.whitelist.has(String(s.hash)))
      .sort((a, b) => Number(b.dateActive ?? 0) - Number(a.dateActive ?? 0));

    if (fresh) {
      this._log(`[${acct}] fresh window active — proposing no evictions`);
      return { listed: sessions.length, proposed: 0, removed: 0, skipped: "fresh-window", pending: candidates.length };
    }

    // Rate cap: never fire a thundering mass-eviction in one sweep; whittle a
    // flood down over successive sweeps.
    const batch = candidates.slice(0, this._p.MAX_EVICT_PER_SWEEP);
    let removed = 0;
    for (const s of batch) {
      try {
        const body = await this._gw.call("EVICT_SESSION", { hash: String(s.hash), authorized: view.authToken });
        if (body.removed) removed += 1;
      } catch (e) {
        // The gateway refused (e.g. the session was on the signed whitelist after
        // all, or became current). The detection proposing is not authority; a
        // refusal is expected and logged, never fatal.
        this._log(`[${acct}] evict ${s.hash} refused by gateway: ${e.message}`);
      }
    }
    return { listed: sessions.length, proposed: batch.length, removed, pending: Math.max(0, candidates.length - batch.length) };
  }

  // Reset-protection: while a 2FA-password reset is pending and the signed policy
  // keeps reset-protection on, propose DECLINE_RESET to cancel it.
  async checkSecurity(acct) {
    const view = await this._policyView(acct);
    const sec = await this._gw.call("READ_SECURITY_STATE", {});
    if (sec.pendingReset && view?.resetProtection) {
      try {
        const body = await this._gw.call("DECLINE_RESET", { authorized: view.authToken });
        return { declined: !!body.declined, pendingReset: true };
      } catch (e) {
        this._log(`[${acct}] decline-reset refused: ${e.message}`);
        return { declined: false, pendingReset: true, refused: e.message };
      }
    }
    return { declined: false, pendingReset: !!sec.pendingReset };
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
