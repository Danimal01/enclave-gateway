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

import { classifyReplay } from "./replay-detect.mjs";

export const DEFAULTS = Object.freeze({
  MAX_EVICT_PER_SWEEP: 3,
  FRESH_WINDOW_MS: 24 * 60 * 60 * 1000,
});

// Resolve the signed trusted-locations allowlist (v2 §4) into the SET of localities active
// right now: a permanent entry (until==null) is always active; a time-boxed entry is active
// ONLY while the master travel_mode toggle is ON and now < until. Returns a Set of the `loc`
// strings (country wildcards and/or "City, Country") for the detector to match against. The
// allowlist relaxes ONLY Tier C; Tier A/B never consult it.
export function resolveActiveAllowlist(list, travelMode, now) {
  const active = new Set();
  for (const e of Array.isArray(list) ? list : []) {
    if (!e || typeof e.loc !== "string" || !e.loc) continue;
    if (e.until == null) { active.add(e.loc); continue; } // permanent (home)
    if (!travelMode) continue; // time-boxed entries require travel mode ON
    const until = new Date(e.until).getTime();
    if (Number.isFinite(until) && now < until) active.add(e.loc);
  }
  return active;
}

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

    let { sessions } = await this._gw.call("LIST_SESSIONS", {});

    // ROSTER-SANITY GATE (fail SAFE). account.getAuthorizations never throws; a torn
    // read returns a short/empty list with no current:true row. Acting on one fired a
    // real false positive (danimaled 2026-06-25: the iPhone + the guard's own hash-0
    // logged as "signed out elsewhere" from a single torn read). Retry ONCE on the same
    // connection; we never classify, evict, or re-baseline from a roster that has no
    // current session. On a still-torn read we return rosterTorn so the gateway skips
    // the diff/emit + lastRoster/geo updates (never skip-OPEN, which would fail unsafe).
    let rosterTorn = false;
    if (!sessions.some((s) => s.current)) {
      const retry = await this._gw.call("LIST_SESSIONS", {}).catch(() => null);
      if (retry?.sessions?.some((s) => s.current)) sessions = retry.sessions;
      else rosterTorn = true;
    }
    if (rosterTorn) {
      this._log(`[${acct}] torn roster (no current session) — watch-only this sweep`);
      return { listed: sessions.length, proposed: 0, removed: 0, skipped: "roster-torn", rosterTorn: true, sessions, evicted: [], replayVerdicts: [] };
    }

    // REPLAY DETECTION. Classify the EXISTING/whitelisted hashes by their movement
    // BEFORE the candidate filter below: a tdata replay rides the victim's own
    // whitelisted desktop hash, so the whitelist check at :candidate-filter would drop
    // it and it would never be classified. classifyReplay mutates view.geo (== ctx.geo
    // by reference) and returns verdicts; the gateway turns tier>=2 into replay_suspected
    // + fast-poll. (P3 will turn a tier-3 verdict into a contested burn here.)
    let replayVerdicts = [];
    if (view.geo) {
      // Resolve the ACTIVE trusted-locations allowlist from the SIGNED authority (permanent
      // entries always; time-boxed only while travel_mode is on and unexpired) and pass it to
      // the detector so an allowlisted same-identity teleport is suppressed silently (Tier C
      // only; never Tier A/B). The allowlist is a RELAXATION; the burn-enable stays signed.
      const activeAllowlist = resolveActiveAllowlist(view.localityAllowlist, view.travelMode, this._now());
      try { replayVerdicts = classifyReplay(sessions, view.geo, this._now(), { ...this._p.detect, activeAllowlist }); }
      catch (e) { this._log(`[${acct}] classifyReplay failed: ${e.message}`); }
    }

    const fresh = view.freshUntil && this._now() < view.freshUntil;
    // ENROLLMENT HOLD (D11): while a SIGNED, auto-expiring enroll window is open, HOLD the
    // MVP eviction batch so a newly-logged-in device survives long enough for the operator
    // to whitelist its LIVE hash (re-login would mint a different one). The window rides the
    // signed authority (enroll_until), so a tdata/console path can never open it. Contested
    // flap/teleport burns still run (P3) -- the hold is for the benign add-a-device flow,
    // not a blanket amnesty. Detection/alerting above already ran (never hold-gated).
    const enrollUntilMs = view.enrollUntil ? Date.parse(view.enrollUntil) : 0;
    const enrollHold = Number.isFinite(enrollUntilMs) && this._now() < enrollUntilMs;

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
    const candidatesAll = sessions
      .filter((s) => !s.current
        && String(s.hash) !== "0" // belt-and-suspenders: hash 0 is the guard's own session; !current already excludes it
        && !view.whitelist.has(String(s.hash))
        && !(recentlyKilled && recentlyKilled.has(String(s.hash))))
      .sort((a, b) => Number(b.dateActive ?? 0) - Number(a.dateActive ?? 0));

    // CONTESTED BURNS (v2 §4/§5.3). A burnable replay verdict marks an EXISTING hash (usually
    // the victim's OWN whitelisted desktop) as a tdata replay. Burn it with contestOverride:true,
    // which the gateway permits ONLY under the signed auto_burn policy (D4) -- the ENABLE is never
    // sourced here, only the request. PLATFORM-AWARE, ALLOWLIST-AWARE routing (a RELAXATION layer;
    // the dangerous direction stays signed): Tier A (flap) + Tier B (client-identity change) burn
    // on BOTH platforms; Tier C (same-identity teleport) burns ONLY on desktop -- mobile Tier C is
    // alert-only (the replay_suspected already fired). The detector already suppressed allowlisted
    // Tier C silently. These run REGARDLESS of the fresh/enroll hold (a replay is not benign setup;
    // D8). NEVER current (the gate refuses it absolutely anyway). NO-2FA BURN (v2): the enable no
    // longer requires 2FA -- in every contested case the attacker proved session-clone capability,
    // not phone capability, so burning + forcing a phone-code re-login is protective without 2FA.
    // Keep the 2FA NUDGE.
    const burnEnabled = view.contestProtection === "auto_burn";
    const tier3 = new Map((replayVerdicts ?? [])
      .filter((v) => v.tier === 3 && (v.tierClass === "A" || v.tierClass === "B" || (v.tierClass === "C" && v.platform === "desktop")))
      .map((v) => [String(v.hash), v]));
    if (tier3.size > 0 && burnEnabled && view.has2fa === false) {
      this._log(`[${acct}] contested burn without 2FA (protective: attacker holds a clone, not the phone code); nudge user to enable 2FA`);
    }
    const contestedBurns = burnEnabled
      ? [...tier3.keys()]
          .map((h) => sessions.find((s) => String(s.hash) === h))
          .filter((s) => s && !s.current && String(s.hash) !== "0"
            && !(recentlyKilled && recentlyKilled.has(String(s.hash))))
      : [];
    const contestedSet = new Set(contestedBurns.map((s) => String(s.hash)));

    // Dedup BEFORE the slice: a contested hash never also runs through the MVP batch (it
    // carries the override; the MVP path would refuse it as whitelisted anyway).
    const mvpCandidates = candidatesAll.filter((s) => !contestedSet.has(String(s.hash)));
    const holding = fresh || enrollHold;

    // One shared MAX_EVICT_PER_SWEEP budget: contested burns take priority, then the MVP
    // batch fills the remainder. The MVP batch is suppressed entirely during the fresh/enroll
    // hold; contested burns are not.
    const cap = this._p.MAX_EVICT_PER_SWEEP;
    const plan = [];
    for (const s of contestedBurns) { if (plan.length >= cap) break; plan.push({ s, contested: true }); }
    if (!holding) {
      for (const s of mvpCandidates) { if (plan.length >= cap) break; plan.push({ s, contested: false }); }
    }

    let removed = 0;
    let contestedRemoved = 0;
    const evicted = [];
    for (const { s, contested } of plan) {
      try {
        const arg = { hash: String(s.hash), authorized: view.authToken };
        if (contested) arg.contestOverride = true;
        const body = await this._gw.call("EVICT_SESSION", arg);
        if (body.removed) {
          removed += 1;
          if (contested) {
            contestedRemoved += 1;
            const v = tier3.get(String(s.hash));
            // Tag the row so the gateway emits contested_session_burned (with device_model),
            // not device_evicted, and sources the "please reconnect" text from the burn row.
            evicted.push({ ...s, contested: true, trigger: v?.trigger ?? "replay", tierClass: v?.tierClass ?? null, locality: v?.locality ?? s.country ?? null });
          } else {
            evicted.push(s);
          }
        }
      } catch (e) {
        // The gateway refused (e.g. became current, or auto_burn not signed). Proposing is
        // not authority; a refusal is expected and logged, never fatal.
        this._log(`[${acct}] evict ${s.hash}${contested ? " (contested)" : ""} refused by gateway: ${e.message}`);
      }
    }

    const mvpProposed = plan.filter((p) => !p.contested).length;
    return {
      listed: sessions.length,
      proposed: plan.length,
      removed,
      contestedRemoved, // excluded from eviction_rate_capped (a contested burn is not a flood)
      pending: holding ? mvpCandidates.length : Math.max(0, mvpCandidates.length - mvpProposed),
      sessions, evicted, replayVerdicts,
      skipped: holding ? (enrollHold ? "enroll-hold" : "fresh-window") : undefined,
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
