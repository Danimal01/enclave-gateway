// gateway/tg-chokepoint.mjs: THE ONLY PATH TO THE WIRE. Published verbatim.
// (docs/gateway-brain-architecture.md 4.3, 4.10.5)
//
// This module IS the capability list. Every account-capable frame the gateway
// can emit passes assertAllowed() at the encrypted serialization boundary,
// immediately before encryptMessageData, including frames the sender enqueues
// internally. The recursive unwrap closes the nesting bypass
// (InvokeWithLayer{query: messages.GetHistory} etc.); the per-RequestState
// check at serialization closes the enqueue bypass; the two-write-site structure
// of the connection (connection.mjs) closes the pre-auth and alternate-socket bypasses.
//
// There is NO generic invoke. A request type absent from these sets cannot be
// sent, and adding one changes this published file and therefore PCR0_G.

import { Api } from "telegram";

export const MODES = Object.freeze({ ARMED: "ARMED", ONBOARDING: "ONBOARDING" });

// The complete, closed allowlist of TL constructor IDs the gateway may send
// as a REQUEST in ARMED mode. This Map IS the capability list (spec 2.1, 2.2).
export const ALLOWED = new Map([
  [Api.account.GetAuthorizations.CONSTRUCTOR_ID,    "account.getAuthorizations"],
  [Api.account.ResetAuthorization.CONSTRUCTOR_ID,   "account.resetAuthorization"],
  [Api.account.DeclinePasswordReset.CONSTRUCTOR_ID, "account.declinePasswordReset"],
  [Api.account.GetPassword.CONSTRUCTOR_ID,          "account.getPassword"],
  [Api.account.GetAccountTTL.CONSTRUCTOR_ID,        "account.getAccountTTL"],
  [Api.auth.LogOut.CONSTRUCTOR_ID,                  "auth.logOut"],
  [Api.users.GetUsers.CONSTRUCTOR_ID,               "users.getUsers"],      // self-only, asserted below
  // unavoidable transport/migration (spec 2.2), each constrained below:
  [Api.help.GetConfig.CONSTRUCTOR_ID,               "help.getConfig"],
  [Api.updates.GetState.CONSTRUCTOR_ID,             "updates.getState"],
  [Api.auth.ExportAuthorization.CONSTRUCTOR_ID,     "auth.exportAuthorization"],
  [Api.auth.ImportAuthorization.CONSTRUCTOR_ID,     "auth.importAuthorization"],
]);

// Login-minting constructors, reachable ONLY while the connection's immutable
// mode is ONBOARDING (spec 4.10.5). auth.logOut is permitted in onboarding
// solely as the gateway-internal case-2 teardown revoke; no ONB_* input frame
// maps to it.
export const ONBOARDING_ONLY = new Map([
  [Api.auth.SendCode.CONSTRUCTOR_ID,      "auth.sendCode"],
  [Api.auth.SignIn.CONSTRUCTOR_ID,        "auth.signIn"],
  [Api.auth.CheckPassword.CONSTRUCTOR_ID, "auth.checkPassword"],
]);

// Armed mutating ops are blocked while ONBOARDING (symmetric mode partition).
const ARMED_ONLY = new Set([
  Api.account.ResetAuthorization.CONSTRUCTOR_ID,
  Api.account.DeclinePasswordReset.CONSTRUCTOR_ID,
  Api.account.GetAccountTTL.CONSTRUCTOR_ID,
]);

// The few internal frame types the sender legitimately self-sends. Enumerated
// by EXACT type, never a catch-all; the pinned build self-sends nothing outside
// this set.
export const TRANSPORT = new Set([
  Api.MsgsAck.CONSTRUCTOR_ID,
  Api.Ping.CONSTRUCTOR_ID,
  Api.PingDelayDisconnect.CONSTRUCTOR_ID,
  Api.MsgsStateInfo.CONSTRUCTOR_ID,
]);

export const WRAPPERS = new Set([
  Api.InvokeWithLayer.CONSTRUCTOR_ID,
  Api.InitConnection.CONSTRUCTOR_ID,
  Api.InvokeAfterMsg.CONSTRUCTOR_ID,
  Api.InvokeAfterMsgs.CONSTRUCTOR_ID,
]);

export const HARD_BLOCKED_WRAPPERS = new Set([
  Api.InvokeWithTakeout.CONSTRUCTOR_ID,        // bulk export, never permitted
  Api.InvokeWithMessagesRange.CONSTRUCTOR_ID,  // never permitted
]);

// MsgContainer is handled structurally (defensive only: the load-bearing
// check is per-RequestState at the serialization site, BELOW which the
// sender assembles containers).
const MSG_CONTAINER_ID = Api.MsgContainer ? Api.MsgContainer.CONSTRUCTOR_ID : null;

function checkLeaf(req, mode, hooks) {
  const id = req.CONSTRUCTOR_ID;
  let name = ALLOWED.get(id);
  if (name === undefined) {
    name = ONBOARDING_ONLY.get(id);
    if (name === undefined) throw new Error(`BLOCKED non-allowlisted TL constructor ${id}`);
    if (mode !== MODES.ONBOARDING) throw new Error(`BLOCKED ${name} outside onboarding mode`);
  }
  if (ONBOARDING_ONLY.has(id) && mode !== MODES.ONBOARDING) {
    throw new Error(`BLOCKED ${name} outside onboarding mode`);
  }
  if (mode === MODES.ONBOARDING && ARMED_ONLY.has(id)) {
    throw new Error(`BLOCKED ${name} in onboarding mode`);
  }
  if (req instanceof Api.users.GetUsers) {
    const selfOnly = Array.isArray(req.id) && req.id.length === 1 && req.id[0] instanceof Api.InputUserSelf;
    if (!selfOnly) throw new Error("BLOCKED users.getUsers with non-self peer");
  }
  if (req instanceof Api.account.ResetAuthorization) {
    // Policy gate (M-1): the gateway re-derives the signed policy and re-lists
    // the roster inside the same guarded op; this hook is that enforcement.
    if (typeof hooks?.assertEvictAllowed !== "function") {
      throw new Error("BLOCKED evict without a bound policy gate");
    }
    hooks.assertEvictAllowed(req.hash);
  }
  if (req instanceof Api.auth.LogOut && mode === MODES.ONBOARDING) {
    if (hooks?.onboardingTeardown !== true) {
      throw new Error("BLOCKED auth.logOut in onboarding outside internal teardown");
    }
  }
}

// Recursively validate a request and EVERY nested query/leaf.
export function assertAllowed(req, mode, hooks) {
  if (mode !== MODES.ARMED && mode !== MODES.ONBOARDING) throw new Error(`invalid mode ${mode}`);
  if (req === null || req === undefined || typeof req.CONSTRUCTOR_ID !== "number") {
    throw new Error("BLOCKED non-TL frame");
  }
  const id = req.CONSTRUCTOR_ID;
  if (HARD_BLOCKED_WRAPPERS.has(id)) throw new Error(`BLOCKED wrapper ${id}`);
  if (MSG_CONTAINER_ID !== null && id === MSG_CONTAINER_ID) {
    for (const m of req.messages ?? []) assertAllowed(m.body ?? m, mode, hooks);
    return;
  }
  if (TRANSPORT.has(id)) return;
  if (WRAPPERS.has(id)) {
    if (id === Api.InitConnection.CONSTRUCTOR_ID) {
      // InitConnection.query is pinned to the exact bring-up queries only.
      const q = req.query;
      const ok = q instanceof Api.help.GetConfig || q instanceof Api.auth.ImportAuthorization;
      if (!ok) throw new Error("BLOCKED InitConnection.query not a bring-up query");
      return assertAllowed(q, mode, hooks);
    }
    return assertAllowed(req.query, mode, hooks); // InvokeWithLayer / InvokeAfterMsg(s)
  }
  checkLeaf(req, mode, hooks);
}

// One chokepoint per connection. The mode is set ONCE at construction and is
// immutable; it is read from the sender the gateway constructed, NEVER from
// any field in a relayed or brain frame (spec 4.10.5). The sender binds once.
export function makeChokepoint({ mode, hooks = {} }) {
  if (mode !== MODES.ARMED && mode !== MODES.ONBOARDING) throw new Error(`invalid mode ${mode}`);
  const MODE = mode;          // captured, no setter exists
  let SENDER = null;          // module-private; never exported or re-readable

  // Op-scoped, module-private grants the GATEWAY sets around a privileged op and
  // the AUDITED SEAM consumes (audited-sender.mjs calls assertAllowed WITHOUT
  // per-op hooks, so a per-call extraHook never reaches the seam — these do). Only
  // the gateway's own transport code can set them; a relayed/brain frame cannot,
  // because bindEvict/bindTeardown are not on any wire path. The seam still
  // re-validates the EXACT request against the bound value (the bound evict hash
  // must equal the request hash), so this grants nothing beyond the one op the
  // policy layer already approved.
  let boundEvict = null;      // policy-approved ResetAuthorization hash, for the duration of the evict
  let boundTeardown = false;  // internal onboarding auth.logOut teardown, for the duration of the logout

  // Effective hooks: fold the op-scoped grants into the base + per-call hooks so
  // they reach assertAllowed at BOTH the API layer and the audited seam.
  function eff(extraHooks) {
    const merged = { ...hooks, ...extraHooks };
    const userEvict = merged.assertEvictAllowed;
    return {
      ...merged,
      // checkLeaf calls this only for account.ResetAuthorization.
      assertEvictAllowed: (hash) => {
        if (boundEvict !== null && String(hash) === boundEvict) return;   // exactly the policy-approved hash
        if (typeof userEvict === "function") return userEvict(hash);      // explicit per-call gate (direct callers/tests)
        throw new Error("BLOCKED evict without a bound policy gate");
      },
      // checkLeaf reads this only for auth.logOut in ONBOARDING mode.
      onboardingTeardown: boundTeardown === true || merged.onboardingTeardown === true,
    };
  }

  return Object.freeze({
    get mode() { return MODE; },
    // Gateway-only op-scoped grants (set immediately before the op, cleared after).
    bindEvict(hash) { boundEvict = (hash === null || hash === undefined) ? null : String(hash); },
    bindTeardown(on) { boundTeardown = on === true; },
    assertAllowed(request, extraHooks) {
      assertAllowed(request, MODE, eff(extraHooks));
    },
    bindSender(s) {
      if (SENDER !== null) throw new Error("sender already bound");
      if (!s || typeof s.send !== "function") throw new Error("not a sender");
      SENDER = s;
    },
    async send(request, extraHooks) {
      if (SENDER === null) throw new Error("no sender bound");
      assertAllowed(request, MODE, eff(extraHooks));
      return SENDER.send(request);
    },
  });
}
