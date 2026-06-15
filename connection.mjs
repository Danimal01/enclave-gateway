// gateway/connection.mjs: the gateway's OWN low-level MTProto connection
// (gateway-brain-architecture.md 4.2, 4.3). Built from GramJS's exported
// primitives (MTProtoSender + ConnectionTCPFull) WITHOUT the high-level
// TelegramClient, so the ~200 invoke-wrapping helpers are not in the process.
// The high-level client is never instantiated and no `telegram/client/*` helper
// path is imported: this file imports only the low-level network primitives below.
//
// This module is the connectionFactory gateway-main.mjs injects into the
// composed Gateway. Every account-capable frame passes the audited
// serialization boundary (installAuditedSerialization on sender._sendQueue),
// which runs assertAllowed before _state.encryptMessageData. The bring-up is the
// pinned InvokeWithLayer(InitConnection(help.getConfig)); DC migration uses the
// chokepoint-constrained export/importAuthorization handshake.
//
// LIVE-ONLY: connect() opens a real socket and runs the auth-key handshake, which
// run only inside the enclave against real Telegram DCs. The construction below
// mirrors GramJS _connectSender exactly so the behavior matches the pinned client
// semantics.

// telegram is CommonJS; the low-level sender/connection live in the network
// submodule, not the root. Default-import + destructure is the reliable ESM
// interop (named imports of CJS re-exports are flaky). telegram/network is the
// permitted low-level path; the banned paths are telegram/client/* (the helpers).
import pkg from "telegram";
import netPkg from "telegram/network/index.js";
import extPkg from "telegram/extensions/index.js";
import tlObjects from "telegram/tl/AllTLObjects.js";
import helpersPkg from "telegram/Helpers.js";
import { makeChokepoint, MODES } from "./tg-chokepoint.mjs";
import { installAuditedSerialization } from "./audited-sender.mjs";
import { makeNoOpEntityCache } from "./mtproto-client.mjs";

const { Api, Logger, sessions } = pkg;
const { returnBigInt } = helpersPkg;

// Keep the MTProto connection WARM. Without this the connection idles, the
// enclave's user-mode network (gvproxy/NAT) drops it, and the next operation
// pays a full reconnect+handshake (~20s through the slow path) -- the source of
// the per-op latency and the dashboard "reconnecting" flaps. A PingDelayDisconnect
// is a transport-level service message (allowed in BOTH modes, pre-auth), so it
// keeps both the onboarding and armed connections alive. Interval well under any
// reasonable idle timeout; disconnectDelay gives slack for a missed ping.
const KEEPALIVE_INTERVAL_MS = 15_000;
const KEEPALIVE_DISCONNECT_DELAY_S = 75;
// A pong must arrive within this window; otherwise the socket is silently dead
// (NAT dropped us with no FIN/RST) and we force a reconnect. This is the
// dead-connection DETECTION half of GramJS's _updateLoop that the minimal client
// otherwise lacks -- without it the keepalive only keeps a LIVE socket warm.
const KEEPALIVE_PING_TIMEOUT_MS = 10_000;
const { MTProtoSender, ConnectionTCPFull } = netPkg;
const { PromisedNetSockets } = extPkg;
const { LAYER } = tlObjects;
const { StringSession } = sessions;

// GramJS production DC addresses. The LOW-LEVEL MTProtoSender+ConnectionTCPFull
// (which we use deliberately, instead of the high-level TelegramClient) has NO
// built-in default DC table, so an onboarding ceremony with an EMPTY session must
// be told a concrete IP -- otherwise connect() dials ip:undefined -> localhost ->
// ECONNREFUSED and the handshake never completes (the "Lost the secure connection"
// bug). help.getConfig after bring-up can refine these; the parent may override via
// TG_DC{n}_IP. Source: Telegram production DC list.
const DEFAULT_DC_IPS = { 1: "149.154.175.53", 2: "149.154.167.51", 3: "149.154.175.100", 4: "149.154.167.91", 5: "91.108.56.130" };

// Resolve a usable cold-connect timeout. GramJS's own connectTimeout is not read in
// the pinned build, so we bound connect()/bring-up ourselves.
const CONNECT_TIMEOUT_MS = Number(process.env.TG_CONNECT_TIMEOUT_MS || 20000);
// L0 (always-healthy design): bound EVERY steady-state Telegram round-trip. GramJS's
// sender.send() resolves only when the recv loop matches a reply; on a silent NAT/idle
// drop the socket neither throws nor emits close, so an un-bounded await orphans
// FOREVER and wedges the whole per-account op chain (the 2026-06-14 silent-death root
// cause). A hard wall-clock deadline turns that invisible hang into a thrown,
// catchable, recoverable error. Well under the lease TTL and the L1 liveness window.
const INVOKE_TIMEOUT_MS = Number(process.env.TG_INVOKE_TIMEOUT_MS || 25000);
function withTimeout(p, ms, what) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out after ${ms}ms`)), ms); });
  return Promise.race([Promise.resolve(p).finally(() => clearTimeout(t)), timeout]);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Detect a Telegram DC-migration error + its target DC. GramJS's high-level
// client.invoke transparently migrates on ANY call; the minimal client lost that,
// so an armed account that gets a USER/NETWORK_MIGRATE silently stops being guarded.
// Mirrors onboarding-transport.mjs mapTgError but at the connection layer.
function migrateTarget(e) {
  if (!e) return null;
  const name = String(e?.constructor?.name ?? "");
  const msg = String(e?.errorMessage ?? e?.message ?? "");
  let dcId = Number(e?.newDc);
  if (!Number.isInteger(dcId)) {
    const m = /(?:PHONE|NETWORK|USER)_MIGRATE_(\d+)/i.exec(msg) || /associated with DC\s+(\d+)/i.exec(msg);
    if (m) dcId = Number(m[1]);
  }
  if (!Number.isInteger(dcId) || dcId < 1 || dcId > 5) return null;
  if (/Migrate/i.test(name) || /_MIGRATE_\d+/i.test(msg) || /associated with DC/i.test(msg)) return { dcId };
  return null;
}

// Transient server errors GramJS's client.invoke retried (up to requestRetries).
// We lost that loop with the high-level client; a bare -503/RPC_CALL_FAIL should
// not abort a sweep or delay a protective eviction a full poll cycle.
function isTransient(e) {
  if (e && (e.code === -503 || e.code === 500 || e.code === 503)) return true;
  const msg = String(e?.errorMessage ?? e?.message ?? "");
  return /RPC_CALL_FAIL|RPC_MCGET_FAIL|INTERNAL|MsgWaitError|ServerError/i.test(msg);
}

// Honest device identity on the wire (spec 2.2): deviceModel "Sessions Guard". apiId
// comes from the gateway config (passed as a param), NOT process.env (which loadConfig
// never sets -> would be NaN and reject the InitConnection).
function initConnection(query, apiId) {
  return new Api.InitConnection({
    apiId: Number(apiId),
    deviceModel: "Sessions Guard",
    systemVersion: "1.0",
    appVersion: "1.0",
    langCode: "en",
    systemLangCode: "en",
    langPack: "",
    query,
  });
}

// Build one connection for one account. `mode` selects the chokepoint surface
// (ARMED for a sealed session, ONBOARDING for an empty session being minted).
// Returns the `conn` contract mtproto-client.mjs / gateway.mjs expect:
//   { sender, connect, disconnect, invoke, onUpdate, migrateDc, chokepoint }
export async function makeConnection({ session, mode, apiId, apiHash, onAutoReconnect, onRtOk, logger, onTiming }) {
  const emitT = (m) => { try { if (onTiming) onTiming(`${mode} ${m}`); } catch { /* timing is best-effort */ } };
  if (mode !== MODES.ARMED && mode !== MODES.ONBOARDING) throw new Error("makeConnection: bad mode");
  // GramJS needs a Logger OBJECT (with .error/.warn/.info). The gateway passes a
  // plain message function for its own logging, which is fine for the brain but
  // would make GramJS crash with "this._log.error is not a function" on the
  // reconnect/DC-migrate path. Only adopt the caller's logger if it is a real
  // Logger; otherwise build a fresh GramJS Logger.
  const log = (logger && typeof logger.error === "function") ? logger : new Logger();

  // 1. Load the session (authKey, dcId, serverAddress, port). For onboarding the
  //    session is empty and connect() mints the auth key via the handshake.
  const store = new StringSession(session || "");
  await store.load();

  const chokepoint = makeChokepoint({
    mode,
    hooks: {
      // evict gate is re-bound per op by the dispatcher; default fail-closed.
      assertEvictAllowed: () => { throw new Error("evict gate not bound for this op"); },
    },
  });

  let updateHandler = null;
  // MTProtoSender assumes its client context supplies the socket constructor
  // during reconnects and an optional top-level error hook. The high-level
  // TelegramClient normally provides this object; our low-level client must do
  // so explicitly.
  // floodSleepThreshold:0 is inert today (we drive sender.send directly, not the
  // high-level client.invoke that reads it) but future-proofs against a refactor
  // that routes through client.invoke and would otherwise auto-SLEEP up to 60s on a
  // flood, blocking the call. Matches lib/telegram.ts's throw-don't-sleep stance.
  const senderClient = { networkSocket: PromisedNetSockets, _errorHandler: null, floodSleepThreshold: 0 };
  const buildSender = (authKey, dcId) => {
    const next = new MTProtoSender(authKey, {
      logger: log,
      dcId,
      retries: 5,
      delay: 1,
      autoReconnect: true,
      connectTimeout: 15000,
      authKeyCallback: async (key, keyDcId) => {
        store.setDC(keyDcId, store.serverAddress || DEFAULT_DC_IPS[keyDcId], store.port || 443);
        store.setAuthKey(key);
      },
      updateCallback: (_client, update) => { if (updateHandler) updateHandler(update); },
      autoReconnectCallback: async () => { if (onAutoReconnect) await onAutoReconnect(); },
      isMainSender: true,
      securityChecks: true,
      client: senderClient,
    });
    if ("_entityCache" in next) next._entityCache = makeNoOpEntityCache();
    // Install the audited serialization boundary on EVERY sender before it can
    // connect, including a fresh sender created for pre-login DC migration.
    installAuditedSerialization(next, chokepoint);
    return next;
  };

  let sender = buildSender(store.authKey, store.dcId || Number(process.env.TG_DEFAULT_DC || 4));

  // 2. Bind the initial audited sender. Connection methods below always dispatch
  // through the current closure-held sender.
  chokepoint.bindSender(sender);

  // Default DC 4 matches the high-level GramJS client the worker used successfully
  // (DEFAULT_DC_ID=4); help.getConfig refines the address after bring-up.
  const defaultDcId = () => store.dcId || Number(process.env.TG_DEFAULT_DC || 4) || 4;
  const dcAddress = (dcId) => {
    // For an ARMED session the address comes from the loaded session. For onboarding
    // (empty session) resolve a concrete default DC IP -- the low-level sender has no
    // built-in table, so a missing IP is what dialed localhost and hung the ceremony.
    const d = dcId || defaultDcId();
    if (store.serverAddress && d === store.dcId) return { ip: store.serverAddress, port: store.port || 443, dcId: d };
    const ip = process.env[`TG_DC${d}_IP`] || DEFAULT_DC_IPS[d];
    if (!ip) throw new Error(`onboarding: no DC IP for dc ${d}`);
    return { ip, port: 443, dcId: d };
  };

  let connected = false;
  let keepaliveTimer = null;
  let pingCounter = 0;
  function stopKeepalive() { if (keepaliveTimer) { clearInterval(keepaliveTimer); keepaliveTimer = null; } }
  function startKeepalive() {
    stopKeepalive();
    let pinging = false;
    keepaliveTimer = setInterval(async () => {
      if (!connected || pinging) return;
      pinging = true;
      pingCounter += 1;
      try {
        // PingDelayDisconnect is a TRANSPORT service message (allowed in any mode,
        // pre-auth). AWAIT the pong with a timeout: if it doesn't come back, the
        // socket is silently dead -> force a reconnect (GramJS _updateLoop parity).
        await withTimeout(
          invoke(new Api.PingDelayDisconnect({ pingId: returnBigInt(pingCounter), disconnectDelay: KEEPALIVE_DISCONNECT_DELAY_S })),
          KEEPALIVE_PING_TIMEOUT_MS, "keepalive ping"
        );
      } catch {
        try { if (typeof sender.reconnect === "function") sender.reconnect(); }
        catch { /* the send/recv loop will also retry */ }
      } finally {
        pinging = false;
      }
    }, KEEPALIVE_INTERVAL_MS);
    if (keepaliveTimer.unref) keepaliveTimer.unref();
  }

  async function connect() {
    const tc = Date.now();
    const dc = dcAddress(store.dcId);
    // Persist the resolved DC into the store BEFORE the handshake so authKeyCallback
    // and exportSession() carry a concrete address -- otherwise the empty onboarding
    // session stays addressless and sealRecovery throws 'seal: missing session'.
    store.setDC(dc.dcId, dc.ip, dc.port);
    const connection = new ConnectionTCPFull({
      ip: dc.ip, port: dc.port, dcId: dc.dcId, loggers: log,
      socket: PromisedNetSockets,
    });
    // sender.connect() RETURNS false (it does not throw) when the socket/handshake
    // fails after its internal retries; honor that instead of proceeding to a send()
    // that would hang forever on a dead transport. Bound both legs with a timeout.
    const ok = await withTimeout(sender.connect(connection, false), CONNECT_TIMEOUT_MS, "MTProto DC connect");
    if (ok === false) throw new Error(`onboarding: MTProto connect to DC${dc.dcId} (${dc.ip}) failed`);
    emitT(`CONNECT-SOCKET dc${dc.dcId} ${Date.now() - tc}ms`); // [instr] handshake time
    const tb = Date.now();
    // Bring-up: the pinned InvokeWithLayer(InitConnection(help.getConfig)). The
    // chokepoint permits exactly this nesting (InitConnection.query == getConfig).
    await withTimeout(
      sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.help.GetConfig(), apiId) })),
      CONNECT_TIMEOUT_MS, "MTProto bring-up"
    );
    connected = true;
    startKeepalive();
    emitT(`CONNECT-DONE dc${dc.dcId} bringup=${Date.now() - tb}ms total=${Date.now() - tc}ms`); // [instr] catches a 20s bring-up
  }

  async function disconnect() {
    connected = false;
    stopKeepalive();
    try { await sender.disconnect(); } catch { /* already down */ }
  }

  // invoke routes through the audited sender; extraHooks re-bind the evict gate
  // to the exact policy-approved hash for a single ResetAuthorization.
  async function invoke(request, extraHooks) {
    if (!connected) throw new Error("not connected");
    chokepoint.assertAllowed(request, extraHooks); // validate at the API layer too
    const op = request?.className || request?.constructor?.name || request?.CONSTRUCTOR_ID;
    const t0 = Date.now();
    let migrated = false;
    for (let attempt = 0; ; attempt++) {
      try {
        // L0: hard deadline on the round-trip. A silently-dead socket can no longer
        // orphan this promise forever; it throws and the per-account chain unblocks.
        const r = await withTimeout(sender.send(request), INVOKE_TIMEOUT_MS, `invoke ${op}`);
        if (onRtOk) { try { onRtOk(); } catch { /* liveness stamp is best-effort */ } } // proven-work signal
        emitT(`INVOKE ${op} ${Date.now() - t0}ms a=${attempt}`); // [instrumentation] true per-op RTT
        return r;
      } catch (e) {
        // L0: a timed-out call means the socket is wedged. Tear the sender down so it
        // is not reused, and SURFACE it (never silently retry a hang) so L1's
        // per-account watchdog rebuilds the connection.
        if (/timed out after/.test(String(e?.message || ""))) {
          connected = false;
          try { if (typeof sender.reconnect === "function") sender.reconnect(); } catch { /* L1 will rebuild */ }
          emitT(`INVOKE-TIMEOUT ${op} ${Date.now() - t0}ms`);
          throw e;
        }
        // ARMED auto-migrate (parity with GramJS client.invoke): a USER/NETWORK_MIGRATE
        // transparently switches DC and retries once, so the account is never silently
        // un-guarded. Onboarding migrates via the manager's cold-switch, so skip here.
        if (!migrated && mode === MODES.ARMED) {
          const mig = migrateTarget(e);
          if (mig) { emitT(`MIGRATE ${op} dc${mig.dcId}`); await migrateDc(mig.dcId); chokepoint.assertAllowed(request, extraHooks); migrated = true; continue; }
        }
        // Transient server errors: bounded retry (GramJS retried these). Caps the
        // total at 3 sends so a hard error still surfaces promptly.
        if (isTransient(e) && attempt < 2) { emitT(`RETRY ${op} a=${attempt}`); await sleep(800 * (attempt + 1)); continue; }
        emitT(`INVOKE-FAIL ${op} ${Date.now() - t0}ms ${String(e?.message || e).slice(0, 50)}`);
        throw e;
      }
    }
  }

  // DC migration (4.2): export from the current DC, import on the target, each
  // call chokepoint-constrained. Used only when Telegram redirects the account.
  async function migrateDc(targetDcId) {
    if (mode !== MODES.ARMED) throw new Error("export/import DC migration is armed-only");
    // Export the authorization from the CURRENT (home) DC sender first (raw send to
    // avoid invoke's migrate-retry recursing on this very call). Bounded so a wedged
    // home-DC socket cannot hang the migration forever (L0).
    const auth = await withTimeout(sender.send(new Api.auth.ExportAuthorization({ dcId: targetDcId })), INVOKE_TIMEOUT_MS, "migrate export");
    const target = dcAddress(targetDcId);
    await disconnect();
    // Mint a FRESH key on the target DC and rebuild the sender (the home-DC key is
    // invalid on a different DC; reusing it was the prior bug). Mirrors the onboarding
    // cold-switch and GramJS's per-DC exported sender; import then authorizes it.
    store.setAuthKey(undefined);
    store.setDC(targetDcId, target.ip, target.port);
    sender = buildSender(undefined, targetDcId);
    const connection = new ConnectionTCPFull({
      ip: target.ip, port: target.port, dcId: targetDcId, loggers: log,
      socket: PromisedNetSockets,
    });
    const ok = await withTimeout(sender.connect(connection, false), CONNECT_TIMEOUT_MS, "MTProto DC migrate connect");
    if (ok === false) throw new Error(`MTProto migrate-connect to DC${targetDcId} (${target.ip}) failed`);
    await withTimeout(
      sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.auth.ImportAuthorization({ id: auth.id, bytes: auth.bytes }), apiId) })),
      CONNECT_TIMEOUT_MS, "MTProto migrate bring-up"
    );
    connected = true;
    startKeepalive(); // FIX: the prior migrateDc never restarted the keepalive
  }

  // Pre-login migration for PHONE_MIGRATE_x. Unlike an armed account, an
  // onboarding auth key is not yet a user authorization, so export/import is
  // invalid. Telegram's own auth flow cold-switches instead: disconnect, discard
  // the source-DC auth key, mint a fresh key on the target DC, then retry the
  // login RPC. The manager rotates the RECOVERY envelope after this returns and
  // before retrying auth.sendCode.
  async function migrateOnboardingDc(targetDcId) {
    if (mode !== MODES.ONBOARDING) throw new Error("cold DC migration is onboarding-only");
    const target = dcAddress(targetDcId);
    await disconnect();
    store.setAuthKey(undefined);
    store.setDC(targetDcId, target.ip, target.port);
    sender = buildSender(undefined, targetDcId);
    await connect();
  }

  function onUpdate(cb) { updateHandler = cb; }

  return {
    get sender() { return sender; },
    chokepoint, connect, disconnect, invoke, migrateDc, migrateOnboardingDc, onUpdate, session: store,
  };
}
