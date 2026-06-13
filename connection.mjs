// gateway/connection.mjs: the gateway's OWN low-level MTProto connection
// (gateway-brain-architecture.md 4.2, 4.3). Built from GramJS's exported
// primitives (MTProtoSender + ConnectionTCPFull) WITHOUT the high-level
// TelegramClient, so the ~200 invoke-wrapping helpers are not in the process.
// The static census (tests/gateway-audited-sender.test.ts) asserts the
// high-level client is never instantiated and no banned `telegram/client/*`
// helper path is imported.
//
// This module is the connectionFactory gateway-main.mjs injects into the
// composed Gateway. Every account-capable frame passes the audited
// serialization boundary (installAuditedSerialization on sender._sendQueue),
// which runs assertAllowed before _state.encryptMessageData. The bring-up is the
// pinned InvokeWithLayer(InitConnection(help.getConfig)); DC migration uses the
// chokepoint-constrained export/importAuthorization handshake.
//
// LIVE-ONLY: connect() opens a real socket and runs the auth-key handshake; it
// is validated by the fake-DC captured-wire suite on the Nitro host (gate 4),
// not off-host. The construction below mirrors GramJS _connectSender exactly so
// the behavior matches the audited, pinned client semantics.

// telegram is CommonJS; the low-level sender/connection live in the network
// submodule, not the root. Default-import + destructure is the reliable ESM
// interop (named imports of CJS re-exports are flaky). telegram/network is the
// permitted low-level path; the banned paths are telegram/client/* (the helpers).
import pkg from "telegram";
import netPkg from "telegram/network/index.js";
import extPkg from "telegram/extensions/index.js";
import tlObjects from "telegram/tl/AllTLObjects.js";
import { makeChokepoint, MODES } from "./tg-chokepoint.mjs";
import { installAuditedSerialization } from "./audited-sender.mjs";
import { makeNoOpEntityCache } from "./mtproto-client.mjs";

const { Api, Logger, sessions } = pkg;
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
function withTimeout(p, ms, what) {
  let t;
  const timeout = new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out after ${ms}ms`)), ms); });
  return Promise.race([Promise.resolve(p).finally(() => clearTimeout(t)), timeout]);
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
export async function makeConnection({ session, mode, apiId, apiHash, onAutoReconnect, logger }) {
  if (mode !== MODES.ARMED && mode !== MODES.ONBOARDING) throw new Error("makeConnection: bad mode");
  const log = logger ?? new Logger();

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
  const senderClient = { networkSocket: PromisedNetSockets, _errorHandler: null };
  const sender = new MTProtoSender(store.authKey, {
    logger: log,
    dcId: store.dcId || Number(process.env.TG_DEFAULT_DC || 4),
    retries: 5,
    delay: 1,
    autoReconnect: true,
    connectTimeout: 15000,
    authKeyCallback: async (authKey, dcId) => { store.setDC(dcId, store.serverAddress || DEFAULT_DC_IPS[dcId], store.port || 443); store.setAuthKey(authKey); },
    updateCallback: (_client, update) => { if (updateHandler) updateHandler(update); },
    autoReconnectCallback: async () => { if (onAutoReconnect) await onAutoReconnect(); },
    isMainSender: true,
    securityChecks: true,
    client: senderClient,
  });

  // H-2: disable the entity cache so no peer entity from a message update or RPC
  // result is ever ingested (4.4, 5.6).
  if ("_entityCache" in sender) sender._entityCache = makeNoOpEntityCache();

  // 2. Install the audited serialization boundary BEFORE connect, so even the
  //    bring-up and handshake-adjacent frames are validated.
  installAuditedSerialization(sender, chokepoint);
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

  async function connect() {
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
    // Bring-up: the pinned InvokeWithLayer(InitConnection(help.getConfig)). The
    // chokepoint permits exactly this nesting (InitConnection.query == getConfig).
    await withTimeout(
      sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.help.GetConfig(), apiId) })),
      CONNECT_TIMEOUT_MS, "MTProto bring-up"
    );
    connected = true;
  }

  async function disconnect() {
    connected = false;
    try { await sender.disconnect(); } catch { /* already down */ }
  }

  // invoke routes through the audited sender; extraHooks re-bind the evict gate
  // to the exact policy-approved hash for a single ResetAuthorization.
  async function invoke(request, extraHooks) {
    if (!connected) throw new Error("not connected");
    chokepoint.assertAllowed(request, extraHooks); // validate at the API layer too
    return sender.send(request);
  }

  // DC migration (4.2): export from the current DC, import on the target, each
  // call chokepoint-constrained. Used only when Telegram redirects the account.
  async function migrateDc(targetDcId) {
    const auth = await invoke(new Api.auth.ExportAuthorization({ dcId: targetDcId }));
    const target = dcAddress(targetDcId);
    await disconnect();
    store.setDC(targetDcId, target.ip, target.port);
    const connection = new ConnectionTCPFull({
      ip: target.ip, port: target.port, dcId: targetDcId, loggers: log,
      socket: PromisedNetSockets,
    });
    const ok = await withTimeout(sender.connect(connection, false), CONNECT_TIMEOUT_MS, "MTProto DC migrate connect");
    if (ok === false) throw new Error(`onboarding: MTProto migrate-connect to DC${targetDcId} (${target.ip}) failed`);
    await withTimeout(
      sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.auth.ImportAuthorization({ id: auth.id, bytes: auth.bytes }), apiId) })),
      CONNECT_TIMEOUT_MS, "MTProto migrate bring-up"
    );
    connected = true;
  }

  function onUpdate(cb) { updateHandler = cb; }

  return { sender, chokepoint, connect, disconnect, invoke, migrateDc, onUpdate, session: store };
}
