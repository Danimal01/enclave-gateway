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
import tlObjects from "telegram/tl/AllTLObjects.js";
import { makeChokepoint, MODES } from "./tg-chokepoint.mjs";
import { installAuditedSerialization } from "./audited-sender.mjs";
import { makeNoOpEntityCache } from "./mtproto-client.mjs";

const { Api, Logger, sessions } = pkg;
const { MTProtoSender, ConnectionTCPFull } = netPkg;
const { LAYER } = tlObjects;
const { StringSession } = sessions;

// Honest device identity on the wire (spec 2.2): deviceModel "Sessions Guard".
function initConnection(query) {
  return new Api.InitConnection({
    apiId: Number(process.env.TG_API_ID),
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
  const sender = new MTProtoSender(store.authKey, {
    logger: log,
    dcId: store.dcId || Number(process.env.TG_DEFAULT_DC || 2),
    retries: 5,
    delay: 1,
    autoReconnect: true,
    connectTimeout: 15000,
    authKeyCallback: async (authKey, dcId) => { store.setDC(dcId, store.serverAddress, store.port); store.setAuthKey(authKey); },
    updateCallback: (update) => { if (updateHandler) updateHandler(update); },
    autoReconnectCallback: async () => { if (onAutoReconnect) await onAutoReconnect(); },
    isMainSender: true,
    securityChecks: true,
  });

  // H-2: disable the entity cache so no peer entity from a message update or RPC
  // result is ever ingested (4.4, 5.6).
  if ("_entityCache" in sender) sender._entityCache = makeNoOpEntityCache();

  // 2. Install the audited serialization boundary BEFORE connect, so even the
  //    bring-up and handshake-adjacent frames are validated.
  installAuditedSerialization(sender, chokepoint);
  chokepoint.bindSender(sender);

  const dcAddress = (dcId) => {
    // Production DC IPs are resolved from help.getConfig after bring-up and
    // cached by the parent; the initial address comes from the loaded session.
    // For onboarding (empty session) the parent injects the default DC address.
    if (store.serverAddress && (!dcId || dcId === store.dcId)) return { ip: store.serverAddress, port: store.port || 443, dcId: store.dcId };
    return { ip: process.env[`TG_DC${dcId}_IP`], port: 443, dcId };
  };

  let connected = false;

  async function connect() {
    const dc = dcAddress(store.dcId);
    const connection = new ConnectionTCPFull({ ip: dc.ip, port: dc.port, dcId: dc.dcId, loggers: log });
    await sender.connect(connection, false);
    // Bring-up: the pinned InvokeWithLayer(InitConnection(help.getConfig)). The
    // chokepoint permits exactly this nesting (InitConnection.query == getConfig).
    await sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.help.GetConfig()) }));
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
    const connection = new ConnectionTCPFull({ ip: target.ip, port: target.port, dcId: targetDcId, loggers: log });
    await sender.connect(connection, false);
    await sender.send(new Api.InvokeWithLayer({ layer: LAYER, query: initConnection(new Api.auth.ImportAuthorization({ id: auth.id, bytes: auth.bytes })) }));
    connected = true;
  }

  function onUpdate(cb) { updateHandler = cb; }

  return { sender, chokepoint, connect, disconnect, invoke, migrateDc, onUpdate, session: store };
}
