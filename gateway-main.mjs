// gateway/gateway-main.mjs: the EIF entrypoint that wires the published,
// unit-tested gateway modules to the REAL enclave effects (gateway-brain-
// architecture.md 4.2). This is the boundary between the pure logic verified in
// the test suite and the live-only machinery that can be validated solely on the
// Nitro host against real Telegram DCs (the fake-DC captured-wire suite, gate 4).
//
// Everything imported here is published and already tested in isolation:
//   - Gateway (gateway.mjs)                 : the composed server (tested)
//   - makeKmstoolTransport (kms-envelope-v3): KMS data-key transport (patched
//                                             kmstool, --encryption-context)
//   - StateAuthorityClient (state-authority): signed lease/head client (tested)
//   - makeArmedTransport (mtproto-client)   : the armed transport wiring (tested)
//   - OnboardingManager (onboarding)        : the ceremony state machine (tested)
//
// The ONLY live-only pieces this file introduces, each validated on the host:
//   1. the forked GramJS connection package with the TWO audited write sites
//      (the plaintext auth-key handshake writer + the encrypted serialization
//      site). The census test (gate 4) asserts exactly two sites on the host.
//   2. the vsock relays to the parent (KMS proxy :8000, creds :8001, the brain
//      channel, the browser onboarding channel, the State Authority relay).
//   3. fresh STS credentials from IMDS via the parent.
//
// Until the batched Nitro rebuild, this entrypoint is NOT exercised; the EIF it
// produces is validated by the captured-wire suite before any cutover.

import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import net from "node:net";
import { Gateway } from "./gateway.mjs";
import { makeKmstoolTransport, openEnvelopeV3, sealEnvelopeV3, envelopeDigest, newContextId, zeroize } from "./kms-envelope-v3.mjs";
import { makeArmCompleter } from "./arm.mjs";
import { StateAuthorityClient } from "./state-authority.mjs";
import { makeArmedTransport } from "./mtproto-client.mjs";
import { makeConnection } from "./connection.mjs";
import { MODES } from "./tg-chokepoint.mjs";
import { deriveAuthority } from "./policy-verify.mjs";
import { createPgDb } from "./pg-shim.mjs";
import { makeOnboardingTransport } from "./onboarding-transport.mjs";
import { makeOnboardingEffects } from "./onboarding-serve.mjs";
import { makeOnboardingService } from "./onboarding-service.mjs";
import { verifyOnboardingGrant } from "./onboarding-grant.mjs";

const execFileP = promisify(execFile);

// vsock contract (parent CID 3), mirrors the worker:
//   :8000  vsock-proxy -> KMS    (kmstool_enclave_cli --proxy-port 8000)
//   :8001  provider    -> {creds, kms_key_id, region, config_cipher}
//   :8003  State Authority relay (gateway -> security account, request/response)
const PROVIDER_CID = "3";
const PROVIDER_PORT = "8001";
const KMS_PROXY_PORT = "8000";
const STATE_AUTHORITY_PORT = "8003";

// Bounded retry for the parent vsock relays. The fork-per-connection socat
// listeners (provider :8001, State Authority :8003) can transiently fail with
// ENOTCONN ("Transport endpoint is not connected") under concurrent bursts
// (adopt + lease-renew + 5-min security check landing together, esp. with >1
// guarded link). A single such blip used to fail freshCreds() at adopt or a lease
// renewal and flap the guard DOWN (C6); a short retry masks it. These calls are
// connection-establish request/response to idempotent/CAS endpoints, so a retry
// after a failed connect is safe.
async function vsockRetry(fn, attempts = 3) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try { return await fn(); }
    catch (e) { last = e; if (i < attempts - 1) await new Promise((r) => setTimeout(r, 150 * (i + 1))); }
  }
  throw last;
}

// State Authority response reader. DUAL-MODE so the enclave is robust to either
// backend across a cutover/rollback:
//   - LEGACY (per-call sa-service.mjs): the response is bare JSON delimited by the
//     socat connection close (EOF). First byte is '{' (0x7B).
//   - FRAMED (persistent sa-service-persistent.mjs): a 4-byte big-endian length
//     prefix followed by exactly that many JSON bytes. We resolve the INSTANT the
//     frame is complete -- never waiting for EOF. This is the fix for the flap:
//     the per-call node-spawn storm (each call EXEC'd a fresh @aws-sdk node ~330ms)
//     saturated the host so the enclave's VSOCK-CONNECT reset with ENOTCONN
//     ("Transport endpoint is not connected") and 3-retry exhaustion fenced the
//     guard. A persistent backend removes the spawn storm, and length-framing
//     removes the dependence on vsock propagating the half-close EOF (the reason
//     every persistent-backend attempt that relied on EOF stalled/truncated).
// The reader is a pure state machine (Buffers in, verdict out) so it is unit- and
// integration-testable off the enclave; the only thing not testable off-box is the
// vsock byte transport itself, which this design no longer trusts for delimiting.
export function makeSAReader() {
  const chunks = []; let total = 0; let mode = null; let frameLen = -1; let settled = false;
  const MAX = 4 << 20; // 4 MiB sanity ceiling on a framed response
  const buf = () => Buffer.concat(chunks, total);
  return {
    // Feed one chunk (Buffer). Returns { done:false } | { done:true, value } | { done:true, error }.
    push(d) {
      if (settled) return { done: false };
      if (d && d.length) { chunks.push(d); total += d.length; }
      if (mode === null) { if (total < 1) return { done: false }; mode = (buf()[0] === 0x7B) ? "legacy" : "framed"; }
      if (mode === "legacy") return { done: false }; // legacy resolves on eof()
      if (total < 4) return { done: false };
      if (frameLen < 0) frameLen = buf().readUInt32BE(0);
      if (frameLen > MAX || frameLen < 2) { settled = true; return { done: true, error: new Error(`framed length out of range (${frameLen})`) }; }
      if (total < 4 + frameLen) return { done: false };
      settled = true;
      const body = buf().subarray(4, 4 + frameLen).toString("utf8");
      try { return { done: true, value: JSON.parse(body) }; }
      catch (e) { return { done: true, error: new Error(`framed parse failed (len=${frameLen}: ${e.message})`) }; }
    },
    // Connection closed. Resolves the legacy path; for an incomplete frame returns a
    // rich error (the diagnostic surface -- it reaches guard_state.notes.reason).
    eof(stderr = "") {
      if (settled) return { done: false };
      settled = true;
      if (mode === "legacy") {
        try { return { done: true, value: JSON.parse(buf().toString("utf8")) }; }
        catch (e) { return { done: true, error: new Error(`empty/bad response (rx=${total}B ${stderr || e.message})`) }; }
      }
      return { done: true, error: new Error(`incomplete response (mode=${mode ?? "none"} rx=${total}B need=${frameLen < 0 ? "?" : 4 + frameLen}B ${stderr})`) };
    },
    stats() { return { mode: mode ?? "none", rx: total, need: frameLen < 0 ? -1 : 4 + frameLen }; },
  };
}

// --- configuration delivered over vsock from the parent (nothing baked in) ---
// MUST spawn + close stdin (NOT execFile): socat's `-t 20` is a HALF-CLOSE
// timeout -- after the provider responds and EOFs its side, socat waits up to
// 20s for the OTHER direction (our stdin) to EOF before exiting. execFile leaves
// the child's stdin pipe open forever, so every fetch blocked the full 20s. Since
// freshCreds() runs before every envelope seal, that 20s was added to every
// seal/rotate/finalize/adopt op (the ~21s/step latency). Closing stdin makes
// socat return the instant the provider responds. Wrapped in vsockRetry for the
// transient ENOTCONN fork-race (C6).
function fetchProviderOnce() {
  return new Promise((resolve, reject) => {
    const child = spawn("socat", ["-t", "20", "-", `VSOCK-CONNECT:${PROVIDER_CID}:${PROVIDER_PORT}`]);
    let stdout = "", stderr = "";
    child.stdout.on("data", (d) => { stdout += d; });
    child.stderr.on("data", (d) => { stderr += d; });
    child.on("error", reject);
    child.on("close", () => {
      try { resolve(JSON.parse(stdout)); }
      catch (e) { reject(new Error(`provider: empty/bad response (${stderr.trim() || e.message})`)); }
    });
    try { child.stdin.end(); } catch (e) { reject(e); }   // EOF stdin -> socat returns immediately
  });
}
function fetchProvider() { return vsockRetry(fetchProviderOnce); }

// Fresh IMDS creds each call (they rotate); config is static after boot.
async function freshCreds() {
  const { creds } = await fetchProvider();
  if (!creds?.AccessKeyId) throw new Error("provider returned no creds");
  return creds;
}

// Plain (non-context) attested decrypt for the bootstrap config blob. The
// patched kmstool makes --encryption-context optional, so this works for the
// config while the v3 session path uses the context-bound transport. NOTE: if
// the gateway KMS policy requires SessionsContextId on every Decrypt, the config
// must be sealed under a fixed config context and CONFIG_KMS_CONTEXT supplied;
// otherwise the config key/policy must permit a contextless Decrypt. This is a
// deployment alignment captured in the runbook.
async function kmsDecryptConfig({ region, keyId, ciphertext, creds, context }) {
  const args = [
    "decrypt", "--region", region, "--proxy-port", KMS_PROXY_PORT,
    "--aws-access-key-id", creds.AccessKeyId, "--aws-secret-access-key", creds.SecretAccessKey,
    "--aws-session-token", creds.Token, "--encryption-algorithm", "SYMMETRIC_DEFAULT",
    "--key-id", keyId, "--ciphertext", ciphertext,
  ];
  if (context) args.push("--encryption-context", context);
  let stdout;
  try {
    ({ stdout } = await execFileP("kmstool_enclave_cli", args, { encoding: "utf8", maxBuffer: 1 << 20 }));
  } catch (e) {
    // Surface the REAL kmstool/KMS stderr (execFile otherwise reports only the
    // generic "Command failed: <cmd>"), and REDACT the creds the command echoes
    // so they never reach a log/standby reason.
    const redact = (s) => String(s || "")
      .split(creds.AccessKeyId || " ").join("AKID")
      .split(creds.SecretAccessKey || " ").join("SECRET")
      .split(creds.Token || " ").join("TOKEN");
    // Prefer real error lines (kmstool/aws-c emit a wall of [INFO] then the
    // failure at the END); fall back to the stderr tail.
    const full = redact(e.stderr || e.message);
    const errLines = full.split(/\r?\n/).filter((l) => /error|fatal|denied|exception|invalid|fail|refused|timeout|not authorized/i.test(l) && !/\[INFO\]/i.test(l));
    const detail = (errLines.join(" | ") || full).replace(/\s+/g, " ").trim();
    throw new Error(`config decrypt failed (ctx=${context ? "yes" : "no"}): ${detail.slice(-450)}`);
  }
  const m = stdout.match(/PLAINTEXT:\s*(\S+)/i);
  if (!m) throw new Error("kmstool: no plaintext in config decrypt");
  return Buffer.from(m[1], "base64").toString("utf8");
}

async function loadConfig() {
  const p = await fetchProvider();
  if (!p?.kms_key_id || !p?.config_cipher || !p?.creds?.AccessKeyId) {
    throw new Error("provider missing kms_key_id / config_cipher / creds");
  }
  const region = p.region || "us-east-1";
  const raw = await kmsDecryptConfig({ region, keyId: p.kms_key_id, ciphertext: p.config_cipher, creds: p.creds, context: p.config_kms_context });
  const config = JSON.parse(raw);
  if (!config?.GUARD_DB_URL || !config?.TELEGRAM_API_ID || !config?.TELEGRAM_API_HASH || !config?.STATE_AUTHORITY_PUBKEY) {
    throw new Error("decrypted config incomplete (need TELEGRAM_API_ID/HASH, GUARD_DB_URL, STATE_AUTHORITY_PUBKEY)");
  }
  // The gateway talks to Postgres AS the narrow guard_gateway role (5.3): SELECT
  // on the v3 seal columns + policy chain, EXECUTE on the gateway-only seal
  // functions, no general table write.
  const db = createPgDb(config.GUARD_DB_URL);
  const webauthnOrigins = String(config.WEBAUTHN_ORIGIN || config.WEBAUTHN_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);

  return {
    KMS_REGION: region,
    KMS_PROXY_PORT,
    KMS_KEY_ID: config.KMS_SESSION_KEY_ID || p.kms_key_id,
    STATE_AUTHORITY_PUBKEY: config.STATE_AUTHORITY_PUBKEY,
    TG_API_ID: Number(config.TELEGRAM_API_ID),
    TG_API_HASH: config.TELEGRAM_API_HASH,
    WEBAUTHN_RP_ID: config.WEBAUTHN_RP_ID || "",
    WEBAUTHN_ORIGINS: webauthnOrigins,
    GOOGLE_CLIENT_ID: config.GOOGLE_CLIENT_ID || config.NEXT_PUBLIC_GOOGLE_CLIENT_ID || "",
    // Onboarding channel binds these so the browser can match the published release.
    // They are PUBLIC (a PCR0 + a release digest), not secrets, and they change on
    // every reproducible rebuild — so the PARENT injects them at runtime (p.*),
    // authoritative over any value baked into the sealed secret config. This means a
    // rebuild never requires re-sealing the secret config: only the parent's
    // pcr0_g/release_record_digest are updated. (Falls back to the sealed config for
    // backward compatibility.) The browser still verifies the REAL measured PCR0 from
    // the live attestation against the published release record, so a wrong injected
    // value cannot forge "verified" — it would only mis-claim in the grant candidate.
    PCR0_G: p.pcr0_g || config.PCR0_G || "",
    RELEASE_RECORD_DIGEST: p.release_record_digest || config.RELEASE_RECORD_DIGEST || "",
    // PRIMARY new-login detection cadence (ms). The pushed UpdateNewAuthorization is a
    // best-effort SPEEDUP (measured 2026-06-17: unreliable on long-lived connections),
    // so the account.getAuthorizations roster diff IS the reliable detector and this
    // cadence bounds detection latency: the first poll that catches a tdata replay rides
    // THIS interval, so near-instant detection needs a tight baseline. Lab flood-probe
    // (2026-06-25, single account) found account.getAuthorizations safe down to 0.1s with
    // zero FLOOD_WAIT across ~540 calls, so 2s carries a 20x+ per-account margin. Kept a
    // RUNTIME KNOB (p.sweep_ms / config.GUARD_SWEEP_MS) so it can be dialed BACK at scale,
    // where the limit is aggregate per-IP / per-api_id load (N accounts), not per-account.
    SWEEP_MS: Number(p.sweep_ms ?? config.GUARD_SWEEP_MS ?? 2000),
    // Adaptive fast-poll base (P4): resolved HERE (where `config` is in scope), read via
    // cfg.FAST_SWEEP_MS in the runtime below. Parent-injectable to tune without a rebuild.
    FAST_SWEEP_MS: Number(p.fast_sweep_ms ?? config.GUARD_FAST_SWEEP_MS ?? 1000),
    db,
    // State Authority relay: one request/response per call over vsock :8003. The
    // parent relays opaque frames to the security account; it cannot forge a
    // signed response (verified in StateAuthorityClient against the pinned key).
    // MUST write the child's stdin via spawn: execFile has no `input` option (only
    // spawnSync/execSync do), so the old execFile({input}) sent NOTHING and the
    // parent sa-service hung forever reading stdin -- the bug that froze the first
    // live onboarding at `authorize` (createOnboardingIfAbsent). Same fix family as
    // pipeToParentVsock, but this path needs the response back, so capture stdout.
    stateAuthorityTransport: (method, args) => vsockRetry(() => new Promise((resolve, reject) => {
      const child = spawn("socat", ["-t", "20", "-", `VSOCK-CONNECT:${PROVIDER_CID}:${STATE_AUTHORITY_PORT}`]);
      const reader = makeSAReader();
      let stderr = "", settled = false;
      // NOTE: do NOT setEncoding on stdout -- the reader needs raw Buffers to read
      // the 4-byte length prefix; default chunks are Buffers.
      const finish = (err, val) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { child.kill(); } catch { /* already gone */ } // we have the full frame; don't wait on socat's half-close linger
        if (err) reject(new Error(`state authority: ${err.message}`)); else resolve(val);
      };
      child.stdout.on("data", (d) => { const r = reader.push(d); if (r.done) finish(r.error, r.value); });
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("error", (e) => finish(e));
      child.on("close", () => { const r = reader.eof(stderr.trim()); if (r.done) finish(r.error, r.value); });
      // Backstop: a complete frame resolves immediately; this only fires if the
      // bytes never arrive (e.g. ENOTCONN with no stderr, or a wedged vsock).
      const timer = setTimeout(() => finish(new Error(`timeout ${JSON.stringify(reader.stats())} ${stderr.trim()}`)), 10_000);
      try { child.stdin.write(JSON.stringify({ method, args })); child.stdin.end(); }
      catch (e) { finish(e); }
    })),
    // policyStore: the ordered signed policy_envelopes chain for a link.
    policyStore: async (linkId) => {
      const rows = await db.from("policy_envelopes").select("version,action,core,core_hash,sigs").eq("link_id", linkId).order("version", { ascending: true });
      return (rows?.data ?? rows ?? []).map((r) => ({ version: r.version, action: r.action, core: r.core, core_hash: r.core_hash, sigs: r.sigs }));
    },
    emitNewAuth: () => {},   // wired to the brain channel when the brain attaches
    onAutoReconnect: async () => {},
    logger: (message) => console.log(message),
  };
}

function dbSessionRows(sessions) {
  if (sessions == null) return null;
  return sessions.map((s) => ({
    hash: String(s.hash),
    device_model: s.deviceModel ?? null,
    platform: s.platform ?? null,
    system_version: s.systemVersion ?? null,
    app_name: s.appName ?? null,
    ip: s.ip ?? null,
    country: s.country ?? null,
    region: s.region ?? null,
    date_created: s.dateCreated ?? null,
    date_active: s.dateActive ?? null,
    api_id: s.apiId ?? null,
    official_app: s.officialApp ?? null,
    app_version: s.appVersion ?? null,
    is_current: !!s.current,
  }));
}

export async function main() {
  const cfg = await loadConfig();

  const kms = timed(makeKmstoolTransport({ region: cfg.KMS_REGION, proxyPort: cfg.KMS_PROXY_PORT, keyId: cfg.KMS_KEY_ID }), "KMS"); // [diag]
  // [diag] time each State Authority round-trip (the bare transport is a function,
  // not an object, so wrap it directly rather than via timed()).
  const sat = cfg.stateAuthorityTransport;
  const timedSAT = (method, args) => {
    const t0 = Date.now();
    return Promise.resolve(sat(method, args)).finally(() => emitTiming(`SA ${method} ${Date.now() - t0}ms`));
  };
  const authorityClient = new StateAuthorityClient({
    pinnedPublicKey: cfg.STATE_AUTHORITY_PUBKEY,
    transport: timedSAT,   // vsock relay to the security account
  });

  const gateway = new Gateway({
    kms,
    freshCreds,
    openEnvelopeV3,
    authorityClient,
    policyStore: cfg.policyStore,              // narrow guard_gateway SELECT on policy_envelopes
    verifierCfg: { rpId: cfg.WEBAUTHN_RP_ID, origins: cfg.WEBAUTHN_ORIGINS, googleClientId: cfg.GOOGLE_CLIENT_ID },
    // transportFactory builds the forked-connection armed transport. The
    // connection owns its chokepoint and installs the audited serialization (the
    // two write sites are in connection.mjs, host-validated by the captured-wire
    // suite); makeArmedTransport just wraps it into the high-level op surface.
    transportFactory: async ({ mode, session, onNewAuth, onReconnect, onRtOk }) => {
      // Per-account onReconnect fires the gateway's catch-up sweep after a drop;
      // fall back to the shared cfg.onAutoReconnect. onRtOk stamps proven-work
      // liveness (the L1 watchdog's only health signal) on every successful round-trip.
      const conn = await makeConnection({ session, mode, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH, onAutoReconnect: onReconnect ?? cfg.onAutoReconnect, onRtOk, logger: cfg.logger, onTiming: emitTiming });
      // onNewAuth is supplied per-account by the gateway and drives the in-process
      // detection sweep (Option A); fall back to a no-op if absent.
      return makeArmedTransport({ conn, onNewAuth: onNewAuth ?? ((evt) => cfg.emitNewAuth(evt)) });
    },
    now: () => Date.now(),
    monotonic: () => Number(process.hrtime.bigint() / 1_000_000n),
    publishState: ({ linkId, sessions, status, notes }) => cfg.db.rpc("gateway_publish_state", {
      p_link: linkId,
      p_sessions: sessions == null ? null : JSON.stringify(dbSessionRows(sessions)),
      p_guard_status: status ?? null,
      p_notes: JSON.stringify(notes ?? {}),
    }),
    recordEvent: ({ linkId, hash, deviceModel, ip, country, reason, kind, detail }) =>
      cfg.db.rpc("gateway_record_event", {
        p_link: linkId,
        p_hash: hash ?? null,
        p_device_model: deviceModel ?? null,
        p_ip: ip ?? null,
        p_country: country ?? null,
        p_reason: reason,
        p_kind: kind ?? null,
        p_detail: JSON.stringify(detail ?? {}),
      }),
    // Eviction-cooldown oracle: the device_evicted hashes already removed for this
    // link since cutoffIso, aggregated to { hash, lastAt(ms), count }. Direct SELECT
    // (the gateway role already reads eviction_log, e.g. the guard_connected dedup
    // below) — no RPC needed for a read. Used by sweepAccount to avoid re-evicting a
    // session Telegram still lists as a ghost after a successful reset.
    recentlyEvicted: async ({ linkId, cutoffIso }) => {
      const { data, error } = await cfg.db
        .from("eviction_log")
        .select("hash,evicted_at")
        .eq("link_id", linkId)
        // Cooldown also covers contested burns (tdata-replay): a contested_session_burned
        // hash that Telegram still ghosts must not be re-burned every sweep. The detector's
        // liveness gate already blocks re-firing on a dead ghost, but this is belt+braces
        // and keeps recentlyKilled honest for the contested batch in brain.sweep.
        .in("kind", ["device_evicted", "contested_session_burned", "replay_burned", "flap_burned"])
        .gt("evicted_at", cutoffIso);
      if (error || !Array.isArray(data)) return [];
      const byHash = new Map();
      for (const r of data) {
        if (r.hash == null) continue;
        const h = String(r.hash);
        const at = Date.parse(r.evicted_at) || 0;
        const e = byHash.get(h);
        if (e) { e.count += 1; if (at > e.lastAt) e.lastAt = at; }
        else byHash.set(h, { lastAt: at, count: 1 });
      }
      return [...byHash.entries()].map(([hash, v]) => ({ hash, lastAt: v.lastAt, count: v.count }));
    },
    // Finalize a user-initiated disconnect: move the link 'disconnecting' ->
    // 'disconnected' and record the event. Enclave-only RPC (gateway_finalize_disconnect
    // is owned by guard_enclave so the 0017 fence authorizes the protected transition).
    finalizeDisconnect: ({ linkId, stateId }) => cfg.db.rpc("gateway_finalize_disconnect", {
      p_link: linkId,
      p_state_id: stateId,
    }),
  });

  // HOST: adopt all armed v3 links (read State Authority -> acquire lease -> KMS
  // open -> binding-1/2 -> derive authority -> serve), then run the in-process
  // detection (Option A) on a poll, and a lease watchdog that renews on cadence
  // and self-fences before expiry (5.5).
  void deriveAuthority; // used inside Gateway.adopt
  const holder = "gw-" + randomUUID();
  const LEASE_TTL_MS = 60_000, RENEW_MS = 20_000;
  // The pushed NEW_AUTH update, WHEN it fires, triggers an IMMEDIATE sweep (sub-second),
  // but it is unreliable on long-lived connections (measured), so this roster sweep is
  // the RELIABLE detector: account.getAuthorizations always lists a new session, so a
  // ~7s cadence bounds detection at ~7-10s regardless of the push. Flood-tested safe;
  // each account also self-throttles via its own FLOOD_WAIT backoff. The base is
  // parent-injectable (cfg.SWEEP_MS) to tune without a rebuild; a small per-boot offset
  // desyncs sweeps across accounts so a fleet never bursts in lockstep.
  const SWEEP_MS = cfg.SWEEP_MS + Math.floor(Math.random() * 3_000);
  // Adaptive fast-poll (P4): while an account is in a replay fast-window (ctx.fastUntil, set
  // on a tier>=2 replay suspicion), a second timer sweeps ONLY that account at ~2s so a
  // teleport-and-burn lands inside one short cycle. A small per-boot offset desyncs the fleet.
  // Telegram is SILENT on a replay (no push), so polling cadence IS the detection latency.
  const FAST_SWEEP_MS = cfg.FAST_SWEEP_MS + Math.floor(Math.random() * 500);
  // Reset-protection reads two extra MTProto calls (GetPassword + GetAccountTTL)
  // per account. The reset DELAY is days-scale so protection is unaffected by
  // cadence, but the dashboard also surfaces 2FA/recovery/TTL state from this
  // read, so a user toggling 2FA wants to see it reflect quickly. 90s balances
  // that UX against flood risk (two lightweight calls).
  const SECURITY_SWEEP_MS = 90_000;

  // ARM completion (Piece 2b): when the backend has written a signed v1 policy
  // genesis for a CONNECTED link, the gateway re-verifies it, re-seals FINAL under
  // signersCommit(v1), promotes the State Authority record to ARMED, and flips
  // status->armed. Only the enclave can (it alone re-opens the sealed session).
  const armCompleter = makeArmCompleter({
    db: cfg.db, kms, openEnvelopeV3, sealEnvelopeV3, envelopeDigest, newContextId, zeroize,
    freshCreds, authorityClient, holder,
    verifierCfg: { rpId: cfg.WEBAUTHN_RP_ID, origins: cfg.WEBAUTHN_ORIGINS, googleClientId: cfg.GOOGLE_CLIENT_ID },
    now: () => Date.now(),
  });
  const ARM_SWEEP_MS = 15_000;

  // Complete any pending arms first, then adopt every armed v3 link.
  await armCompleter.sweepPendingArms()
    .then(logArmFailures)
    .catch((e) => console.error("arm sweep:", e?.message));
  await adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS);
  // Publish security state (2FA/recovery/reset/TTL) into guard_state.notes right
  // away so the dashboard hardening card is correct on boot, not blank until the
  // first 90s security tick.
  await gateway.checkSecurityAll().catch((e) => console.error("initial security check:", e?.message));

  // Lease watchdog: renew every adopted lease before it expires; a failed renewal
  // self-fences that account (drops the live sender, zeroes session material).
  setInterval(() => { gateway.renewAllLeases(LEASE_TTL_MS).catch((e) => console.error("lease renew:", e?.message)); }, RENEW_MS);
  // L1 liveness watchdog (always-healthy design): on its OWN timer, OUTSIDE every
  // per-account op chain, detect an account whose last proven Telegram round-trip is
  // stale and surgically rebuild THAT connection (no enclave restart, lease kept).
  // This is what the 2026-06-14 silent death lacked: the renew loop kept running, so
  // a wedged sweep chain was never noticed. Also emit a per-account GWSTATUS:LIVE
  // beacon (proven-work age) so the host can observe per-account health.
  const WATCHDOG_MS = 20_000;
  setInterval(() => {
    try { gateway.accountWatchdog(); } catch (e) { console.error("watchdog:", e?.message); }
    for (const a of gateway.livenessAges()) emitStatus(`LIVE ${a.stateId} ${Math.round(a.ageMs)} gen=${a.gen}`).catch(() => {});
  }, WATCHDOG_MS);
  // Fast re-adopt poke: re-acquire any unadopted armed link every 10s (not only on
  // the 150s sweep). After a lease frees (self-fence escalation, or a prior enclave's
  // ~60s TTL expiry post-restart) the handoff is then seconds, not minutes.
  const FAST_READOPT_MS = 10_000;
  setInterval(() => {
    adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS).catch((e) => console.error("fast re-adopt:", e?.message));
  }, FAST_READOPT_MS);
  // Update-channel warmth (instant new-login detection). Telegram pushes
  // UpdateNewAuthorization to our otherwise-quiet connection only while it keeps
  // receiving a CONTENT request inside its short delivery window (~30s, measured in
  // experiments/probe.mjs) -- a transport ping does NOT count, but updates.getState
  // does. A lightweight getState every ~12s holds that window open, so a new login is
  // detected in ~60ms instead of waiting up to the ~45s sweep. Driven through the
  // gateway so it shares each account's FLOOD_WAIT backoff (flood-safe by design: it
  // cannot hammer during a wait); the getAuthorizations sweep stays the authoritative
  // fallback. Base is parent-injectable (cfg.WARMTH_MS); a per-boot offset desyncs the
  // fleet so restarts never burst in lockstep.
  const WARMTH_MS = (cfg.WARMTH_MS || 12_000) + Math.floor(Math.random() * 3_000);
  setInterval(() => {
    try { gateway.refreshUpdatesAll(); } catch (e) { console.error("warmth refresh:", e?.message); }
  }, WARMTH_MS);
  // Session sweep (fallback): an intruder login should be removed promptly. Each
  // account self-throttles via its own FLOOD_WAIT backoff, so the ~45s base (above)
  // stays safe even across accounts. The pushed update is the instant detector; this
  // is the safety net. Re-adopt FIRST: adoptArmedLinks ran once at boot, so a restart that raced a
  // lingering lease, a self-fenced account, or a link armed while a previous adopt
  // failed would otherwise stay silently UNGUARDED until the next reboot. Running
  // it every sweep makes adoption self-healing (it skips already-guarded links).
  setInterval(() => {
    adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS)
      .catch((e) => console.error("re-adopt:", e?.message))
      .then(() => gateway.reconcileDisconnectsAll().catch((e) => console.error("disconnect reconcile:", e?.message)))
      .then(() => gateway.reconcilePolicyAll().catch((e) => console.error("policy reconcile:", e?.message)))
      .finally(() => gateway.sweepAll().catch((e) => console.error("session sweep:", e?.message)));
  }, SWEEP_MS);
  // Fast-poll timer (P4): sweeps ONLY accounts currently in a replay fast-window. No re-adopt/
  // reconcile preamble (those stay on the baseline timer); just the tight sweep. The min-gap
  // skips an account the baseline timer swept moments ago, so the two timers never double-poll.
  setInterval(() => {
    gateway.sweepAll({ fastOnly: true, minGapMs: Math.max(1_000, FAST_SWEEP_MS - 250) })
      .catch((e) => console.error("fast sweep:", e?.message));
  }, FAST_SWEEP_MS);
  // Reset-protection check (slow): see SECURITY_SWEEP_MS — days-scale state polled
  // every 5 min, not every minute.
  setInterval(() => {
    gateway.checkSecurityAll().catch((e) => console.error("security check:", e?.message));
  }, SECURITY_SWEEP_MS);
  // Arm poll: complete pending arms, then adopt the newly-armed links.
  setInterval(() => {
    armCompleter.sweepPendingArms()
      .then((r) => {
        logArmFailures(r);
        if (r && r.completed > 0) return adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS);
      })
      .catch((e) => console.error("arm poll:", e?.message));
  }, ARM_SWEEP_MS);
  // Honest heartbeat: report accounts proven alive by a recent round-trip
  // (healthyCount), NOT mere map membership (adoptedCount). This is the fix for the
  // heartbeat that read guarding=2 for hours while both sweeps were dead.
  const heartbeat = () => cfg.db.rpc("gateway_heartbeat", {
    p_worker_id: "gateway-primary",
    p_guarding: gateway.healthyCount(),
    p_notes: JSON.stringify({ mode: "gateway-brain-folded" }),
  }).catch((e) => console.error("heartbeat:", e?.message));
  await heartbeat();
  setInterval(heartbeat, 60_000);

  // Serve enclave-born onboarding over the attested channel (4.10). The parent
  // relays each browser session to vsock :8005, bridged to this local server.
  startOnboardingService({ cfg, kms, authorityClient, holder });

  return gateway;
}

// ── enclave-born onboarding service (4.10) ───────────────────────────────────
// Attest WITH a per-ceremony X25519 public key (attest.c argv[1] = hex pubkey),
// so the browser can bind the channel to this exact enclave.
async function attestWithKey(hexPubkey) {
  const { stdout } = await execFileP("/attest", [hexPubkey], { encoding: "utf8", maxBuffer: 1 << 20 });
  const m = stdout.match(/ATTDOC:([A-Za-z0-9+/=]+)/);
  if (!m) throw new Error("attest: no ATTDOC in output");
  return m[1].trim();
}

// Wrap a socket as the {readFrame, writeFrame} the service expects: newline-
// delimited JSON frames. The parent's vsock relay shuttles these to the browser.
function frameTransport(socket) {
  let buf = "";
  const queue = [], waiters = [];
  socket.setEncoding("utf8");
  const deliver = (f) => { const w = waiters.shift(); if (w) w(f); else queue.push(f); };
  socket.on("data", (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      let frame; try { frame = JSON.parse(line); } catch { continue; }
      deliver(frame);
    }
  });
  socket.on("end", () => deliver(null));
  socket.on("close", () => deliver(null));
  return {
    readFrame: () => (queue.length ? Promise.resolve(queue.shift()) : new Promise((r) => waiters.push(r))),
    writeFrame: async (f) => { if (f === null) { try { socket.end(); } catch { /* closing */ } return; } socket.write(JSON.stringify(f) + "\n"); },
  };
}

function startOnboardingService({ cfg, kms, authorityClient, holder }) {
  const makeTransport = async () => {
    const conn = await makeConnection({ session: "", mode: MODES.ONBOARDING, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH, onAutoReconnect: cfg.onAutoReconnect, logger: cfg.logger, onTiming: emitTiming });
    return makeOnboardingTransport({ conn, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH });
  };
  const effects = timed(makeOnboardingEffects({
    db: cfg.db, kms, freshCreds, authorityClient, makeTransport, holder, now: () => Date.now(),
    verifyGrant: ({ candidate, signerGenesis, authorization, nowMs }) =>
      verifyOnboardingGrant({ candidate, signerGenesis, authorization, nowMs, cfg: { rpId: cfg.WEBAUTHN_RP_ID, origins: cfg.WEBAUTHN_ORIGINS, googleClientId: cfg.GOOGLE_CLIENT_ID } }),
  }), "OP"); // [diag] time each onboarding effect (DB/KMS/SA side-effects)
  const svc = makeOnboardingService({
    effects, attest: attestWithKey,
    pcr0g: cfg.PCR0_G ?? "", releaseRecordDigest: cfg.RELEASE_RECORD_DIGEST ?? "",
    onTiming: emitTiming, // [diag] STEP timing (full browser-observed step)
  });
  const server = net.createServer((socket) => {
    socket.on("error", () => { /* client gone */ });
    svc.handleConnection(frameTransport(socket)).catch(() => { try { socket.destroy(); } catch { /* gone */ } });
  });
  server.on("error", (e) => console.error("onboarding server:", e?.message));
  server.listen(9005, "127.0.0.1", () => console.log("onboarding service on 127.0.0.1:9005"));
  return server;
}

// Read every armed, version-3 FINAL link as the narrow guard_gateway role and
// adopt each. A failed adopt for one link is logged and skipped; the others still
// come up. With no v3 links yet (pre-onboarding) this is a clean no-op.
async function adoptArmedLinks(gateway, db, holder, ttlMs) {
  let rows = [];
  try {
    const r = await db.from("telegram_links")
      .select("id,state_id,tg_user_id,fresh_until,signers_commit,seal_generation,kms_context_id,seal_encrypted_data_key,seal_nonce,seal_ciphertext,seal_tag")
      .in("status", ["armed", "disconnecting"]).eq("seal_version", 3).eq("seal_phase", "FINAL");
    rows = r?.data ?? r ?? [];
  } catch (e) {
    console.error("adopt: armed-link query failed:", e?.message);
    return;
  }
  let adopted = 0, skipped = 0;
  for (const row of rows) {
    // Idempotent: this now runs every sweep, so skip links already guarded.
    if (gateway.isAdopted(row.state_id)) { skipped += 1; continue; }
    try {
      const { handle } = await gateway.adopt(row, holder, ttlMs);
      adopted += 1;
      // Once-per-link GOOD event so the user sees "your guard connected" (the only
      // positive confirmation protection is live). Durable dedup against eviction_log
      // so a restart / periodic re-adopt does not re-announce.
      try {
        const prior = await db.from("eviction_log").select("id").eq("link_id", row.id).eq("kind", "guard_connected");
        const seen = (prior?.data ?? prior ?? []).length > 0;
        if (!seen) {
          await db.rpc("gateway_record_event", { p_link: row.id, p_hash: null, p_device_model: null, p_ip: null, p_country: null, p_reason: "your Sessions guard connected", p_kind: "guard_connected", p_detail: JSON.stringify({}) });
        }
      } catch (e) { console.error("guard_connected emit:", row.id, e?.message); }
      gateway.sweepAccount(handle).catch(() => {}); // immediate protective sweep on adopt
    } catch (e) {
      console.error("adopt: link", row.id, "failed:", e?.message);
    }
  }
  if (adopted > 0 || rows.length !== skipped) console.log(`gateway: adopted ${adopted}, already-guarding ${skipped}, of ${rows.length} armed link(s)`);
}

function logArmFailures(result) {
  for (const failure of result?.failures ?? []) {
    console.error("arm: link", failure.link, "failed:", failure.error);
  }
  return result;
}

// Pipe a payload to a parent vsock port through socat by WRITING the child's
// stdin. execFile has no `input` option (only spawnSync/execSync do), so the old
// execFile({input}) silently sent nothing -- the bug that broke node-driven
// re-attestation and status emits while the entrypoint's shell-piped boot attest
// kept working.
function pipeToParentVsock(port, payload) {
  return new Promise((resolve) => {
    const child = spawn("socat", ["-t", "8", "-", `VSOCK-CONNECT:3:${port}`]);
    child.on("error", () => resolve());
    child.on("close", () => resolve());
    try { child.stdin.write(payload); child.stdin.end(); } catch { resolve(); }
  });
}

// Re-emit the boot attestation to the parent (vsock :8002) for liveness, so the
// public proof artifact stays fresh. NSM is local; no network or secrets.
async function reattest() {
  try {
    const { stdout } = await execFileP("/attest", [], { encoding: "utf8", maxBuffer: 1 << 20 });
    await pipeToParentVsock(8002, stdout);
  } catch (e) { console.error("reattest failed:", e?.message); }
}

// Boot/health observability: production enclaves have no console, so emit a one-
// line status to the parent (vsock :8004). Carries NO secret: just whether the
// gateway came up in full mode (and how many links it serves) or parked in
// standby with the reason. The parent listener logs it.
async function emitStatus(msg) {
  await pipeToParentVsock(8004, `GWSTATUS:${msg}\n`);
}

// [diag] Per-leg latency probe. Fire-and-forget to the parent status pipe (:8004),
// which timestamps each line on receipt in gw-status.log. Carries ONLY op names +
// durations (no session/secret material). Lets one clean onboard decompose where
// every millisecond goes: STEP (browser-observed) -> OP (effect) -> {KMS,SA,INVOKE}.
function emitTiming(line) { pipeToParentVsock(8004, `GWSTATUS:T ${line}\n`); }

// [diag] Wrap every async method of a plain transport/effects object so each call
// emits `<tag> <method> <ms>ms`. Return values and thrown errors pass through
// unchanged; non-function properties are copied as-is.
function timed(obj, tag) {
  if (!obj || typeof obj !== "object") return obj;
  const out = {};
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    if (typeof v !== "function") { out[k] = v; continue; }
    out[k] = async (...a) => {
      const t0 = Date.now();
      try { return await v.apply(obj, a); }
      finally { emitTiming(`${tag} ${k} ${Date.now() - t0}ms`); }
    };
  }
  return out;
}

// The EIF runs main(). A REAL deployment has a provider (config + creds over
// vsock) and the gateway adopts + guards. An attestation-only deployment has no
// provider: main() throws at loadConfig, we log it, and park in ATTESTED STANDBY
// — the enclave stays alive and re-attests on a cadence rather than crash-
// looping. Either way the public proof artifact stays live and fresh.
if (process.env.SESSIONS_GATEWAY_MAIN === "1") {
  // A single ceremony's GramJS auto-reconnect can reject in the background (no
  // awaiter) or a socket can emit an unhandled 'error'. Without these handlers Node
  // crashes the WHOLE enclave process -- closing EVERY live channel and surfacing to
  // the browser as "Lost the secure connection". Per-ceremony failures are already
  // isolated and torn down by the onboarding manager, so log + survive here.
  process.on("unhandledRejection", (e) => { try { console.error("unhandledRejection:", e?.message || e); } catch { /* never throw from the handler */ } });
  process.on("uncaughtException", (e) => { try { console.error("uncaughtException:", e?.message || e); } catch { /* never throw from the handler */ } });
  const ATTEST_EVERY_MS = 30 * 60 * 1000;
  (async () => {
    try {
      const gw = await main();
      console.log("gateway: armed and serving");
      await emitStatus(`READY adopted=${gw.adoptedCount()}`);
    } catch (e) {
      console.error("gateway: attested standby:", e?.message);
      await emitStatus(`STANDBY ${String(e?.message || e).slice(0, 500)}`);
    }
    setInterval(reattest, ATTEST_EVERY_MS); // keeps the event loop alive + artifact fresh
  })().catch((e) => { console.error("gateway-main fatal:", e?.message); process.exit(1); });
}
