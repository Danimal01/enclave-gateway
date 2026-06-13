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

// --- configuration delivered over vsock from the parent (nothing baked in) ---
async function fetchProvider() {
  const { stdout } = await execFileP("socat", ["-t", "20", "-", `VSOCK-CONNECT:${PROVIDER_CID}:${PROVIDER_PORT}`], { encoding: "utf8", maxBuffer: 1 << 20 });
  return JSON.parse(stdout);
}

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
  const { stdout } = await execFileP("kmstool_enclave_cli", args, { encoding: "utf8", maxBuffer: 1 << 20 });
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
    db,
    // State Authority relay: one request/response per call over vsock :8003. The
    // parent relays opaque frames to the security account; it cannot forge a
    // signed response (verified in StateAuthorityClient against the pinned key).
    // MUST write the child's stdin via spawn: execFile has no `input` option (only
    // spawnSync/execSync do), so the old execFile({input}) sent NOTHING and the
    // parent sa-service hung forever reading stdin -- the bug that froze the first
    // live onboarding at `authorize` (createOnboardingIfAbsent). Same fix family as
    // pipeToParentVsock, but this path needs the response back, so capture stdout.
    stateAuthorityTransport: (method, args) => new Promise((resolve, reject) => {
      const child = spawn("socat", ["-t", "20", "-", `VSOCK-CONNECT:${PROVIDER_CID}:${STATE_AUTHORITY_PORT}`]);
      let stdout = "", stderr = "";
      child.stdout.on("data", (d) => { stdout += d; });
      child.stderr.on("data", (d) => { stderr += d; });
      child.on("error", reject);
      child.on("close", () => {
        try { resolve(JSON.parse(stdout)); }
        catch (e) { reject(new Error(`state authority: empty/bad response (${stderr.trim() || e.message})`)); }
      });
      try { child.stdin.write(JSON.stringify({ method, args })); child.stdin.end(); }
      catch (e) { reject(e); }
    }),
    // policyStore: the ordered signed policy_envelopes chain for a link.
    policyStore: async (linkId) => {
      const rows = await db.from("policy_envelopes").select("version,action,core,core_hash,sigs").eq("link_id", linkId).order("version", { ascending: true });
      return (rows?.data ?? rows ?? []).map((r) => ({ version: r.version, action: r.action, core: r.core, core_hash: r.core_hash, sigs: r.sigs }));
    },
    emitNewAuth: () => {},   // wired to the brain channel when the brain attaches
    onAutoReconnect: async () => {},
    logger: undefined,
  };
}

export async function main() {
  const cfg = await loadConfig();

  const kms = makeKmstoolTransport({ region: cfg.KMS_REGION, proxyPort: cfg.KMS_PROXY_PORT, keyId: cfg.KMS_KEY_ID });
  const authorityClient = new StateAuthorityClient({
    pinnedPublicKey: cfg.STATE_AUTHORITY_PUBKEY,
    transport: cfg.stateAuthorityTransport,   // vsock relay to the security account
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
    transportFactory: async ({ mode, session, onNewAuth }) => {
      const conn = await makeConnection({ session, mode, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH, onAutoReconnect: cfg.onAutoReconnect, logger: cfg.logger });
      // onNewAuth is supplied per-account by the gateway and drives the in-process
      // detection sweep (Option A); fall back to a no-op if absent.
      return makeArmedTransport({ conn, onNewAuth: onNewAuth ?? ((evt) => cfg.emitNewAuth(evt)) });
    },
    now: () => Date.now(),
    monotonic: () => Number(process.hrtime.bigint() / 1_000_000n),
  });

  // HOST: adopt all armed v3 links (read State Authority -> acquire lease -> KMS
  // open -> binding-1/2 -> derive authority -> serve), then run the in-process
  // detection (Option A) on a poll, and a lease watchdog that renews on cadence
  // and self-fences before expiry (5.5).
  void deriveAuthority; // used inside Gateway.adopt
  const holder = "gw-" + randomUUID();
  const LEASE_TTL_MS = 60_000, RENEW_MS = 20_000, SWEEP_MS = 5 * 60_000;

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
  await armCompleter.sweepPendingArms().catch((e) => console.error("arm sweep:", e?.message));
  await adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS);

  // Lease watchdog: renew every adopted lease before it expires; a failed renewal
  // self-fences that account (drops the live sender, zeroes session material).
  setInterval(() => { gateway.renewAllLeases(LEASE_TTL_MS).catch((e) => console.error("lease renew:", e?.message)); }, RENEW_MS);
  // Detection poll: a protective sweep + reset-protection check across all accounts.
  setInterval(() => { gateway.sweepAll().catch(() => {}); gateway.checkSecurityAll().catch(() => {}); }, SWEEP_MS);
  // Arm poll: complete pending arms, then adopt the newly-armed links.
  setInterval(() => {
    armCompleter.sweepPendingArms()
      .then((r) => { if (r && r.completed > 0) return adoptArmedLinks(gateway, cfg.db, holder, LEASE_TTL_MS); })
      .catch((e) => console.error("arm poll:", e?.message));
  }, ARM_SWEEP_MS);

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
    const conn = await makeConnection({ session: "", mode: MODES.ONBOARDING, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH, onAutoReconnect: cfg.onAutoReconnect, logger: cfg.logger });
    return makeOnboardingTransport({ conn, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH });
  };
  const effects = makeOnboardingEffects({
    db: cfg.db, kms, freshCreds, authorityClient, makeTransport, holder, now: () => Date.now(),
    verifyGrant: ({ candidate, signerGenesis, authorization, nowMs }) =>
      verifyOnboardingGrant({ candidate, signerGenesis, authorization, nowMs, cfg: { rpId: cfg.WEBAUTHN_RP_ID, origins: cfg.WEBAUTHN_ORIGINS, googleClientId: cfg.GOOGLE_CLIENT_ID } }),
  });
  const svc = makeOnboardingService({
    effects, attest: attestWithKey,
    pcr0g: cfg.PCR0_G ?? "", releaseRecordDigest: cfg.RELEASE_RECORD_DIGEST ?? "",
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
      .select("id,state_id,tg_user_id,signers_commit,seal_generation,kms_context_id,seal_encrypted_data_key,seal_nonce,seal_ciphertext,seal_tag")
      .eq("status", "armed").eq("seal_version", 3).eq("seal_phase", "FINAL");
    rows = r?.data ?? r ?? [];
  } catch (e) {
    console.error("adopt: armed-link query failed:", e?.message);
    return;
  }
  let adopted = 0;
  for (const row of rows) {
    try {
      const { handle } = await gateway.adopt(row, holder, ttlMs);
      adopted += 1;
      gateway.sweepAccount(handle).catch(() => {}); // immediate protective sweep on adopt
    } catch (e) {
      console.error("adopt: link", row.id, "failed:", e?.message);
    }
  }
  console.log(`gateway: adopted ${adopted}/${rows.length} armed link(s)`);
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

// The EIF runs main(). A REAL deployment has a provider (config + creds over
// vsock) and the gateway adopts + guards. An attestation-only deployment has no
// provider: main() throws at loadConfig, we log it, and park in ATTESTED STANDBY
// — the enclave stays alive and re-attests on a cadence rather than crash-
// looping. Either way the public proof artifact stays live and fresh.
if (process.env.SESSIONS_GATEWAY_MAIN === "1") {
  const ATTEST_EVERY_MS = 30 * 60 * 1000;
  (async () => {
    try {
      const gw = await main();
      console.log("gateway: armed and serving");
      await emitStatus(`READY adopted=${gw.adoptedCount()}`);
    } catch (e) {
      console.error("gateway: attested standby:", e?.message);
      await emitStatus(`STANDBY ${String(e?.message || e).slice(0, 220)}`);
    }
    setInterval(reattest, ATTEST_EVERY_MS); // keeps the event loop alive + artifact fresh
  })().catch((e) => { console.error("gateway-main fatal:", e?.message); process.exit(1); });
}
