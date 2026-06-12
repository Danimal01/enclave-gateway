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

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Gateway } from "./gateway.mjs";
import { makeKmstoolTransport, openEnvelopeV3 } from "./kms-envelope-v3.mjs";
import { StateAuthorityClient } from "./state-authority.mjs";
import { makeArmedTransport } from "./mtproto-client.mjs";
import { makeConnection } from "./connection.mjs";
import { deriveAuthority } from "./policy-verify.mjs";
import { createPgDb } from "./pg-shim.mjs";

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
    db,
    // State Authority relay: one request/response per call over vsock :8003. The
    // parent relays opaque frames to the security account; it cannot forge a
    // signed response (verified in StateAuthorityClient against the pinned key).
    stateAuthorityTransport: async (method, args) => {
      const { stdout } = await execFileP("socat", ["-t", "20", "-", `VSOCK-CONNECT:${PROVIDER_CID}:${STATE_AUTHORITY_PORT}`], {
        encoding: "utf8", maxBuffer: 1 << 20, input: JSON.stringify({ method, args }),
      });
      return JSON.parse(stdout);
    },
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
    transportFactory: async ({ mode, session }) => {
      const conn = await makeConnection({ session, mode, apiId: cfg.TG_API_ID, apiHash: cfg.TG_API_HASH, onAutoReconnect: cfg.onAutoReconnect, logger: cfg.logger });
      return makeArmedTransport({ conn, onNewAuth: (evt) => cfg.emitNewAuth(evt) });
    },
    now: () => Date.now(),
    monotonic: () => Number(process.hrtime.bigint() / 1_000_000n),
  });

  // HOST: adopt all armed links (read State Authority -> acquire lease -> KMS
  // open -> binding-1/2 -> derive authority -> serve), then accept the brain
  // channel (Brain Admission) and the browser onboarding channel. The lease
  // watchdog renews on cadence and self-fences before expiry (5.5).
  void deriveAuthority; // used inside Gateway.adopt
  return gateway;
}

// Re-emit the boot attestation to the parent (vsock :8002) for liveness, so the
// public proof artifact stays fresh. NSM is local; no network or secrets.
async function reattest() {
  try {
    const { stdout } = await execFileP("/attest", [], { encoding: "utf8", maxBuffer: 1 << 20 });
    await execFileP("socat", ["-t", "8", "-", "VSOCK-CONNECT:3:8002"], { input: stdout, encoding: "utf8", maxBuffer: 1 << 20 });
  } catch (e) { console.error("reattest failed:", e?.message); }
}

// The EIF runs main(). A REAL deployment has a provider (config + creds over
// vsock) and the gateway adopts + guards. An attestation-only deployment has no
// provider: main() throws at loadConfig, we log it, and park in ATTESTED STANDBY
// — the enclave stays alive and re-attests on a cadence rather than crash-
// looping. Either way the public proof artifact stays live and fresh.
if (process.env.SESSIONS_GATEWAY_MAIN === "1") {
  const ATTEST_EVERY_MS = 30 * 60 * 1000;
  (async () => {
    try { await main(); console.log("gateway: armed and serving"); }
    catch (e) { console.error("gateway: attested standby (awaiting provider):", e?.message); }
    setInterval(reattest, ATTEST_EVERY_MS); // keeps the event loop alive + artifact fresh
  })().catch((e) => { console.error("gateway-main fatal:", e?.message); process.exit(1); });
}
