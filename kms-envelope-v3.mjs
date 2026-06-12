// Version-3 session envelope (docs/gateway-brain-architecture.md 5.2, 5.6).
//
// Seal:  attested kms:GenerateDataKey (AES_256, EncryptionContext =
//        {SessionsContextId}) -> local AES-256-GCM over the canonical inner
//        payload, with a deterministic TLV AAD -> persist {encrypted data key,
//        nonce, ciphertext, tag}; zero the plaintext key.
// Open:  attested kms:Decrypt of the encrypted data key with the EXACT
//        per-row context (NO contextless fallback exists in this module, by
//        construction) -> local GCM open -> byte-compare every inner binding
//        against the row before any session use.
//
// The KMS transport is injected (makeKmstoolTransport below) because the
// stock kmstool_enclave_cli has no --encryption-context (docs/enclave-setup.md
// gate 5); the patched CLI ships in the batched Nitro rebuild. Everything
// else in this file is pure Node crypto and is exercised by
// tests/kms-envelope-v3.test.ts, including the AAD no-collision launch gate.

import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

export const SEAL_VERSION = 3;
export const AAD_DOMAIN = "sessions.fyi/kms-session/v3";
const NONCE_BYTES = 12;            // 96-bit GCM nonce, fresh per seal
const KEY_BYTES = 32;              // AES-256
const NULL_FIELD = 0xffffffff;     // length-prefix marker for a NULL field;
                                   // distinct from an empty string (length 0)

// ---------------------------------------------------------------------------
// Canonical AAD: deterministic length-prefixed (TLV) encoding of the ordered
// fields {domain, sealPhase, sealGeneration, link_id, nullable_tg_user_id,
// state_id, kmsContextId, signers_commit}. Every variable-width field carries
// a 4-byte big-endian length prefix; sealGeneration is fixed-width u32. Bare
// concatenation is forbidden (canonicalization-ambiguous); the launch-gate
// test asserts no AAD collision across field-boundary-shifted inputs.
// ---------------------------------------------------------------------------
function lpString(value) {
  if (value === null || value === undefined) {
    const b = Buffer.alloc(4);
    b.writeUInt32BE(NULL_FIELD, 0);
    return b;
  }
  const bytes = Buffer.from(String(value), "utf8");
  if (bytes.length >= NULL_FIELD) throw new Error("aad: field too long");
  const len = Buffer.alloc(4);
  len.writeUInt32BE(bytes.length, 0);
  return Buffer.concat([len, bytes]);
}

function u32(value) {
  if (!Number.isInteger(value) || value < 0 || value >= NULL_FIELD) {
    throw new Error(`aad: not a u32: ${value}`);
  }
  const b = Buffer.alloc(4);
  b.writeUInt32BE(value, 0);
  return b;
}

export function encodeAad({ sealPhase, sealGeneration, linkId, tgUserId, stateId, kmsContextId, signersCommit }) {
  if (sealPhase !== "RECOVERY" && sealPhase !== "FINAL") throw new Error(`aad: bad sealPhase ${sealPhase}`);
  if (sealPhase === "RECOVERY" && tgUserId !== null && tgUserId !== undefined) {
    throw new Error("aad: RECOVERY phase requires null tg_user_id");
  }
  if (sealPhase === "FINAL" && (tgUserId === null || tgUserId === undefined || String(tgUserId) === "")) {
    throw new Error("aad: FINAL phase requires tg_user_id");
  }
  for (const [name, v] of [["linkId", linkId], ["stateId", stateId], ["kmsContextId", kmsContextId], ["signersCommit", signersCommit]]) {
    if (v === null || v === undefined || String(v) === "") throw new Error(`aad: missing ${name}`);
  }
  return Buffer.concat([
    lpString(AAD_DOMAIN),
    lpString(sealPhase),
    u32(sealGeneration),
    lpString(linkId),
    tgUserId === null || tgUserId === undefined ? lpString(null) : lpString(tgUserId),
    lpString(stateId),
    lpString(kmsContextId),
    lpString(signersCommit),
  ]);
}

// ---------------------------------------------------------------------------
// Seal / open
// ---------------------------------------------------------------------------
export function sealEnvelopeV3({ dataKey, session, sealPhase, sealGeneration, linkId, tgUserId, stateId, kmsContextId, signersCommit }) {
  if (!Buffer.isBuffer(dataKey) || dataKey.length !== KEY_BYTES) {
    throw new Error("seal: dataKey must be a 32-byte Buffer");
  }
  if (typeof session !== "string" || session.length === 0) throw new Error("seal: missing session");
  const aad = encodeAad({ sealPhase, sealGeneration, linkId, tgUserId, stateId, kmsContextId, signersCommit });
  const inner = Buffer.from(JSON.stringify({
    link_id: String(linkId),
    tg_user_id: tgUserId === null || tgUserId === undefined ? null : String(tgUserId),
    state_id: String(stateId),
    seal_phase: sealPhase,
    seal_generation: sealGeneration,
    kms_context_id: String(kmsContextId),
    ciphertext_version: SEAL_VERSION,
    session,
    signers_commit: String(signersCommit),
  }), "utf8");
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", dataKey, nonce);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(inner), cipher.final()]);
  const tag = cipher.getAuthTag();
  inner.fill(0);
  return {
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function openEnvelopeV3({ dataKey, nonce, ciphertext, tag, expected }) {
  const { sealPhase, sealGeneration, linkId, tgUserId, stateId, kmsContextId, signersCommit } = expected;
  const aad = encodeAad({ sealPhase, sealGeneration, linkId, tgUserId, stateId, kmsContextId, signersCommit });
  const decipher = createDecipheriv("aes-256-gcm", dataKey, Buffer.from(nonce, "base64"));
  decipher.setAAD(aad);
  decipher.setAuthTag(Buffer.from(tag, "base64"));
  let inner;
  try {
    inner = Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]);
  } catch {
    throw new Error("open: GCM authentication failed (tampered envelope, wrong key, or binding mismatch)");
  }
  let payload;
  try {
    payload = JSON.parse(inner.toString("utf8"));
  } finally {
    inner.fill(0);
  }
  // Byte-compare EVERY inner binding against the row (binding-1). The AAD
  // already authenticated these, so a mismatch here means an encoder bug or a
  // forged payload sealed under correct AAD fields; either way fail closed.
  const expectTg = tgUserId === null || tgUserId === undefined ? null : String(tgUserId);
  const checks = [
    ["link_id", payload.link_id, String(linkId)],
    ["tg_user_id", payload.tg_user_id, expectTg],
    ["state_id", payload.state_id, String(stateId)],
    ["seal_phase", payload.seal_phase, sealPhase],
    ["seal_generation", payload.seal_generation, sealGeneration],
    ["kms_context_id", payload.kms_context_id, String(kmsContextId)],
    ["ciphertext_version", payload.ciphertext_version, SEAL_VERSION],
    ["signers_commit", payload.signers_commit, String(signersCommit)],
  ];
  for (const [name, got, want] of checks) {
    if (got !== want) throw new Error(`open: inner binding mismatch on ${name}`);
  }
  if (typeof payload.session !== "string" || payload.session.length === 0) {
    throw new Error("open: decrypted payload has no session");
  }
  return { session: payload.session, tgUserId: payload.tg_user_id, signersCommit: payload.signers_commit };
}

// ---------------------------------------------------------------------------
// Envelope digest: the CAS token the 0032 DB functions compare. Computed over
// the persisted envelope fields; base64/uuid/int tokens cannot contain "|",
// so the join is unambiguous.
// ---------------------------------------------------------------------------
export function envelopeDigest({ encryptedDataKey, nonce, ciphertext, tag, kmsContextId, sealGeneration }) {
  for (const [n, v] of [["encryptedDataKey", encryptedDataKey], ["nonce", nonce], ["ciphertext", ciphertext], ["tag", tag], ["kmsContextId", kmsContextId]]) {
    if (typeof v !== "string" || v.length === 0) throw new Error(`digest: missing ${n}`);
    if (v.includes("|")) throw new Error(`digest: field ${n} contains separator`);
  }
  if (!Number.isInteger(sealGeneration) || sealGeneration < 1) throw new Error("digest: bad generation");
  return createHash("sha256")
    .update([encryptedDataKey, nonce, ciphertext, tag, kmsContextId, String(sealGeneration)].join("|"), "utf8")
    .digest("hex");
}

export function newContextId() {
  return randomUUID();
}

export function zeroize(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}

// ---------------------------------------------------------------------------
// KMS transport. Context-bound, attestation-gated, NO contextless fallback:
// if the CLI rejects --encryption-context (stock build), every call throws.
// The patched kmstool_enclave_cli (genkey + encryption context) ships in the
// batched Nitro rebuild; until then this transport is wired but unreachable.
// ---------------------------------------------------------------------------
export function makeKmstoolTransport({ region, proxyPort, keyId, bin = "kmstool_enclave_cli" }) {
  if (!region || !proxyPort || !keyId) throw new Error("kms transport: region, proxyPort, keyId required");

  const ctxArgs = (contextId) => {
    if (typeof contextId !== "string" || contextId.length === 0) {
      throw new Error("kms transport: SessionsContextId is REQUIRED (no contextless path)");
    }
    // The patched kmstool parses --encryption-context as JSON (matches the
    // SDK's aws_kms_*_blocking_with_context, which json-decodes the arg).
    return ["--encryption-context", JSON.stringify({ SessionsContextId: contextId })];
  };

  async function run(args, creds) {
    const { stdout } = await execFileP(bin, [
      ...args,
      "--region", region,
      "--proxy-port", String(proxyPort),
      "--aws-access-key-id", creds.AccessKeyId,
      "--aws-secret-access-key", creds.SecretAccessKey,
      "--aws-session-token", creds.Token,
      "--key-id", keyId,
    ], { encoding: "utf8", maxBuffer: 1 << 20 });
    return stdout;
  }

  return {
    // -> { plaintextKey: Buffer(32), encryptedDataKey: base64 string }
    async generateDataKey({ contextId, creds }) {
      const out = await run(["genkey", "--key-spec", "AES-256", ...ctxArgs(contextId)], creds);
      const ct = out.match(/CIPHERTEXT:\s*(\S+)/i);
      const pt = out.match(/PLAINTEXT:\s*(\S+)/i);
      if (!ct || !pt) throw new Error("kms genkey: malformed kmstool output");
      const plaintextKey = Buffer.from(pt[1], "base64");
      if (plaintextKey.length !== KEY_BYTES) throw new Error("kms genkey: data key is not 32 bytes");
      return { plaintextKey, encryptedDataKey: ct[1] };
    },
    // -> Buffer(32). Throws on missing context by construction.
    async decryptDataKey({ encryptedDataKey, contextId, creds }) {
      const out = await run([
        "decrypt",
        "--encryption-algorithm", "SYMMETRIC_DEFAULT",
        "--ciphertext", encryptedDataKey,
        ...ctxArgs(contextId),
      ], creds);
      const m = out.match(/PLAINTEXT:\s*(\S+)/i);
      if (!m) throw new Error("kms decrypt: no plaintext in kmstool output");
      const key = Buffer.from(m[1], "base64");
      if (key.length !== KEY_BYTES) throw new Error("kms decrypt: data key is not 32 bytes");
      return key;
    },
  };
}
