// gateway/onboarding-grant.mjs: the OnboardingGrant verifier (spec 4.10.6, the
// C-6 / C-4 fixes). Published and frozen into PCR0_G.
//
// Before Telegram is contacted, the user enrolls an authority root from the
// EXISTING signer set (passkey / wallet / Google OIDC) and authorizes a grant
// over the canonical hash of:
//   { domain:"sessions.fyi/onboard/v1", link_id, normalized_phone,
//     signers_commit, gateway_nonce, pcr0_g, channel_key_hash, expires_at }
// The gateway generates link_id/state_id/nonce, verifies the authorization
// against the committed signer genesis, requires exact equality with its held
// candidates, a short unexpired lifetime, and consumes the nonce once. This
// closes relay/backend substitution of the bound account (C-6) AFTER an honest
// setup page obtained the user's intended signer. It does NOT defend against a
// malicious setup page (C-4, the disclosed trust-on-first-use boundary).
//
// The grant signature uses the SAME primitives as the policy verifier, but over
// the grant hash, with WebAuthn clientDataJSON pinned to origin
// https://sessions.fyi and type webauthn.get/create, and OIDC to full Core
// 3.1.3.7 discipline. Because this is frozen into PCR0_G, the checks are
// enumerated now to SRP-downgrade-level detail; adding a check later forces a
// governed re-pin.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

export const GRANT_DOMAIN = "sessions.fyi/onboard/v1";
const GRANT_TTL_MAX_MS = 15 * 60 * 1000;
const ORIGIN = "https://sessions.fyi";

// Canonical grant hash. Field order is fixed and published; every field is
// length-tagged via JSON of an ordered object so no two field tuples collide.
export function grantHash(g) {
  const ordered = {
    domain: GRANT_DOMAIN,
    link_id: String(g.link_id),
    normalized_phone: String(g.normalized_phone),
    signers_commit: String(g.signers_commit),
    gateway_nonce: String(g.gateway_nonce),
    pcr0_g: String(g.pcr0_g),
    channel_key_hash: String(g.channel_key_hash),
    expires_at: Number(g.expires_at),
  };
  return createHash("sha256").update(JSON.stringify(ordered)).digest("base64url");
}

// COSE -> KeyObject (passkey enrollment public key), same as policy-verify.
function cborDecodeMap(buf) {
  let off = 0;
  const u8 = () => buf[off++];
  const len = (info) => {
    if (info < 24) return info;
    if (info === 24) return u8();
    if (info === 25) { const v = buf.readUInt16BE(off); off += 2; return v; }
    if (info === 26) { const v = buf.readUInt32BE(off); off += 4; return v; }
    throw new Error("cbor: length too large");
  };
  const item = () => {
    const b = u8(); const major = b >> 5, info = b & 0x1f;
    if (major === 0) return len(info);
    if (major === 1) return -1 - len(info);
    if (major === 2 || major === 3) { const n = len(info); const v = buf.subarray(off, off + n); off += n; return Buffer.from(v); }
    throw new Error(`cbor: unsupported major ${major}`);
  };
  const first = u8();
  if (first >> 5 !== 5) throw new Error("cbor: not a map");
  const count = len(first & 0x1f);
  const m = new Map();
  for (let i = 0; i < count; i++) { const k = item(); if (typeof k !== "number") throw new Error("cbor: non-int key"); m.set(k, item()); }
  return m;
}
function coseToKey(cose) {
  const m = cborDecodeMap(cose);
  const kty = m.get(1);
  if (kty === 2) {
    if (m.get(-1) !== 1) throw new Error("unsupported EC curve");
    const x = m.get(-2), y = m.get(-3);
    return { key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") }, format: "jwk" }), scheme: "ec" };
  }
  if (kty === 3) {
    const n = m.get(-1), e = m.get(-2);
    return { key: createPublicKey({ key: { kty: "RSA", n: n.toString("base64url"), e: e.toString("base64url") }, format: "jwk" }), scheme: "rsa" };
  }
  if (kty === 1) {
    if (m.get(-1) !== 6) throw new Error("unsupported OKP curve");
    return { key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: m.get(-2).toString("base64url") }, format: "jwk" }), scheme: "ed25519" };
  }
  throw new Error(`unsupported COSE kty ${kty}`);
}

// Passkey: WebAuthn assertion over the grant hash, origin pinned to exactly
// https://sessions.fyi, type webauthn.get or webauthn.create (ceremony), and
// challenge === grant hash. Closes same-RP cross-context signature reuse.
function verifyPasskeyGrant(hash, auth, signer) {
  if (auth.credentialId !== signer.credId) return false;
  const clientDataBytes = Buffer.from(auth.clientDataJSON, "base64url");
  const clientData = JSON.parse(clientDataBytes.toString("utf8"));
  if (clientData.type !== "webauthn.get" && clientData.type !== "webauthn.create") return false;
  if (clientData.origin !== ORIGIN) return false;             // EXACTLY, not includes
  if (clientData.challenge !== hash) return false;            // challenge IS the grant hash
  const authData = Buffer.from(auth.authenticatorData, "base64url");
  if (authData.length < 37) return false;
  const rpIdHash = createHash("sha256").update("sessions.fyi").digest();
  if (!authData.subarray(0, 32).equals(rpIdHash)) return false;
  if ((authData[32] & 0x01) === 0) return false;              // user present
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientDataBytes).digest()]);
  const { key, scheme } = coseToKey(Buffer.from(signer.publicKey, "base64url"));
  const signature = Buffer.from(auth.signature, "base64url");
  if (scheme === "ed25519") return cryptoVerify(null, signedData, key, signature);
  return cryptoVerify("sha256", signedData, key, signature);
}

// Wallet: EIP-191 personal_sign over the canonical onboarding message naming
// the grant hash. The external wallet prompt is the stronger UX surface.
function onboardWalletMessage(hash, nonce) {
  return (
    `sessions.fyi wants you to authorize connecting a Telegram account.\n\n` +
    `You are authorizing a one-time setup for this exact connection.\n\n` +
    `This does not move funds or grant any spending permission.\n\n` +
    `Grant: ${hash}\n\n` +
    `URI: https://sessions.fyi\nNonce: ${nonce}`
  );
}
function verifyWalletGrant(hash, auth, signer) {
  if (String(auth.address).toLowerCase() !== String(signer.address).toLowerCase()) return false;
  const nonceMatch = /\nNonce: (\S+)$/.exec(String(auth.message));
  if (!nonceMatch) return false;
  if (String(auth.message) !== onboardWalletMessage(hash, nonceMatch[1])) return false;
  const msgBytes = Buffer.from(auth.message, "utf8");
  const digest = keccak_256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${msgBytes.length}`, "utf8"), msgBytes]));
  const raw = Buffer.from(String(auth.signature).replace(/^0x/, ""), "hex");
  let rs, rec;
  if (raw.length === 65) { rs = raw.subarray(0, 64); rec = raw[64] >= 27 ? raw[64] - 27 : raw[64]; }
  else if (raw.length === 64) { const r = raw.subarray(0, 32); const ys = Buffer.from(raw.subarray(32, 64)); rec = (ys[0] & 0x80) ? 1 : 0; ys[0] &= 0x7f; rs = Buffer.concat([r, ys]); }
  else return false;
  if (rec !== 0 && rec !== 1) return false;
  const pub = secp256k1.Signature.fromBytes(rs, "compact").addRecoveryBit(rec).recoverPublicKey(digest);
  const addr = "0x" + Buffer.from(keccak_256(pub.toBytes(false).subarray(1))).subarray(12).toString("hex");
  return addr === String(signer.address).toLowerCase();
}

// Google OIDC: full Core 3.1.3.7 discipline; nonce === grant hash binds the
// token to this exact connection. Enumerated to downgrade-level detail (frozen).
const GOOGLE_ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);
async function verifyGoogleGrant(hash, auth, signer, cfg) {
  if (!cfg.googleClientId) return false;
  const parts = String(auth.idToken).split(".");
  if (parts.length !== 3) return false;
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header.alg !== "RS256" || !header.kid) return false;
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (!GOOGLE_ISSUERS.has(payload.iss)) return false;
  if (payload.aud !== cfg.googleClientId) return false;                 // exact audience
  if (payload.azp && cfg.googleClientId && payload.azp !== cfg.googleClientId) return false;
  if (payload.sub !== signer.sub) return false;
  if (payload.nonce !== hash) return false;                             // nonce IS the grant hash
  const now = cfg.nowMs ?? Date.now();
  const skew = 5 * 60 * 1000;
  if (Number(payload.exp) * 1000 < now - skew) return false;
  if (Number(payload.iat) * 1000 > now + skew) return false;
  if (payload.nbf && Number(payload.nbf) * 1000 > now + skew) return false;
  const fetchImpl = cfg.fetchImpl ?? fetch;
  const r = await fetchImpl("https://www.googleapis.com/oauth2/v3/certs");
  if (!r.ok) return false;
  const k = ((await r.json()).keys ?? []).find((x) => x.kid === header.kid && x.kty === "RSA");
  if (!k) return false;
  const key = createPublicKey({ key: { kty: "RSA", n: k.n, e: k.e }, format: "jwk" });
  return cryptoVerify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"), key, Buffer.from(parts[2], "base64url"));
}

/**
 * Verify an OnboardingGrant against the gateway's HELD candidate values.
 * `candidate` = { link_id, normalized_phone, signers_commit, gateway_nonce,
 *   pcr0_g, channel_key_hash, expires_at } exactly as the gateway generated/held.
 * `signerGenesis` = the committed initial signer (one of passkey/wallet/google).
 * `authorization` = { kind, ...signature material }.
 * Returns { ok:true, grantDigest } or { ok:false, reason }. grantDigest is the
 * single-use token persisted to telegram_links.onboarding_grant_digest.
 */
export async function verifyOnboardingGrant({ candidate, signerGenesis, authorization, cfg = {}, nowMs = Date.now() }) {
  const bad = (reason) => ({ ok: false, reason });
  // exact-equality with held candidates (the relay cannot substitute)
  for (const f of ["link_id", "normalized_phone", "signers_commit", "gateway_nonce", "pcr0_g", "channel_key_hash", "expires_at"]) {
    if (candidate[f] === undefined || candidate[f] === null) return bad(`candidate missing ${f}`);
  }
  if (Number(candidate.expires_at) <= nowMs) return bad("grant expired");
  if (Number(candidate.expires_at) > nowMs + GRANT_TTL_MAX_MS) return bad("grant lifetime exceeds the cap");
  if (signerGenesis.commit && signerGenesis.commit !== candidate.signers_commit) return bad("signer genesis does not match committed signers_commit");

  const hash = grantHash(candidate);
  let ok = false;
  try {
    if (authorization.kind === "passkey") ok = verifyPasskeyGrant(hash, authorization, signerGenesis);
    else if (authorization.kind === "wallet") ok = verifyWalletGrant(hash, authorization, signerGenesis);
    else if (authorization.kind === "google") ok = await verifyGoogleGrant(hash, authorization, signerGenesis, { ...cfg, nowMs });
    else return bad(`unknown authorization kind ${authorization.kind}`);
  } catch (e) {
    return bad(`authorization verify error: ${e.message}`);
  }
  if (!ok) return bad("authorization signature did not verify over the grant hash");
  return { ok: true, grantDigest: createHash("sha256").update(`grant:${hash}`).digest("hex") };
}

export { onboardWalletMessage, GRANT_TTL_MAX_MS };
