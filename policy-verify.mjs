// gateway/policy-verify.mjs: the OPEN policy-authority verifier (4.8).
//
// This is published precisely so "Sessions only acts on your signed policy" is
// verifiable by reading it. It is standard quorum/chain verification, NOT the
// proprietary detection IP (that lives in the closed brain). Vendored into the
// gateway build context (6.5): zero imports from private monorepo packages; it
// may depend only on its own lockfile's public packages.
//
// Responsibilities (4.2, 4.8):
//   - verify the signed policy_envelopes CHAIN from the State-Authority-anchored
//     head: each version signed by a quorum of the PRECEDING accepted signer set
//     (this is correct signer rotation: vN+1 may change the set but must be
//     signed by vN's set);
//   - bind every accepted core to this link_id + tg_user_id;
//   - derive the authorized {whitelist, signers, threshold, resetProtection,
//     headVersion} the gateway enforces every mutating op against.
//
// The exact-delta transition check is kept here (open) rather than moved to the
// closed brain: passkey/Google approvals are opaque hashes, so without it a
// compromised frontend could obtain one blind approval over a core that smuggles
// extra changes. Keeping it open is strictly safer and is "standard verification."
//
// MUST STAY IN SYNC with lib/envelope.ts and the web verifier (canonical hash,
// challenge/nonce construction, COSE handling).

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

const RESET_WINDOW_MS = 8 * 24 * 60 * 60 * 1000;
const ENROLL_WINDOW_MS = 30 * 60 * 1000; // MUST match lib/envelope.ts ENROLL_WINDOW_MS
const ISSUED_FUTURE_SKEW_MS = 60 * 60 * 1000;

const ACTION_LABELS = {
  disconnect: "disconnect your guard",
  "set-whitelist": "change which devices are kept",
  "set-threshold": "change how many keys are required to approve a change",
  "allow-reset": "allow a 2FA password reset for 8 days",
  "protect-reset": "re-enable reset protection",
  "add-key": "add a key",
  "remove-key": "remove a key",
  arm: "turn on your guard with this exact policy",
  // MUST stay byte-identical to lib/proof.ts ACTION_LABELS (the wallet message is rebuilt
  // from these and matched exactly on both the web and gateway sides).
  "set-contest-protection": "change how your guard responds to a copied login",
  "set-allow-ip-jumping": "allow a device to change its location",
  "set-locality-allowlist": "change your trusted locations",
  "set-travel-mode": "turn travel mode on or off",
  "open-enroll": "open a short window to add a new device",
};

function canonicalWalletMessage(action, detailsHash, nonce) {
  return (
    `sessions.fyi wants you to verify your wallet for Sessions.\n\n` +
    `You are authorizing: ${ACTION_LABELS[action]}.\n\n` +
    `This does not move funds or grant any spending permission.\n\n` +
    `Details: ${detailsHash}\n\n` +
    `URI: https://sessions.fyi\nNonce: ${nonce}`
  );
}

function canon(v) {
  if (Array.isArray(v)) return [...v].map(canon).sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  if (v && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v).sort()) o[k] = canon(v[k]);
    return o;
  }
  return v;
}

export function payloadHash(action, payload) {
  return createHash("sha256").update(JSON.stringify({ a: action, p: canon(payload ?? {}) })).digest("base64url");
}

export function canonicalEq(a, b) {
  return JSON.stringify(canon(a)) === JSON.stringify(canon(b));
}

// The signer-set commitment the KMS-attested seal binds (v1 anchor, F2).
export function signersCommit(signers, threshold) {
  return payloadHash("sgsigners1", { signers, threshold });
}

function validNewSigner(s) {
  if (!s || typeof s.id !== "string") return false;
  if (s.kind === "passkey") return typeof s.credId === "string" && typeof s.publicKey === "string";
  if (s.kind === "wallet") return typeof s.address === "string" && /^0x[0-9a-f]{40}$/i.test(s.address);
  if (s.kind === "google") return typeof s.sub === "string" && s.sub.length > 0;
  return false;
}

function sameExcept(action, prev, core, changed) {
  // HIGHEST-RISK HOLE if a field is omitted here: any signed delta (e.g. set-whitelist)
  // could smuggle a contest_protection / allow_ip_jumping / enroll_until change under a
  // signature meant for something else (arm/disarm the burn on a benign approval). Every
  // policy field the gateway derives MUST be pinned-equal for actions that don't change it.
  for (const f of ["whitelist", "threshold", "reset_allowed_until", "signers", "contest_protection", "allow_ip_jumping", "enroll_until", "locality_allowlist", "travel_mode"]) {
    if (changed.includes(f)) continue;
    if (!canonicalEq(prev[f], core[f])) return `${action} may not change ${f}, but it did`;
  }
  return null;
}

export function verifyDelta(action, prev, core) {
  switch (action) {
    case "set-whitelist":
      return sameExcept(action, prev, core, ["whitelist"]);
    case "set-threshold": {
      const e = sameExcept(action, prev, core, ["threshold"]);
      if (e) return e;
      return core.threshold >= 1 && core.threshold <= core.signers.length ? null : "threshold out of range for signer set";
    }
    case "allow-reset": {
      const e = sameExcept(action, prev, core, ["reset_allowed_until"]);
      if (e) return e;
      if (!core.reset_allowed_until) return "allow-reset must set a non-null reset window";
      const until = new Date(core.reset_allowed_until).getTime();
      const issued = new Date(core.issued_at).getTime();
      if (!Number.isFinite(until) || !Number.isFinite(issued)) return "allow-reset has malformed timestamps";
      if (Math.abs(until - (issued + RESET_WINDOW_MS)) > 60_000) return "allow-reset window must be issued_at + 8 days";
      return null;
    }
    case "protect-reset": {
      const e = sameExcept(action, prev, core, ["reset_allowed_until"]);
      if (e) return e;
      return core.reset_allowed_until === null ? null : "protect-reset must clear the reset window";
    }
    case "disconnect":
      return sameExcept(action, prev, core, []);
    case "set-contest-protection": {
      const e = sameExcept(action, prev, core, ["contest_protection"]);
      if (e) return e;
      return ["off", "alert", "auto_burn"].includes(core.contest_protection)
        ? null : "contest_protection must be off|alert|auto_burn";
    }
    case "set-allow-ip-jumping": {
      // DEPRECATED (v2): no longer consumed by the detector/gate, but still verifiable so a
      // pre-v2 chain that carries it stays valid. Shape-validated like before.
      const e = sameExcept(action, prev, core, ["allow_ip_jumping"]);
      if (e) return e;
      if (!Array.isArray(core.allow_ip_jumping) || core.allow_ip_jumping.length > 50) return "malformed allow_ip_jumping";
      if (core.allow_ip_jumping.some((h) => typeof h !== "string" || h.length > 64)) return "malformed allow_ip_jumping entry";
      return null;
    }
    case "set-locality-allowlist": {
      const e = sameExcept(action, prev, core, ["locality_allowlist"]);
      if (e) return e;
      const al = core.locality_allowlist;
      if (al != null) {
        if (!Array.isArray(al) || al.length > 50) return "malformed locality_allowlist";
        for (const en of al) {
          if (!en || typeof en !== "object") return "malformed locality_allowlist entry";
          if (typeof en.loc !== "string" || en.loc.length < 1 || en.loc.length > 96) return "malformed locality_allowlist loc";
          if (en.until != null && (typeof en.until !== "string" || !Number.isFinite(new Date(en.until).getTime()))) return "malformed locality_allowlist until";
        }
      }
      return null;
    }
    case "set-travel-mode": {
      const e = sameExcept(action, prev, core, ["travel_mode"]);
      if (e) return e;
      return typeof core.travel_mode === "boolean" ? null : "travel_mode must be boolean";
    }
    case "open-enroll": {
      const e = sameExcept(action, prev, core, ["enroll_until"]);
      if (e) return e;
      if (!core.enroll_until) return "open-enroll must set a non-null enroll window";
      const until = new Date(core.enroll_until).getTime();
      const issued = new Date(core.issued_at).getTime();
      if (!Number.isFinite(until) || !Number.isFinite(issued)) return "open-enroll has malformed timestamps";
      if (Math.abs(until - (issued + ENROLL_WINDOW_MS)) > 60_000) return "open-enroll window must be issued_at + 30 minutes";
      return null;
    }
    case "remove-key": {
      const e = sameExcept(action, prev, core, ["signers", "threshold"]);
      if (e) return e;
      const prevIds = new Set(prev.signers.map((s) => s.id));
      if (core.signers.length !== prev.signers.length - 1) return "remove-key must drop exactly one signer";
      for (const s of core.signers) {
        if (!prevIds.has(s.id)) return "remove-key introduced a new signer";
        if (!canonicalEq(prev.signers.find((x) => x.id === s.id), s)) return "remove-key altered a surviving signer";
      }
      const expectedThreshold = Math.min(prev.threshold, core.signers.length);
      if (core.threshold !== expectedThreshold) return "remove-key threshold must be min(prev.threshold, remaining signers)";
      return null;
    }
    case "add-key": {
      const e = sameExcept(action, prev, core, ["signers"]);
      if (e) return e;
      const prevIds = new Set(prev.signers.map((s) => s.id));
      const coreIds = new Set(core.signers.map((s) => s.id));
      if (core.signers.length !== prev.signers.length + 1) return "add-key must add exactly one signer";
      for (const id of prevIds) if (!coreIds.has(id)) return "add-key removed an existing signer";
      let added = 0;
      for (const s of core.signers) {
        if (prevIds.has(s.id)) {
          if (!canonicalEq(prev.signers.find((x) => x.id === s.id), s)) return "add-key altered an existing signer";
        } else {
          added++;
          if (!validNewSigner(s)) return "add-key signer is malformed";
        }
      }
      return added === 1 ? null : "add-key must add exactly one signer";
    }
    default:
      return `unknown action for delta: ${action}`;
  }
}

function envelopeChallenge(action, ph, randBuf) {
  return createHash("sha256").update(`${action}:${ph}:`).update(randBuf).digest();
}
function envelopeNonce(ph, rand) {
  return createHash("sha256").update(`sgenv1:${ph}:${rand}`).digest("base64url");
}

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
    const b = u8();
    const major = b >> 5, info = b & 0x1f;
    if (major === 0) return len(info);
    if (major === 1) return -1 - len(info);
    if (major === 2 || major === 3) { const n = len(info); const v = buf.subarray(off, off + n); off += n; return Buffer.from(v); }
    throw new Error(`cbor: unsupported major ${major}`);
  };
  const first = u8();
  if (first >> 5 !== 5) throw new Error("cbor: not a map");
  const count = len(first & 0x1f);
  const m = new Map();
  for (let i = 0; i < count; i++) {
    const k = item();
    if (typeof k !== "number") throw new Error("cbor: non-int key");
    m.set(k, item());
  }
  return m;
}

function coseToKey(cose) {
  const m = cborDecodeMap(cose);
  const kty = m.get(1);
  if (kty === 2) {
    if (m.get(-1) !== 1) throw new Error("unsupported EC curve");
    const x = m.get(-2), y = m.get(-3);
    if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y)) throw new Error("bad EC key");
    return { key: createPublicKey({ key: { kty: "EC", crv: "P-256", x: x.toString("base64url"), y: y.toString("base64url") }, format: "jwk" }), scheme: "ec" };
  }
  if (kty === 3) {
    const n = m.get(-1), e = m.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) throw new Error("bad RSA key");
    return { key: createPublicKey({ key: { kty: "RSA", n: n.toString("base64url"), e: e.toString("base64url") }, format: "jwk" }), scheme: "rsa" };
  }
  if (kty === 1) {
    if (m.get(-1) !== 6) throw new Error("unsupported OKP curve");
    const x = m.get(-2);
    if (!Buffer.isBuffer(x)) throw new Error("bad OKP key");
    return { key: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: x.toString("base64url") }, format: "jwk" }), scheme: "ed25519" };
  }
  throw new Error(`unsupported COSE kty ${kty}`);
}

function verifyPasskeySig(action, ph, sig, signer, cfg) {
  if (!cfg.rpId || !cfg.origins?.length) return false;
  if (sig.credentialId !== signer.credId) return false;
  const clientDataBytes = Buffer.from(sig.clientDataJSON, "base64url");
  const clientData = JSON.parse(clientDataBytes.toString("utf8"));
  if (clientData.type !== "webauthn.get") return false;
  if (!clientData.origin || !cfg.origins.includes(clientData.origin)) return false;
  const expected = envelopeChallenge(action, ph, Buffer.from(sig.rand, "base64url")).toString("base64url");
  if (clientData.challenge !== expected) return false;
  const authData = Buffer.from(sig.authenticatorData, "base64url");
  if (authData.length < 37) return false;
  const rpIdHash = createHash("sha256").update(cfg.rpId).digest();
  if (!authData.subarray(0, 32).equals(rpIdHash)) return false;
  const flags = authData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) return false;
  const signedData = Buffer.concat([authData, createHash("sha256").update(clientDataBytes).digest()]);
  const { key, scheme } = coseToKey(Buffer.from(signer.publicKey, "base64url"));
  const signature = Buffer.from(sig.signature, "base64url");
  if (scheme === "ed25519") return cryptoVerify(null, signedData, key, signature);
  return cryptoVerify("sha256", signedData, key, signature);
}

function verifyWalletSig(action, ph, sig, signer) {
  if (String(sig.address).toLowerCase() !== String(signer.address).toLowerCase()) return false;
  if (!ACTION_LABELS[action]) return false;
  const nonceMatch = /\nNonce: (\S+)$/.exec(String(sig.message));
  if (!nonceMatch) return false;
  if (String(sig.message) !== canonicalWalletMessage(action, ph, nonceMatch[1])) return false;
  const msgBytes = Buffer.from(sig.message, "utf8");
  const digest = keccak_256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${msgBytes.length}`, "utf8"), msgBytes]));
  const raw = Buffer.from(String(sig.signature).replace(/^0x/, ""), "hex");
  let rs, rec;
  if (raw.length === 65) {
    rs = raw.subarray(0, 64);
    const v = raw[64];
    rec = v >= 27 ? v - 27 : v;
  } else if (raw.length === 64) {
    const r = raw.subarray(0, 32);
    const ys = Buffer.from(raw.subarray(32, 64));
    rec = (ys[0] & 0x80) ? 1 : 0;
    ys[0] &= 0x7f;
    rs = Buffer.concat([r, ys]);
  } else return false;
  if (rec !== 0 && rec !== 1) return false;
  const pub = secp256k1.Signature.fromBytes(rs, "compact").addRecoveryBit(rec).recoverPublicKey(digest);
  const addr = "0x" + Buffer.from(keccak_256(pub.toBytes(false).subarray(1))).subarray(12).toString("hex");
  return addr === String(signer.address).toLowerCase();
}

let jwks = { keys: [], at: 0 };
async function googleKey(kid, fetchImpl, nowMs) {
  const fresh = nowMs - jwks.at < 6 * 60 * 60 * 1000;
  if (!fresh || !jwks.keys.some((k) => k.kid === kid)) {
    const r = await fetchImpl("https://www.googleapis.com/oauth2/v3/certs");
    if (!r.ok) throw new Error(`jwks fetch ${r.status}`);
    jwks = { keys: (await r.json()).keys ?? [], at: nowMs };
  }
  return jwks.keys.find((k) => k.kid === kid && k.kty === "RSA") ?? null;
}

const GOOGLE_ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);

async function verifyGoogleSig(ph, sig, signer, cfg) {
  if (!cfg.googleClientId) return false;
  const parts = String(sig.idToken).split(".");
  if (parts.length !== 3) return false;
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header.alg !== "RS256" || !header.kid) return false;
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (!GOOGLE_ISSUERS.has(payload.iss)) return false;
  if (payload.aud !== cfg.googleClientId) return false;
  if (payload.sub !== signer.sub) return false;
  if (payload.nonce !== envelopeNonce(ph, sig.rand)) return false;
  const iatMs = Number(payload.iat) * 1000;
  if (!Number.isFinite(iatMs) || Math.abs(iatMs - Date.parse(cfg.issuedAt)) > 15 * 60 * 1000) return false;
  const fetchImpl = cfg.fetchImpl ?? fetch;
  const nowMs = cfg.nowMs ?? Date.now();
  const k = await googleKey(header.kid, fetchImpl, nowMs);
  if (!k) return false;
  const key = createPublicKey({ key: { kty: "RSA", n: k.n, e: k.e }, format: "jwk" });
  return cryptoVerify("sha256", Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"), key, Buffer.from(parts[2], "base64url"));
}

async function verifyEnvelopeSigs(action, ph, sigs, trusted, cfg) {
  const byId = new Map(trusted.map((s) => [s.id, s]));
  const valid = new Set();
  for (const sig of (sigs ?? []).slice(0, 16)) {
    if (!sig || valid.has(sig.signerId)) continue;
    const signer = byId.get(sig.signerId);
    if (!signer || signer.kind !== sig.kind) continue;
    try {
      if (sig.kind === "passkey" && verifyPasskeySig(action, ph, sig, signer, cfg)) valid.add(sig.signerId);
      else if (sig.kind === "wallet" && verifyWalletSig(action, ph, sig, signer)) valid.add(sig.signerId);
      else if (sig.kind === "google" && (await verifyGoogleSig(ph, sig, signer, cfg))) valid.add(sig.signerId);
    } catch { /* a malformed signature never counts and never crashes */ }
  }
  return valid;
}

const nowMs = (cfg) => cfg.nowMs ?? Date.now();

// Verify ONE row on top of the accepted floor (prevCore). Returns {ok} | {ok:false, reason}.
export async function verifyEnvelopeRow(row, prevCore, cfg) {
  const bad = (reason) => ({ ok: false, reason });
  const core = row?.core;
  if (!core || typeof core !== "object") return bad("malformed core");
  if (core.v !== 1) return bad(`unknown core format v=${core.v}`);
  if (String(core.link_id) !== String(cfg.linkId)) return bad("link binding mismatch");
  if (!cfg.tgUserId || String(core.tg_user_id) !== String(cfg.tgUserId)) return bad("identity binding mismatch");

  const prevVersion = prevCore ? prevCore.policy_version : 0;
  if (core.policy_version !== prevVersion + 1) return bad(`version ${core.policy_version}, expected ${prevVersion + 1} (gap or regression)`);
  if (row.version !== core.policy_version) return bad("row/core version mismatch");

  if (!Array.isArray(core.whitelist) || core.whitelist.length > 50) return bad("malformed whitelist");
  if (!Number.isInteger(core.threshold) || core.threshold < 1 || core.threshold > 3) return bad("malformed threshold");
  if (!Array.isArray(core.signers) || core.signers.length < 1 || core.signers.length > 10) return bad("malformed signer set");
  if (core.threshold > core.signers.length) return bad("threshold exceeds signer count");
  if (new Set(core.signers.map((s) => s.id)).size !== core.signers.length) return bad("duplicate signer ids");

  const issuedMs = new Date(core.issued_at).getTime();
  if (!Number.isFinite(issuedMs)) return bad("malformed issued_at");
  if (issuedMs > nowMs(cfg) + ISSUED_FUTURE_SKEW_MS) return bad("issued_at is in the future");
  if (prevCore) {
    const prevIssued = new Date(prevCore.issued_at).getTime();
    if (Number.isFinite(prevIssued) && issuedMs < prevIssued) return bad("issued_at regressed below the floor");
  }

  const action = String(row.action);
  const ph = payloadHash(action, core);
  if (row.core_hash && row.core_hash !== ph) return bad("core hash mismatch");

  if (!prevCore && action !== "arm") return bad(`v1 anchor must be 'arm', not '${action}'`);
  if (prevCore && action === "arm") return bad("'arm' is only valid as the v1 anchor");

  if (!prevCore) {
    if (!cfg.signersCommit) return bad("v1 anchor has no attested signer commitment (re-arm required)");
    if (signersCommit(core.signers, core.threshold) !== cfg.signersCommit) return bad("v1 anchor signer set is not bound to the attested seal");
  }

  const sigs = Array.isArray(row.sigs) ? row.sigs : [];
  if (sigs.length === 0) {
    if (!prevCore) return bad("unsigned anchor");
    if (action !== "protect-reset") return bad(`unsigned ${action} is not allowed`);
    const delta = verifyDelta("protect-reset", prevCore, core);
    return delta ? bad(`unsigned change is not strictly protective: ${delta}`) : { ok: true };
  }

  if (prevCore) {
    const delta = verifyDelta(action, prevCore, core);
    if (delta) return bad(`action/delta mismatch: ${delta}`);
  }

  const trusted = prevCore ? prevCore.signers : core.signers;
  const threshold = prevCore ? prevCore.threshold : core.threshold;
  const need = Math.min(threshold, trusted.length);
  const valid = await verifyEnvelopeSigs(action, ph, sigs, trusted, { ...cfg, issuedAt: core.issued_at });
  if (valid.size < need) return bad(`signature quorum ${valid.size}/${need} from the trusted set`);
  return { ok: true };
}

/**
 * Walk the FULL signed chain from the anchor to the head and derive the
 * gateway-enforced authority (4.8). `rows` is the ordered policy_envelopes
 * chain (version 1..N). `anchor` is the State-Authority-anchored expected head
 * {version, hash}: the derived head MUST match it byte-for-byte, else the chain
 * is rejected (this is what makes a Postgres restore fail closed rather than
 * silently resurrect an older signer set).
 *
 * Returns { ok:true, authority } or { ok:false, reason }. authority =
 * { whitelist, signers, threshold, resetProtection, headVersion, headHash }.
 */
export async function deriveAuthority(rows, cfg, anchor) {
  if (!Array.isArray(rows) || rows.length === 0) return { ok: false, reason: "empty chain" };
  const ordered = [...rows].sort((a, b) => a.version - b.version);
  let prevCore = null;
  for (const row of ordered) {
    const r = await verifyEnvelopeRow(row, prevCore, cfg);
    if (!r.ok) return { ok: false, reason: `v${row.version}: ${r.reason}` };
    prevCore = row.core;
  }
  const head = ordered[ordered.length - 1];
  const headHash = payloadHash(String(head.action), head.core);
  if (anchor) {
    if (head.version !== anchor.version) return { ok: false, reason: `head version ${head.version} != anchored ${anchor.version}` };
    if (anchor.hash && headHash !== anchor.hash) return { ok: false, reason: "head hash does not match the anchored State Authority head" };
  }
  const c = head.core;
  return {
    ok: true,
    authority: {
      whitelist: c.whitelist,
      signers: c.signers,
      threshold: c.threshold,
      resetProtection: c.reset_allowed_until === null || c.reset_allowed_until === undefined,
      resetAllowedUntil: c.reset_allowed_until ?? null,
      disconnected: String(head.action) === "disconnect",
      // tdata-replay (P2). Read ONLY from the signed core (deriveAuthority), never from a
      // brain/ctx/arg field. D2: absent contest_protection reads as "alert" (a NON-burn
      // value) so a pre-v0 policy never silently arms auto_burn. The per-row head-hash
      // anchor (payloadHash over the whole core) already covers these, so a State-Authority
      // rollback that resurrects an old value fails closed.
      contestProtection: c.contest_protection ?? "alert",
      allowIpJumping: Array.isArray(c.allow_ip_jumping) ? c.allow_ip_jumping.map(String) : [], // DEPRECATED (v2)
      enrollUntil: c.enroll_until ?? null,
      // tdata-replay v2 (P3). Trusted-locations allowlist + travel-mode master toggle, read
      // ONLY from the signed core. These RELAX Tier C in the brain (a safe direction); the
      // dangerous burn-enable stays contestProtection==="auto_burn" in the EVICT gate.
      localityAllowlist: Array.isArray(c.locality_allowlist)
        ? c.locality_allowlist
            .filter((e) => e && typeof e.loc === "string")
            .map((e) => ({ loc: String(e.loc), until: e.until ?? null }))
        : [],
      travelMode: !!c.travel_mode,
      headVersion: head.version,
      headHash,
    },
  };
}

/**
 * The op-enforcement gate (4.8): given derived authority, decide whether a
 * proposed mutating op is permitted. The brain PROPOSES; this is the ceiling.
 *   - EVICT_SESSION{hash}: permitted iff hash is ABSENT from the whitelist AND
 *     present-and-non-current in the fresh roster the caller supplies.
 *   - DECLINE_RESET: permitted iff reset protection is on.
 *   - LOGOUT_SELF: permitted iff the head action is a signed disconnect.
 */
export function assertOpAllowed(authority, op, arg = {}) {
  if (authority.disconnected && op !== "LOGOUT_SELF") {
    return { ok: false, reason: "account is disconnected; only logout-self is permitted" };
  }
  switch (op) {
    case "EVICT_SESSION": {
      // Refuse current FIRST, unconditionally: the guard's own session is NEVER burnable,
      // not even under a contest override (absolute, gameplan §5).
      const roster = arg.freshRoster;
      if (!Array.isArray(roster)) return { ok: false, reason: "evict requires a fresh roster taken in the same op (M-1)" };
      const inRoster = roster.find((s) => String(s.hash) === String(arg.hash));
      if (!inRoster) return { ok: false, reason: "hash not present in the fresh roster" };
      if (inRoster.current) return { ok: false, reason: "refusing to evict the current (guard's own) session" };
      const wl = new Set((authority.whitelist ?? []).map(String));
      if (wl.has(String(arg.hash))) {
        // A whitelisted hash is normally KEPT. The ONE exception is a tdata replay riding
        // the victim's own whitelisted desktop: burn iff the SIGNED contest-protection is
        // auto_burn AND the brain requested the override for this op. The ENABLE is read
        // ONLY from `authority` (signed, via deriveAuthority); arg.contestOverride is merely
        // a request to USE it. If the enable were ever sourced from arg/ctx/a brain field, a
        // compromised brain could burn any kept hash (the M-of-N RLS lesson). D4: this is
        // === "auto_burn" exactly (NOT !== "off", which would wrongly burn in alert mode).
        const burnEnabled = authority.contestProtection === "auto_burn";
        if (!(arg.contestOverride === true && burnEnabled)) {
          return { ok: false, reason: "hash is on the signed whitelist (kept session)" };
        }
        // permitted: signed contest-protection authorizes a whitelist-burn override
      }
      return { ok: true };
    }
    case "DECLINE_RESET":
      return authority.resetProtection ? { ok: true } : { ok: false, reason: "reset protection is off in the signed policy" };
    case "LOGOUT_SELF":
      return authority.disconnected ? { ok: true } : { ok: false, reason: "logout-self requires a signed disconnect at the head" };
    case "LIST_SESSIONS":
    case "READ_SECURITY_STATE":
    case "WHO_AM_I":
      return { ok: true };
    default:
      return { ok: false, reason: `unknown op ${op}` };
  }
}
