// gateway/brain-protocol.mjs: the ONLY vocabulary that crosses between the
// closed brain and the open gateway (gateway-brain-architecture.md 4.7, 4.9).
//
// The contract is a CLOSED VERB SET. There is NO generic invoke(method, params).
// That single rule is what makes the published gateway the exclusive capability
// list. Each verb maps 1:1 to one allowlisted Telegram method. The session
// string and auth_key are NEVER a field in any type, either direction. The
// Event union has no MESSAGE variant and no content field, so the closed brain
// cannot receive message content even in principle.
//
// Wire format (decision 10.1.8): length-prefixed deterministic CBOR with a
// versioned closed schema. Unknown fields, duplicate map keys, non-canonical
// encodings, unknown versions, oversized frames, and trailing bytes fail closed.
// This module implements a minimal canonical CBOR codec for the fixed schema
// (integers, byte strings, text strings, arrays, maps, bool, null) and the
// frame validators. It does NOT depend on a general CBOR library, so the
// published surface is small and auditable.

const PROTO_VERSION = 1;
const MAX_FRAME = 64 * 1024;

export const OPS = Object.freeze([
  "LIST_SESSIONS", "EVICT_SESSION", "DECLINE_RESET",
  "READ_SECURITY_STATE", "LOGOUT_SELF", "WHO_AM_I",
]);
const OP_SET = new Set(OPS);
const MUTATING = new Set(["EVICT_SESSION", "DECLINE_RESET", "LOGOUT_SELF"]);

// ---------------------------------------------------------------------------
// Minimal canonical CBOR (deterministic encoding; rejects non-canonical input).
// ---------------------------------------------------------------------------
function encHead(major, n) {
  const mt = major << 5;
  if (n < 24) return Buffer.from([mt | n]);
  if (n < 0x100) return Buffer.from([mt | 24, n]);
  if (n < 0x10000) { const b = Buffer.alloc(3); b[0] = mt | 25; b.writeUInt16BE(n, 1); return b; }
  if (n < 0x100000000) { const b = Buffer.alloc(5); b[0] = mt | 26; b.writeUInt32BE(n, 1); return b; }
  const b = Buffer.alloc(9); b[0] = mt | 27; b.writeBigUInt64BE(BigInt(n), 1); return b;
}

export function encode(value) {
  if (value === null) return Buffer.from([0xf6]);
  if (value === true) return Buffer.from([0xf5]);
  if (value === false) return Buffer.from([0xf4]);
  if (typeof value === "bigint") {
    if (value < 0n) throw new Error("cbor: negative bigint unsupported");
    const b = Buffer.alloc(9); b[0] = (0 << 5) | 27; b.writeBigUInt64BE(value, 1); return b;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 0) throw new Error("cbor: only unsigned ints");
    return encHead(0, value);
  }
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([encHead(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([encHead(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([encHead(4, value.length), ...value.map(encode)]);
  if (typeof value === "object") {
    // Canonical map ordering: keys sorted by their encoded byte sequence
    // (RFC 8949 4.2.1 length-first, then lexicographic).
    const keys = Object.keys(value);
    const encoded = keys.map((k) => [encode(k), k]);
    encoded.sort((a, b) => (a[0].length - b[0].length) || Buffer.compare(a[0], b[0]));
    const parts = [encHead(5, keys.length)];
    for (const [ek, k] of encoded) { parts.push(ek, encode(value[k])); }
    return Buffer.concat(parts);
  }
  throw new Error(`cbor: unsupported value ${typeof value}`);
}

export function decode(buf) {
  let off = 0;
  const readHead = () => {
    const ib = buf[off++];
    const major = ib >> 5, info = ib & 0x1f;
    let n;
    if (info < 24) n = info;
    else if (info === 24) { n = buf[off++]; if (n < 24) throw new Error("cbor: non-canonical 1-byte"); }
    else if (info === 25) { n = buf.readUInt16BE(off); off += 2; if (n < 0x100) throw new Error("cbor: non-canonical 2-byte"); }
    else if (info === 26) { n = buf.readUInt32BE(off); off += 4; if (n < 0x10000) throw new Error("cbor: non-canonical 4-byte"); }
    else if (info === 27) { const v = buf.readBigUInt64BE(off); off += 8; if (v < 0x100000000n) throw new Error("cbor: non-canonical 8-byte"); n = v; }
    else throw new Error("cbor: bad info");
    return { major, info, n };
  };
  const item = (depth) => {
    if (depth > 8) throw new Error("cbor: too deep");
    const ib = buf[off];
    if (ib === 0xf6) { off++; return null; }
    if (ib === 0xf5) { off++; return true; }
    if (ib === 0xf4) { off++; return false; }
    const { major, n } = readHead();
    const len = typeof n === "bigint" ? Number(n) : n;
    if (major === 0) return typeof n === "bigint" ? n : n;
    if (major === 2) { const v = buf.subarray(off, off + len); off += len; return Buffer.from(v); }
    if (major === 3) { const v = buf.subarray(off, off + len).toString("utf8"); off += len; return v; }
    if (major === 4) { const a = []; for (let i = 0; i < len; i++) a.push(item(depth + 1)); return a; }
    if (major === 5) {
      const m = {};
      let prevKey = null;
      for (let i = 0; i < len; i++) {
        const kStart = off;
        const k = item(depth + 1);
        if (typeof k !== "string") throw new Error("cbor: non-string map key");
        const kBytes = buf.subarray(kStart, off);
        if (prevKey && !(kBytes.length > prevKey.length || (kBytes.length === prevKey.length && Buffer.compare(kBytes, prevKey) > 0))) {
          throw new Error("cbor: map keys not canonically ordered / duplicate");
        }
        prevKey = kBytes;
        m[k] = item(depth + 1);
      }
      return m;
    }
    throw new Error(`cbor: unsupported major ${major}`);
  };
  const out = item(0);
  if (off !== buf.length) throw new Error("cbor: trailing bytes");
  return out;
}

// ---------------------------------------------------------------------------
// Frame validation. The session/auth_key can never be a field; we assert the
// closed shape and reject anything else.
// ---------------------------------------------------------------------------
const FORBIDDEN_KEYS = new Set(["session", "auth_key", "authKey", "stringSession", "dc", "method", "params"]);

function assertNoForbidden(obj) {
  for (const k of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(k)) throw new Error(`protocol: forbidden field ${k}`);
  }
}

export function encodeRequest(req) {
  if (!OP_SET.has(req.op)) throw new Error(`protocol: unknown op ${req.op}`);
  if (typeof req.id !== "number" || typeof req.gen !== "number") throw new Error("protocol: id/gen required");
  if (typeof req.acct !== "string" || req.acct.length === 0) throw new Error("protocol: acct handle required");
  const arg = req.arg ?? {};
  assertNoForbidden(arg);
  if (MUTATING.has(req.op) && typeof arg.authorized !== "string") {
    throw new Error(`protocol: ${req.op} requires an authorized policy token`);
  }
  if (req.op === "EVICT_SESSION" && typeof arg.hash !== "string") {
    throw new Error("protocol: EVICT_SESSION requires a string hash");
  }
  const frame = encode({ v: PROTO_VERSION, id: req.id, gen: req.gen, acct: req.acct, op: req.op, arg });
  if (frame.length > MAX_FRAME) throw new Error("protocol: frame too large");
  return frame;
}

export function decodeRequest(buf) {
  if (buf.length > MAX_FRAME) throw new Error("protocol: frame too large");
  const m = decode(buf);
  if (!m || typeof m !== "object" || Array.isArray(m)) throw new Error("protocol: not a map");
  if (m.v !== PROTO_VERSION) throw new Error(`protocol: unknown version ${m.v}`);
  const allowed = new Set(["v", "id", "gen", "acct", "op", "arg"]);
  for (const k of Object.keys(m)) if (!allowed.has(k)) throw new Error(`protocol: unknown field ${k}`);
  if (!OP_SET.has(m.op)) throw new Error(`protocol: unknown op ${m.op}`);
  if (typeof m.acct !== "string") throw new Error("protocol: acct must be a string handle");
  assertNoForbidden(m.arg ?? {});
  if (MUTATING.has(m.op) && typeof (m.arg ?? {}).authorized !== "string") {
    throw new Error(`protocol: ${m.op} missing authorized token`);
  }
  return { id: m.id, gen: m.gen, acct: m.acct, op: m.op, arg: m.arg ?? {} };
}

const RESP_BODY_KEYS = {
  LIST_SESSIONS: ["sessions"],
  EVICT_SESSION: ["removed"],
  DECLINE_RESET: ["declined"],
  READ_SECURITY_STATE: ["hasPwd", "hasRecovery", "pendingReset", "pendingResetAt", "loginEmailPattern", "accountTtlDays", "sessionTtlDays"],
  LOGOUT_SELF: ["goneOrDead"],
  WHO_AM_I: ["tgUserId"],
};

export function encodeResponse(resp) {
  const body = resp.body ?? {};
  assertNoForbidden(body);
  const frame = encode({ v: PROTO_VERSION, id: resp.id, ok: !!resp.ok, code: resp.code ?? null, body });
  if (frame.length > MAX_FRAME) throw new Error("protocol: response too large");
  return frame;
}

export function decodeResponse(buf, expectedOp) {
  const m = decode(buf);
  if (m.v !== PROTO_VERSION) throw new Error("protocol: unknown version");
  assertNoForbidden(m.body ?? {});
  if (expectedOp && m.ok && RESP_BODY_KEYS[expectedOp]) {
    const allowed = new Set(RESP_BODY_KEYS[expectedOp]);
    for (const k of Object.keys(m.body ?? {})) {
      if (!allowed.has(k)) throw new Error(`protocol: ${expectedOp} response has unexpected field ${k}`);
    }
  }
  return { id: m.id, ok: m.ok, code: m.code, body: m.body ?? {} };
}

// Events: the published union IS the honest answer to "can you read my
// messages" — there is no field that could carry message content.
export function encodeEvent(evt) {
  if (evt.kind !== "NEW_AUTH") throw new Error(`protocol: unknown event ${evt.kind}`);
  const body = evt.body ?? {};
  const allowed = new Set(["hash", "unconfirmed", "device", "location"]);
  for (const k of Object.keys(body)) if (!allowed.has(k)) throw new Error(`protocol: NEW_AUTH body field ${k} not allowed`);
  assertNoForbidden(body);
  return encode({ v: PROTO_VERSION, kind: "NEW_AUTH", acct: evt.acct, body });
}

export function decodeEvent(buf) {
  const m = decode(buf);
  if (m.v !== PROTO_VERSION) throw new Error("protocol: unknown version");
  if (m.kind !== "NEW_AUTH") throw new Error("protocol: only NEW_AUTH events exist");
  const allowed = new Set(["hash", "unconfirmed", "device", "location"]);
  for (const k of Object.keys(m.body ?? {})) if (!allowed.has(k)) throw new Error("protocol: NEW_AUTH body field not allowed");
  return { kind: m.kind, acct: m.acct, body: m.body ?? {} };
}

export { PROTO_VERSION, MAX_FRAME, MUTATING, FORBIDDEN_KEYS };
