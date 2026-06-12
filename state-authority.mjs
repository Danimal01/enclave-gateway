// gateway/state-authority.mjs: the client + signed protocol for the Gateway
// State Authority (gateway-brain-architecture.md 4.8, 5.3, 5.5).
//
// The State Authority is the security root for monotonic lifecycle/policy
// anchoring and the single-writer gateway lease. It lives in a separate AWS
// security account on a Multi-AZ strongly-consistent conditional store
// (DynamoDB, cost-lean decision 12d). The untrusted parent relays requests but
// cannot forge a fresh response or advance a head.
//
// This module is two things:
//   1. The GATEWAY-SIDE CLIENT: nonce-bound request/response, response signature
//      verification against the State Authority key pinned in the published
//      gateway image, the conservative local lease deadline (5.5), and the
//      self-fence rule.
//   2. A REFERENCE STORE (`InMemoryAuthority`) implementing the exact conditional
//      semantics the DynamoDB backend must implement, so the chaos/lease/restore
//      tests (launch gate 12) run deterministically without AWS. The production
//      backend is a thin DynamoDB adapter behind the same interface.
//
// Phases move only ONBOARDING -> ARMED -> TERMINAL. Every mutating op requires
// the exact current holder key and epoch. Terminalization atomically clears the
// lease and permanently rejects acquisition, promotion, and advancement.

import {
  generateKeyPairSync,
  randomUUID,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
} from "node:crypto";

export const PHASES = Object.freeze({ ONBOARDING: "ONBOARDING", ARMED: "ARMED", TERMINAL: "TERMINAL" });

// Canonical, deterministic encoding of a signed response record. Keys are
// ordered; the signature covers exactly these bytes plus the request nonce.
function canonicalRecordBytes(nonce, record) {
  const ordered = {
    state_id: record.state_id ?? null,
    phase: record.phase ?? null,
    policy_version: record.policy_version ?? null,
    policy_head_hash: record.policy_head_hash ?? null,
    lease_epoch: record.lease_epoch ?? null,
    lease_holder: record.lease_holder ?? null,
    lease_expires_at: record.lease_expires_at ?? null,
    terminal_reason: record.terminal_reason ?? null,
    issued_at: record.issued_at ?? null,
    expires_at: record.expires_at ?? null,
  };
  return Buffer.from(`sessions.fyi/state-authority/v1\n${nonce}\n${JSON.stringify(ordered)}`, "utf8");
}

// ---------------------------------------------------------------------------
// Reference store: the exact conditional semantics the DynamoDB backend mirrors.
// Signs every response with an Ed25519 key; the gateway pins the public half.
// ---------------------------------------------------------------------------
export class InMemoryAuthority {
  constructor({ now = () => Date.now(), keyPair } = {}) {
    this._now = now;
    this._store = new Map(); // state_id -> record
    this._kp = keyPair ?? generateKeyPairSync("ed25519");
    this.publicKey = this._kp.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  }

  _sign(nonce, record) {
    const issued = this._now();
    const full = { ...record, issued_at: issued, expires_at: issued + 30_000 };
    const signature = edSign(null, canonicalRecordBytes(nonce, full), this._kp.privateKey);
    return { record: full, signature: signature.toString("base64"), nonce };
  }

  create_onboarding_if_absent(nonce, stateId) {
    let rec = this._store.get(stateId);
    if (!rec) {
      rec = { state_id: stateId, phase: PHASES.ONBOARDING, policy_version: null, policy_head_hash: null,
              lease_epoch: 0, lease_holder: null, lease_expires_at: null, terminal_reason: null };
      this._store.set(stateId, rec);
    }
    return this._sign(nonce, rec);
  }

  read(nonce, stateId) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    return this._sign(nonce, rec);
  }

  acquire_lease(nonce, stateId, holder, ttlMs) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.phase === PHASES.TERMINAL) throw new Error("terminal: lease acquisition permanently rejected");
    const t = this._now();
    if (rec.lease_holder && rec.lease_expires_at > t) throw new Error("lease held by an unexpired holder");
    rec.lease_epoch += 1;            // strictly increasing, never decreases
    rec.lease_holder = holder;
    rec.lease_expires_at = t + ttlMs;
    return this._sign(nonce, rec);
  }

  renew_lease(nonce, stateId, holder, epoch, ttlMs) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.phase === PHASES.TERMINAL) throw new Error("terminal");
    if (rec.lease_holder !== holder || rec.lease_epoch !== epoch) throw new Error("not the current holder/epoch");
    rec.lease_expires_at = this._now() + ttlMs;
    return this._sign(nonce, rec);
  }

  release_lease(nonce, stateId, holder, epoch) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.lease_holder !== holder || rec.lease_epoch !== epoch) throw new Error("not the current holder/epoch");
    rec.lease_holder = null;
    rec.lease_expires_at = null;
    return this._sign(nonce, rec);
  }

  promote_to_armed(nonce, stateId, holder, epoch, genesisVersion, genesisHash) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.phase === PHASES.TERMINAL) throw new Error("terminal");
    if (rec.lease_holder !== holder || rec.lease_epoch !== epoch) throw new Error("not the current holder/epoch");
    if (rec.phase === PHASES.ARMED) {
      // idempotent ONLY for the exact genesis values
      if (rec.policy_version !== genesisVersion || rec.policy_head_hash !== genesisHash) {
        throw new Error("already armed with different genesis");
      }
      return this._sign(nonce, rec);
    }
    rec.phase = PHASES.ARMED;
    rec.policy_version = genesisVersion;
    rec.policy_head_hash = genesisHash;
    return this._sign(nonce, rec);
  }

  compare_and_advance(nonce, stateId, holder, epoch, expectedVersion, expectedHash, nextVersion, nextHash) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.phase !== PHASES.ARMED) throw new Error("can only advance an ARMED record");
    if (rec.lease_holder !== holder || rec.lease_epoch !== epoch) throw new Error("not the current holder/epoch");
    if (rec.policy_version !== expectedVersion || rec.policy_head_hash !== expectedHash) throw new Error("CAS: prior head mismatch");
    if (!(nextVersion > expectedVersion)) throw new Error("head version must strictly increase");
    rec.policy_version = nextVersion;
    rec.policy_head_hash = nextHash;
    return this._sign(nonce, rec);
  }

  mark_terminal(nonce, stateId, holder, epoch, expectedPhase, reason, expectedVersion, expectedHash) {
    const rec = this._store.get(stateId);
    if (!rec) throw new Error("no such state_id");
    if (rec.phase === PHASES.TERMINAL) return this._sign(nonce, rec); // idempotent
    if (rec.phase !== expectedPhase) throw new Error("phase mismatch");
    if (rec.lease_holder && (rec.lease_holder !== holder || rec.lease_epoch !== epoch)) throw new Error("not the current holder/epoch");
    if (expectedPhase === PHASES.ARMED && (rec.policy_version !== expectedVersion || rec.policy_head_hash !== expectedHash)) {
      throw new Error("terminal CAS: head mismatch");
    }
    rec.phase = PHASES.TERMINAL;
    rec.terminal_reason = reason;
    rec.lease_holder = null;          // terminalization clears the lease atomically
    rec.lease_expires_at = null;
    return this._sign(nonce, rec);
  }
}

// ---------------------------------------------------------------------------
// Gateway-side client. Verifies the signed response, binds the nonce, enforces
// response freshness, and computes the conservative local lease deadline (5.5).
// ---------------------------------------------------------------------------
export class StateAuthorityClient {
  // pinnedPublicKey: base64 SPKI DER of the State Authority Ed25519 key, baked
  //   into the published gateway image.
  // transport: async (method, args) => signedResponse (relayed through parent).
  // now / monotonic: injectable clocks for test determinism.
  constructor({ pinnedPublicKey, transport, now = () => Date.now(), monotonic = () => performance.now(), safetyMarginMs = 5_000 }) {
    if (!pinnedPublicKey) throw new Error("pinnedPublicKey required");
    this._pub = createPublicKeyFromB64Spki(pinnedPublicKey);
    this._transport = transport;
    this._now = now;
    this._monotonic = monotonic;
    this._safety = safetyMarginMs;
  }

  _verify(nonce, signed) {
    if (!signed || signed.nonce !== nonce) throw new Error("nonce mismatch (replay or substitution)");
    const bytes = canonicalRecordBytes(nonce, signed.record);
    if (!edVerify(null, bytes, this._pub, Buffer.from(signed.signature, "base64"))) {
      throw new Error("State Authority response signature invalid");
    }
    const t = this._now();
    if (typeof signed.record.expires_at === "number" && signed.record.expires_at < t) {
      throw new Error("State Authority response is stale (expired)");
    }
    return signed.record;
  }

  async _call(method, args) {
    const nonce = randomUUID();
    const before = this._monotonic();
    const signed = await this._transport(method, { ...args, nonce });
    const rttFull = this._monotonic() - before;
    const record = this._verify(nonce, signed);
    return { record, rttFull };
  }

  async read(stateId) { return (await this._call("read", { stateId })).record; }

  async createOnboardingIfAbsent(stateId) {
    return (await this._call("create_onboarding_if_absent", { stateId })).record;
  }

  // Returns { record, localDeadline }: the conservative monotonic deadline the
  // write chokepoint checks before EVERY frame (5.5). Derived only from the
  // signed lease duration minus the full measured RTT and the safety margin;
  // never extended from parent/wall-clock input.
  async acquireLease(stateId, holder, ttlMs) {
    const { record, rttFull } = await this._call("acquire_lease", { stateId, holder, ttlMs });
    return { record, localDeadline: this._monotonic() + ttlMs - rttFull - this._safety };
  }

  async renewLease(stateId, holder, epoch, ttlMs) {
    const { record, rttFull } = await this._call("renew_lease", { stateId, holder, epoch, ttlMs });
    return { record, localDeadline: this._monotonic() + ttlMs - rttFull - this._safety };
  }

  async releaseLease(stateId, holder, epoch) { return (await this._call("release_lease", { stateId, holder, epoch })).record; }
  async promoteToArmed(stateId, holder, epoch, v, h) { return (await this._call("promote_to_armed", { stateId, holder, epoch, genesisVersion: v, genesisHash: h })).record; }
  async compareAndAdvance(stateId, holder, epoch, ev, eh, nv, nh) {
    return (await this._call("compare_and_advance", { stateId, holder, epoch, expectedVersion: ev, expectedHash: eh, nextVersion: nv, nextHash: nh })).record;
  }
  async markTerminal(stateId, holder, epoch, expectedPhase, reason, ev, eh) {
    return (await this._call("mark_terminal", { stateId, holder, epoch, expectedPhase, reason, expectedVersion: ev, expectedHash: eh })).record;
  }
}

function createPublicKeyFromB64Spki(b64) {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}

// A trivial in-process transport that routes client calls to a reference store,
// used by tests and by single-host dev. Production uses a vsock->parent->
// security-account relay behind the same async signature.
export function inProcessTransport(authority) {
  return async (method, args) => {
    const { nonce, stateId, holder, ttlMs, epoch, genesisVersion, genesisHash,
            expectedVersion, expectedHash, nextVersion, nextHash, expectedPhase, reason } = args;
    switch (method) {
      case "create_onboarding_if_absent": return authority.create_onboarding_if_absent(nonce, stateId);
      case "read": return authority.read(nonce, stateId);
      case "acquire_lease": return authority.acquire_lease(nonce, stateId, holder, ttlMs);
      case "renew_lease": return authority.renew_lease(nonce, stateId, holder, epoch, ttlMs);
      case "release_lease": return authority.release_lease(nonce, stateId, holder, epoch);
      case "promote_to_armed": return authority.promote_to_armed(nonce, stateId, holder, epoch, genesisVersion, genesisHash);
      case "compare_and_advance": return authority.compare_and_advance(nonce, stateId, holder, epoch, expectedVersion, expectedHash, nextVersion, nextHash);
      case "mark_terminal": return authority.mark_terminal(nonce, stateId, holder, epoch, expectedPhase, reason, expectedVersion, expectedHash);
      default: throw new Error(`unknown method ${method}`);
    }
  };
}

export { canonicalRecordBytes };
