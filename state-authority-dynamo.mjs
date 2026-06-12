// gateway/state-authority-dynamo.mjs: the PRODUCTION State Authority backend
// (gateway-brain-architecture.md 4.8, 5.3, cost-lean decision 12d).
//
// This runs in the separate AWS security account, NOT in the gateway enclave.
// It is a thin adapter over DynamoDB conditional writes that implements the
// EXACT semantics the in-memory reference store (state-authority.mjs) defines,
// signs every response with a KMS-asymmetric Ed25519 key whose public half is
// pinned in the published gateway image, and is the only writer of the
// monotonic lifecycle/policy/lease state.
//
// DynamoDB gives Multi-AZ strong consistency for free (no custom HA), and
// conditional expressions give the compare-and-set primitives. The table:
//   PK: state_id (S)
//   attrs: phase, policy_version, policy_head_hash, lease_epoch, lease_holder,
//          lease_expires_at, terminal_reason
//
// The service exposes ONLY attested-gateway operations over its relay endpoint;
// the untrusted parent may relay but cannot forge a fresh signed response. The
// runtime role can use ONLY conditional item operations; admin/break-glass is
// isolated, hardware-MFA protected, and logged (spec 4.8 authority isolation).

import { sign as edSign, randomUUID } from "node:crypto";
import { canonicalRecordBytes, PHASES } from "./state-authority.mjs";

// deps:
//   ddb   : a minimal DynamoDB client { getItem, putItem, updateItem,
//           transactWriteItems } (AWS SDK v3 DynamoDBDocument or compatible)
//   table : table name
//   signRecord : async (bytes) => signature Buffer (KMS asymmetric Sign, or a
//                local Ed25519 key in dev). Keeps the signing key out of this
//                module so prod can gate it behind KMS.
//   now   : () => epoch ms
export function makeDynamoAuthority({ ddb, table, signRecord, now = () => Date.now() }) {
  if (!ddb || !table || typeof signRecord !== "function") throw new Error("dynamo authority: ddb, table, signRecord required");

  async function load(stateId) {
    const r = await ddb.getItem({ TableName: table, Key: { state_id: stateId }, ConsistentRead: true });
    return r.Item ?? null;
  }

  async function sign(nonce, rec) {
    const issued = now();
    const full = {
      state_id: rec.state_id, phase: rec.phase,
      policy_version: rec.policy_version ?? null, policy_head_hash: rec.policy_head_hash ?? null,
      lease_epoch: rec.lease_epoch ?? 0, lease_holder: rec.lease_holder ?? null,
      lease_expires_at: rec.lease_expires_at ?? null, terminal_reason: rec.terminal_reason ?? null,
      issued_at: issued, expires_at: issued + 30_000,
    };
    const signature = await signRecord(canonicalRecordBytes(nonce, full));
    return { record: full, signature: Buffer.from(signature).toString("base64"), nonce };
  }

  return {
    async create_onboarding_if_absent(nonce, stateId) {
      try {
        await ddb.putItem({
          TableName: table,
          Item: { state_id: stateId, phase: PHASES.ONBOARDING, lease_epoch: 0 },
          ConditionExpression: "attribute_not_exists(state_id)",
        });
      } catch (e) {
        if (e.name !== "ConditionalCheckFailedException") throw e; // already exists -> idempotent
      }
      return sign(nonce, await load(stateId));
    },

    async read(nonce, stateId) {
      const rec = await load(stateId);
      if (!rec) throw new Error("no such state_id");
      return sign(nonce, rec);
    },

    async acquire_lease(nonce, stateId, holder, ttlMs) {
      const rec = await load(stateId);
      if (!rec) throw new Error("no such state_id");
      if (rec.phase === PHASES.TERMINAL) throw new Error("terminal: lease acquisition permanently rejected");
      const t = now();
      // Conditional: phase != TERMINAL AND (no holder OR lease expired) AND epoch unchanged.
      const next = (rec.lease_epoch ?? 0) + 1;
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET lease_epoch = :ne, lease_holder = :h, lease_expires_at = :exp",
          ConditionExpression: "phase <> :term AND lease_epoch = :cur AND (attribute_not_exists(lease_holder) OR lease_holder = :null OR lease_expires_at < :t)",
          ExpressionAttributeValues: { ":ne": next, ":h": holder, ":exp": t + ttlMs, ":term": PHASES.TERMINAL, ":cur": rec.lease_epoch ?? 0, ":null": null, ":t": t },
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("lease held by an unexpired holder or epoch raced");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },

    async renew_lease(nonce, stateId, holder, epoch, ttlMs) {
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET lease_expires_at = :exp",
          ConditionExpression: "phase <> :term AND lease_holder = :h AND lease_epoch = :ep",
          ExpressionAttributeValues: { ":exp": now() + ttlMs, ":term": PHASES.TERMINAL, ":h": holder, ":ep": epoch },
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("not the current holder/epoch (or terminal)");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },

    async release_lease(nonce, stateId, holder, epoch) {
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET lease_holder = :null, lease_expires_at = :null",
          ConditionExpression: "lease_holder = :h AND lease_epoch = :ep",
          ExpressionAttributeValues: { ":null": null, ":h": holder, ":ep": epoch },
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("not the current holder/epoch");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },

    async promote_to_armed(nonce, stateId, holder, epoch, genesisVersion, genesisHash) {
      const rec = await load(stateId);
      if (!rec) throw new Error("no such state_id");
      if (rec.phase === PHASES.ARMED) {
        if (rec.policy_version !== genesisVersion || rec.policy_head_hash !== genesisHash) throw new Error("already armed with different genesis");
        return sign(nonce, rec); // idempotent for exact genesis
      }
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET phase = :armed, policy_version = :v, policy_head_hash = :h",
          ConditionExpression: "phase = :onb AND lease_holder = :ho AND lease_epoch = :ep",
          ExpressionAttributeValues: { ":armed": PHASES.ARMED, ":onb": PHASES.ONBOARDING, ":v": genesisVersion, ":h": genesisHash, ":ho": holder, ":ep": epoch },
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("promote precondition failed (phase/holder/epoch)");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },

    async compare_and_advance(nonce, stateId, holder, epoch, expectedVersion, expectedHash, nextVersion, nextHash) {
      if (!(nextVersion > expectedVersion)) throw new Error("head version must strictly increase");
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET policy_version = :nv, policy_head_hash = :nh",
          ConditionExpression: "phase = :armed AND lease_holder = :ho AND lease_epoch = :ep AND policy_version = :ev AND policy_head_hash = :eh",
          ExpressionAttributeValues: { ":armed": PHASES.ARMED, ":ho": holder, ":ep": epoch, ":ev": expectedVersion, ":eh": expectedHash, ":nv": nextVersion, ":nh": nextHash },
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("CAS failed (phase/holder/epoch/prior-head mismatch)");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },

    async mark_terminal(nonce, stateId, holder, epoch, expectedPhase, reason, expectedVersion, expectedHash) {
      const rec = await load(stateId);
      if (!rec) throw new Error("no such state_id");
      if (rec.phase === PHASES.TERMINAL) return sign(nonce, rec); // idempotent
      const values = { ":term": PHASES.TERMINAL, ":reason": reason ?? null, ":null": null, ":ep_phase": expectedPhase };
      let cond = "phase = :ep_phase";
      if (expectedPhase === PHASES.ARMED) {
        cond += " AND policy_version = :ev AND policy_head_hash = :eh";
        values[":ev"] = expectedVersion; values[":eh"] = expectedHash;
      }
      // If a holder is set it must be the caller's; if unset (cleared lease) allow.
      cond += " AND (attribute_not_exists(lease_holder) OR lease_holder = :null OR (lease_holder = :ho AND lease_epoch = :epc))";
      values[":ho"] = holder; values[":epc"] = epoch;
      try {
        await ddb.updateItem({
          TableName: table, Key: { state_id: stateId },
          UpdateExpression: "SET phase = :term, terminal_reason = :reason, lease_holder = :null, lease_expires_at = :null",
          ConditionExpression: cond,
          ExpressionAttributeValues: values,
        });
      } catch (e) {
        if (e.name === "ConditionalCheckFailedException") throw new Error("terminal precondition failed (phase/head/holder)");
        throw e;
      }
      return sign(nonce, await load(stateId));
    },
  };
}

// Convenience: a local Ed25519 signRecord for dev/staging (prod uses KMS Sign).
export function localEd25519Signer(privateKey) {
  return async (bytes) => edSign(null, bytes, privateKey);
}

export { randomUUID };
