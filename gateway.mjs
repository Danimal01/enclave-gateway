// gateway/gateway.mjs: the gateway RPC server that composes the audited modules
// into the session-holding open enclave (gateway-brain-architecture.md 4.2).
//
// It owns the ENTIRE session/Telegram/decrypt surface and nothing else:
//   - KMS decrypt of the v3 sealed session (kms-envelope-v3) -> binding-1;
//   - the MTProto sender behind the audited chokepoint (tg-chokepoint +
//     audited-sender) -> binding-2 after connect and every reconnect;
//   - the open policy-authority verifier (policy-verify) -> op enforcement;
//   - the State Authority lease/head client (state-authority) -> self-fence;
//   - the closed-verb-set brain protocol (brain-protocol) -> handle requests.
//
// This module is the orchestration seam. The Telegram transport (the minimal
// MTProto client, 4.2) and the live KMS credentials are injected so the bulk of
// the gateway is unit-testable without an enclave; the EIF wires the real
// implementations. The brain holds none of this: it talks only the closed verb
// set over the admitted channel.

import { MODES } from "./tg-chokepoint.mjs";
import { deriveAuthority, assertOpAllowed } from "./policy-verify.mjs";
import { decodeRequest, encodeResponse, encodeEvent } from "./brain-protocol.mjs";

export class Gateway {
  // deps:
  //   kms              : { generateDataKey, decryptDataKey } (kms-envelope-v3 transport)
  //   openEnvelopeV3   : the v3 open function (binding-1 byte-compares)
  //   authorityClient  : StateAuthorityClient
  //   policyStore      : async (linkId) => ordered policy_envelopes rows
  //   verifierCfg      : { rpId, origins, googleClientId } for signature checks
  //   transportFactory : async ({ mode }) => { sender, connect, disconnect,
  //                       whoAmI, listSessions, readSecurityState, onNewAuth }
  //                       a minimal MTProto client bound to ONE connection
  //   now/monotonic    : injectable clocks
  constructor(deps) {
    this._d = deps;
    this._accts = new Map();   // acctHandle -> live account context (private)
    this._byState = new Map(); // state_id -> acctHandle
  }

  // Adopt an armed link: acquire the lease, KMS-open the v3 FINAL envelope under
  // the exact context, run binding-1/2, derive authority, and start serving.
  async adopt(row, holder, leaseTtlMs) {
    const { authorityClient, openEnvelopeV3, policyStore, verifierCfg, transportFactory } = this._d;

    // 1. State Authority: read -> reject TERMINAL -> acquire the exclusive lease.
    const rec = await authorityClient.read(row.state_id);
    if (rec.phase === "TERMINAL") throw new Error("adopt: account is terminal");
    if (rec.phase !== "ARMED") throw new Error(`adopt: account not ARMED (phase ${rec.phase})`);
    const lease = await authorityClient.acquireLease(row.state_id, holder, leaseTtlMs);
    const gen = lease.record.lease_epoch;

    // 2. KMS-open the FINAL envelope; binding-1 byte-compares inner vs row.
    const dataKey = await this._d.kms.decryptDataKey({ encryptedDataKey: row.seal_encrypted_data_key, contextId: row.kms_context_id, creds: await this._d.freshCreds() });
    let opened;
    try {
      opened = openEnvelopeV3({
        dataKey,
        nonce: row.seal_nonce, ciphertext: row.seal_ciphertext, tag: row.seal_tag,
        expected: {
          sealPhase: "FINAL", sealGeneration: row.seal_generation,
          linkId: row.id, tgUserId: row.tg_user_id, stateId: row.state_id,
          kmsContextId: row.kms_context_id, signersCommit: row.signers_commit,
        },
      });
    } finally {
      dataKey.fill(0);
    }

    // 3. Build the audited armed transport and connect; binding-2 = whoAmI.
    //    The connection (connection.mjs) owns the chokepoint and installs the
    //    audited serialization; the gateway consumes the transport it returns.
    const tx = await transportFactory({ mode: MODES.ARMED, session: opened.session });
    await tx.connect();
    const me = await tx.whoAmI();
    if (String(me.tgUserId) !== String(row.tg_user_id)) {
      await tx.disconnect();
      throw new Error("adopt: binding-2 identity mismatch");
    }

    // 4. Derive authority from the signed chain anchored at the State Authority head.
    const rows = await policyStore(row.id);
    const derived = await deriveAuthority(rows, {
      linkId: row.id, tgUserId: row.tg_user_id, signersCommit: row.signers_commit,
      now: this._d.now ?? (() => Date.now()), ...verifierCfg,
    }, { version: rec.policy_version, hash: rec.policy_head_hash });
    if (!derived.ok) {
      await tx.disconnect();
      throw new Error(`adopt: policy authority rejected: ${derived.reason}`);
    }

    const handle = `acct-${row.state_id}`;
    const ctx = {
      handle, stateId: row.state_id, linkId: row.id, tgUserId: String(row.tg_user_id),
      gen, holder, leaseDeadline: lease.localDeadline, tx, authority: derived.authority,
    };
    this._accts.set(handle, ctx);
    this._byState.set(row.state_id, handle);
    return { handle, gen };
  }

  _ctx(acct, gen) {
    const ctx = this._accts.get(acct);
    if (!ctx) throw new Error("unknown acct handle");
    if (gen !== undefined && gen !== ctx.gen) throw new Error("stale gen: request outside current leased epoch");
    if ((this._d.monotonic ?? (() => 0))() > ctx.leaseDeadline) throw new Error("lease expired: self-fenced");
    return ctx;
  }

  // Handle one decoded brain request. Reads need no token; mutating ops are
  // re-checked against the freshly derived authority (the gateway is the ceiling).
  async handleRequest(frame) {
    const req = decodeRequest(frame);
    try {
      const ctx = this._ctx(req.acct, req.gen);
      const body = await this._dispatch(ctx, req);
      return encodeResponse({ id: req.id, ok: true, body });
    } catch (e) {
      return encodeResponse({ id: req.id, ok: false, code: e.message.slice(0, 80), body: {} });
    }
  }

  async _dispatch(ctx, req) {
    switch (req.op) {
      case "WHO_AM_I":
        return { tgUserId: ctx.tgUserId };
      case "LIST_SESSIONS":
        return { sessions: await ctx.tx.listSessions() };
      case "READ_SECURITY_STATE":
        return await ctx.tx.readSecurityState();
      case "EVICT_SESSION": {
        const freshRoster = await ctx.tx.listSessions();
        const gate = assertOpAllowed(ctx.authority, "EVICT_SESSION", { hash: req.arg.hash, freshRoster });
        if (!gate.ok) throw new Error(`evict refused: ${gate.reason}`);
        // Re-bind the chokepoint's evict gate to THIS exact, policy-approved hash.
        const removed = await ctx.tx.evictSession(req.arg.hash, {
          assertEvictAllowed: (h) => { if (String(h) !== String(req.arg.hash)) throw new Error("evict hash drift"); },
        });
        return { removed };
      }
      case "DECLINE_RESET": {
        const gate = assertOpAllowed(ctx.authority, "DECLINE_RESET");
        if (!gate.ok) throw new Error(`decline refused: ${gate.reason}`);
        return { declined: await ctx.tx.declineReset() };
      }
      case "LOGOUT_SELF": {
        const gate = assertOpAllowed(ctx.authority, "LOGOUT_SELF");
        if (!gate.ok) throw new Error(`logout refused: ${gate.reason}`);
        return { goneOrDead: await ctx.tx.logOutSelf() };
      }
      default:
        throw new Error(`unknown op ${req.op}`);
    }
  }

  // The gateway emits only the typed NEW_AUTH event; the raw stream never crosses.
  encodeNewAuth(acct, body) {
    return encodeEvent({ kind: "NEW_AUTH", acct, body: { hash: body.hash, unconfirmed: body.unconfirmed, device: body.device, location: body.location } });
  }

  // Self-fence: stop accepting RPC, drop the live sender, zero session material,
  // on any lease-renewal failure or stale-gen (5.5 H-4).
  async selfFence(acct, reason) {
    const ctx = this._accts.get(acct);
    if (!ctx) return;
    this._accts.delete(acct);
    this._byState.delete(ctx.stateId);
    try { await ctx.tx.disconnect(); } catch { /* already down */ }
  }
}
