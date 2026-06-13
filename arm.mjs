// gateway/arm.mjs: the ARM completion step (Piece 2b, spec 3.F + 4.10).
//
// Onboarding seals the session FINAL while bound to the ONBOARDING signer commit
// (the single grant signer), because the user has not yet chosen their key set.
// ARM is where the user's real v1 policy (their full signer set + threshold +
// kept devices) becomes the account's authority. Because the gateway REFUSES any
// v1 anchor whose signersCommit(signers, threshold) does not equal the seal's
// bound commit (policy-verify line ~352, the F2 binding), arming REQUIRES the
// enclave to RE-SEAL the FINAL envelope under the v1 policy's commit. Only the
// enclave can: it alone can KMS-open the sealed session.
//
// Trust model: the gateway does NOT trust the backend that wrote the genesis. It
// re-derives everything from scratch:
//   1. the v1 genesis signer set MUST equal the link's REGISTERED signers (the
//      ownership anchor — only keys the authenticated user enrolled count);
//   2. the genesis MUST carry a valid signature quorum of its own signer set;
//   3. only then does it re-seal FINAL(gen+1) under signersCommit(v1) and promote
//      the State Authority record ONBOARDING/CONNECTED -> ARMED at that exact
//      genesis hash, atomically flipping status to 'armed'.
// A compromised backend can therefore at most stall arming, never arm a link with
// an attacker key set or a forged policy.
//
// All effects are injected so the security logic is unit-tested without an
// enclave; the EIF wires the real KMS/DB/State-Authority implementations.

import { canonicalEq, signersCommit, payloadHash, deriveAuthority } from "./policy-verify.mjs";

const ARM_LEASE_TTL_MS = 5 * 60 * 1000;

// The registered-signer rows -> the EnvelopeSigner shape policy-verify expects.
// Mirrors lib/envelope.ts signersSnapshot EXACTLY (a malformed credential simply
// cannot sign and is dropped — never a free pass).
function rowToSigner(s) {
  const cred = s.credential ?? {};
  if (s.kind === "passkey" && typeof cred.id === "string" && typeof cred.publicKey === "string") {
    return { id: String(s.id), kind: "passkey", credId: cred.id, publicKey: cred.publicKey };
  }
  if (s.kind === "wallet" && typeof cred.address === "string") {
    return { id: String(s.id), kind: "wallet", address: cred.address.toLowerCase() };
  }
  if (s.kind === "google" && typeof cred.sub === "string") {
    return { id: String(s.id), kind: "google", sub: cred.sub };
  }
  return null;
}

export function makeArmCompleter({
  db, kms, openEnvelopeV3, sealEnvelopeV3, envelopeDigest, newContextId, zeroize,
  freshCreds, authorityClient, holder, verifierCfg = {}, now = () => Date.now(),
}) {
  if (!db?.from || !db?.rpc || !kms?.decryptDataKey || !kms?.generateDataKey
      || typeof openEnvelopeV3 !== "function" || typeof sealEnvelopeV3 !== "function"
      || typeof freshCreds !== "function" || !authorityClient || !holder) {
    throw new Error("arm completer: missing dependency");
  }

  async function loadRows(table, sel, link) {
    const r = await db.from(table).select(sel).eq("link_id", link);
    return r?.data ?? r ?? [];
  }

  async function loadGenesis(link) {
    const rows = await loadRows("policy_envelopes", "version,action,core,core_hash,sigs", link);
    const g = rows.find((row) => row.version === 1);
    if (!g) return null;
    return g;
  }

  async function loadRegisteredSigners(link) {
    const rows = await loadRows("signers", "id,kind,credential", link);
    return rows.map(rowToSigner).filter(Boolean);
  }

  // Complete arming for ONE pending link row (status 'arming', seal_version 3,
  // seal_phase FINAL). Idempotent-safe: re-running after a partial failure opens
  // the still-onboarding-commit seal again and re-promotes (promote_to_armed is
  // idempotent at the same genesis).
  async function completeArm({ row }) {
    const link = String(row.id);
    const state = String(row.state_id);
    const tgUserId = String(row.tg_user_id);

    // 1. genesis present?
    const genesis = await loadGenesis(link);
    if (!genesis) throw new Error("arm: no v1 genesis to complete");
    const core = genesis.core;
    if (!core || core.v !== 1) throw new Error("arm: malformed v1 genesis core");

    // 2. OWNERSHIP ANCHOR: the genesis signer set must equal the registered set.
    const registered = await loadRegisteredSigners(link);
    if (registered.length === 0) throw new Error("arm: link has no registered signers");
    if (!canonicalEq(registered, core.signers)) {
      throw new Error("arm: genesis signer set does not match the link's registered signers");
    }

    // 3. the commit the re-seal will bind, and the genesis head hash.
    const expectedCommit = signersCommit(core.signers, core.threshold);
    const genesisHash = payloadHash(String(genesis.action), core);

    // 4. VERIFY the genesis (signature quorum of its own signers + all bindings).
    //    We pass expectedCommit as the attested commit so the F2 self-anchor check
    //    passes by construction (the re-seal below makes it true); the real gate is
    //    the signature quorum inside deriveAuthority.
    const derived = await deriveAuthority(
      [genesis],
      { linkId: link, tgUserId, signersCommit: expectedCommit, now, ...verifierCfg },
      { version: 1, hash: genesisHash },
    );
    if (!derived.ok) throw new Error(`arm: genesis verification failed: ${derived.reason}`);

    // 5. RE-SEAL: open the current FINAL envelope (binding-1 under the OLD commit),
    //    then re-seal FINAL(gen+1) under a fresh attested key bound to the v1 commit.
    const newGen = Number(row.seal_generation) + 1;
    const openKey = await kms.decryptDataKey({
      encryptedDataKey: row.seal_encrypted_data_key, contextId: row.kms_context_id, creds: await freshCreds(),
    });
    let session;
    try {
      const opened = openEnvelopeV3({
        dataKey: openKey,
        nonce: row.seal_nonce, ciphertext: row.seal_ciphertext, tag: row.seal_tag,
        expected: {
          sealPhase: "FINAL", sealGeneration: Number(row.seal_generation),
          linkId: link, tgUserId: row.tg_user_id, stateId: state,
          kmsContextId: row.kms_context_id, signersCommit: row.signers_commit,
        },
      });
      session = opened.session;
    } finally {
      openKey.fill?.(0);
    }

    const contextId = newContextId();
    const { plaintextKey, encryptedDataKey } = await kms.generateDataKey({ contextId, creds: await freshCreds() });
    let env;
    try {
      env = sealEnvelopeV3({
        dataKey: plaintextKey, session,
        sealPhase: "FINAL", sealGeneration: newGen,
        linkId: link, tgUserId, stateId: state, kmsContextId: contextId, signersCommit: expectedCommit,
      });
    } finally {
      zeroize(plaintextKey);
      session = null; // strings are immutable in JS; drop the reference promptly
    }
    const digest = envelopeDigest({
      encryptedDataKey, nonce: env.nonce, ciphertext: env.ciphertext, tag: env.tag,
      kmsContextId: contextId, sealGeneration: newGen,
    });

    // 6. PROMOTE the State Authority record to ARMED at this exact genesis (only the
    //    lease holder may; idempotent if already armed with the same genesis).
    const lease = await authorityClient.acquireLease(state, holder, ARM_LEASE_TTL_MS);
    const epoch = lease.record.lease_epoch;
    await authorityClient.promoteToArmed(state, holder, epoch, 1, genesisHash);

    // 7. Atomically commit the new seal + commit + status='armed' (gateway-only fn,
    //    CAS on the expected old generation so a concurrent writer cannot clobber).
    await db.rpc("gateway_complete_arm", {
      p_link: link, p_state_id: state,
      p_expected_generation: Number(row.seal_generation), p_new_generation: newGen,
      p_encrypted_data_key: encryptedDataKey, p_nonce: env.nonce, p_ciphertext: env.ciphertext, p_tag: env.tag,
      p_context_id: contextId, p_signers_commit: expectedCommit, p_envelope_digest: digest,
    });

    // 8. release the arm lease so the adopt loop re-acquires cleanly.
    try { await authorityClient.releaseLease(state, holder, epoch); } catch { /* terminal/renewed elsewhere */ }

    return { armed: true, link, genesisHash, newGeneration: newGen, signersCommit: expectedCommit };
  }

  // Sweep: arm any CONNECTED FINAL link for which the backend has written a v1
  // policy genesis (the arm-pending signal — no extra status column needed). A
  // connected link with no genesis is simply skipped (mid-onboarding, not an
  // error). Best-effort: an unsigned/forged genesis fails ONLY its own link.
  async function sweepPendingArms() {
    let rows = [];
    try {
      const r = await db.from("telegram_links")
        .select("id,state_id,tg_user_id,signers_commit,seal_generation,kms_context_id,seal_encrypted_data_key,seal_nonce,seal_ciphertext,seal_tag")
        .eq("status", "connected").eq("seal_version", 3).eq("seal_phase", "FINAL");
      rows = r?.data ?? r ?? [];
    } catch (e) {
      return { completed: 0, failed: 0, skipped: 0, error: e?.message };
    }
    let completed = 0, failed = 0, skipped = 0;
    for (const row of rows) {
      let genesis;
      try { genesis = await loadGenesis(String(row.id)); }
      catch { genesis = null; }
      if (!genesis) { skipped += 1; continue; } // no arm requested yet
      try { await completeArm({ row }); completed += 1; }
      catch { failed += 1; }
    }
    return { completed, failed, skipped };
  }

  return { completeArm, sweepPendingArms, _loadGenesis: loadGenesis, _loadRegisteredSigners: loadRegisteredSigners };
}
