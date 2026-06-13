// gateway/onboarding-service.mjs: serves ONE browser onboarding connection over
// the attested channel (spec 4.10.7). Transport-agnostic: it operates on a
// {readFrame, writeFrame} pair (newline-delimited JSON frames the parent relay
// shuttles to/from the browser over vsock), so the handshake + dispatch logic is
// testable without a socket.
//
// Handshake:
//   1. gateway generates an ephemeral X25519 key and attests WITH it (attest.c's
//      public-key arg), then sends {hello, attestation, releaseRecordDigest};
//   2. the browser validates the attestation to the AWS root + the published PCR0_G,
//      derives the channel, and replies {connect, browserEphemeralKey, onb, gen};
//   3. both ends now share the AEAD channel. Every op the browser sends is SEALED;
//      the relay sees only ciphertext. The gateway opens it, dispatches to the
//      OnboardingManager (which runs the proven credential effects), and seals the
//      reply. Login inputs (phone, code, SRP proof) are unreadable to the relay.
//
// The gateway creates link_id + state_id (never the browser); the browser supplies
// phone + the signer genesis it is enrolling. onb + gen are bound into the channel
// transcript at connect, so a relay cannot splice a different ceremony.

import { createHash, randomUUID } from "node:crypto";
import { gatewayAccept, generateKeyPairSync, rawPub } from "./onboarding-channel.mjs";
import { OnboardingManager } from "./onboarding.mjs";

const sha256b64 = (s) => createHash("sha256").update(Buffer.from(s, "base64")).digest("base64");

export function makeOnboardingService({ effects, attest, pcr0g, releaseRecordDigest, ownerEmailFor }) {
  if (typeof attest !== "function" || !pcr0g || !releaseRecordDigest) {
    throw new Error("onboarding service: attest, pcr0g, releaseRecordDigest required");
  }
  const manager = new OnboardingManager(effects);

  async function handleConnection({ readFrame, writeFrame }) {
    // 1. ephemeral X25519 key + attestation carrying it.
    const { publicKey: selfPub, privateKey: selfPriv } = generateKeyPairSync("x25519");
    const attestation = await attest(rawPub(selfPub).toString("hex"));
    await writeFrame({ type: "hello", attestation, releaseRecordDigest });

    // 2. the browser's connect frame (binds onb + gen into the channel transcript).
    const c = await readFrame();
    if (!c || c.type !== "connect" || !c.browserEphemeralKey || !c.onb) throw new Error("onboarding: bad connect frame");
    const onb = String(c.onb);
    const gen = c.gen ?? 0;
    const channel = gatewayAccept({
      selfPriv, selfPub, browserEphemeralKey: c.browserEphemeralKey,
      attestationDigest: sha256b64(attestation), releaseRecordDigest, onb, gen,
    });
    const channelKeyHash = createHash("sha256").update(channel.transcript).digest("hex");

    // 3. sealed op/reply loop. A thrown effect (refusal, cap, teardown) becomes a
    //    sealed {ok:false} reply; the connection stays usable for retriable steps.
    for (;;) {
      const f = await readFrame();
      if (!f) {
        // Browser/channel closed mid-ceremony (e.g. a dropped connection). Tear the
        // ceremony down so its in-memory session, State Authority lease, and the
        // 'connecting' link row are released -- otherwise prepare() rejects the phone
        // as "already in flight" on the next attempt until an enclave restart.
        try { await dispatch({ op: "abort", args: {}, onb, gen, pcr0g, channelKeyHash, ownerEmailFor }); } catch { /* best-effort cleanup */ }
        return;
      }
      if (f.type !== "op" || !f.frame) continue;
      let reply;
      try {
        const { op, args } = channel.open(f.frame);
        reply = { ok: true, result: await dispatch({ op, args, onb, gen, pcr0g, channelKeyHash, ownerEmailFor }) };
      } catch (e) {
        reply = { ok: false, error: String(e?.message ?? e).slice(0, 200) };
      }
      await writeFrame({ type: "reply", frame: channel.seal(reply) });
    }
  }

  // The gateway owns link_id/state_id; the browser only ever supplies phone, the
  // signer genesis, and the per-step inputs.
  async function dispatch({ op, args, onb, gen, pcr0g, channelKeyHash, ownerEmailFor }) {
    switch (op) {
      case "prepare": {
        const link = randomUUID(), state = randomUUID();
        return manager.prepare({
          onb, link, state, phone: args.phone, signerGenesis: args.signerGenesis,
          nonce: args.nonce, pcr0g, channelKeyHash,
        });
      }
      case "authorize":
        return manager.authorize({
          onb, candidate: args.candidate, authorization: args.authorization,
          ownerEmail: ownerEmailFor ? await ownerEmailFor(onb) : (args.ownerEmail ?? null),
          userId: args.userId ?? null, // browser's auth user id; ownership matched server-side
        });
      case "startLogin": return manager.startLogin({ onb });
      case "submitCode": return manager.submitCode({ onb, code: args.code });
      case "submitSrpProof": return manager.submitSrpProof({ onb, A: args.A, M1: args.M1 });
      case "abort": return manager.abort({ onb });
      default: throw new Error(`unknown onboarding op: ${op}`);
    }
  }

  return { manager, handleConnection };
}

export { sha256b64 };
