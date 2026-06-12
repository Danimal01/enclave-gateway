// gateway/onboarding-channel.mjs: the attested browser-gateway onboarding relay
// channel (gateway-brain-architecture.md 4.10.7).
//
// The login inputs (phone, SMS code, SRP proof, signer genesis, OnboardingGrant)
// must be UNREADABLE and UNSUBSTITUTABLE by the relay (web + parent) in transit.
// The browser validates the gateway's NSM attestation to a HARDCODED AWS Nitro
// root and confirms PCR0_G against the published release record, then both ends
// derive a channel key from their attested ephemeral X25519 keys and AEAD-
// encrypt every secret field with strictly increasing per-direction sequence
// numbers. The transcript binds both ephemeral keys, the attestation digest, the
// release-record digest, onb, and gen. The relay sees only ciphertext and cannot
// read or forge contents.
//
// HONEST LIMIT (disclosed, not closed): the browser code doing the attestation
// check is itself web-served, so the check is trust-on-first-use. This module is
// the transport; it does not turn the served page into an independent trust root.
//
// This is the same machinery as the gateway-brain channel (4.7) with one end
// being the browser. The attestation validation itself is injected so the
// channel crypto (ECDH, HKDF, AEAD, sequencing, transcript binding) is testable.

import { diffieHellman, createHash, createHmac, createCipheriv, createDecipheriv, randomBytes, generateKeyPairSync, createPublicKey, createPrivateKey } from "node:crypto";

const HKDF_INFO = "sessions.fyi/onboard-channel/v1";

function hkdfSha256(ikm, salt, info, len = 32) {
  const prk = createHmac("sha256", salt).update(ikm).digest();
  let t = Buffer.alloc(0), okm = Buffer.alloc(0), i = 0;
  while (okm.length < len) {
    i += 1;
    t = createHmac("sha256", prk).update(Buffer.concat([t, Buffer.from(info, "utf8"), Buffer.from([i])])).digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, len);
}

function rawPub(keyObject) {
  return keyObject.export({ type: "spki", format: "der" });
}

export function transcriptDigest({ browserPub, gatewayPub, attestationDigest, releaseRecordDigest, onb, gen }) {
  return createHash("sha256").update(JSON.stringify([
    HKDF_INFO,
    Buffer.from(browserPub).toString("base64"),
    Buffer.from(gatewayPub).toString("base64"),
    attestationDigest, releaseRecordDigest, onb, String(gen),
  ])).digest();
}

// One channel endpoint. role is "browser" or "gateway"; the two derive the same
// key and use direction-separated sub-keys + monotonic sequence numbers.
export class OnboardingChannel {
  constructor({ role, selfPriv, selfPub, peerPub, transcript }) {
    if (role !== "browser" && role !== "gateway") throw new Error("bad role");
    this.role = role;
    const shared = diffieHellman({ privateKey: selfPriv, publicKey: peerPub });
    const key = hkdfSha256(shared, transcript, HKDF_INFO);
    // Direction-separated keys so a frame can't be reflected across directions.
    this._sendKey = hkdfSha256(key, Buffer.from(role), "send");
    this._recvKey = hkdfSha256(key, Buffer.from(role === "browser" ? "gateway" : "browser"), "send");
    this._sendSeq = 0;
    this._recvSeq = 0;
    this.transcript = transcript;
  }

  seal(plaintextObj) {
    const seq = this._sendSeq++;
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(seq, 8);
    const aad = Buffer.concat([this.transcript, Buffer.from([seq & 0xff])]);
    const cipher = createCipheriv("aes-256-gcm", this._sendKey, nonce);
    cipher.setAAD(Buffer.concat([this.transcript, Buffer.from(String(seq))]));
    const pt = Buffer.from(JSON.stringify(plaintextObj), "utf8");
    const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
    pt.fill(0);
    void aad;
    return { seq, ciphertext: ct.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
  }

  open({ seq, ciphertext, tag }) {
    // Strictly increasing per-direction sequence: rejects replay and reorder.
    if (seq !== this._recvSeq) throw new Error(`channel: out-of-order frame (got ${seq}, expected ${this._recvSeq})`);
    this._recvSeq++;
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(seq, 8);
    const decipher = createDecipheriv("aes-256-gcm", this._recvKey, nonce);
    decipher.setAAD(Buffer.concat([this.transcript, Buffer.from(String(seq))]));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    let pt;
    try {
      pt = Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64")), decipher.final()]);
    } catch {
      throw new Error("channel: AEAD authentication failed (tampered or wrong key)");
    }
    return JSON.parse(pt.toString("utf8"));
  }
}

// Browser-side bring-up (4.10.7): validate the attestation to the hardcoded root
// and the release record, then build the channel. attestationVerifier is the
// web-served (trust-on-first-use) check; it returns the gateway ephemeral key,
// PCR0_G, and the attestation digest, or throws.
export function browserConnect({ attestationDoc, attestationVerifier, expectedPcr0gFromRelease, releaseRecordDigest, onb, gen }) {
  const att = attestationVerifier(attestationDoc);
  if (!att || !att.ok) throw new Error("onboard-channel: attestation invalid");
  if (att.debug) throw new Error("onboard-channel: debug enclave refused");
  if (att.pcr0g !== expectedPcr0gFromRelease) throw new Error("onboard-channel: PCR0_G does not match the published release record");
  const { publicKey: selfPub, privateKey: selfPriv } = generateKeyPairSync("x25519");
  const gatewayPub = createPublicKey({ key: Buffer.from(att.ephemeralKey, "base64"), type: "spki", format: "der" });
  const transcript = transcriptDigest({
    browserPub: rawPub(selfPub), gatewayPub: Buffer.from(att.ephemeralKey, "base64"),
    attestationDigest: att.digest, releaseRecordDigest, onb, gen,
  });
  const channel = new OnboardingChannel({ role: "browser", selfPriv, selfPub, peerPub: gatewayPub, transcript });
  return { channel, browserEphemeralKey: rawPub(selfPub).toString("base64") };
}

// Gateway-side: it already holds its attested ephemeral key; build the matching
// channel from the browser's presented ephemeral key.
export function gatewayAccept({ selfPriv, selfPub, browserEphemeralKey, attestationDigest, releaseRecordDigest, onb, gen }) {
  const browserPub = createPublicKey({ key: Buffer.from(browserEphemeralKey, "base64"), type: "spki", format: "der" });
  const transcript = transcriptDigest({
    browserPub: Buffer.from(browserEphemeralKey, "base64"), gatewayPub: rawPub(selfPub),
    attestationDigest, releaseRecordDigest, onb, gen,
  });
  return new OnboardingChannel({ role: "gateway", selfPriv, selfPub, peerPub: browserPub, transcript });
}

export { hkdfSha256, generateKeyPairSync, createPrivateKey, createPublicKey, rawPub };
