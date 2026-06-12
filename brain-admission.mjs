// gateway/brain-admission.mjs: the gateway admits a brain channel WITHOUT
// pinning PCR0_B (gateway-brain-architecture.md 4.7, 5.5, H-7).
//
// A malicious brain is already inside the threat model, so pinning PCR0_B would
// only force a gateway/KMS re-pin on every brain release for no security gain.
// Instead the gateway image pins ONE long-lived Brain Admission public key. For
// each deployment, an admission service verifies the brain's live NSM
// attestation and issues a short-lived certificate over {brain_ephemeral_key,
// attestation_digest, deployment_id, expires_at}. PCR0_B is recorded in the
// certificate and deploy record but is NOT an authority input.
//
// The gateway accepts a brain channel only when ALL hold:
//   - the certificate signature verifies under the pinned admission key;
//   - the certificate is unexpired and matches the expected deployment;
//   - the certified ephemeral key and attestation digest match the presented
//     AWS-signed attestation;
//   - the attestation is a valid non-debug Nitro enclave document.
//
// Authorizing an arbitrary/compromised brain does not widen authority: the
// published gateway protocol and policy verifier remain the ceiling, and every
// account RPC is separately fenced by the State Authority lease epoch.

import { verify as edVerify, createPublicKey, createHash } from "node:crypto";

function canonicalCertBytes(cert) {
  const ordered = {
    brain_ephemeral_key: cert.brain_ephemeral_key,
    attestation_digest: cert.attestation_digest,
    deployment_id: cert.deployment_id,
    pcr0_b: cert.pcr0_b ?? null,        // recorded metadata, not authority
    expires_at: cert.expires_at,
  };
  return Buffer.from(`sessions.fyi/brain-admission/v1\n${JSON.stringify(ordered)}`, "utf8");
}

// attestationVerifier: async (doc) => { ok, pcr0, publicKey (ephemeral), digest,
//   debug } — wraps the AWS Nitro attestation validation (the same root Claim A
//   pins). Injected so this module stays pure and testable; production passes
//   the real NSM document verifier.
export function makeBrainAdmission({ pinnedAdmissionKey, expectedDeploymentId, attestationVerifier, now = () => Date.now() }) {
  if (!pinnedAdmissionKey) throw new Error("pinnedAdmissionKey required");
  const admissionPub = createPublicKey({ key: Buffer.from(pinnedAdmissionKey, "base64"), type: "spki", format: "der" });

  return {
    // Returns { ok:true, channelInputs } or throws with a precise reason.
    async admit({ certificate, signature, attestationDoc }) {
      // 1. certificate signature under the pinned admission key
      const certBytes = canonicalCertBytes(certificate);
      if (!edVerify(null, certBytes, admissionPub, Buffer.from(signature, "base64"))) {
        throw new Error("brain-admission: certificate signature invalid under pinned key");
      }
      // 2. unexpired + expected deployment
      if (typeof certificate.expires_at !== "number" || certificate.expires_at < now()) {
        throw new Error("brain-admission: certificate expired");
      }
      if (expectedDeploymentId && certificate.deployment_id !== expectedDeploymentId) {
        throw new Error("brain-admission: deployment_id mismatch");
      }
      // 3-4. the AWS-signed attestation is valid, non-debug, and its ephemeral
      //      key + digest match what the certificate certified.
      const att = await attestationVerifier(attestationDoc);
      if (!att || !att.ok) throw new Error("brain-admission: attestation invalid");
      if (att.debug) throw new Error("brain-admission: debug-mode enclave refused");
      if (att.digest !== certificate.attestation_digest) throw new Error("brain-admission: attestation digest mismatch");
      if (att.publicKey !== certificate.brain_ephemeral_key) throw new Error("brain-admission: ephemeral key mismatch");
      // PCR0_B is recorded, never gated:
      const recordedPcr0B = att.pcr0 ?? certificate.pcr0_b ?? null;
      return {
        ok: true,
        channelInputs: {
          brainEphemeralKey: certificate.brain_ephemeral_key,
          attestationDigest: certificate.attestation_digest,
          deploymentId: certificate.deployment_id,
          pcr0b: recordedPcr0B,
        },
      };
    },
  };
}

// Channel-key derivation transcript binding (4.7): both attested ephemeral keys,
// both attestation digests, the admission certificate, and deployment_id. The
// gateway and brain derive the same key; the parent relay never sees plaintext.
export function channelTranscriptDigest({ gatewayEphemeralKey, brainEphemeralKey, gatewayAttDigest, brainAttDigest, certificateDigest, deploymentId }) {
  return createHash("sha256").update(JSON.stringify([
    "sessions.fyi/brain-channel/v1",
    gatewayEphemeralKey, brainEphemeralKey, gatewayAttDigest, brainAttDigest, certificateDigest, deploymentId,
  ])).digest("base64");
}

export { canonicalCertBytes };
