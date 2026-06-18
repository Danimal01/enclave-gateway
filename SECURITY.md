# Security

## Reporting a vulnerability

Email **security@sessions.fyi** (or hello@sessions.fyi). Include steps to reproduce. We
aim to acknowledge within 72 hours. Please do not open public issues for
security-sensitive reports.

## What is in the trusted base (stated plainly)

Sessions is a **bounded, attested, revocable guard, not a zero-trust vault.** Two parties
are in the trusted base, and we do not hide it:

1. **AWS.** The "this exact code is running" proof rests on AWS Nitro hardware
   attestation chaining to the AWS Nitro Enclaves Root G1. If AWS's hardware root of
   trust were compromised, the attestation would be moot. This is inherent to any Nitro
   design, not specific to Sessions.
2. **The operator (us), via the KMS key policy.** Your Telegram session is sealed with
   AWS KMS under a key policy gated on the enclave's measurement
   (`kms:RecipientAttestation:ImageSha384`, pinned to the published PCR0), so in normal
   operation only an enclave running the exact published image can decrypt it, and the
   host machine cannot. We operate that key and control its policy. We therefore do
   **not** claim it is impossible for us to ever reach your session. What we provide is a
   bounded, hardware-checked capability surface (see `tg-chokepoint.mjs`) plus the ability
   to revoke access at any time: disconnecting logs the guard out of your account.

## Compelled access and legal process

Because the operator controls the KMS key policy, a lawful order could in principle
compel a change to that policy or the deployment of a different image. We will not claim
otherwise. Two facts bound and surface this risk:

- Any change to the running code changes the PCR0, which is visible in the live
  attestation. A silent swap to a wider-capability image is detectable by anyone
  re-checking the attestation against the published PCR0.
- The capability ceiling is enforced inside the enclave: even a different image is bound
  by whatever allowlist it ships, and that allowlist is part of the measured, published
  image.

We do not yet operate a warrant canary or a public, append-only transparency log of PCR0
history. Publishing one (and moving the KMS key policy toward multi-party control) is on
the roadmap; it is the main step toward making the operator's control over the key policy
publicly auditable rather than trust-based.

## AWS account / rogue admin

Whoever can edit the KMS key policy (the operator's AWS control plane) is the trust anchor
for at-rest access. We do not currently use M-of-N / split control over that policy; that
is a known limitation we intend to address.

## What you can verify yourself (no trust required)

- The complete capability surface and its wire-level enforcement: `tg-chokepoint.mjs`,
  `audited-sender.mjs`.
- That the published source reproduces to the published PCR0: `BUILD.md`.
- That a live AWS-signed attestation reports that PCR0: the in-browser verifier at
  https://sessions.fyi/how-it-works, or run your own COSE/Nitro verifier against
  https://jmxqeylkftqmkmvoorhi.supabase.co/storage/v1/object/public/attestation/gateway.json.
