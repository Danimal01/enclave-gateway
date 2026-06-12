# Sessions Enclave Gateway

This is the open source of the Sessions **gateway**: the small enclave that holds
your armed Telegram session and is the only component that can call the Telegram
API through it. Its source is the complete, exclusive list of what Sessions can
ever do to your Telegram account, and you can read it here.

It is account-management only. It has no method to read your messages, see your
chats or contacts, open your files, or change your password.

## What to read first

- **`tg-chokepoint.mjs`** is the capability ceiling. The `ALLOWED` map plus the
  `ONBOARDING_ONLY` set are every Telegram method the gateway can ever send.
  There is no generic `invoke`. If a method is not in those sets, the gateway
  cannot send it, and adding one changes the published source and therefore the
  measured fingerprint (PCR0) below.
- **`audited-sender.mjs`** is the boundary that enforces the allowlist at the
  real wire (every frame is checked before serialization, including internally
  enqueued ones).
- **`policy-verify.mjs`** is the open policy-authority verifier: Sessions only
  acts on your signed policy, and you can check that by reading this file.

## The guarantee, stated honestly

This is a **bounded-surface** guarantee backed by readable source plus hardware
attestation. It is NOT a claim of cryptographic impossibility of misuse.

What you can check yourself:
1. the complete account-capable wire surface (the files above),
2. the absence of any message or file method,
3. that you can rebuild this exact source and get the same enclave fingerprint
   (PCR0) that the live attestation reports (see `BUILD.md`).

What you are trusting: AWS Nitro hardware attestation, and the fact that Sessions
holds the KMS key that unlocks your stored session. These residuals are disclosed, not hidden.

## Status

This source is now bound to a LIVE enclave attestation. A genuine AWS Nitro
enclave running this exact image attests the measurement below, and two
independent `--no-cache` builds reproduce it. Production releases will
additionally be git-tagged and logged in a transparency log.

```
PCR0_G = ee0d4da90ba7b301e394fcdc0f9f956f19c3b02352a2665c10c9672dd1c122a09c31e1bd60ae0e5ddb729c4f7c0fe241
```

Verify it yourself: the live attestation document is published at
`https://sessions.fyi/attestation/gateway.json` and verified in your browser at
`https://sessions.fyi/how-it-works` (or with any COSE/Nitro verifier chaining to
AWS Nitro Root G1). Rebuild this repo and confirm the PCR0 matches. See
`RELEASE.json`.

## License

MIT. See `package.json`.
