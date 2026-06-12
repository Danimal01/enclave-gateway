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
holds the KMS key that unlocks your stored session (so we never claim "we can't
read you"). These residuals are disclosed, not hidden.

## Status

This is the active development source heading toward a tagged, attested
production release. Production releases are git-tagged, logged in a transparency
log, and bound to a live enclave attestation; only a tagged release is the
"this exact code is running" artifact. The current development build reproduces
to:

```
PCR0_G = 351bb9ebe0b4ade6327a50a159eb62a253000d057cfec37e7f8db65f1de8ff88fd160ebea70e5f6ca27f146af5c055dd
```

This value is reproducible (two independent builds match) but is a development
build, not yet the attested production release. See `RELEASE.json`.

## License

MIT. See `package.json`.
