# Sessions Enclave Gateway

This is the complete, open source of the **Sessions gateway** — the small,
hardware-attested enclave that holds your armed Telegram session and is the
*only* component that can act on it. **Its source is the exhaustive list of
everything Sessions can ever do to your Telegram account, and you can read all
of it here.**

It is account-management only. There is no method in this code to read your
messages, open your chats or files, see your contacts, or change your password.
What it *can* do — watch for new logins, remove a session that is not on your
signed keep-list, decline a hostile 2FA-password reset, and surface those events
to you — is the entire surface, enumerated in one file you can audit.

## Why this exists (the problem the off-the-shelf stack can't solve)

To guard a Telegram account you must hold its session key — and that key is the
keys to everything: whoever holds it can read every message and act as you. So
every guard is structurally a custodian. Build on Telegram's high-level clients
(TDLib, GramJS's `TelegramClient`, Telethon) and "we don't read your messages"
is a *promise*, on a server you have to trust, with the full API one call away.

Sessions is built the opposite way. We discarded the high-level client and wrote
a minimal MTProto stack in which **every outbound call is forced through one
audited allowlist** — the code physically cannot send a method that is not on
it. Then we run that code inside an AWS Nitro enclave that measures itself, so
you can verify, cryptographically and from your own browser, that *this exact,
bounded code* is the thing holding your session. **Guard power without custodial
power — and you can check it yourself.** That combination is what the easy
Telegram tooling, designed for full access on a trusted server, cannot offer.

## What to read first

- **`tg-chokepoint.mjs`** — the capability ceiling. The `ALLOWED` map plus the
  `ONBOARDING_ONLY` set are *every* Telegram method the gateway can ever send.
  There is no generic `invoke`. A method that is not in those sets cannot be
  sent, and adding one changes this source and therefore the measured
  fingerprint (PCR0) below.
- **`audited-sender.mjs`** — enforces the allowlist at the real wire: every frame
  is checked before serialization, including internally enqueued ones. There are
  exactly two sites in the whole image that write to Telegram, and a census test
  asserts it.
- **`policy-verify.mjs`** — the open policy-authority verifier. Sessions acts only
  on *your* signed policy; you can confirm that by reading this file.
- **`brain.mjs`** — the detection logic: which non-whitelisted session to evict,
  when to decline a pending password reset, which security changes to surface. It
  holds no extra authority — it can only call the allowlisted verbs, and the
  gateway independently re-derives your signed policy and refuses anything the
  policy does not permit.

## The guarantee, stated honestly

This is a **bounded-surface** guarantee backed by readable source plus hardware
attestation. It is NOT a claim of cryptographic impossibility of misuse.

What you can verify yourself:
1. the complete account-capable wire surface (the files above),
2. the absence of any message, chat, file, or contact method,
3. that you can rebuild this exact source and get the same enclave fingerprint
   (PCR0) that the live attestation reports (see `BUILD.md`).

What you are trusting, disclosed and not hidden: AWS Nitro hardware attestation,
and the fact that Sessions holds the KMS key that unlocks your stored session at
rest. Your own enrolled key can revoke the enclave's access.

## Status — production, live, and reproducible

This is a **production** release: this exact image runs in a live AWS Nitro
enclave guarding real Telegram accounts right now. It is not a development,
staging, or testnet build. A genuine enclave running this image attests the
measurement below, and the build is **umask-independent**: the Dockerfile
canonicalizes every COPYed file's mode and mtime, so a `--no-cache` build on any
host (any umask, any OS via the pinned LF checkout) reproduces the identical PCR0
you see here. The release is recorded in this repository's public git history:
the commit (and tag) in `RELEASE.json` are the immutable, timestamped public
record of exactly this source.

```
PCR0_G = b79e96f77a653c28bda672fc63d05578cbf1ff7d9c21e57056b8ae7b0cb5c80536ebf794f774fbbf0d5fff50e60b0092
```

Verify it yourself, three independent ways:

1. **The capability file.** `sha256sum tg-chokepoint.mjs` prints
   `3a09bb77e4b7a2c9ddc47a5ded548186894cf0680fc2dfd933228998646d3598` (also in
   `RELEASE.json` `files[]`). Note: `RELEASE.json`'s `allowlist_sha256`
   (`42dbe24…`) is a *different, documented* value, the attestation-binding digest
   computed over the `// FILE tg-chokepoint.mjs\n` + bytes preimage (what the live
   attestation and the how-it-works page check). Both numbers are published, so
   whichever you compute matches a documented one.
2. **The live attestation.** Published at
   `https://sessions.fyi/attestation/gateway.json` and verified in your browser at
   `https://sessions.fyi/how-it-works` (or with any COSE/Nitro verifier chaining to
   AWS Nitro Root G1).
3. **The build.** Rebuild this repo (`BUILD.md`) and confirm the PCR0 matches the
   value above. The three host-staged binaries are pinned by sha256 in
   `RELEASE.json` `binaries[]`; confirm them with `sha256sum` before building.

## License

MIT. See `package.json`.
