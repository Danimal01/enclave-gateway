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

> **Current live release: `v1.0.11`, enclave fingerprint PCR0 `8bd012fe223fb1725f796d30636a0829732d6076d4301d38e6f329f7f449c5e5bc6ca8c851ea8f8ae18cadd34f3f8598`** (`v1.0.11` adds tdata-replay session-clone detection and revocation; capability-neutral, so the allowlist is byte-identical to `v1.0.10`).
> **`RELEASE.json` is the single authoritative, machine-readable record of this build.** Only the fingerprint shown here is live. If you encounter any other PCR0 — in an older commit message, an old tag, or a cached page — it is a *superseded* release, not the current one. When in doubt, read `RELEASE.json` and the raw source files directly, not rendered or cached views.

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

**On `auth.exportAuthorization` / `importAuthorization`** (the two most powerful-looking
verbs in the armed allowlist): they are present only because Telegram requires them to
migrate a session between data centers. They are called solely by the gateway's own
internal migration path; no user, relay, or brain input maps to them. The exported
authorization is consumed by a paired `importAuthorization` on the new DC connection
inside the same enclave and never leaves enclave memory, so they cannot be used to hand
your session to another party.

**On `updates.getDifference`** (added in `v1.0.6` for real-time detection): the new-login
alert (`UpdateNewAuthorization`) carries no `pts`/`qts` and is push-only, so to deliver it in
real time the client keeps Telegram's update stream healthy and re-syncs it after a gap with
`updates.getDifference`. Its reply *can* include message updates (`newMessages` /
`newEncryptedMessages`), but the reader is **single-branch**: it processes only `otherUpdates`
(login and session events) and discards the message arrays unread. There is no `messages.*`
method on the allowlist; this is the only call whose reply could surface message data, and it
is read *past*, not *into*.

## The guarantee, stated honestly

This is a **bounded-surface** guarantee backed by readable source plus hardware
attestation. It is NOT a claim of cryptographic impossibility of misuse.

What you can verify yourself:
1. the complete account-capable wire surface (the files above),
2. the absence of any message, chat, file, or contact method,
3. that you can rebuild this exact source and get the same enclave fingerprint
   (PCR0) that the live attestation reports (see `BUILD.md`).

What you are trusting, disclosed and not hidden:
- **AWS is in the trusted base** — the "this exact code is running" proof rests on
  AWS Nitro hardware attestation chaining to AWS's Nitro Enclaves Root G1.
- **The at-rest session key.** Your Telegram session is sealed with AWS KMS under a
  key policy gated on the enclave's measurement (`kms:RecipientAttestation:ImageSha384`,
  pinned to the PCR0 below), so in normal operation only an enclave running this exact
  published image can decrypt it, and the host machine cannot. We operate that key, so
  this is **not** a claim that it is impossible for us to ever reach your session — we
  control the key policy. What you get is a bounded, attested, **revocable** surface:
  disconnecting the guard logs it out of your account and ends its access.

## Status — production, live, and reproducible

This is a **production** release: this exact image runs in a live AWS Nitro
enclave guarding real Telegram accounts right now. It is not a development,
staging, or testnet build. A genuine enclave running this image attests the
measurement below, and the build is **umask-independent**: the Dockerfile
canonicalizes every COPYed file's mode and mtime, and pins the OS toolchain to a
frozen Amazon Linux 2023 snapshot (so the compiled native modules don't drift),
so a `--no-cache` build on any host (any umask, any OS via the pinned LF checkout)
reproduces the identical PCR0 you see here. `RELEASE.json` is the authoritative record of the current build; the
commit and tag it names simply timestamp exactly this source in the public history.

```
PCR0_G = 8bd012fe223fb1725f796d30636a0829732d6076d4301d38e6f329f7f449c5e5bc6ca8c851ea8f8ae18cadd34f3f8598
```

Verify it yourself:

1. **Easiest — live, in your browser, no tools (~10s).** Open
   `https://sessions.fyi/how-it-works`. It fetches the live AWS-signed attestation,
   decodes the COSE document, validates the certificate chain to the **AWS Nitro
   Enclaves Root G1**, extracts PCR0, and checks it equals the published value — all
   client-side, no server of ours involved. It shows green only if every link holds.
   (The raw document is at `https://jmxqeylkftqmkmvoorhi.supabase.co/storage/v1/object/public/attestation/gateway.json` for your own
   COSE/Nitro verifier chaining to AWS Nitro Root G1.)
2. **Check the capability file.** `sha256sum tg-chokepoint.mjs` →
   `18a17758a60fa1f9ec31e63ac1b9beaed7a87bd4601b0cc2cb6de21c31923f66` (= `RELEASE.json`
   `files[].sha256`).
   > **Two hashes on purpose — this is NOT a mismatch.** `files[].sha256` is the plain
   > `sha256sum`. The top-level `allowlist_sha256` (`3e7ebadb…`) is a *different,
   > intentional* value: the attestation-binding digest over the preimage
   > `// FILE tg-chokepoint.mjs\n` + the file bytes. They are **not supposed to be equal** —
   > each is simply what a different verifier (a shell vs the attestation) computes over
   > the same file.
3. **Rebuild it.** Follow `BUILD.md`; the PCR0 you get must equal the value above
   (`8bd012fe…f3f8598`) the same value `RELEASE.json` and the live attestation report.

## License

MIT. See `package.json`.
