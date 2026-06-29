# Reproducible build

Building this gateway twice yields an identical PCR0 (the enclave measurement).
A stranger who rebuilds this source must get the same PCR0 the live attestation
reports, or the "this exact code is running" claim visibly fails in public.

## Pins

- Base image: `public.ecr.aws/amazonlinux/amazonlinux@sha256:df9ca26898d7c01be79e7c84bd008d5c8c867ace2c736421d150179f0aa87c33`
- OS packages: `dnf --releasever=2023.12.20260608` (a frozen Amazon Linux 2023 snapshot). The base image is digest-pinned, but `dnf install` otherwise resolves against AL's rolling "latest" repo, so the toolchain is pinned to this snapshot to keep the compiled native modules and `attest` binary (both measured into PCR0) byte-deterministic over time. Verified: this snapshot rebuilds to the published PCR0_G byte-for-byte.
- Node dependencies: `package-lock.json` (installed with `npm ci`)
- `SOURCE_DATE_EPOCH=1577836800`, arch `aarch64` (AWS Graviton)

## Host-staged binaries (built from pinned sources, not committed)

These three binaries are placed in the build context before building. They are
pinned by sha256 so a verifier can confirm them:

| File | sha256 | Source |
|---|---|---|
| `kmstool_enclave_cli` | `754d5b16d458ad9925578543db78bde92df4bc7306b84c8983961ab7c9d33e8e` | aws-nitro-enclaves-sdk-c v0.4.5 (commit cd61b61) with `patches/apply-kmstool-context-patch.py` applied, built via `containers/Dockerfile.al2 --target kmstool-enclave-cli` |
| `libnsm.so` | `b020f96e39162024bb5248408ce12d9997b049549782f0d65511dfbd3782b0e6` | same SDK build |
| `gvforwarder` | `0f85431ef3dbec8a4fa5bd1ed05dc418a4938e112e4879496056ab23163ecc7f` | gvisor-tap-vsock release, arm64 (aarch64) |

All three are pinned by sha256 (also in `RELEASE.json` `binaries[]`). After staging
them, confirm each: `sha256sum kmstool_enclave_cli libnsm.so gvforwarder` must match
the values above before you build.

`patches/apply-kmstool-context-patch.py` adds `--encryption-context` (JSON) to
the kmstool CLI, wiring it into the SDK's existing
`aws_kms_decrypt_blocking_with_context` and a mirrored
`aws_kms_generate_data_key_blocking_with_context`. The context binds each KMS
data key to a per-session `SessionsContextId`; a decrypt without that exact
context is denied by KMS. This was validated live against real KMS in an
attested enclave.

## Build

```
# stage the three binaries above into this directory, then:
sudo env DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=1577836800 \
  docker build --no-cache -t sessions-gateway:repro .
sudo env TMPDIR=~/btmp \
  nitro-cli build-enclave --docker-uri sessions-gateway:repro --output-file gateway.eif
nitro-cli describe-eif --eif-path gateway.eif   # -> PCR0
```

Build twice and confirm the PCR0 matches. The expected value is:

```
PCR0 = 64cc313eb9f4f699dd306c47e1ffc56dfcdf3fd256b727b752eac175a4d3b935e4fbf41f518110cd6f9fcc86bde76427
```

This is the same `pcr0_g` in `RELEASE.json` and the value the live AWS-signed
attestation reports.

**Don't want to rebuild?** You don't have to, in order to verify. Open
`https://sessions.fyi/how-it-works` — it fetches the live attestation, decodes the
COSE document, validates the certificate chain to **AWS Nitro Enclaves Root G1**,
extracts PCR0, and checks it equals the value above, all in your browser with no
tools and no server of ours involved.
