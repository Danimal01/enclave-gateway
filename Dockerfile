# Reproducible enclave image for the Sessions GATEWAY (spec 6.1, 6.5).
#
# This is the SMALL, published artifact. Building it twice yields an identical
# PCR0_G; a stranger who rebuilds the public mirror tag must get the same value
# the live attestation reports, or Claim A visibly fails in public. The brain is
# NOT in this image by construction (no TelegramClient, no connect, no KMS
# Decrypt grant, no raw stream live here).
#
# Base is DIGEST-pinned; every COPYed file is committed in THIS directory; mtimes
# are normalized. Arch: aarch64 (AWS Graviton). Build on the Nitro host:
#   sudo env DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=1577836800 docker build --no-cache -t sessions-gateway:repro .
#   sudo env TMPDIR=~/btmp nitro-cli build-enclave --docker-uri sessions-gateway:repro --output-file gateway.eif
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:df9ca26898d7c01be79e7c84bd008d5c8c867ace2c736421d150179f0aa87c33 AS builder
RUN dnf install -y nodejs npm python3 make gcc gcc-c++ && dnf clean all
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
 && find node_modules -type d -name obj.target -prune -exec rm -rf {} + 2>/dev/null; \
    find node_modules -type f \( -name '*.o' -o -name 'Makefile' -o -name 'config.gypi' -o -name '*.mk' \) -delete 2>/dev/null; true

FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:df9ca26898d7c01be79e7c84bd008d5c8c867ace2c736421d150179f0aa87c33
RUN dnf install -y nodejs socat iproute ca-certificates findutils && dnf clean all
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
# The published gateway source. Each file is rendered verbatim on the capability
# page at the exact tag this image was built from (spec 6.5, 6.6).
COPY gateway.mjs ./
COPY gateway-main.mjs ./
COPY connection.mjs ./
COPY pg-shim.mjs ./
COPY onboarding.mjs ./
COPY onboarding-grant.mjs ./
COPY onboarding-channel.mjs ./
COPY mtproto-client.mjs ./
COPY tg-chokepoint.mjs ./
COPY audited-sender.mjs ./
COPY policy-verify.mjs ./
COPY state-authority.mjs ./
COPY state-authority-dynamo.mjs ./
COPY brain-protocol.mjs ./
COPY brain-admission.mjs ./
COPY kms-envelope-v3.mjs ./
# Pinned roots baked into the measured image: the Nitro attestation root, the
# Supabase CA, and the patched kmstool (genkey + encryption-context, spec 5.6).
# NOTE: kmstool_enclave_cli here MUST be the PATCHED build (supports
# --encryption-context, exposes `genkey`). Build it on the host from
# aws/aws-nitro-enclaves-sdk-c per the runbook before staging; the stock binary
# fails closed in kms-envelope-v3.mjs (no contextless path).
COPY supabase-ca.pem ./
COPY kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
COPY libnsm.so /usr/lib64/libnsm.so
COPY gvforwarder /usr/local/bin/gvforwarder
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/bin/kmstool_enclave_cli /usr/local/bin/gvforwarder /entrypoint.sh
# Determinism: drop install-timestamped state, pin every mtime to a fixed epoch.
RUN rm -rf /var/lib/rpm /var/lib/dnf /var/cache /var/log /var/tmp/* /root/.npm /tmp/* 2>/dev/null; mkdir -p /tmp; : > /etc/machine-id 2>/dev/null || true; \
    find / -xdev -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -print0 | xargs -0 touch -h -d @1577836800; true
CMD ["/entrypoint.sh"]
