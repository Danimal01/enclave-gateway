#!/bin/bash
# GATEWAY enclave init (gateway-brain-architecture.md 4.2, spec 6.5).
#
# FIRST it emits a boot attestation to the parent (vsock :8002) — the Claim A
# proof that the published image (PCR0_G) is the code genuinely running in a real
# Nitro enclave; the parent publishes it as the public static artifact the open
# proof page verifies in the visitor's browser. THEN it brings up the TAP network
# via the parent gvproxy and runs the gateway main in PRODUCTION mode. If a
# provider serves a session (real deployment) the gateway adopts and guards; if
# none is present (attestation-only deployment) gateway-main parks in attested
# standby and re-attests on a cadence — it never crash-loops.
#
# The gateway is the SESSION-HOLDER. It has the Telegram route (api.telegram.org)
# and the KMS/State-Authority/Supabase routes. The BRAIN runs in a SEPARATE
# enclave on a SEPARATE parent with NO Telegram route (4.1, 5.5) and has its own
# entrypoint; the two never share this image.
set -uo pipefail
mkdir -p /dev/net; [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200; chmod 600 /dev/net/tun
ip link set lo up

# Claim A: emit the boot attestation FIRST (no network needed; NSM is local).
( /attest 2>/tmp/attest.err | socat -t 8 - VSOCK-CONNECT:3:8002 ) || true
cat /tmp/attest.err >&2 || true

# TAP path to Telegram via the parent gvproxy. Best-effort: a guarding deployment
# needs it; an attestation-only deployment does not, so failures here must not
# stop the enclave (gateway-main parks in standby below).
ip tuntap add dev tap0 mode tap 2>/dev/null || true
ip link set tap0 address 5a:94:ef:e4:0c:ee 2>/dev/null || true
ip addr add 192.168.127.2/24 dev tap0 2>/dev/null || true
ip link set tap0 up 2>/dev/null || true
ip route add default via 192.168.127.1 2>/dev/null || true
rm -f /etc/resolv.conf; echo "nameserver 192.168.127.1" > /etc/resolv.conf
/usr/local/bin/gvforwarder -url vsock://3:1024/connect -preexisting 2>/dev/null &

# Enclave-born onboarding: the parent relays each browser session to this enclave's
# vsock :8005; bridge it to the gateway's local onboarding server (127.0.0.1:9005).
socat VSOCK-LISTEN:8005,fork,reuseaddr TCP-CONNECT:127.0.0.1:9005 2>/dev/null &

cd /app
# gateway-main.mjs wires the published modules to the real enclave effects
# (kmstool transport, GramJS connection, vsock relays). It is the EIF entrypoint.
export SESSIONS_GATEWAY_MAIN=1
exec node gateway-main.mjs
