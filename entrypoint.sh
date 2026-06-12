#!/bin/bash
# GATEWAY enclave init (gateway-brain-architecture.md 4.2). Brings up the TAP
# network via the parent gvproxy, then runs the gateway main in PRODUCTION mode.
# If node exits (crash / process.exit, including the self-fence in 5.5), this
# script exits -> the enclave terminates -> the systemd supervisor restarts it,
# which re-reads the State Authority and re-acquires the lease before serving.
#
# The gateway is the SESSION-HOLDER. It has the Telegram route (api.telegram.org)
# and the KMS/State-Authority/Supabase routes. The BRAIN runs in a SEPARATE
# enclave on a SEPARATE parent with NO Telegram route (4.1, 5.5) and has its own
# entrypoint; the two never share this image.
set -uo pipefail
mkdir -p /dev/net; [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200; chmod 600 /dev/net/tun
ip link set lo up
ip tuntap add dev tap0 mode tap
ip link set tap0 address 5a:94:ef:e4:0c:ee
ip addr add 192.168.127.2/24 dev tap0
ip link set tap0 up
ip route add default via 192.168.127.1
rm -f /etc/resolv.conf; echo "nameserver 192.168.127.1" > /etc/resolv.conf
/usr/local/bin/gvforwarder -url vsock://3:1024/connect -preexisting &
# Fail closed: wait (bounded) until the TAP path can actually reach Telegram.
ready=0
for i in $(seq 1 25); do
  if curl -s --max-time 2 -o /dev/null https://api.telegram.org; then ready=1; break; fi
  sleep 1
done
echo "net-ready=$ready"
cd /app
# gateway-main.mjs wires the published modules to the real enclave effects
# (kmstool transport, GramJS connection, vsock relays). It is the EIF entrypoint.
exec node gateway-main.mjs
