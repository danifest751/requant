#!/bin/bash
# Install or upgrade a Requant node as a confined systemd service (run as root on the target host).
# usage: install-node.sh THREADS [PEER_IP ...]     with the new binary uploaded to /tmp/requantd first
# Data in /var/lib/requant survives upgrades; the service restarts on the new binary.
set -e
THREADS=$1; shift
CONNECT=""
for p in "$@"; do CONNECT="$CONNECT --connect $p:19333"; done

id requant >/dev/null 2>&1 || useradd --system --home-dir /var/lib/requant --shell /usr/sbin/nologin requant
install -d -o requant -g requant -m 750 /var/lib/requant
install -d -m 755 /opt/requant
install -m 755 /tmp/requantd /opt/requant/requantd
rm -f /tmp/requantd

cat > /etc/systemd/system/requantd.service <<EOF
[Unit]
Description=Requant test network node (requantd)
After=network-online.target
Wants=network-online.target

[Service]
User=requant
Group=requant
ExecStart=/opt/requant/requantd --network test --datadir /var/lib/requant --listen 0.0.0.0:19333 --rpc 127.0.0.1:19334 --threads $THREADS$CONNECT
Restart=always
RestartSec=10
Nice=10
MemoryMax=1536M
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/requant

[Install]
WantedBy=multi-user.target
EOF

if ufw status | grep -q "Status: active"; then
  ufw allow 19333/tcp comment 'requant testnet p2p' >/dev/null
fi
systemctl daemon-reload
systemctl enable requantd >/dev/null 2>&1
systemctl restart requantd
sleep 2
systemctl is-active requantd
ss -tlnp | grep -E ":1933[34]" || true
