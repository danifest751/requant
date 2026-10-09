#!/bin/bash
# Install or upgrade a Requant node as a confined systemd service (run as root on the target host).
# usage: [EXPLORER_PORT=19380] [POOL_PORT=19340 POOL_ARGS="..."] [AUTO_UPDATE=1] install-node.sh THREADS [PEER_IP ...]
#        with the new binary uploaded to /tmp/requantd first
# Data in /var/lib/requant survives upgrades; the service restarts on the new binary.
set -e
THREADS=$1; shift
CONNECT=""
for p in "$@"; do CONNECT="$CONNECT --connect $p:19333"; done
# optional: EXPLORER_PORT=19380 serves the read-only block explorer on that public port
EXTRA=""
[ -n "$EXPLORER_PORT" ] && EXTRA=" --explorer 0.0.0.0:$EXPLORER_PORT"
# optional: AUTO_UPDATE=1 installs newer releases signed with the Requant release key by itself (the node
# then owns /opt/requant to replace its binary; see crates/node/src/release.rs)
[ "$AUTO_UPDATE" = 1 ] && EXTRA="$EXTRA --auto-update"
# optional: POOL_PORT=19340 runs the mining pool there (pool wallet key created once in /var/lib/requant)
# with POOL_ARGS for --pool-fee, --pool-share-bits, --pool-min-payout
if [ -n "$POOL_PORT" ]; then
  if [ ! -f /var/lib/requant/pool.key ]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /var/lib/requant/pool.key
  fi
  chown requant:requant /var/lib/requant/pool.key 2>/dev/null || true
  chmod 600 /var/lib/requant/pool.key
  EXTRA="$EXTRA --pool 0.0.0.0:$POOL_PORT --pool-key /var/lib/requant/pool.key $POOL_ARGS"
fi

id requant >/dev/null 2>&1 || useradd --system --home-dir /var/lib/requant --shell /usr/sbin/nologin requant
install -d -o requant -g requant -m 750 /var/lib/requant
if [ "$AUTO_UPDATE" = 1 ]; then
  install -d -o requant -g requant -m 755 /opt/requant
  install -o requant -g requant -m 755 /tmp/requantd /opt/requant/requantd
  RW="/var/lib/requant /opt/requant"
else
  install -d -m 755 /opt/requant
  install -m 755 /tmp/requantd /opt/requant/requantd
  RW="/var/lib/requant"
fi
rm -f /tmp/requantd

cat > /etc/systemd/system/requantd.service <<EOF
[Unit]
Description=Requant test network node (requantd)
After=network-online.target
Wants=network-online.target

[Service]
User=requant
Group=requant
ExecStart=/opt/requant/requantd --network test --datadir /var/lib/requant --listen 0.0.0.0:19333 --rpc 127.0.0.1:19334 --threads $THREADS$CONNECT$EXTRA
Restart=always
RestartSec=10
Nice=10
MemoryMax=1536M
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$RW

[Install]
WantedBy=multi-user.target
EOF

if ufw status | grep -q "Status: active"; then
  ufw allow 19333/tcp comment 'requant testnet p2p' >/dev/null
  [ -n "$EXPLORER_PORT" ] && ufw allow $EXPLORER_PORT/tcp comment 'requant explorer' >/dev/null
  [ -n "$POOL_PORT" ] && ufw allow $POOL_PORT/tcp comment 'requant pool' >/dev/null
fi
systemctl daemon-reload
systemctl enable requantd >/dev/null 2>&1
systemctl restart requantd
sleep 2
systemctl is-active requantd
ss -tlnp | grep -E ":1933[34]" || true
