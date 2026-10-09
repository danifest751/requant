# Deploying and upgrading nodes

Nodes run as a confined systemd service (`requantd.service`, user `requant`, binary `/opt/requant/requantd`,
data `/var/lib/requant`, P2P port 19333 open, JSON-RPC on 127.0.0.1:19334 only).

## Build

A static binary runs on any x86-64 Linux:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl -p requant-node -p requant-wallet
```

## Install or upgrade a node

```sh
scp target/x86_64-unknown-linux-musl/release/requantd root@HOST:/tmp/requantd
scp deploy/install-node.sh root@HOST:/tmp/
ssh root@HOST 'bash /tmp/install-node.sh 2 SEED_IP_1 SEED_IP_2'    # threads, peers to keep connected
```

The script creates the user and directories, installs the binary, writes the unit (memory capped at
1.5 GiB, `Nice=10`, read-only system), opens 19333/tcp in ufw if ufw is active, and restarts the service.
Blocks in `/var/lib/requant` are kept; on start the node replays them without re-verifying the work.

Check a node: `journalctl -u requantd -f`, `curl -s -X POST 127.0.0.1:19334 -d '{"method":"getinfo","params":[]}'`.
A node with the explorer also answers `GET /health` (JSON; HTTP 503 when it has no peers, no block for
20 minutes, or is still syncing), for an uptime monitor.

With `AUTO_UPDATE=1` the node runs with `--auto-update` and owns `/opt/requant`, so it can replace its
binary with a newer signed release (see `TESTNET.md`, Updates).

## Publish a release (maintainers)

```sh
python scripts/release.py 0.7.1 --linux requantd --windows requantd.exe --key ~/key/requant-release.key --publish
curl -s -X POST 127.0.0.1:19334 -d "{\"method\":\"submitrelease\",\"params\":[$(python -c 'import json;print(json.dumps(open("release-0.7.1.txt").read()))'), \"$(cat release-0.7.1.sig)\"]}"
```

The script writes the manifest (binary hashes and download URLs), signs it with the release key and
creates the GitHub release. `submitrelease` on any node announces it; peers spread it within seconds and
`--auto-update` nodes install it over the next 30 minutes. Keep the release key offline: whoever holds
it can update every `--auto-update` node.

## Compatibility

- **Protocol** (`crates/node/src/msg.rs`): nodes refuse peers below `MIN_PROTOCOL`. `Hello` ignores fields it
  does not know, so new fields can be added without a break; raising `MIN_PROTOCOL` needs all nodes upgraded
  together.
- **Consensus** (`CHAIN.md`): a rule change on the test network is a reset: new genesis time, wipe
  `/var/lib/requant/test`, upgrade every node. On a main network it would need activation at a height.

## Miner

`requant-miner.service` is a template for a GPU miner next to a node.

## Windows miner package

`deploy/windows/` holds the scripts of the Windows test-network package: `config.bat` (payee, seeds,
GPU), `start-all.bat`, `start-node.bat`, `start-miner.bat`, `balance.bat`, `selftest.bat` and a Russian
`README.txt`. The package adds `requantd.exe` and `requant-wallet.exe` (`cargo build --release`, only system
DLLs) and `cppminer.exe` from the CPPminer `feat/tnet-backend` branch built with
`build.ps1 -Backend Cuda -EnableCublas -CudaArch "75;86;89;120-virtual"`, with `cudart64_12.dll`,
`cublas64_12.dll` and `cublasLt64_12.dll` from CUDA 12.9.
