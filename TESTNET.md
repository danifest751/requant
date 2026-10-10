# Requant test network

Running since **2026-10-09 17:34 UTC** (genesis time of the `test` network). Coins on it have no value; the
chain may be reset when the rules change (a reset changes the genesis time in `crates/consensus/src/params.rs`).

| | |
|---|---|
| Work function | TNet v1 (`SPEC.md`): `n = 8192, B = 65536, L = 8, w = 256` |
| Block time | 60 s, ASERT (half-life 2 h), starting target `2^229 - 1` |
| P2P port | 19333 |
| Seed nodes | `193.187.93.29:19333`, `193.32.188.248:19333`, `185.174.40.96:19333` |
| Explorer | http://193.187.93.29:19380/ |
| Mining pool | `193.187.93.29:19340` (1% fee, PPLNS, payouts from 1 RQT; stats at http://193.187.93.29:19380/pool) |
| Faucet | http://193.187.93.29:19380/faucet (10 RQT a day per address); top it up at `trq1q8pqnx3uqer6jcxszen4tg3hylh5q645ae23yvra62a2nu98slqaqvvyume` |
| Node and wallet | `requantd`, `requant-wallet` for Linux and Windows: [releases](https://github.com/danifest751/requant/releases/latest) |
| GPU miner | CPPminer `--algo tnet`: [releases](https://github.com/danifest751/CPPminer/releases/latest) |
| Development fund | `trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems` (6%, `CHAIN.md` §8) |

## Run a node

With the downloaded binary (or `cargo build --release` and `target/release/requantd`):

```sh
requantd --network test --datadir ~/requant-test --auto-update \
  --connect 193.187.93.29:19333 --connect 193.32.188.248:19333 --connect 185.174.40.96:19333
curl -s -X POST 127.0.0.1:19334 -d '{"method":"getinfo","params":[]}'
```

The node keeps the TNet weights of the current epoch (512 MiB) in a file under its data directory and
reads them through the operating system's cache, so its own memory stays small (a few MB; the cache is
given back when other programs need it). A block is verified in about 0.1 s. JSON-RPC listens on
`127.0.0.1:19334` only.

**Updates.** Releases are signed with the Requant release key, built into the node. Nodes pass the newest
signed release to each other; `getinfo` shows `update_available` and the log says so. Started with
`--auto-update`, a node installs it by itself: at a random moment within 30 minutes it downloads its
platform's binary from the GitHub release, checks the signed SHA-256 and the version the binary reports,
replaces its executable and exits for its service (systemd, or the loop in `start-node.bat`) to start the
new one. It never installs a version older than its own. Without the flag nothing is downloaded.

## Test coins

The faucet at http://193.187.93.29:19380/faucet sends 10 RQT to a test-network address, once a day per
address. A node runs one with `--faucet-key FILE` (an unencrypted key; `--faucet-amount`, `--faucet-daily`).

## Wallet

The wallet talks to a node's RPC (`--rpc HOST:PORT`, default `127.0.0.1:19334`); the test network is the
default (`--network regtest` for local tests).

```sh
target/release/requant-wallet keygen my.key                # asks a passphrase; prints address and key hash
target/release/requant-wallet encrypt old.key              # encrypt an older key file, or change the passphrase
target/release/requant-wallet balance my.key               # an address works too, everywhere a key file is shown
target/release/requant-wallet history my.key 20
target/release/requant-wallet coins my.key                 # unspent outputs
target/release/requant-wallet tx <txid>
target/release/requant-wallet send my.key <address> 1.5    # shows amount and fee, asks before sending
target/release/requant-wallet send my.key <addr1> 1 <addr2> 0.25   # several recipients in one transaction
target/release/requant-wallet send my.key <address> all    # everything spendable, minus the fee
target/release/requant-wallet consolidate my.key           # merge many small coins (e.g. pool payouts) into one
```

The fee follows the transaction's size: `--fee-rate` atoms per byte (default 5, at least 1000 atoms). A
transaction takes at most 600 inputs; with more coins, `send ... all` and `consolidate` handle the first
600, so run them again. `--yes` skips the question (scripts).

## Get the miner

The GPU miner is **CPPminer** (`--algo tnet`, NVIDIA GPUs from Turing / RTX 20xx on), released at
[danifest751/CPPminer](https://github.com/danifest751/CPPminer/releases/latest): `cppminer-win64-cuda.zip` for Windows, `cppminer-linux-x64-cuda.tar.gz`
for Linux. Nothing else is needed besides a current NVIDIA driver; check the GPU with
`cppminer --algo tnet --selftest`. Source and build notes: `docs/tnet.md` in that repository.

## Mine in the pool (no node needed)

```sh
cppminer --algo tnet --rpc 193.187.93.29:19340 --payee <key hash from requant-wallet> --worker rig1
```

`--worker` names the device in the pool's statistics (several devices can share one address). Shares are
credited PPLNS, rewards after 100 confirmations, paid automatically from 1 RQT.

## Mine solo (NVIDIA GPU)

Run a node as above, then:

```sh
cppminer --algo tnet --rpc 127.0.0.1:19334 --payee <key hash from requant-wallet>
```

A CMP 50HX (Turing) does about 3.6 M tickets/s, an RTX 5070 about 5 M, an RTX 3090 about 6.3 M.

## Known limits of this version

Block-first sync (no headers-first yet), address book in memory and `peers.txt` only; see `ROADMAP.md`.
Upgrading nodes: `deploy/README.md`.
