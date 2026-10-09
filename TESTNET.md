# Requant test network

Running since **2026-10-09 17:34 UTC** (genesis time of the `test` network). Coins on it have no value; the
chain may be reset when the rules change (a reset changes the genesis time in `crates/consensus/src/params.rs`).

| | |
|---|---|
| Work function | TNet v1 (`SPEC.md`): `n = 8192, B = 65536, L = 8, w = 256` |
| Block time | 60 s, ASERT (half-life 2 h), starting target `2^229` |
| P2P port | 19333 |
| Seed nodes | `193.187.93.29:19333`, `193.32.188.248:19333`, `185.174.40.96:19333` |
| Explorer | http://193.187.93.29:19380/ |
| Mining pool | `193.187.93.29:19340` (1% fee, PPLNS, payouts from 1 RQT; stats at http://193.187.93.29:19380/pool) |
| Development fund | `trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems` (6%, `CHAIN.md` §8) |

## Run a node

```sh
cargo build --release
target/release/requantd --network test --datadir ~/requant-test \
  --connect 193.187.93.29:19333 --connect 193.32.188.248:19333 --connect 185.174.40.96:19333
curl -s -X POST 127.0.0.1:19334 -d '{"method":"getinfo","params":[]}'
```

The node needs about 1 GiB of memory (two epochs of TNet weights) and verifies a block in 10–80 ms on
a laptop or VPS CPU. JSON-RPC listens on `127.0.0.1:19334` only.

## Wallet

```sh
target/release/requant-wallet keygen my.key --network test        # asks a passphrase; prints address and key hash
target/release/requant-wallet encrypt old.key --network test       # encrypt an older unencrypted key file
target/release/requant-wallet balance <address> --network test
target/release/requant-wallet history <address> --network test
target/release/requant-wallet tx <txid> --network test
target/release/requant-wallet send my.key <address> 1.5 --network test
```

## Mine in the pool (no node needed)

```sh
cppminer --algo tnet --rpc 193.187.93.29:19340 --payee <key hash from requant-wallet>
```

Shares are credited PPLNS, rewards after 100 confirmations, paid automatically from 1 RQT.

## Mine solo (NVIDIA GPU)

Build CPPminer from the `feat/tnet-backend` branch of
[danifest751/CPPminer](https://github.com/danifest751/CPPminer/tree/feat/tnet-backend) with CUDA and cuBLAS
(`docs/tnet.md` there), run a node as above, then:

```sh
cppminer --algo tnet --rpc 127.0.0.1:19334 --payee <key hash from requant-wallet>
```

A CMP 50HX (Turing) does about 3.5 M tickets/s; an RTX 3090 about 6.3 M.

## Known limits of this version

Block-first sync (no headers-first yet), address book in memory and `peers.txt` only; see `ROADMAP.md`.
Upgrading nodes: `deploy/README.md`.
