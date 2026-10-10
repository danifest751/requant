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
| Node and wallet | `requantd`, `requant-wallet` for Linux and Windows: [releases](https://github.com/requant-network/requant/releases/latest) |
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

**RPC.** JSON-RPC 2.0 (`"jsonrpc": "2.0"`, an `id`, batches of up to 100, notifications without an `id`,
standard error codes); requests without `"jsonrpc"` are answered in the older `{"result", "error"}` form,
which miners and older tools use. Parameters are positional. Methods: `getinfo`, `getnetworkinfo`,
`getpeerinfo`, `addpeer`, `getblock` and `getblockheader` (a height or an id), `getblockhash`,
`getchaintips`, `gettx`, `decodetx`, `sendtx`, `getrawmempool [verbose]`, `getmempoolinfo`,
`estimatefee [blocks]` (atoms per byte to get in within that many blocks of the pool's queue),
`utxos`, `getbalance`, `history` (by key hash), `validateaddress`, `getwork payee [longpollid]` (with the
`longpollid` of the last work it waits up to 60 s for the next block), `submitwork`, `auditsupply`,
`getevents`, `getrelease`, `submitrelease`, `stop` (from localhost only). With `--rpc-cookie` the node
writes a random token to `<datadir>/test/.cookie` at start and requires it (`Authorization: Bearer`);
the wallet takes the file with `--rpc-cookie FILE`. `--rpc-token-file` sets a fixed token.

```sh
curl -s 127.0.0.1:19334 -d '{"jsonrpc":"2.0","id":1,"method":"estimatefee","params":[3]}'
curl -s 127.0.0.1:19334 -d '[{"jsonrpc":"2.0","id":1,"method":"getblockhash","params":[0]},
                              {"jsonrpc":"2.0","id":2,"method":"getmempoolinfo"}]'
```

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

The wallet talks to a node's RPC (`--rpc HOST:PORT`, default `127.0.0.1:19334`), or without a node of
one's own to a node's public API: `--api http://193.187.93.29:19380` (see below). The test network is the
default (`--network regtest` for local tests).

A wallet is one file with many addresses, all restored from one 24-word backup phrase (BIP 39; keys by
SLIP-0010 for ed25519 at `m/44'/1'/0'/chain'/index'`). The phrase is encrypted in the file under a
passphrase (Argon2id, XChaCha20-Poly1305); the addresses are not, so looking needs no passphrase and
spending does.

```sh
requant-wallet create my.wallet               # asks a passphrase; shows the backup phrase once and the address
requant-wallet address my.wallet              # the current receive address and its key hash (for --payee)
requant-wallet newaddress my.wallet           # a fresh address (one per payer keeps payments apart)
requant-wallet addresses my.wallet            # the addresses handed out, with their coins
requant-wallet balance my.wallet              # the whole wallet; an address or a key file works too
requant-wallet history my.wallet 20           # moves between the wallet's own addresses net out to the fee
requant-wallet coins my.wallet                # unspent outputs
requant-wallet tx <txid>
requant-wallet send my.wallet <address> 1.5   # shows amount, change and fee, asks before sending
requant-wallet send my.wallet <addr1> 1 <addr2> 0.25   # several recipients in one transaction
requant-wallet send my.wallet <address> all   # everything spendable, minus the fee
requant-wallet consolidate my.wallet          # merge many small coins (e.g. pool payouts) into one
requant-wallet phrase my.wallet               # show the backup phrase again
requant-wallet encrypt my.wallet              # change the passphrase
requant-wallet restore new.wallet             # from the phrase; asks a node which addresses were used
```

Change goes to a new change address each time. A restore scans each chain until 20 unused addresses in a
row; `--no-scan` restores without a node (the other addresses come back with a later restore).

**Offline signing** keeps the phrase on a machine without network. The online machine needs only a
watch-only copy:

```sh
requant-wallet watchonly my.wallet watch.wallet                      # on the offline machine; copy watch.wallet over
requant-wallet prepare watch.wallet <address> 1.5 --out pay.json     # online: no passphrase, nothing secret
requant-wallet sign my.wallet pay.json --out pay.signed              # offline: shows and checks the payment
requant-wallet broadcast pay.signed                                  # online
```

`pay.json` carries the transactions that created the coins it spends: signatures do not cover the coins'
values, so the signer reads them from those transactions (checked by txid) rather than trusting the
online machine about the fee, and refuses a payment whose coins or change are not its own.

**Single keys** (the older format) still work: `keygen my.key`, `encrypt my.key`, `address my.key`, and
`balance`, `history`, `coins`, `send`, `consolidate` with a key file in place of the wallet.

The fee follows the transaction's size, at least 1000 atoms: `--fee-rate` takes atoms per byte or `fast`,
`normal` (the default) or `slow`, the node's `estimatefee` for the next 1, 3 or 10 blocks (5 atoms per byte
with a node that has no estimate). A
transaction takes at most 600 inputs; with more coins, `send ... all` and `consolidate` handle the first
600, so run them again. `--yes` skips the question (scripts).

## Public API

A node with an explorer (`--explorer ADDR`) also answers JSON under `/api/` on that port, open to any
origin and rate-limited per client address (a burst of 120 requests, then 20 a second; 429 beyond):

| Request | Answer |
|---|---|
| `GET /api/info` | network, height, tip, version, pool size, fee rate for 3 blocks |
| `GET /api/fee?blocks=N` | the fee rate (atoms per byte) to get in within N blocks |
| `GET /api/block/<height or id>` | header fields, confirmations, txids |
| `GET /api/tx/<txid>` | inputs (with the values and owners they spend), outputs, fee, height |
| `GET /api/address/<address or key hash>/balance` | confirmed, unconfirmed, immature atoms |
| `GET /api/address/<...>/utxos`, `/history?limit=N` | spendable coins; transactions, newest first |
| `GET /api/utxos?owners=K1,K2,...`, `/api/history?owners=...&limit=N` | up to 200 owners at once, entries name their `owner` |
| `POST /api/tx` (body: hex, or `{"hex": ...}`) | relays a signed transaction: `{"txid": ...}` |

```sh
curl -s http://193.187.93.29:19380/api/info
curl -s http://193.187.93.29:19380/api/address/trq1q8pqnx3uqer6jcxszen4tg3hylh5q645ae23yvra62a2nu98slqaqvvyume/balance
```

The answers are that node's view: a wallet using it trusts it for balances and history (it cannot spend:
keys never leave the wallet), and the node learns which addresses are asked about.

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
Spending conditions and time locks (CHAIN.md §4.1) are active from height 1400; nodes older than 0.15.0
reject blocks that use them. RPC `conditionaddress` gives the address of a 2-of-2 or HTLC; there is no
swap or channel software yet ([SWAPS.md](SWAPS.md)).
Upgrading nodes: `deploy/README.md`.
