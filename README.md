# Requant

A proof-of-work coin (ticker **RQT**, provisional) whose work is the forward pass of a deep int8
network: the arithmetic that GPU tensor cores and AI inference accelerators are built for. The name
is the step that makes the work hard to shortcut: exact integer **requant**ization between layers.
The work function is called **TNet**.

**Status: pre-alpha; a public test network is running** ([`TESTNET.md`](TESTNET.md), explorer
http://193.187.93.29:19380/). The work
function (**TNet v1**) is frozen with test vectors and reference implementations; a node, a wallet and a GPU
miner exist; there is no main network and the test coins have no value. See [`ROADMAP.md`](ROADMAP.md).
Nothing here is a security or investment claim.

## Try the test network

1. **Wallet.** Download `requant-wallet` for Windows or Linux from the
   [latest release](https://github.com/danifest751/requant/releases/latest) and make a key:
   `requant-wallet keygen my.key` prints your address (`trq1...`) and key hash.
2. **Test coins.** The **faucet** at http://193.187.93.29:19380/faucet sends 10 RQT to your address, once a
   day per address.
3. **Mine.** The GPU miner is **CPPminer** (NVIDIA, RTX 20xx / Turing or newer): download
   `cppminer-win64-cuda.zip` or `cppminer-linux-x64-cuda.tar.gz` from the
   [CPPminer releases](https://github.com/danifest751/CPPminer/releases/latest), check the GPU with
   `cppminer --algo tnet --selftest`, and mine in the pool:

   ```sh
   cppminer --algo tnet --rpc 193.187.93.29:19340 --payee <your key hash> --worker rig1
   ```

   The pool pays PPLNS (1% fee) automatically from 1 RQT, 100 blocks after a block is found; your
   devices and payouts are on the [pool page](http://193.187.93.29:19380/pool).
4. **Look around.** Blocks, transactions and any address on the
   [explorer](http://193.187.93.29:19380/); peers and pending transactions on the
   [network page](http://193.187.93.29:19380/network).
5. **Run a node** (optional; the wallet sends payments through one): `requantd` from the same release,
   `requantd --network test --connect 193.187.93.29:19333`, then `requant-wallet balance my.key` and
   `requant-wallet send my.key <address> 1.5`. With `--auto-update` it installs new signed releases by
   itself. Everything else: [`TESTNET.md`](TESTNET.md).

## How the work function works

Every epoch, eight 8192 x 8192 int8 weight matrices are derived from the chain. For each nonce, an
input of 65,536 int8 rows is derived from the block header and pushed through the eight layers, with
an exact integer requantization between them. Every 256-byte piece of an output row is a lottery
ticket hashed with SHA-256. A block carries the winning ticket's `(nonce, row, piece index, piece)`,
272 bytes. A node checks the hash, then recomputes that one row: about 11 ms on a laptop CPU.

- **Miners** run int8 matrix multiplication on tensor cores (88% of an attempt on a Turing GPU).
  Computing fewer rows does not make a ticket cheaper.
- **Verification** needs no proof system and no trusted setup, only SHA-256 and integer
  arithmetic, plus 512 MiB of epoch weights.
- **Shortcuts** were tested in the research: approximate arithmetic produces no valid tickets, and
  table-based precomputation is bounded to be slower. See [`RATIONALE.md`](RATIONALE.md).

Full definition: [`SPEC.md`](SPEC.md). Chain rules (draft): [`CHAIN.md`](CHAIN.md): one-minute blocks, a
smooth emission of 2^24 RQT with a small tail, no premine, and a 6% development fund for the first four
years that ends by itself.

## Quick start

Rust (stable; the `tnet` crate has no dependencies, the chain uses `ed25519-dalek` and `serde_json`) and
Python 3.10+ with `pytest`:

```sh
python scripts/check.py                      # pytest, rustfmt, clippy -D warnings, cargo test
cargo test --release -- --ignored            # frozen-parameter vectors (512 MiB, ~15 s)
cargo run --release --bin tnet -- bench      # CPU verification time at the v1 parameters
```

GPU miner: CPPminer `--algo tnet` (see [Try the test network](#try-the-test-network)); it mines in the pool
or through a node's `getwork`/`submitwork`. GPU benchmark and parity tool: [`miner/cuda/`](miner/cuda/README.md).

A local regtest node that mines on the CPU (instant blocks, small work function):

```sh
cargo run --release --bin requantd -- --network regtest --mine <32-byte key hash, hex>
curl -s -X POST 127.0.0.1:19445 -d '{"method":"getinfo","params":[]}'
```

Wallet (regtest: add `--network regtest`): `requant-wallet keygen my.key`, then `--mine <key hash>` on the node,
`requant-wallet balance my.key`, `requant-wallet send my.key <address> 1.5`; see `TESTNET.md` for the rest.

## Layout

```
SPEC.md          TNet v1 work function (normative)
crates/tnet/     Rust reference: derivations, verifier (Epoch), CLI (vectors, check, bench)
crates/consensus/ chain rules of CHAIN.md: transactions, blocks, difficulty, emission, chain state
crates/node/     requantd: storage, peer-to-peer sync and relay, mempool, JSON-RPC, regtest miner
crates/wallet/   requant-wallet: keys, bech32m addresses, balance, payments through a node
reference/       pure-Python reference written from SPEC.md
vectors/         frozen test vectors
miner/cuda/      GPU attempt benchmark, the starting point of the miner
tests/           Python tests (reference vs vectors vs Rust)
scripts/check.py local gate
```

## Background

Requant and TNet come out of the [Abacus](https://github.com/danifest751/Abacus) research lab, which tested
linear-algebra proofs of work (Freivalds-verified matrix products, NTT, int8 GEMM with proofs) and
recorded why most of them fail. TNet is its candidate T (ADR 0015/0016 there).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
