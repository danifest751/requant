# Roadmap

The work function is frozen (`SPEC.md`). Everything below is open. Items marked **owner** are
decisions for the project owner, not engineering defaults.

## 0. Before any code depends on it

- [x] Second architecture: RTX 3090 (Ampere), 159.5 ns per ticket, 86.7% tensor share, parity holds
      (Abacus `tnet-ampere-v1`). Next: Ada / Hopper / Blackwell.
- [ ] External review of `SPEC.md` and `crates/tnet`.
- [x] Coin name and repository: Requant (`danifest751/requant`); ticker RQT, provisional until checked
      against exchanges and trademarks (**owner**).

## 1. Chain parameters

Draft rules: `CHAIN.md` (60 s blocks, ASERT, daily epochs, smooth emission with a tail, UTXO + ed25519);
consensus core in `crates/consensus` (encoding, transactions, blocks, difficulty, emission, in-memory chain
with reorganisation, regtest miner). Funding: a 6% development fund for the first 2^21 blocks (`CHAIN.md` §8). Open below: genesis of the
test network.


- [ ] Block time and retarget rule; target encoding (compact or full 256-bit) (**owner** for the
      block time).
- [ ] Epoch length `E` and look-back `K` (`SPEC.md` §8); node behaviour at epoch boundaries
      (derive the next weights in the background; 512 MiB per epoch held).
- [ ] Header layout and `header_digest`; block id; genesis.
- [x] Emission: smooth curve with a 0.25 RQT tail; 6% development fund for heights 1..2^21 (**owner**).
- [x] Test network fund key: `trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems` (**owner**).
- [ ] Before the test network starts: the genesis time in `crates/consensus/src/params.rs`.

## 2. Node

- [x] Block and header validation (claim check order of `SPEC.md` §7; peers sending invalid blocks are
      disconnected) — `crates/consensus`.
- [x] UTXO ledger with ed25519 signatures (**owner**: UTXO).
- [x] Storage (append-only block file, replay on start), reorgs, cumulative-work fork choice.
- [x] P2P v0: block-first sync by locator, block and transaction relay, orphan pool, bounded messages —
      `crates/node` (`requantd`).
- [x] Mempool (no chains of unconfirmed transactions yet) and JSON-RPC (`getinfo`, `getblock`,
      `getwork`/`submitwork`, `sendtx`, `utxos`, `addpeer`, `peers`).
- [x] Wallet CLI (`requant-wallet`): key generation from the OS RNG, bech32m addresses (`rq1`, `trq1`,
      `rqrt1`), balance, send. Next: spending unconfirmed change, several payments per block, encrypted
      key files, hardware wallets.
- [ ] Headers-first sync; peer discovery and address gossip; persistent ban list.
- [x] Deep-fork protection: forks more than `--max-reorg` blocks below the tip (default one epoch) are
      refused before their work is checked (node policy; recovery after a longer partition is manual).
- [x] The current and next epoch's weights are derived on a background thread once their seeds are known.
- [ ] Keep a UTXO snapshot instead of replaying all blocks on start; transaction index.
- [ ] Return transactions of disconnected blocks to the pool after a reorg.
- [ ] RPC authentication (now: no auth, bind to localhost only).

## 3. Miner

- [x] GPU miner: CPPminer `--algo tnet` (branch `feat/tnet-backend` of
      [danifest751/CPPminer](https://github.com/danifest751/CPPminer/tree/feat/tnet-backend)): solo mining
      through `getwork`/`submitwork`, row batches (`--batch`, any size works on small GPUs), self-test.
      Mined 20 regtest blocks and 15 blocks at the TNet v1 parameters into `requantd` (CMP 50HX).
- [ ] Merge into CPPminer's release builds; Windows build; several GPUs in one process.
- [ ] Optional fused requantization in the GEMM epilogue, bit-exact with `SPEC.md` §5.
- [ ] Pool protocol (share = ticket at a lower target).

## 4. Network launch

- [ ] Private testnet, then a public testnet with a reset policy.
- [ ] Security policy for consensus bugs; release signing.

## Research still open (tracked in the Abacus repository)

- An int8-GEMM ASIC cost model; a measured LUT-precomputation kernel; light-client options.
