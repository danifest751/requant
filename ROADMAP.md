# Roadmap

The work function is frozen (`SPEC.md`). Everything below is open. Items marked **owner** are
decisions for the project owner, not engineering defaults.

## 0. Before any code depends on it

- [x] Second architecture: RTX 3090 (Ampere), 159.5 ns per ticket, 86.7% tensor share, parity holds
      (Abacus `tnet-ampere-v1`). Next: Ada / Hopper / Blackwell.
- [ ] External review of `SPEC.md` and `crates/tnet`.
- [x] Coin name and repository: Requant (`requant-network/requant`, first `danifest751/requant`); ticker RQT, provisional until checked
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
      `rqrt1`), balance (confirmed, unconfirmed, immature), history, transaction details, send (also from
      unconfirmed change), several recipients per payment, `all`, coin listing and consolidation, fees
      by size, a confirmation before sending. Key files are encrypted with a passphrase (Argon2id +
      XChaCha20-Poly1305; `encrypt` converts older files). Next: several keys per wallet, hardware wallets.
- [x] Node 0.2: protocol 2 (node id, listening port, agent; extensible greeting), address gossip with an
      on-disk address book and an outbound connection manager, pings and idle timeouts, one-hour bans for
      invalid data, transaction and address index (`history`, `gettx`), chains of unconfirmed
      transactions in the pool, reorged transactions returned to the pool, optional RPC token.
- [x] Read-only block explorer in the node (`--explorer ADDR`): summary, latest blocks, block, transaction
      and address pages, search.
- [x] Resource bounds for public nodes: orphan blocks limited by bytes (16 MiB), per peer (64) and height
      (4096 above the tip); four inbound connections per IP; explorer serves 32 requests at once.
- [x] Headers-first sync (node 0.3, protocol 3): headers and work claims verified without bodies
      (`crates/consensus/src/headers.rs`), bodies downloaded from several peers in parallel and accepted
      without re-verifying claims; peers on protocol 2 are still synced block by block.
- [ ] Persistent ban list.
- [x] Deep-fork protection: forks more than `--max-reorg` blocks below the tip (default one epoch) are
      refused before their work is checked (node policy; recovery after a longer partition is manual).
- [x] The current and next epoch's weights are derived on a background thread once their seeds are known.
- [ ] Keep a UTXO snapshot instead of replaying all blocks on start; transaction index.
- [x] RPC token (`--rpc-token-file`; clients send `REQUANT_RPC_TOKEN`).

## 3. Miner

- [x] GPU miner: CPPminer `--algo tnet` (branch `feat/tnet-backend` of
      [danifest751/CPPminer](https://github.com/danifest751/CPPminer/tree/feat/tnet-backend)): solo mining
      through `getwork`/`submitwork`, row batches (`--batch`, any size works on small GPUs), self-test.
      Mined 20 regtest blocks and 15 blocks at the TNet v1 parameters into `requantd` (CMP 50HX).
- [ ] Merge into CPPminer's release builds; Windows build; several GPUs in one process.
- [ ] Optional fused requantization in the GEMM epilogue, bit-exact with `SPEC.md` §5.
- [x] Mining pool in the node (`--pool`, node 0.4): the node's getwork/submitwork with a share target,
      PPLNS rewards credited at maturity, automatic multi-output payouts, state in `pool.json`, explorer
      page `/pool`; CPPminer sends its payee with each share.

## 4. Network launch

- [x] Public test network since 2026-10-09 17:34 UTC: three seed nodes and one GPU miner (`TESTNET.md`);
      it may be reset when the rules change.
- [ ] Run it for weeks: reorgs between miners, epoch changes (every 1440 blocks), restarts, attacks;
      more miners (RTX 3090).
- [ ] Before the main network: genesis time and target, fund key, external review.
- [x] Before the test network started: the genesis time in `crates/consensus/src/params.rs`.
- [ ] Security policy for consensus bugs; release signing.

## Research still open (tracked in the Abacus repository)

- An int8-GEMM ASIC cost model; a measured LUT-precomputation kernel; light-client options.
