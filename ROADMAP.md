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

- [ ] Block time and retarget rule; target encoding (compact or full 256-bit) (**owner** for the
      block time).
- [ ] Epoch length `E` and look-back `K` (`SPEC.md` §8); node behaviour at epoch boundaries
      (derive the next weights in the background; 512 MiB per epoch held).
- [ ] Header layout and `header_digest`; block id; genesis.
- [ ] Emission schedule, supply, fees (**owner**).

## 2. Node

- [ ] Block and header validation (claim check order of `SPEC.md` §7, peer banning on failure).
- [ ] Transactions and ledger model (UTXO or accounts), signatures (**owner** for the model).
- [ ] P2P: header-first sync, block relay, bounded resources.
- [ ] Storage, reorgs, cumulative-work fork choice.
- [ ] RPC and a minimal wallet.

## 3. Miner

- [ ] Turn `miner/cuda/tnet_bench.cu` into a miner: work from the node or a pool, row sub-batches of
      `B`, ticket submission.
- [ ] Optional fused requantization in the GEMM epilogue, bit-exact with `SPEC.md` §5.
- [ ] Multi-GPU, memory-limited GPUs (rows are independent; any batch size is valid).
- [ ] Pool protocol (share = ticket at a lower target).

## 4. Network launch

- [ ] Private testnet, then a public testnet with a reset policy.
- [ ] Security policy for consensus bugs; release signing.

## Research still open (tracked in the Abacus repository)

- An int8-GEMM ASIC cost model; a measured LUT-precomputation kernel; light-client options.
