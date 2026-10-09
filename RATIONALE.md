# Why TNet v1 looks the way it does

A summary of the research behind the design. The full record, with measurements, source hashes
and negative results, is in the [Abacus](https://github.com/danifest751/Abacus) repository; references
below are to its files.

## Goal

A proof of work whose best hardware is general-purpose tensor hardware (GPUs, AI accelerators), with
verification cheap enough for ordinary nodes and no proof system.

## What did not work

| Design | Why it fails | Abacus record |
|---|---|---|
| Matrix product verified by Freivalds | sound, but blocks carry the `8 n^2`-byte product and the linear algebra adds cost, not security | ADR 0004–0010, `docs/ASSESSMENT.md` |
| Linear folds of the product | prefix sums bypass the work | ADR 0010 |
| Gathered (memory-hard) operands | becomes an Ethash-style bandwidth PoW | ADR 0011 |
| int8 product with a per-attempt commitment | the commitment costs more than the int8 product (19–57x measured) | ADR 0012–0013 |
| Winner-only succinct proof | minutes per block | `docs/research/e1-hash-proof-v1.md` |

What survived is the structure of Pearl's per-tile lottery (ePrint 2025/685): many small pieces of
the result are tickets, and a winner is checked by recomputing only its piece. TNet uses it without
noise and without a usefulness claim.

## Design choices

- **Deep network, not one product.** A single product `X W` would let a miner score linear
  functions of the result without computing it. Eight layers with exact rounding between them
  leave no linear shortcut, and the verifier still recomputes only one row (`L n^2` multiply-adds).
- **Header-seeded input, no free data.** The miner chooses only the nonce (and header fields), so
  there is nothing to grind except more attempts.
- **Fixed-point requantization** `clamp((y M + 2^23) >> 24)` with `M = round(2^24 / (74 sqrt(n)))`
  keeps all eight bits of the activations in use. Power-of-two scales saturated (15%) or collapsed
  (`docs/research/tnet-v1.md`).
- **`n = 8192`** puts 88% of an attempt on tensor cores without fusing requantization into the GEMM
  (6.7% of an attempt). `n = 4096` reached only 79–83%.
- **Pieces of 256 bytes**: 32 tickets per row; hashing is ~2% of an attempt; a claim is 272 bytes.
- **The piece travels in the block** so that a claim without work is rejected after one SHA-256
  instead of a recomputation (ADR 0016).
- **Epoch weights** change regularly, so they cannot be wired into silicon; nodes hold 512 MiB.

## Measurements (Abacus `tnet-v1`, `tnet-v2`, `tnet-ampere-v1`)

| | |
|---|---|
| GPU attempt (CMP 50HX, Turing) | 611.6 ms per nonce, 88.2% int8 GEMM, 57.5 TMAC/s, 292 ns per ticket |
| GPU attempt (RTX 3090, Ampere) | 334.5 ms per nonce, 86.7% int8 GEMM, 105 TMAC/s, 159.5 ns per ticket, ~328 W |
| GPU/Rust parity | byte-identical tickets on both GPUs (CUDA 13.3 and 12.8) |
| Single-row mining | 42–51x more expensive per ticket than batched |
| CPU verification | 11.2 ms (8 threads) / 21.7 ms (1 thread), portable build |
| Lottery | 388 / 902 tickets found against 384 / 896 expected |
| Error propagation | one ±1 error after layer 1 changes 55% of the final row |
| Approximate last layer | dropping 64 of 8192 terms: 26% exact pieces; int7 weights: none |
| Precomputation (bound) | bit-plane tables: 4–12x slower than tensor cores on that GPU; ≥128x weight storage in silicon |

## Open questions

- An ASIC for int8 GEMM without the rest of an AI accelerator: its advantage is unmeasured (such a
  chip is an inference chip, which is the design's intent, but the margin matters).
- Newer GPU generations (Ada, Hopper, Blackwell) and AI accelerators: tensor share and ns per ticket.
- A measured LUT kernel to replace the precomputation bound.
- Light clients: 512 MiB of weights and ~11 ms per header, or trust in full nodes.
