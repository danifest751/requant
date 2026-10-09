# Requant

A proof-of-work coin (ticker **RQT**, provisional) whose work is the forward pass of a deep int8
network: the arithmetic that GPU tensor cores and AI inference accelerators are built for. The name
is the step that makes the work hard to shortcut: exact integer **requant**ization between layers.
The work function is called **TNet**.

**Status: pre-alpha.** The work function (**TNet v1**) is frozen with test vectors and reference
implementations. There is no node, no network and no coin yet; see [`ROADMAP.md`](ROADMAP.md).
Nothing here is a security or investment claim.

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

Full definition: [`SPEC.md`](SPEC.md).

## Quick start

Rust (stable, no third-party crates) and Python 3.10+ with `pytest`:

```sh
python scripts/check.py                      # pytest, rustfmt, clippy -D warnings, cargo test
cargo test --release -- --ignored            # frozen-parameter vectors (512 MiB, ~15 s)
cargo run --release --bin tnet -- bench      # CPU verification time at the v1 parameters
```

GPU attempt benchmark (CUDA, cuBLAS): [`miner/cuda/`](miner/cuda/README.md).

## Layout

```
SPEC.md          TNet v1 work function (normative)
crates/tnet/     Rust reference: derivations, verifier (Epoch), CLI (vectors, check, bench)
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
