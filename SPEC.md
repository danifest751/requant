# TNet v1 — work function specification

Status: **frozen** (2026-10-09). Any change to a constant, derivation or rounding rule below is a new
version with new test vectors. Sections 1–7 are normative for the work function; section 8 lists the
requirements a chain must meet to use it, with the chain-level values still open (`ROADMAP.md`).

Reference implementations: Rust `crates/tnet` (normative in case of doubt), Python
`reference/tnet_ref.py`, CUDA attempt `miner/cuda/tnet_bench.cu`. Vectors: `vectors/`.

## 1. Notation and primitives

- `SHA256` is FIPS 180-4 SHA-256. `||` is byte concatenation. `LE32(x)`, `LE64(x)` are little-endian
  encodings of unsigned integers.
- An int8 value is a byte read as two's complement (`0x80 = -128`, `0xff = -1`); an int8 vector is
  encoded as its bytes in order.
- Matrices are row-major: entry `(r, k)` of an `R x n` matrix is element `r n + k`.
- **Expansion stream.** For a 32-byte `seed`, `E(seed)` is the byte stream
  `SHA256("abacus/expand" || seed || LE32(0)) || SHA256("abacus/expand" || seed || LE32(1)) || ...`;
  `E(seed)[a .. a + m]` denotes `m` bytes starting at offset `a`.
- Domain strings are ASCII without terminator: `"abacus/expand"` (13 bytes), `"abacus/tnet-w"`
  (13 bytes), `"abacus/tnet-x0"` (14 bytes). They keep the names of the research repository so its
  vectors stay valid.

## 2. Parameters (v1)

| Symbol | Value | Meaning |
|---|---:|---|
| `n` | 8192 | width of every layer |
| `B` | 65536 | rows per nonce (bound on the row index) |
| `L` | 8 | layers |
| `w` | 256 | ticket width in bytes; `n / w = 32` tickets per row |
| `M` | 2505 | requantization multiplier, `round(2^24 / (74 sqrt(n)))` |
| `S` | 24 | requantization shift |

## 3. Epoch weights

For a 32-byte `epoch_seed` and `l = 0 .. L-1`:

```
W_l = int8( E( SHA256("abacus/tnet-w" || epoch_seed || LE32(l)) )[0 .. n^2] )      (n x n, row-major)
```

`W_l` totals `L n^2 = 512 MiB`. How `epoch_seed` is chosen is a chain rule (section 8).

## 4. Input of a nonce

For the 32-byte `header_digest` (section 8) and a 64-bit `nonce`:

```
s   = SHA256("abacus/tnet-x0" || header_digest || LE64(nonce))
X_0 = int8( E(s)[0 .. B n] )                                                       (B x n, row-major)
```

Row `i` of `X_0` is `int8(E(s)[i n .. (i + 1) n])` and can be derived alone.

## 5. Layers

For `l = 1 .. L`, entry `(r, j)`:

```
y        = sum_{k=0}^{n-1} X_{l-1}[r, k] * W_{l-1}[k, j]          (exact integer; |y| <= n 2^14 = 2^27)
X_l[r,j] = clamp( floor( (y M + 2^(S-1)) / 2^S ), -128, 127 )     (exact integer; y M fits in 64 bits)
```

`floor` rounds towards negative infinity (an arithmetic right shift of a two's-complement 64-bit
value). Rows are independent: row `r` of `X_L` depends only on row `r` of `X_0` and the weights.

## 6. Tickets

A ticket is a pair `(i, c)` with `0 <= i < B` and `0 <= c < n / w`. Its piece and hash are

```
piece = X_L[i, c w .. (c + 1) w]                                               (w int8 bytes)
H     = SHA256( piece || 0x54 || header_digest || LE64(nonce) || LE32(i) || LE32(c) )
```

A ticket meets a 256-bit target `T` iff `H <= T`, both read as big-endian unsigned integers.

## 7. Work claim and verification

A work claim is `(nonce, i, c, piece)`: 8 + 4 + 4 + 256 = 272 bytes. A verifier holding the epoch
weights accepts it iff, in this order:

1. `i < B`, `c < n / w` and `piece` has `w` bytes;
2. `H(piece) <= T` (one SHA-256; rejects a claim without work before any recomputation);
3. recomputing row `i` of `X_L` (sections 4–5: one row of `X_0` and `L n^2` multiply-adds) yields
   exactly `piece` at columns `[c w, (c + 1) w)`.

Measured cost of step 3 (`crates/tnet`, laptop CPU, AMD Ryzen 7 8745HS, portable build with run-time
AVX2 dispatch): 21.7 ms on one thread, 11.2 ms on eight. Per epoch: deriving and transposing the
weights takes ~7 s on one thread.

## 8. Requirements on a chain using TNet v1

1. `header_digest` is a SHA-256 commitment to every header field except the work claim (the previous
   block, the transactions root, the time, the target, ...). The work claim is stored next to it.
2. `epoch_seed` changes every `E` blocks and is fixed by blocks far enough in the past that every node
   can derive the next weights before they are needed (e.g. the id of block `e E - K` for epoch `e`, with
   `K` covering the derivation time).
3. The block's work is `2^256 / (T + 1)` expected tickets; the chain compares cumulative work.
4. Nodes must reject claims in the order of section 7 and should ban peers that send claims failing
   step 2 or 3.

Values for `E`, `K`, the target encoding, block time and retargeting are open (`ROADMAP.md`).

## 9. Properties (measured, not guaranteed)

From the research record (`RATIONALE.md`):

- Every ticket costs `L n w` multiply-adds whatever the miner computes; batching many rows (int8 GEMM
  on tensor cores) is 42–45x cheaper per ticket than single rows. On a Turing GPU 88.2% of an attempt
  is int8 tensor-core GEMM (57.5 TMAC/s).
- One ±1 error after the first layer changes 55% of the final row; approximate computation yields no
  valid tickets at useful rates.
- Table-based precomputation on the epoch weights is bounded (not measured) at 4–12x slower than
  tensor cores on the measured GPU.
- Not established: ASIC resistance (an int8-GEMM chip is an AI inference chip), usefulness of the work,
  behaviour on other GPU architectures.

## 10. Test vectors

`vectors/README.md`. `tnet-v1-frozen.jsonl` pins section 2's parameters (four rows; one row matches
a ticket found by the GPU attempt); `tnet-v1-small.jsonl` (`n = 256`) is checked by the pure-Python
reference.
