# GPU attempt benchmark (TNet v1)

`tnet_bench.cu` runs complete TNet attempts on one GPU with cuBLAS int8 GEMM (tensor cores), an
integer requantization kernel and SHA-256 ticket hashing, and reports per-phase times, the tensor-core
share, activation statistics, ticket counts and one sample ticket. The sample is checked with
`tnet check` (see `vectors/README.md`). It is a benchmark, not yet a miner (`ROADMAP.md` §3).

```sh
nvcc -O3 -arch=sm_75 tnet_bench.cu -lcublas -o tnet_bench     # set -arch for your GPU (sm_86: Ampere)
# n b L w mult attempts bits [epoch_hex hd_hex warm_s]
./tnet_bench 8192 65536 8 256 2505 3 14 \
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f 1
```

| GPU | attempt | GEMM share | TMAC/s | ns / ticket |
|---|---:|---:|---:|---:|
| CMP 50HX (Turing, sm_75, CUDA 13.3) | 611.6 ms | 88.2% | 57.5 | 292 |
| RTX 3090 (Ampere, sm_86, CUDA 12.8, ~328 W) | 334.5 ms | 86.7% | 105.2 | 159.5 |

Both produce tickets accepted byte for byte by `tnet check` (e.g. `(0, 255, 23)` of `vectors/README.md`). Memory: the
weights (512 MiB, plus a transposed copy) and `b n` bytes of activations with `4 b n` bytes of int32
accumulators; reduce `b` on smaller GPUs (rows are independent).

The `bits` argument counts leading zero bits; the chain uses a 256-bit target (`SPEC.md` §6).
