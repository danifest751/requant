# TNet v1 test vectors

One JSON object per line, as printed by `tnet vectors n b L w mult epoch hd nonce i...`. Fields:
parameters, `epoch` and `hd` (hex), `nonce`, row `i`, `weights_sha256` (SHA-256 of each `W_l`,
row-major int8), `x0_sha256` and `row_sha256` (SHA-256 of row `i` of `X_0` and of `X_L`), `row`
(hex, only when `n <= 1024`) and `tickets` (the `n / w` ticket hashes of row `i`, `c = 0, 1, ...`).

| File | Parameters | Checked by |
|---|---|---|
| `tnet-v1-small.jsonl` | `n = 256, b = 64, L = 4, w = 64, M = 14170`, nonce 7, rows 0 and 63 | `cargo test`, `tests/test_reference.py` (pure Python) |
| `tnet-v1-frozen.jsonl` | v1: `n = 8192, b = 65536, L = 8, w = 256, M = 2505`, nonce 0, rows 0, 1, 255, 65535 | `cargo test --release -- --ignored` |

Both use `epoch = 00 01 .. 1f` and `hd = 20 21 .. 3f`. Ticket `(nonce 0, i 255, c 23)` of the frozen
file, `00019838…` (15 leading zero bits), was found by the CUDA attempt `miner/cuda/tnet_bench.cu` on a
CMP 50HX and recomputed by Rust; `tnet check` accepts it:

```sh
cargo build --release
E=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
H=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
target/release/tnet vectors 8192 65536 8 256 2505 $E $H 0 0 1 255 65535 | diff - vectors/tnet-v1-frozen.jsonl
```

The files are identical to `spec/vectors/` of the research repository.
