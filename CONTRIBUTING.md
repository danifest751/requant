# Contributing

- Run `python scripts/check.py` before every commit (pytest, rustfmt, clippy with warnings as errors,
  cargo test). For changes touching derivations also run `cargo test --release -- --ignored`.
- **Consensus rules are frozen per version.** A change to anything in `SPEC.md` §1–7 is a new version
  with a new spec section, new vectors and agreement of the Rust, Python and CUDA implementations.
  Never weaken a check or edit committed vectors to make a test pass.
- The Rust crate stays dependency-free; the Python reference uses only the standard library.
- Performance claims come with the hardware, build flags, source hash and raw numbers.
- Commit messages: imperative subject, a short body explaining why.
- No paid CI, Git LFS or cloud jobs by default; checks run locally.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
