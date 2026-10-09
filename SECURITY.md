# Security policy

## Status

Pre-alpha. There is no network and no coin. The code is a reference implementation of a work
function; do not use it where funds depend on it.

## In scope

- A divergence between `SPEC.md`, the Rust crate, the Python reference or the CUDA code (any input
  on which two of them disagree is a consensus bug).
- A **work-model break**: a way to obtain valid tickets for less than the stated `L n w`
  multiply-adds each, or to pass verification without the recomputed piece.
- Crashes, panics or unbounded resource use in the verifier on malformed claims.

## How to report

Open a private security advisory on this repository (`Security` -> `Report a vulnerability`). For
non-sensitive findings a regular issue is fine. Include the affected commit, a minimal reproduction
and the expected versus observed result.

Before a network exists, work-model breaks are published as results rather than embargoed.
