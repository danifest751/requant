//! TNet v1: a proof-of-work whose work is the forward pass of a deep requantized int8 network.
//!
//! Per epoch, `L` weight matrices `W_l` (`n x n`, int8) are derived from an epoch seed. Per nonce, an
//! input `X_0` (`B x n`, int8) is derived from the header digest, and the miner computes
//!
//! ```text
//! X_l = requant(X_{l-1} * W_{l-1}),   requant(y) = clamp((y * M + 2^23) >> 24, -128, 127),   l = 1..L
//! ```
//!
//! A ticket is a `w`-byte piece of a row of `X_L`, scored by
//! `SHA256(piece || 0x54 || header_digest || LE64(nonce) || LE32(i) || LE32(c))`. A block carries
//! `(nonce, i, c, piece)`; a verifier checks the hash against the target, then recomputes row `i`
//! (`L n^2` multiply-adds) and compares the piece. See `SPEC.md`.

pub mod sha256;

use sha256::sha256;

pub const DOM_EXPAND: &[u8] = b"abacus/expand";
pub const DOM_W: &[u8] = b"abacus/tnet-w";
pub const DOM_X0: &[u8] = b"abacus/tnet-x0";
pub const TICKET_TAG: u8 = 0x54;
/// Fractional bits of the requantization multiplier.
pub const REQ_SHIFT: u32 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Width of every layer.
    pub n: usize,
    /// Rows of `X_0` per nonce (bound on the row index `i`).
    pub b: usize,
    /// Number of layers.
    pub layers: usize,
    /// Ticket width in bytes (divides `n`).
    pub w: usize,
    /// Requantization multiplier `M`.
    pub mult: i32,
}

/// The frozen TNet v1 parameters.
pub const V1: Params = Params { n: 8192, b: 1 << 16, layers: 8, w: 256, mult: 2505 };

impl Params {
    pub fn tickets_per_row(&self) -> usize {
        self.n / self.w
    }

    /// Multiply-adds per ticket, whatever the batch size: `L n w`.
    pub fn macs_per_ticket(&self) -> u64 {
        (self.layers * self.n * self.w) as u64
    }
}

/// `round(2^24 / (74 sqrt(n)))`: keeps the activation spread constant for uniform int8 weights.
pub fn default_mult(n: usize) -> i32 {
    ((1u64 << REQ_SHIFT) as f64 / (74.0 * (n as f64).sqrt())).round() as i32
}

fn expand_block(seed: &[u8; 32], counter: u32) -> [u8; 32] {
    let mut m = Vec::with_capacity(DOM_EXPAND.len() + 36);
    m.extend_from_slice(DOM_EXPAND);
    m.extend_from_slice(seed);
    m.extend_from_slice(&counter.to_le_bytes());
    sha256(&m)
}

/// Bytes `[start, start + len)` of the stream `SHA256("abacus/expand" || seed || LE32(k))`, `k = 0, 1, ...`
pub fn expand_range(seed: &[u8; 32], start: usize, len: usize) -> Vec<u8> {
    let skip = start % 32;
    let mut out = Vec::with_capacity(len + 64);
    let mut k = (start / 32) as u32;
    while out.len() < skip + len {
        out.extend_from_slice(&expand_block(seed, k));
        k += 1;
    }
    out.drain(..skip);
    out.truncate(len);
    out
}

fn i8s(bytes: Vec<u8>) -> Vec<i8> {
    bytes.into_iter().map(|x| x as i8).collect()
}

/// `W_l`, row-major (`W[k][j]` at `k n + j`).
pub fn layer_weights(epoch_seed: &[u8; 32], n: usize, l: u32) -> Vec<i8> {
    let mut m = Vec::with_capacity(DOM_W.len() + 36);
    m.extend_from_slice(DOM_W);
    m.extend_from_slice(epoch_seed);
    m.extend_from_slice(&l.to_le_bytes());
    i8s(expand_range(&sha256(&m), 0, n * n))
}

/// `SHA256("abacus/tnet-x0" || header_digest || LE64(nonce))`.
pub fn x0_seed(header_digest: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut m = Vec::with_capacity(DOM_X0.len() + 40);
    m.extend_from_slice(DOM_X0);
    m.extend_from_slice(header_digest);
    m.extend_from_slice(&nonce.to_le_bytes());
    sha256(&m)
}

/// Row `i` of `X_0`.
pub fn x0_row(seed: &[u8; 32], n: usize, i: usize) -> Vec<i8> {
    i8s(expand_range(seed, i * n, n))
}

#[inline]
pub fn requant(y: i32, mult: i32) -> i8 {
    let v = (y as i64 * mult as i64 + (1i64 << (REQ_SHIFT - 1))) >> REQ_SHIFT;
    v.clamp(-128, 127) as i8
}

/// `SHA256(piece || 0x54 || header_digest || LE64(nonce) || LE32(i) || LE32(c))`.
pub fn ticket_hash(piece: &[i8], header_digest: &[u8; 32], nonce: u64, i: u32, c: u32) -> [u8; 32] {
    let mut m = Vec::with_capacity(piece.len() + 49);
    m.extend(piece.iter().map(|&x| x as u8));
    m.push(TICKET_TAG);
    m.extend_from_slice(header_digest);
    m.extend_from_slice(&nonce.to_le_bytes());
    m.extend_from_slice(&i.to_le_bytes());
    m.extend_from_slice(&c.to_le_bytes());
    sha256(&m)
}

/// `hash <= target`, both read as 256-bit big-endian integers.
pub fn meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash <= target
}

/// The target that accepts exactly the hashes with at least `bits` leading zero bits.
pub fn target_from_bits(bits: u32) -> [u8; 32] {
    let mut t = [0xffu8; 32];
    for (k, byte) in t.iter_mut().enumerate() {
        let lo = 8 * k as u32;
        if bits >= lo + 8 {
            *byte = 0;
        } else if bits > lo {
            *byte = 0xff >> (bits - lo);
        }
    }
    t
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut lead = 0;
    for &b in hash {
        lead += b.leading_zeros();
        if b != 0 {
            break;
        }
    }
    lead
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// `i >= B`, `c >= n / w` or a piece of the wrong length.
    BadIndex,
    /// The claimed piece does not hash below the target (cheap check, no recomputation).
    AboveTarget,
    /// The recomputed piece differs from the claimed one.
    WrongPiece,
}

/// Row-major reference forward pass for one row (slow; used to cross-check [`Epoch`]).
pub fn reference_row(weights: &[Vec<i8>], p: &Params, seed: &[u8; 32], i: usize) -> Vec<i8> {
    let n = p.n;
    let mut x = x0_row(seed, n, i);
    for w in weights {
        let mut acc = vec![0i32; n];
        for (k, &xk) in x.iter().enumerate() {
            for (a, &wkj) in acc.iter_mut().zip(&w[k * n..(k + 1) * n]) {
                *a += xk as i32 * wkj as i32;
            }
        }
        x = acc.into_iter().map(|y| requant(y, p.mult)).collect();
    }
    x
}

type DotFn = fn(&[i8], &[i8]) -> i32;

#[inline(always)]
fn dot_body(x: &[i8], col: &[i8]) -> i32 {
    x.iter().zip(col).map(|(&a, &b)| a as i32 * b as i32).sum()
}

fn dot_generic(x: &[i8], col: &[i8]) -> i32 {
    dot_body(x, col)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn dot_avx2_inner(x: &[i8], col: &[i8]) -> i32 {
    dot_body(x, col)
}

#[cfg(target_arch = "x86_64")]
fn dot_avx2(x: &[i8], col: &[i8]) -> i32 {
    // SAFETY: only selected by `pick_dot` after `is_x86_feature_detected!("avx2")`.
    unsafe { dot_avx2_inner(x, col) }
}

fn pick_dot() -> DotFn {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("avx2") {
        return dot_avx2;
    }
    dot_generic
}

/// Where an epoch's transposed weights live when they are not held in memory (e.g. a file the operating
/// system caches: same speed while cached, and the memory stays reclaimable).
pub trait LayerSource: Send + Sync {
    /// Fill `out` with rows `j0 .. j0 + out.len() / n` of `WT_l` (row `j` is column `j` of `W_l`). A source
    /// that cannot read must not return wrong bytes: an error here aborts the check with a panic.
    fn read(&self, l: usize, j0: usize, out: &mut [i8]) -> std::io::Result<()>;
}

enum Weights {
    Memory(Vec<Vec<i8>>),
    External(Box<dyn LayerSource>),
}

/// Rows of `WT_l` read at once from a [`LayerSource`] (2 MiB for TNet v1).
const ROWS_PER_READ: usize = 256;

/// Verifier state for one epoch: the weights stored transposed (`WT[j][k] = W[k][j]`, `L n^2` bytes), so
/// every output entry is one contiguous int8 dot product. Built once per epoch.
pub struct Epoch {
    pub p: Params,
    wt: Weights,
    dot: DotFn,
}

/// `WT_l`, the transposed weights of layer `l` (`n^2` bytes) as an [`Epoch`] keeps them, for storing them
/// elsewhere and reading them back through a [`LayerSource`].
pub fn transposed_layer(epoch_seed: &[u8; 32], p: Params, l: u32) -> Vec<i8> {
    transpose(&layer_weights(epoch_seed, p.n, l), p.n)
}

/// `n x n` transpose in 64 x 64 tiles.
fn transpose(w: &[i8], n: usize) -> Vec<i8> {
    const T: usize = 64;
    let mut t = vec![0i8; n * n];
    for k0 in (0..n).step_by(T) {
        for j0 in (0..n).step_by(T) {
            for k in k0..(k0 + T).min(n) {
                for j in j0..(j0 + T).min(n) {
                    t[j * n + k] = w[k * n + j];
                }
            }
        }
    }
    t
}

impl Epoch {
    /// Derive the epoch weights, one layer at a time, keeping only the transposed copy.
    pub fn from_seed(epoch_seed: &[u8; 32], p: Params) -> Self {
        let wt = (0..p.layers as u32).map(|l| transposed_layer(epoch_seed, p, l)).collect();
        Epoch { p, wt: Weights::Memory(wt), dot: pick_dot() }
    }

    /// From row-major weights (`W_l` as returned by [`layer_weights`]).
    pub fn from_weights(weights: &[Vec<i8>], p: Params) -> Self {
        Epoch { p, wt: Weights::Memory(weights.iter().map(|w| transpose(w, p.n)).collect()), dot: pick_dot() }
    }

    /// With the transposed weights read from `source` at every check instead of held in memory.
    pub fn from_source(p: Params, source: Box<dyn LayerSource>) -> Self {
        Epoch { p, wt: Weights::External(source), dot: pick_dot() }
    }

    fn layer(&self, x: &[i8], l: usize, threads: usize) -> Vec<i8> {
        let n = self.p.n;
        let (mult, dot) = (self.p.mult, self.dot);
        let mut out = vec![0i8; n];
        let chunk = n.div_ceil(threads.clamp(1, n));
        std::thread::scope(|s| {
            for (t, dst) in out.chunks_mut(chunk).enumerate() {
                let wt = &self.wt;
                s.spawn(move || match wt {
                    Weights::Memory(wt) => {
                        let wt = &wt[l];
                        for (q, d) in dst.iter_mut().enumerate() {
                            let j = t * chunk + q;
                            *d = requant(dot(x, &wt[j * n..(j + 1) * n]), mult);
                        }
                    }
                    Weights::External(src) => {
                        let mut buf = vec![0i8; ROWS_PER_READ.min(dst.len()) * n];
                        for (b, block) in dst.chunks_mut(ROWS_PER_READ).enumerate() {
                            let j0 = t * chunk + b * ROWS_PER_READ;
                            let rows = &mut buf[..block.len() * n];
                            src.read(l, j0, rows).expect("epoch weights could not be read");
                            for (q, d) in block.iter_mut().enumerate() {
                                *d = requant(dot(x, &rows[q * n..(q + 1) * n]), mult);
                            }
                        }
                    }
                });
            }
        });
        out
    }

    /// Row `i` of `X_L` for the nonce whose `X_0` seed is `seed`.
    pub fn forward_row(&self, seed: &[u8; 32], i: usize, threads: usize) -> Vec<i8> {
        let mut x = x0_row(seed, self.p.n, i);
        for l in 0..self.p.layers {
            x = self.layer(&x, l, threads);
        }
        x
    }

    /// Check a claimed ticket `(nonce, i, c, piece)` against `target`: the hash first (cheap), then the
    /// recomputation of row `i`.
    #[allow(clippy::too_many_arguments)]
    pub fn check(
        &self,
        header_digest: &[u8; 32],
        nonce: u64,
        i: u32,
        c: u32,
        piece: &[i8],
        target: &[u8; 32],
        threads: usize,
    ) -> Result<(), Reject> {
        let p = &self.p;
        let (iu, cu) = (i as usize, c as usize);
        if iu >= p.b || cu >= p.tickets_per_row() || piece.len() != p.w {
            return Err(Reject::BadIndex);
        }
        if !meets_target(&ticket_hash(piece, header_digest, nonce, i, c), target) {
            return Err(Reject::AboveTarget);
        }
        let row = self.forward_row(&x0_seed(header_digest, nonce), iu, threads);
        if row[cu * p.w..(cu + 1) * p.w] != *piece {
            return Err(Reject::WrongPiece);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Params {
        Params { n: 64, b: 16, layers: 4, w: 16, mult: default_mult(64) }
    }

    #[test]
    fn requant_rounds_half_up_and_saturates() {
        let m = 1 << (REQ_SHIFT - 4); // scale 1/16
        let got: Vec<i8> = [0, 7, 8, -8, -9, 1 << 20, -(1 << 20)].iter().map(|&y| requant(y, m)).collect();
        assert_eq!(got, [0, 0, 1, 0, -1, 127, -128]);
        assert_eq!(default_mult(V1.n), V1.mult);
    }

    #[test]
    fn expand_range_matches_the_stream() {
        let seed = [3u8; 32];
        let full = expand_range(&seed, 0, 64 * 10);
        for (start, len) in [(0, 5), (31, 2), (32, 32), (100, 333), (64 * 9, 64)] {
            assert_eq!(expand_range(&seed, start, len), full[start..start + len]);
        }
    }

    #[test]
    fn epoch_matches_reference_for_any_thread_count() {
        let p = Params { n: 128, b: 32, layers: 3, w: 32, mult: default_mult(128) };
        let w: Vec<Vec<i8>> = (0..p.layers as u32).map(|l| layer_weights(&[9u8; 32], p.n, l)).collect();
        let e = Epoch::from_weights(&w, p);
        let seed = x0_seed(&[1u8; 32], 3);
        for i in [0, 5, 31] {
            let want = reference_row(&w, &p, &seed, i);
            for t in [1, 3, 8] {
                assert_eq!(e.forward_row(&seed, i, t), want);
            }
            assert_eq!(dot_generic(&want, &want), pick_dot()(&want, &want));
        }
    }

    #[test]
    fn targets() {
        let t = target_from_bits(12);
        assert_eq!(&t[..3], &[0x00, 0x0f, 0xff]);
        let mut h = [0u8; 32];
        h[1] = 0x10;
        assert!(!meets_target(&h, &t) && leading_zero_bits(&h) == 11);
        h[1] = 0x0f;
        assert!(meets_target(&h, &t) && leading_zero_bits(&h) == 12);
        assert_eq!(target_from_bits(0), [0xff; 32]);
        assert_eq!(target_from_bits(256), [0; 32]);
    }

    #[test]
    fn found_ticket_checks_and_forgeries_fail() {
        let p = small();
        let e = Epoch::from_seed(&[6u8; 32], p);
        let (hd, target) = ([7u8; 32], target_from_bits(6));
        for nonce in 0..64u64 {
            let seed = x0_seed(&hd, nonce);
            for i in 0..p.b as u32 {
                let row = e.forward_row(&seed, i as usize, 1);
                for c in 0..p.tickets_per_row() as u32 {
                    let piece = &row[c as usize * p.w..(c as usize + 1) * p.w];
                    if !meets_target(&ticket_hash(piece, &hd, nonce, i, c), &target) {
                        continue;
                    }
                    assert_eq!(e.check(&hd, nonce, i, c, piece, &target, 2), Ok(()));
                    let mut forged = piece.to_vec();
                    forged[0] = forged[0].wrapping_add(1);
                    let any = [0xff; 32];
                    assert_eq!(e.check(&hd, nonce, i, c, &forged, &any, 2), Err(Reject::WrongPiece));
                    assert_eq!(e.check(&hd, nonce, i, c, piece, &target_from_bits(60), 2), Err(Reject::AboveTarget));
                    assert_eq!(e.check(&hd, nonce, p.b as u32, c, piece, &any, 2), Err(Reject::BadIndex));
                    assert_eq!(e.check(&hd, nonce, i, c, &piece[1..], &any, 2), Err(Reject::BadIndex));
                    return;
                }
            }
        }
        panic!("no 6-bit ticket in 64 nonces");
    }

    /// Transposed layers kept apart, read back like a file would be.
    struct Rows(Vec<Vec<i8>>, usize);

    impl LayerSource for Rows {
        fn read(&self, l: usize, j0: usize, out: &mut [i8]) -> std::io::Result<()> {
            out.copy_from_slice(&self.0[l][j0 * self.1..j0 * self.1 + out.len()]);
            Ok(())
        }
    }

    #[test]
    fn external_weights_give_the_same_rows() {
        // n larger than ROWS_PER_READ, so every thread reads several blocks
        let p = Params { n: 640, b: 4, layers: 3, w: 64, mult: default_mult(640) };
        let seed = [9u8; 32];
        let mem = Epoch::from_seed(&seed, p);
        let layers = (0..p.layers as u32).map(|l| transposed_layer(&seed, p, l)).collect();
        let ext = Epoch::from_source(p, Box::new(Rows(layers, p.n)));
        let x = x0_seed(&[3u8; 32], 5);
        for threads in [1, 2, 3, 7] {
            assert_eq!(ext.forward_row(&x, 2, threads), mem.forward_row(&x, 2, 1), "{threads} threads");
        }
    }
}
