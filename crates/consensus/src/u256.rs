//! Minimal unsigned 256-bit integer for targets and chain work (CHAIN.md §3, §5, §7).

use std::cmp::Ordering;

/// Little-endian 64-bit limbs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: U256 = U256([0; 4]);
    pub const ONE: U256 = U256([1, 0, 0, 0]);
    pub const MAX: U256 = U256([u64::MAX; 4]);

    /// `2^bits - 1` for `bits <= 256`.
    pub fn low_mask(bits: u32) -> U256 {
        let mut l = [0u64; 4];
        for (k, limb) in l.iter_mut().enumerate() {
            let lo = 64 * k as u32;
            if bits >= lo + 64 {
                *limb = u64::MAX;
            } else if bits > lo {
                *limb = (1u64 << (bits - lo)) - 1;
            }
        }
        U256(l)
    }

    pub fn from_be_bytes(b: &[u8; 32]) -> U256 {
        let mut l = [0u64; 4];
        for (k, limb) in l.iter_mut().enumerate() {
            let off = 32 - 8 * (k + 1);
            *limb = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
        }
        U256(l)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for k in 0..4 {
            let off = 32 - 8 * (k + 1);
            b[off..off + 8].copy_from_slice(&self.0[k].to_be_bytes());
        }
        b
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    pub fn bits(&self) -> u32 {
        for k in (0..4).rev() {
            if self.0[k] != 0 {
                return 64 * k as u32 + 64 - self.0[k].leading_zeros();
            }
        }
        0
    }

    fn bit(&self, i: u32) -> bool {
        (self.0[(i / 64) as usize] >> (i % 64)) & 1 == 1
    }

    pub fn checked_add(&self, o: &U256) -> Option<U256> {
        let mut r = [0u64; 4];
        let mut carry = 0u128;
        for (k, rk) in r.iter_mut().enumerate() {
            let s = self.0[k] as u128 + o.0[k] as u128 + carry;
            *rk = s as u64;
            carry = s >> 64;
        }
        (carry == 0).then_some(U256(r))
    }

    pub fn saturating_add(&self, o: &U256) -> U256 {
        self.checked_add(o).unwrap_or(U256::MAX)
    }

    fn sub(&self, o: &U256) -> U256 {
        let mut r = [0u64; 4];
        let mut borrow = 0i128;
        for (k, rk) in r.iter_mut().enumerate() {
            let d = self.0[k] as i128 - o.0[k] as i128 - borrow;
            *rk = d as u64;
            borrow = (d < 0) as i128;
        }
        U256(r)
    }

    fn shl1(&self) -> U256 {
        let l = self.0;
        U256([l[0] << 1, (l[1] << 1) | (l[0] >> 63), (l[2] << 1) | (l[1] >> 63), (l[3] << 1) | (l[2] >> 63)])
    }

    /// Floor division (`d` nonzero), bit by bit.
    pub fn div(&self, d: &U256) -> U256 {
        assert!(!d.is_zero(), "division by zero");
        let mut q = U256::ZERO;
        let mut r = U256::ZERO;
        for i in (0..self.bits()).rev() {
            r = r.shl1();
            if self.bit(i) {
                r.0[0] |= 1;
            }
            if r >= *d {
                r = r.sub(d);
                q.0[(i / 64) as usize] |= 1 << (i % 64);
            }
        }
        q
    }

    /// Expected tickets for `target`: `floor(2^256 / (target + 1))`.
    pub fn work(target: &U256) -> U256 {
        if *target == U256::MAX {
            return U256::ONE;
        }
        // 2^256 / (t + 1) = (2^256 - 1 - t) / (t + 1) + 1
        let t1 = target.checked_add(&U256::ONE).unwrap();
        U256([!target.0[0], !target.0[1], !target.0[2], !target.0[3]]).div(&t1).saturating_add(&U256::ONE)
    }

    /// `self * m * 2^shift` (right shift for negative `shift`), or `None` if the result exceeds 256 bits.
    pub fn mul_shift(&self, m: u64, shift: i64) -> Option<U256> {
        // 320-bit product.
        let mut w = [0u64; 5];
        let mut carry = 0u128;
        for (wk, &limb) in w.iter_mut().zip(&self.0) {
            let p = limb as u128 * m as u128 + carry;
            *wk = p as u64;
            carry = p >> 64;
        }
        w[4] = carry as u64;
        let bitlen = (0..5).rev().find(|&k| w[k] != 0).map(|k| 64 * k as i64 + 64 - w[k].leading_zeros() as i64);
        let Some(bitlen) = bitlen else { return Some(U256::ZERO) };
        if bitlen + shift > 256 {
            return None;
        }
        let get = |i: i64| -> bool { (0..320).contains(&i) && (w[(i / 64) as usize] >> (i % 64)) & 1 == 1 };
        let mut r = U256::ZERO;
        for i in 0..256i64 {
            if get(i - shift) {
                r.0[(i / 64) as usize] |= 1 << (i % 64);
            }
        }
        Some(r)
    }
}

impl Ord for U256 {
    fn cmp(&self, o: &Self) -> Ordering {
        for k in (0..4).rev() {
            match self.0[k].cmp(&o.0[k]) {
                Ordering::Equal => continue,
                x => return x,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for U256 {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(x: u128) -> U256 {
        U256([x as u64, (x >> 64) as u64, 0, 0])
    }

    #[test]
    fn bytes_roundtrip_and_order() {
        let mut b = [0u8; 32];
        b[0] = 0x80;
        b[31] = 7;
        let x = U256::from_be_bytes(&b);
        assert_eq!(x.to_be_bytes(), b);
        assert_eq!(x.bits(), 256);
        assert!(x > U256::low_mask(255) && U256::low_mask(255) > n(7));
        assert_eq!(U256::low_mask(256), U256::MAX);
        assert_eq!(U256::low_mask(70), U256([u64::MAX, 63, 0, 0]));
    }

    #[test]
    fn division_and_work() {
        assert_eq!(n(1000).div(&n(7)), n(142));
        assert_eq!(U256::MAX.div(&U256::MAX), U256::ONE);
        // target 2^255 - 1 -> work 2
        assert_eq!(U256::work(&U256::low_mask(255)), n(2));
        // target 2^240 - 1 -> work 2^16
        assert_eq!(U256::work(&U256::low_mask(240)), n(1 << 16));
        assert_eq!(U256::work(&U256::MAX), U256::ONE);
        assert_eq!(U256::work(&U256::ZERO).bits(), 256); // 2^256 saturates to MAX
    }

    #[test]
    fn mul_shift() {
        assert_eq!(n(3).mul_shift(5, 0), Some(n(15)));
        assert_eq!(n(15).mul_shift(1, -2), Some(n(3)));
        assert_eq!(n(1).mul_shift(1, 255), Some(U256([0, 0, 0, 1 << 63])));
        assert_eq!(n(1).mul_shift(1, 256), None);
        assert_eq!(U256::MAX.mul_shift(65536, -16), Some(U256::MAX));
        assert_eq!(U256::MAX.mul_shift(65537, -16), None);
        assert_eq!(n(5).mul_shift(1, -300), Some(U256::ZERO));
    }
}
