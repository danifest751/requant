//! Difficulty (CHAIN.md §7) and emission (CHAIN.md §8).

use crate::params::{Network, ATOMS_PER_RQT};
use crate::u256::U256;

/// Target of the block after a parent at `parent_height` with timestamp `parent_time`: BCH aserti3-2d
/// anchored at genesis.
pub fn next_target(net: &Network, parent_height: u64, parent_time: u64) -> U256 {
    let time_diff = parent_time as i128 - net.genesis_time as i128;
    let lag = time_diff - net.spacing as i128 * parent_height as i128;
    let exponent = (lag * 65536) / net.half_life as i128; // truncates toward zero
    let shifts = exponent >> 16; // floor
    let frac = (exponent & 0xffff) as u128;
    let poly = (195_766_423_245_049u128 * frac
        + 971_821_376u128 * frac * frac
        + 5127u128 * frac * frac * frac
        + (1u128 << 47))
        >> 48;
    let factor = 65536 + poly as u64;
    let shift = (shifts - 16).clamp(-1024, 1024) as i64;
    let t = match net.genesis_target.mul_shift(factor, shift) {
        Some(t) if t.is_zero() => U256::ONE,
        Some(t) => t,
        None => net.pow_limit,
    };
    t.min(net.pow_limit)
}

/// `S = 2^24 RQT` in atoms.
pub const MAIN_EMISSION: u64 = (1 << 24) * ATOMS_PER_RQT;
/// 0.25 RQT per block.
pub const TAIL_REWARD: u64 = ATOMS_PER_RQT / 4;

/// Block reward given the amount issued by all earlier blocks.
pub fn reward(generated: u64) -> u64 {
    (MAIN_EMISSION.saturating_sub(generated) >> 22).max(TAIL_REWARD)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net_with_target(bits: u32) -> Network {
        let mut n = Network::regtest();
        n.genesis_target = U256::low_mask(bits);
        n
    }

    #[test]
    fn on_schedule_keeps_the_target() {
        let net = net_with_target(200);
        for h in [0u64, 1, 10, 100_000] {
            assert_eq!(next_target(&net, h, net.genesis_time + 60 * h), net.genesis_target);
        }
    }

    #[test]
    fn one_half_life_doubles_or_halves() {
        let net = net_with_target(200);
        let g = net.genesis_time;
        let t = net.genesis_target;
        // 2 hours behind schedule: target doubles (easier); ahead: halves.
        assert_eq!(next_target(&net, 100, g + 6000 + 7200), t.mul_shift(1, 1).unwrap());
        assert_eq!(next_target(&net, 100, g + 6000 - 7200), t.mul_shift(1, -1).unwrap());
        assert_eq!(next_target(&net, 0, g + 2 * 7200), t.mul_shift(1, 2).unwrap());
    }

    #[test]
    fn fractional_steps_follow_the_bch_polynomial() {
        let net = net_with_target(200);
        let g = net.genesis_time;
        // half a half-life late: factor 65536 + poly(32768) = 92674 (2^0.5 * 65536 = 92681.9)
        let half = next_target(&net, 0, g + 3600);
        let ratio = half.div(&net.genesis_target.mul_shift(1, -16).unwrap());
        assert!((92673..=92674).contains(&ratio.0[0]), "{}", ratio.0[0]);
        // monotone in time
        let mut last = U256::ZERO;
        for dt in (0..20_000).step_by(37) {
            let t = next_target(&net, 0, g + dt);
            assert!(t >= last);
            last = t;
        }
    }

    #[test]
    fn clamps() {
        let net = net_with_target(250);
        assert_eq!(next_target(&net, 0, net.genesis_time + 100 * 7200), net.pow_limit);
        let net = net_with_target(8);
        assert_eq!(next_target(&net, 1_000_000, net.genesis_time), U256::ONE);
    }

    #[test]
    fn emission_schedule() {
        assert_eq!(reward(0), 4 * ATOMS_PER_RQT);
        let mut generated = 0u64;
        let mut h = 0u64;
        let mut half_at = None;
        while reward(generated) > TAIL_REWARD {
            generated += reward(generated);
            h += 1;
            if half_at.is_none() && generated >= MAIN_EMISSION / 2 {
                half_at = Some(h);
            }
        }
        let years = |blocks: u64| blocks as f64 / (525_600.0);
        assert!((5.0..6.0).contains(&years(half_at.unwrap())), "{}", years(half_at.unwrap()));
        assert!((21.0..23.5).contains(&years(h)), "tail after {} years", years(h));
        assert!(generated < MAIN_EMISSION);
        assert_eq!(reward(MAIN_EMISSION + 1), TAIL_REWARD);
    }
}
