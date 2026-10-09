//! Network parameters (CHAIN.md §2).

use crate::u256::U256;
use tnet::sha256::sha256;

/// `H(tag, x) = SHA256(tag || x)`.
pub fn tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let mut m = Vec::with_capacity(tag.len() + parts.iter().map(|p| p.len()).sum::<usize>());
    m.extend_from_slice(tag.as_bytes());
    for p in parts {
        m.extend_from_slice(p);
    }
    sha256(&m)
}

pub const ATOMS_PER_RQT: u64 = 100_000_000;
/// Largest serialized block.
pub const MAX_BLOCK_BYTES: usize = 1 << 20;
pub const MAX_TX_IO: u64 = 10_000;
pub const MAX_COINBASE_EXTRA: usize = 64;
/// Largest sum of amounts.
pub const MAX_AMOUNT: u64 = 1 << 63;
pub const MTP_WINDOW: usize = 11;
/// Nodes hold back blocks dated further ahead than this (not a consensus rule).
pub const MAX_FUTURE_SECS: u64 = 7200;

/// Test network genesis time: to be set to the launch time before the test network starts, since ASERT
/// is anchored at genesis (a genesis time far in the past would allow easy blocks until the schedule
/// catches up).
pub const TEST_GENESIS_TIME: u64 = 1_791_504_000;
pub const REGTEST_GENESIS_TIME: u64 = 1_791_504_000;

#[derive(Clone, Debug)]
pub struct Network {
    pub name: &'static str,
    pub chain_id: [u8; 32],
    pub tnet: tnet::Params,
    /// Target spacing `T` in seconds.
    pub spacing: i64,
    /// ASERT half-life `tau` in seconds.
    pub half_life: i64,
    /// Epoch length `E` and look-back `K` in blocks.
    pub epoch_len: u64,
    pub lookback: u64,
    pub pow_limit: U256,
    pub genesis_target: U256,
    pub genesis_time: u64,
    pub maturity: u64,
}

impl Network {
    fn make(
        name: &'static str,
        tnet: tnet::Params,
        epoch: (u64, u64),
        limit_bits: u32,
        time: u64,
        maturity: u64,
    ) -> Self {
        let pow_limit = U256::low_mask(limit_bits);
        Network {
            name,
            chain_id: tagged("requant/chain", &[name.as_bytes()]),
            tnet,
            spacing: 60,
            half_life: 7200,
            epoch_len: epoch.0,
            lookback: epoch.1,
            pow_limit,
            genesis_target: pow_limit,
            genesis_time: time,
            maturity,
        }
    }

    pub fn test() -> Self {
        Self::make("test", tnet::V1, (1440, 60), 248, TEST_GENESIS_TIME, 100)
    }

    pub fn regtest() -> Self {
        let p = tnet::Params { n: 256, b: 64, layers: 4, w: 64, mult: 14170 };
        Self::make("regtest", p, (16, 4), 255, REGTEST_GENESIS_TIME, 2)
    }

    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "test" => Some(Self::test()),
            "regtest" => Some(Self::regtest()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_are_consistent() {
        for net in [Network::test(), Network::regtest()] {
            assert!(net.genesis_target <= net.pow_limit);
            assert!(net.lookback < net.epoch_len);
            assert_eq!(net.tnet.n % net.tnet.w, 0);
            assert_eq!(tnet::default_mult(net.tnet.n), net.tnet.mult);
        }
        assert_ne!(Network::test().chain_id, Network::regtest().chain_id);
    }
}
