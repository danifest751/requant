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

/// Test network launch time. ASERT is anchored at genesis, so this must be the launch moment: a time in
/// the past lets easy blocks through until the height catches up with the schedule.
pub const TEST_GENESIS_TIME: u64 = 1_791_567_240;
/// Test network starting target, `2^229`: about `2^27` tickets per block, one minute on a Turing GPU
/// (3 M tickets/s), so the launch is not an instamine at the easiest target.
pub const TEST_GENESIS_TARGET_BITS: u32 = 229;
pub const REGTEST_GENESIS_TIME: u64 = 1_791_504_000;

/// Development fund: 6% of the block reward for heights `1..=2^21` (about four years).
pub const DEV_FUND_PERCENT: u64 = 6;
pub const DEV_FUND_LAST: u64 = 1 << 21;
/// Test network fund owner: key hash of the project owner's fund key,
/// address `trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems`.
pub const TEST_DEV_FUND: [u8; 32] = [
    0x62, 0x6c, 0x8a, 0xec, 0x88, 0x5a, 0x2d, 0x85, 0xdc, 0x50, 0x9c, 0x9a, 0x14, 0x01, 0xbc, 0x93, 0x7a, 0x76, 0x6c,
    0xaa, 0xc2, 0x34, 0xa6, 0x76, 0x0f, 0x3f, 0x49, 0xff, 0xf2, 0xe9, 0xa2, 0x01,
];

/// Publicly known regtest fund key (`[0xde; 32]`); for tests only.
/// Height from which the test network accepts kind-2 transfers (it ran without them before).
pub const TEST_CONDITIONS_HEIGHT: u64 = 1400;

pub fn regtest_dev_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0xde; 32])
}

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
    /// Owner of the development fund output (CHAIN.md §8).
    pub dev_fund: [u8; 32],
    /// Last height that pays the development fund.
    pub dev_fund_last: u64,
    /// First height whose blocks may contain kind-2 transfers (spending conditions and time locks,
    /// CHAIN.md §4.1). 0 on networks that have them from genesis.
    pub conditions_height: u64,
    /// Cumulative work of a known good chain. Until a node's tip has this much work it is still syncing and
    /// does not apply its reorganisation limit, so a cheap chain served first cannot lock it out of the real
    /// one. Raised at releases; not a consensus rule.
    pub min_chain_work: U256,
}

impl Network {
    fn make(
        name: &'static str,
        tnet: tnet::Params,
        epoch: (u64, u64),
        limit_bits: u32,
        time: u64,
        maturity: u64,
        dev_fund: ([u8; 32], u64),
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
            dev_fund: dev_fund.0,
            dev_fund_last: dev_fund.1,
            conditions_height: 0,
            min_chain_work: U256::ZERO,
        }
    }

    pub fn test() -> Self {
        let mut n =
            Self::make("test", tnet::V1, (1440, 60), 248, TEST_GENESIS_TIME, 100, (TEST_DEV_FUND, DEV_FUND_LAST));
        n.genesis_target = U256::low_mask(TEST_GENESIS_TARGET_BITS);
        // chainwork of the test network at height 355 (2026-10-10)
        n.min_chain_work = U256([0x12_2219_6194, 0, 0, 0]);
        // conditions and time locks came to the running test network at this height (node 0.15.0)
        n.conditions_height = TEST_CONDITIONS_HEIGHT;
        n
    }

    pub fn regtest() -> Self {
        let p = tnet::Params { n: 256, b: 64, layers: 4, w: 64, mult: 14170 };
        Self::make(
            "regtest",
            p,
            (16, 4),
            255,
            REGTEST_GENESIS_TIME,
            2,
            (crate::tx::pkh(&regtest_dev_key().verifying_key().to_bytes()), 8),
        )
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
