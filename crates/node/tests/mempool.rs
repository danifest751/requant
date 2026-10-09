//! Mempool spam bounds on regtest: the minimum fee, eviction by fee rate when full, descendants evicted
//! with their parent.

use ed25519_dalek::SigningKey;
use requant_consensus::chain::{mine, Chain};
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Input, OutPoint, Output, Tx};
use requant_consensus::Error;
use requant_node::mempool::Mempool;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

/// A chain whose first `n` coinbases pay `key()` and have matured.
fn funded(n: u64) -> (Chain, Vec<OutPoint>) {
    let net = Network::regtest();
    let mut chain = Chain::new(net.clone(), 1);
    let me = pkh(&key().verifying_key().to_bytes());
    let mut coins = Vec::new();
    for h in 1..=n + net.maturity {
        let tip = chain.tip();
        let mut b = chain.template_on(&tip, &me, vec![], net.genesis_time + 60 * h);
        let seed = chain.epoch_seed(&tip, h);
        let epoch = chain.epoch(&seed);
        b.claim = mine(&net, &epoch, &b.header, 0, 1000).unwrap();
        if h <= n {
            coins.push(OutPoint { txid: b.txs[0].txid(), vout: 0 });
        }
        chain.accept(b, u64::MAX / 2).unwrap();
    }
    (chain, coins)
}

/// Spend `op` (worth `value`) to ourselves leaving `fee`.
fn spend(chain: &Chain, op: OutPoint, value: u64, fee: u64) -> Tx {
    let me = pkh(&key().verifying_key().to_bytes());
    let mut tx = Tx::Transfer {
        inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![Output { value: value - fee, pkh: me }],
    };
    tx.sign(&chain.net.chain_id, &[&key()]);
    tx
}

#[test]
fn minimum_fee_eviction_by_rate_and_descendants() {
    let (chain, coins) = funded(4);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len();

    // below 1 atom per byte: refused
    let mut pool = Mempool::default();
    let cheap = spend(&chain, coins[0], value(&coins[0]), size as u64 - 1);
    assert_eq!(pool.add(cheap, &chain), Err(Error::Invalid("fee below the minimum (1 atom per byte)")));

    // a pool with room for two transactions
    let mut pool = Mempool::with_limit(2 * size + 10);
    let low = spend(&chain, coins[0], value(&coins[0]), 1000);
    let low_id = pool.add(low.clone(), &chain).unwrap();
    // its child (spends low's output) rides on it
    let child = spend(&chain, OutPoint { txid: low_id, vout: 0 }, low.outputs()[0].value, 5000);
    let child_id = pool.add(child, &chain).unwrap();
    assert_eq!(pool.len(), 2);
    // full: a lower rate than everything there is refused
    let lower = spend(&chain, coins[1], value(&coins[1]), 500);
    assert_eq!(pool.add(lower, &chain), Err(Error::Invalid("pool full: the fee rate is too low")));
    // a higher rate pushes out the cheapest transaction, and its child with it
    let high = spend(&chain, coins[2], value(&coins[2]), 9000);
    let high_id = pool.add(high, &chain).unwrap();
    assert!(pool.contains(&high_id));
    assert!(!pool.contains(&low_id) && !pool.contains(&child_id), "the cheapest and what spends it are gone");
    assert!(pool.bytes() <= 2 * size + 10);
}
