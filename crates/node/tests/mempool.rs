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
    let mut tx = Tx::Transfer { inputs: vec![Input::new(op)], outputs: vec![Output { value: value - fee, pkh: me }] };
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

#[test]
fn fee_estimate_follows_the_queue() {
    let (chain, coins) = funded(3);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len();
    let mut pool = Mempool::default();
    // an empty pool: the minimum gets in
    assert_eq!(pool.rate_for(1000), 1);
    // three transactions at 10, 20 and 30 atoms per byte
    for (k, r) in [10u64, 20, 30].iter().enumerate() {
        pool.add(spend(&chain, coins[k], value(&coins[k]), r * size as u64), &chain).unwrap();
    }
    // room for all three ahead: the minimum; room for one: beat the second (20); for two: beat 10
    assert_eq!(pool.rate_for(3 * size), 1);
    assert_eq!(pool.rate_for(size), 21);
    assert_eq!(pool.rate_for(2 * size), 11);
    assert_eq!(pool.rate_for(0), 31);
}

/// One more empty block on the tip.
fn grow(chain: &mut Chain) {
    let me = pkh(&key().verifying_key().to_bytes());
    let (tip, h) = (chain.tip(), chain.height() + 1);
    let mut b = chain.template_on(&tip, &me, vec![], chain.net.genesis_time + 60 * h);
    let seed = chain.epoch_seed(&tip, h);
    let epoch = chain.epoch(&seed);
    b.claim = mine(&chain.net, &epoch, &b.header, 0, 1000).unwrap();
    chain.accept(b, u64::MAX / 2).unwrap();
}

#[test]
fn time_locked_transactions_wait_outside_the_pool() {
    let (mut chain, coins) = funded(2);
    let me = pkh(&key().verifying_key().to_bytes());
    let value = chain.coin(&coins[0]).unwrap().output.value;
    let chain_id = chain.net.chain_id;
    let locked = |inp: Input| {
        let mut tx = Tx::Transfer { inputs: vec![inp], outputs: vec![Output { value: value - 1000, pkh: me }] };
        tx.sign(&chain_id, &[&key()]);
        tx
    };
    let not_yet = Err(Error::Invalid("input time lock not yet passed"));
    // absolute: valid from height next+2
    let abs = locked(Input { after_height: chain.height() + 3, ..Input::new(coins[0]) });
    let mut pool = Mempool::default();
    assert_eq!(pool.add(abs.clone(), &chain), not_yet);
    grow(&mut chain);
    assert_eq!(pool.add(abs.clone(), &chain), not_yet);
    grow(&mut chain);
    assert!(pool.add(abs, &chain).is_ok());
    // relative: the coin of block 2 needs 50 blocks above it
    let rel = locked(Input { after_blocks: 50, ..Input::new(coins[1]) });
    assert_eq!(pool.add(rel, &chain), not_yet);
    assert_eq!(pool.len(), 1);
}
