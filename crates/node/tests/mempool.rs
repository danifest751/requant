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

#[test]
fn blocks_take_the_best_package_child_pays_for_parent() {
    let (chain, coins) = funded(3);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len();
    let mut pool = Mempool::default();
    // a cheap parent (minimum fee) and a child paying a lot for both
    let parent = spend(&chain, coins[0], value(&coins[0]), size as u64);
    let parent_id = pool.add(parent.clone(), &chain).unwrap();
    let child = spend(&chain, OutPoint { txid: parent_id, vout: 0 }, parent.outputs()[0].value, 40 * size as u64);
    let child_id = pool.add(child, &chain).unwrap();
    // an unrelated transaction paying more than the parent alone, less than parent with child
    let middle = spend(&chain, coins[1], value(&coins[1]), 10 * size as u64);
    let middle_id = pool.add(middle, &chain).unwrap();
    // room for two: the parent-and-child package wins over the middle one
    let (txs, fees) = pool.select(2 * size + 10);
    let ids: Vec<_> = txs.iter().map(|t| t.txid()).collect();
    assert_eq!(ids, vec![parent_id, child_id], "parent first, then child");
    assert_eq!(fees, 41 * size as u64);
    // with room for all three, everything goes, parents before children
    let (txs, _) = pool.select(10 * size);
    let ids: Vec<_> = txs.iter().map(|t| t.txid()).collect();
    assert_eq!(ids.len(), 3);
    assert!(ids.iter().position(|i| *i == parent_id) < ids.iter().position(|i| *i == child_id));
    assert!(ids.contains(&middle_id));
}

#[test]
fn replace_by_fee_rules() {
    let (chain, coins) = funded(2);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len() as u64;
    let mut pool = Mempool::default();
    let first = spend(&chain, coins[0], value(&coins[0]), 2 * size);
    let first_id = pool.add(first.clone(), &chain).unwrap();
    let child = spend(&chain, OutPoint { txid: first_id, vout: 0 }, first.outputs()[0].value, 2 * size);
    let child_id = pool.add(child, &chain).unwrap();
    // the same coin with too little extra: must cover what it evicts (4 * size) plus its own size
    let weak = spend(&chain, coins[0], value(&coins[0]), 4 * size);
    assert_eq!(
        pool.add(weak, &chain),
        Err(Error::Invalid("replacement must pay more than what it replaces, plus its own size"))
    );
    // enough: replaces the first and its child
    let strong = spend(&chain, coins[0], value(&coins[0]), 5 * size);
    let strong_id = pool.add(strong, &chain).unwrap();
    assert!(pool.contains(&strong_id) && !pool.contains(&first_id) && !pool.contains(&child_id));
    assert_eq!(pool.len(), 1);
    // a later replacement must again pay more, and at a higher rate
    let same = spend(&chain, coins[0], value(&coins[0]), 5 * size);
    assert!(pool.add(same, &chain).is_err());
}

#[test]
fn a_well_paying_child_protects_its_parent_from_eviction() {
    let (chain, coins) = funded(4);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len();
    let mut pool = Mempool::with_limit(3 * size + 10);
    let parent = spend(&chain, coins[0], value(&coins[0]), size as u64);
    let parent_id = pool.add(parent.clone(), &chain).unwrap();
    let child = spend(&chain, OutPoint { txid: parent_id, vout: 0 }, parent.outputs()[0].value, 30 * size as u64);
    let child_id = pool.add(child, &chain).unwrap();
    let other = spend(&chain, coins[1], value(&coins[1]), 4 * size as u64);
    let other_id = pool.add(other, &chain).unwrap();
    // full; a newcomer paying 6 per byte: the parent pays 1 alone but 15.5 with its child, so the
    // 4-per-byte transaction goes instead
    let newcomer = spend(&chain, coins[2], value(&coins[2]), 6 * size as u64);
    let newcomer_id = pool.add(newcomer, &chain).unwrap();
    assert!(pool.contains(&parent_id) && pool.contains(&child_id) && pool.contains(&newcomer_id));
    assert!(!pool.contains(&other_id));
}

/// A parent paying nothing, spending `op` (worth `value`).
fn free_parent(chain: &Chain, op: OutPoint, value: u64) -> Tx {
    spend(chain, op, value, 0)
}

#[test]
fn package_relay_a_child_pays_for_a_parent_below_the_minimum() {
    let (chain, coins) = funded(3);
    let value = |op: &OutPoint| chain.coin(op).unwrap().output.value;
    let size = spend(&chain, coins[0], value(&coins[0]), 1000).encode().len() as u64;
    let mut pool = Mempool::default();
    // a pre-signed parent paying nothing is refused on its own, and its child alone has no parent
    let parent = free_parent(&chain, coins[0], value(&coins[0]));
    let parent_id = parent.txid();
    let child = spend(&chain, OutPoint { txid: parent_id, vout: 0 }, parent.outputs()[0].value, 3 * size);
    assert_eq!(pool.add(parent.clone(), &chain), Err(Error::Invalid("fee below the minimum (1 atom per byte)")));
    assert_eq!(pool.add(child.clone(), &chain), Err(Error::Invalid("missing or spent input")));
    // child first, a lone transaction, an unrelated member: refused
    assert!(pool.add_package(vec![child.clone(), parent.clone()], &chain).is_err());
    assert!(pool.add_package(vec![parent.clone()], &chain).is_err());
    let other = spend(&chain, coins[1], value(&coins[1]), 5 * size);
    assert_eq!(
        pool.add_package(vec![parent.clone(), other], &chain),
        Err(Error::Invalid("not a transaction with its parents"))
    );
    // a child paying for itself and half of the parent: the pair is below the minimum
    let stingy = spend(&chain, OutPoint { txid: parent_id, vout: 0 }, parent.outputs()[0].value, size + size / 2);
    assert_eq!(
        pool.add_package(vec![parent.clone(), stingy], &chain),
        Err(Error::Invalid("package fee below the minimum (1 atom per byte)"))
    );
    assert!(pool.is_empty(), "nothing of a refused package stays");
    // together they pay 1.5 atoms per byte: admitted, and blocks take both, parent first
    let ids = pool.add_package(vec![parent.clone(), child.clone()], &chain).unwrap();
    let child_id = child.txid();
    assert_eq!(ids, vec![parent_id, child_id]);
    assert_eq!(pool.add_package(vec![parent, child], &chain), Err(Error::Duplicate));
    let (txs, fees) = pool.select(10 * size as usize);
    assert_eq!(txs.iter().map(|t| t.txid()).collect::<Vec<_>>(), vec![parent_id, child_id]);
    assert_eq!(fees, 3 * size);
}

#[test]
fn a_parent_nothing_pays_for_leaves_the_pool() {
    let (mut chain, coins) = funded(2);
    let (v0, v1) = (chain.coin(&coins[0]).unwrap().output.value, chain.coin(&coins[1]).unwrap().output.value);
    let size = spend(&chain, coins[0], v0, 1000).encode().len() as u64;
    let me = pkh(&key().verifying_key().to_bytes());
    let mut pool = Mempool::default();
    let parent = free_parent(&chain, coins[0], v0);
    let parent_id = parent.txid();
    // the child spends the parent's coin and another one
    let mut child = Tx::Transfer {
        inputs: vec![Input::new(OutPoint { txid: parent_id, vout: 0 }), Input::new(coins[1])],
        outputs: vec![Output { value: parent.outputs()[0].value + v1 - 6 * size, pkh: me }],
    };
    child.sign(&chain.net.chain_id, &[&key(), &key()]);
    pool.add_package(vec![parent, child.clone()], &chain).unwrap();
    // a new block changes nothing: the child still pays for both
    grow(&mut chain);
    pool.revalidate(&chain);
    assert_eq!(pool.len(), 2);
    // the child is replaced through its other coin: nothing pays for the parent any more
    let replacement = spend(&chain, coins[1], v1, 20 * size);
    let replacement_id = pool.add(replacement, &chain).unwrap();
    assert!(pool.contains(&replacement_id));
    assert!(!pool.contains(&child.txid()) && !pool.contains(&parent_id), "the parent left with its payer");
    assert_eq!(pool.len(), 1);
}
