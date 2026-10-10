//! End-to-end consensus tests on regtest: mining, spending, rejections, reorganisations.

use ed25519_dalek::SigningKey;
use requant_consensus::block::{tx_root, Block};
use requant_consensus::chain::{mine, Accepted, Chain};
use requant_consensus::params::{Network, ATOMS_PER_RQT};
use requant_consensus::pow::reward;
use requant_consensus::tx::{pkh, Hash, Input, OutPoint, Output, Tx};
use requant_consensus::Error;

const NOW: u64 = u64::MAX / 2;

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

fn addr(k: &SigningKey) -> Hash {
    pkh(&k.verifying_key().to_bytes())
}

fn seal(chain: &mut Chain, mut b: Block) -> Block {
    let seed = chain.epoch_seed(&b.header.prev, b.header.height);
    let epoch = chain.epoch(&seed);
    b.claim = mine(&chain.net, &epoch, &b.header, 0, 1000).expect("regtest ticket");
    b
}

fn time_of(chain: &Chain, height: u64) -> u64 {
    chain.net.genesis_time + 60 * height
}

/// Mine one block on `parent` paying `payee`.
fn block_on(chain: &mut Chain, parent: &Hash, payee: &Hash, txs: Vec<Tx>) -> Block {
    let h = chain.block(parent).unwrap().header.height + 1;
    let t = time_of(chain, h);
    let b = chain.template_on(parent, payee, txs, t);
    seal(chain, b)
}

fn extend(chain: &mut Chain, payee: &Hash, txs: Vec<Tx>) -> Block {
    let tip = chain.tip();
    let b = block_on(chain, &tip, payee, txs);
    assert_eq!(chain.accept(b.clone(), NOW), Ok(Accepted::NewTip));
    b
}

fn spend(chain: &Chain, from: &SigningKey, op: OutPoint, to: &Hash, value: u64) -> Tx {
    let coin = chain.coin(&op).expect("coin");
    let mut outputs = vec![Output { value, pkh: *to }];
    if coin.output.value > value + 1000 {
        outputs.push(Output { value: coin.output.value - value - 1000, pkh: addr(from) });
        // fee 1000
    }
    let mut tx = Tx::Transfer { inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }], outputs };
    tx.sign(&chain.net.chain_id, &[from]);
    tx
}

#[test]
fn mine_and_spend() {
    let mut chain = Chain::new(Network::regtest(), 2);
    let (alice, bob) = (key(1), key(2));
    let first = extend(&mut chain, &addr(&alice), vec![]);
    for _ in 0..3 {
        extend(&mut chain, &addr(&alice), vec![]);
    }
    assert_eq!(chain.height(), 4);
    assert_eq!(chain.coins_of(&addr(&alice)).len(), 4);
    let op = OutPoint { txid: first.txs[0].txid(), vout: 0 };
    let tx = spend(&chain, &alice, op, &addr(&bob), ATOMS_PER_RQT);
    let issued_before = chain.issued();
    let b = extend(&mut chain, &addr(&alice), vec![tx]);
    // coinbase collected the reward plus the 1000-atom fee
    let paid: u64 = b.txs[0].outputs().iter().map(|o| o.value).sum();
    assert_eq!(paid, reward(issued_before) + 1000);
    assert_eq!(chain.coins_of(&addr(&bob)).iter().map(|(_, c)| c.output.value).sum::<u64>(), ATOMS_PER_RQT);
    assert!(chain.coin(&op).is_none());
}

#[test]
fn issuance_matches_the_formula() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let mut issued = 0u64;
    for _ in 0..6 {
        let b = extend(&mut chain, &addr(&key(1)), vec![]);
        assert_eq!(b.txs[0].outputs().iter().map(|o| o.value).sum::<u64>(), reward(issued));
        issued += reward(issued);
        assert_eq!(chain.issued(), issued);
    }
}

#[test]
fn rejections() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let alice = key(1);
    let first = extend(&mut chain, &addr(&alice), vec![]);
    let tip = chain.tip();

    // tampered piece
    let mut b = block_on(&mut chain, &tip, &addr(&alice), vec![]);
    b.claim.piece[0] = b.claim.piece[0].wrapping_add(1);
    assert!(matches!(chain.accept(b, NOW), Err(Error::Invalid(_))));

    // wrong target (header changes, so re-mine)
    let mut b = chain.template(&addr(&alice), vec![], time_of(&chain, 2));
    b.header.target = b.header.target.mul_shift(1, -1).unwrap();
    let b = seal(&mut chain, b);
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("target")));

    // time not after median time past
    let mut b = chain.template(&addr(&alice), vec![], 0);
    b.header.time = chain.net.genesis_time;
    let b = seal(&mut chain, b);
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("time not after median time past")));

    // too far in the future
    let b = chain.template(&addr(&alice), vec![], time_of(&chain, 2) + 10_000);
    let b = seal(&mut chain, b);
    assert_eq!(chain.accept(b, time_of(&chain, 2)), Err(Error::Invalid("time too far in the future")));

    // immature coinbase (maturity 2 on regtest; block 1's coinbase spent at height 2)
    let op = OutPoint { txid: first.txs[0].txid(), vout: 0 };
    let tx = spend(&chain, &alice, op, &addr(&key(2)), 1000);
    let b = block_on(&mut chain, &tip, &addr(&alice), vec![tx]);
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("immature coinbase spend")));
    assert_eq!(chain.tip(), tip, "failed block left the chain unchanged");
    assert!(chain.coin(&op).is_some());

    // greedy coinbase
    let mut b = chain.template(&addr(&alice), vec![], time_of(&chain, 2));
    if let Tx::Coinbase { outputs, .. } = &mut b.txs[0] {
        outputs[0].value += 1;
    }
    b.header.tx_root = tx_root(&b.txs);
    let b = seal(&mut chain, b);
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("coinbase pays more than reward plus fees")));

    // unknown parent, duplicate
    let mut b = chain.template(&addr(&alice), vec![], time_of(&chain, 2));
    b.header.prev = [9; 32];
    assert_eq!(chain.accept(b, NOW), Err(Error::UnknownParent));
    let good = block_on(&mut chain, &tip, &addr(&alice), vec![]);
    assert_eq!(chain.accept(good.clone(), NOW), Ok(Accepted::NewTip));
    assert_eq!(chain.accept(good, NOW), Err(Error::Duplicate));
}

#[test]
fn double_spend_and_wrong_key() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let (alice, bob) = (key(1), key(2));
    let first = extend(&mut chain, &addr(&alice), vec![]);
    extend(&mut chain, &addr(&alice), vec![]);
    let op = OutPoint { txid: first.txs[0].txid(), vout: 0 };
    let a = spend(&chain, &alice, op, &addr(&bob), 1000);
    let b = spend(&chain, &alice, op, &addr(&key(3)), 2000);
    let tip = chain.tip();
    let blk = block_on(&mut chain, &tip, &addr(&alice), vec![a.clone(), b]);
    assert_eq!(chain.accept(blk, NOW), Err(Error::Invalid("missing or spent input")));
    // bob signs alice's coin
    let stolen = spend(&chain, &bob, op, &addr(&bob), 1000);
    let blk = block_on(&mut chain, &tip, &addr(&alice), vec![stolen]);
    assert_eq!(chain.accept(blk, NOW), Err(Error::Invalid("input key does not match the output")));
    let blk = block_on(&mut chain, &tip, &addr(&alice), vec![a]);
    assert_eq!(chain.accept(blk, NOW), Ok(Accepted::NewTip));
}

#[test]
fn reorg_to_more_work_and_back_on_invalid() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let (alice, bob) = (key(1), key(2));
    let base = extend(&mut chain, &addr(&alice), vec![]);
    let base_id = base.id(&chain.net);
    // main chain: two more blocks paying alice
    let a1 = extend(&mut chain, &addr(&alice), vec![]);
    extend(&mut chain, &addr(&alice), vec![]);
    let main_tip = chain.tip();
    // side chain from base: three blocks paying bob
    let s1 = block_on(&mut chain, &base_id, &addr(&bob), vec![]);
    let s1_id = s1.id(&chain.net);
    assert_eq!(chain.accept(s1, NOW), Ok(Accepted::SideChain));
    let s2 = block_on(&mut chain, &s1_id, &addr(&bob), vec![]);
    let s2_id = s2.id(&chain.net);
    assert_eq!(chain.accept(s2, NOW), Ok(Accepted::SideChain), "equal work keeps the first seen");
    let s3 = block_on(&mut chain, &s2_id, &addr(&bob), vec![]);
    let s3_id = s3.id(&chain.net);
    assert_eq!(chain.accept(s3, NOW), Ok(Accepted::Reorg { disconnected: 2 }));
    assert_eq!(chain.tip(), s3_id);
    assert_eq!(chain.coins_of(&addr(&bob)).len(), 3);
    assert_eq!(chain.coins_of(&addr(&alice)).len(), 1);
    assert!(chain.coin(&OutPoint { txid: a1.txs[0].txid(), vout: 0 }).is_none());

    // main chain grows to five blocks, but its fourth contains an invalid spend: the chain stays on s3
    let m3 = block_on(&mut chain, &main_tip, &addr(&alice), vec![]);
    let m3_id = m3.id(&chain.net);
    assert_eq!(chain.accept(m3, NOW), Ok(Accepted::SideChain));
    let mut bad_tx = Tx::Transfer {
        inputs: vec![Input { prev: OutPoint { txid: [7; 32], vout: 0 }, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![Output { value: 1, pkh: addr(&bob) }],
    };
    bad_tx.sign(&chain.net.chain_id, &[&bob]);
    let m4 = block_on(&mut chain, &m3_id, &addr(&alice), vec![bad_tx]);
    let m4_id = m4.id(&chain.net);
    assert_eq!(chain.accept(m4, NOW), Err(Error::Invalid("missing or spent input")));
    assert_eq!(chain.tip(), s3_id);
    let m5 = block_on(&mut chain, &m4_id, &addr(&alice), vec![]);
    assert_eq!(chain.accept(m5, NOW), Err(Error::Invalid("invalid parent")));
    assert_eq!(chain.coins_of(&addr(&bob)).len(), 3, "UTXO set restored after the failed reorg");
    assert_eq!(chain.coins_of(&addr(&alice)).len(), 1);
}

#[test]
fn epochs_change_the_weights() {
    let net = Network::regtest();
    let (len, back) = (net.epoch_len, net.lookback);
    let mut chain = Chain::new(net, 1);
    for _ in 0..len + 1 {
        extend(&mut chain, &addr(&key(1)), vec![]);
    }
    let tip = chain.tip();
    let e0 = chain.epoch_seed(&tip, len - 1);
    let e1 = chain.epoch_seed(&tip, len);
    assert_ne!(e0, e1);
    assert_eq!(e1, chain.epoch_seed(&tip, 2 * len - 1));
    // the seed of epoch 1 is fixed by block len - back
    let anchor = chain.active_id(len - back).unwrap();
    let mut m = b"requant/epoch".to_vec();
    m.extend_from_slice(&1u64.to_le_bytes());
    m.extend_from_slice(&anchor);
    assert_eq!(e1, tnet::sha256::sha256(&m));
}

#[test]
fn development_fund_share_and_sunset() {
    let net = Network::regtest();
    let last = net.dev_fund_last;
    let fund = net.dev_fund;
    let mut chain = Chain::new(net, 1);
    let miner = addr(&key(1));
    // a block that pays everything to the miner is rejected while the fund is due
    let mut b = chain.template(&miner, vec![], time_of(&chain, 1));
    let total: u64 = b.txs[0].outputs().iter().map(|o| o.value).sum();
    if let Tx::Coinbase { outputs, .. } = &mut b.txs[0] {
        *outputs = vec![Output { value: total, pkh: miner }];
    }
    b.header.tx_root = tx_root(&b.txs);
    let b = seal(&mut chain, b);
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("coinbase misses the development fund share")));
    // templates pay 6% to the fund up to `last`, nothing after
    let mut issued = 0u64;
    for h in 1..=last + 3 {
        let b = extend(&mut chain, &miner, vec![]);
        let to_fund: u64 = b.txs[0].outputs().iter().filter(|o| o.pkh == fund).map(|o| o.value).sum();
        let expected = if h <= last { reward(issued) * 6 / 100 } else { 0 };
        assert_eq!(to_fund, expected, "height {h}");
        issued += reward(issued);
    }
    // the fund's coins are spendable by its key after maturity
    let dev = requant_consensus::params::regtest_dev_key();
    let coins = chain.coins_of(&fund);
    assert_eq!(coins.len() as u64, last);
    let (op, coin) = coins[0];
    let mut tx = Tx::Transfer {
        inputs: vec![Input { prev: op, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![Output { value: coin.output.value, pkh: miner }],
    };
    tx.sign(&chain.net.chain_id, &[&dev]);
    extend(&mut chain, &miner, vec![tx]);
}

#[test]
fn trusted_replay_locator_and_spend_checks() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let alice = key(1);
    let mut blocks = Vec::new();
    for _ in 0..12 {
        blocks.push(extend(&mut chain, &addr(&alice), vec![]));
    }
    // replay without the work check reaches the same state
    let mut replay = Chain::new(Network::regtest(), 1);
    for b in &blocks {
        replay.accept_trusted(b.clone()).unwrap();
    }
    assert_eq!(replay.tip(), chain.tip());
    assert_eq!(replay.coins_of(&addr(&alice)), chain.coins_of(&addr(&alice)));
    // a trusted replay still enforces the transaction rules
    let mut greedy = chain.template(&addr(&alice), vec![], time_of(&chain, 13));
    if let Tx::Coinbase { outputs, .. } = &mut greedy.txs[0] {
        outputs[0].value += 1;
    }
    greedy.header.tx_root = tx_root(&greedy.txs);
    assert!(replay.accept_trusted(greedy).is_err());

    // locator and blocks_after
    let loc = chain.locator();
    assert_eq!(loc[0], chain.tip());
    assert_eq!(*loc.last().unwrap(), chain.active_id(0).unwrap());
    let fresh = Chain::new(Network::regtest(), 1);
    assert_eq!(
        chain.blocks_after(&fresh.locator(), 5),
        (1..=5).map(|h| chain.active_id(h).unwrap()).collect::<Vec<_>>()
    );
    assert!(chain.blocks_after(&loc, 5).is_empty());

    // spend checks for the mempool
    let op = OutPoint { txid: blocks[0].txs[0].txid(), vout: 0 };
    let tx = spend(&chain, &alice, op, &addr(&key(2)), 5000);
    assert_eq!(chain.check_spend(&tx), Ok(1000));
    let bob_steals = spend(&chain, &key(2), op, &addr(&key(2)), 5000);
    assert_eq!(chain.check_spend(&bob_steals), Err(Error::Invalid("input key does not match the output")));
}

#[test]
fn reorg_limit_refuses_deep_forks() {
    let mut chain = Chain::new(Network::regtest(), 1);
    chain.set_max_reorg(3);
    let alice = addr(&key(1));
    let mut ids = vec![chain.tip()];
    for _ in 0..6 {
        let b = extend(&mut chain, &alice, vec![]);
        ids.push(b.id(&chain.net));
    }
    // tip at 6: a fork from height 2 (depth 4) is refused before any work is checked
    let deep = block_on(&mut chain, &ids[2], &addr(&key(2)), vec![]);
    assert_eq!(chain.accept(deep, NOW), Err(Error::Invalid("fork deeper than the reorg limit")));
    // a fork from height 3 (depth 3) is kept as a side chain
    let ok = block_on(&mut chain, &ids[3], &addr(&key(2)), vec![]);
    assert_eq!(chain.accept(ok, NOW), Ok(Accepted::SideChain));
}

#[test]
fn reorg_limit_waits_for_min_chain_work() {
    // a node still below the known chain work (syncing) follows any fork with more work
    let mut net = Network::regtest();
    net.min_chain_work = requant_consensus::u256::U256::MAX;
    let mut chain = Chain::new(net, 1);
    chain.set_max_reorg(3);
    let alice = addr(&key(1));
    let mut ids = vec![chain.tip()];
    for _ in 0..6 {
        let b = extend(&mut chain, &alice, vec![]);
        ids.push(b.id(&chain.net));
    }
    let deep = block_on(&mut chain, &ids[2], &addr(&key(2)), vec![]);
    assert_eq!(chain.accept(deep, NOW), Ok(Accepted::SideChain));
}

#[test]
fn cheap_checks_come_first() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let alice = key(1);
    let b1 = extend(&mut chain, &addr(&alice), vec![]);
    for _ in 0..chain.net.maturity {
        extend(&mut chain, &addr(&key(9)), vec![]);
    }
    let op = OutPoint { txid: b1.txs[0].txid(), vout: 0 };
    let mut tx = spend(&chain, &alice, op, &addr(&key(2)), 5);
    if let Tx::Transfer { inputs, .. } = &mut tx {
        inputs[0].sig[0] ^= 1;
    }
    // unknown parent is reported before the (expensive) signature check
    let tip = chain.tip();
    let mut b = block_on(&mut chain, &tip, &addr(&key(3)), vec![tx]);
    b.header.prev = [7; 32];
    assert_eq!(chain.accept(b.clone(), NOW), Err(Error::UnknownParent));
    // an out-of-range claim is refused before any epoch weights are touched
    let mut b = block_on(&mut chain, &tip, &addr(&key(3)), vec![]);
    b.claim.i = chain.net.tnet.b as u32;
    assert_eq!(chain.accept(b, NOW), Err(Error::Invalid("claim index")));
}

#[test]
fn upcoming_epochs_are_announced_after_the_anchor() {
    let net = Network::regtest();
    let (len, back) = (net.epoch_len, net.lookback);
    let mut chain = Chain::new(net, 1);
    assert_eq!(chain.upcoming_epoch_seeds().len(), 1);
    while chain.height() < len - back {
        extend(&mut chain, &addr(&key(1)), vec![]);
    }
    let seeds = chain.upcoming_epoch_seeds();
    assert_eq!(seeds.len(), 2);
    assert_eq!(seeds[1], chain.epoch_seed(&chain.tip(), len));
    // precomputed weights are used as they are
    let e = std::sync::Arc::new(tnet::Epoch::from_seed(&seeds[1], chain.net.tnet));
    chain.insert_epoch(seeds[1], e.clone());
    assert!(chain.has_epoch(&seeds[1]));
    assert!(std::sync::Arc::ptr_eq(&chain.epoch(&seeds[1]), &e));
}

#[test]
fn headers_first() {
    use requant_consensus::headers::HeaderChain;
    // a source chain with a side branch
    let mut src = Chain::new(Network::regtest(), 1);
    let alice = addr(&key(1));
    let mut blocks = Vec::new();
    for _ in 0..20 {
        blocks.push(extend(&mut src, &alice, vec![]));
    }

    // headers alone reproduce the best chain, verifying every claim
    let mut weights = Chain::new(Network::regtest(), 1); // provides epoch weights
    let mut hc = HeaderChain::new(Network::regtest(), 1);
    for b in &blocks {
        assert_eq!(hc.accept(b.header, b.claim.clone(), NOW, &mut |s: &Hash| weights.epoch(s)), Ok(true));
    }
    assert_eq!(hc.height(), 20);
    assert_eq!(hc.tip(), src.tip());
    assert_eq!(hc.accept(blocks[3].header, blocks[3].claim.clone(), NOW, &mut |s: &Hash| weights.epoch(s)), Ok(false));
    assert_eq!(hc.locator()[0], src.tip());

    // a tampered claim or a wrong target is refused
    let src_tip = src.tip();
    let mut b = block_on(&mut src, &src_tip, &alice, vec![]);
    let good = b.clone();
    b.claim.piece[0] = b.claim.piece[0].wrapping_add(1);
    assert!(hc.accept(b.header, b.claim, NOW, &mut |s: &Hash| weights.epoch(s)).is_err());
    let mut t = good.clone();
    t.header.target = t.header.target.mul_shift(1, -1).unwrap();
    assert!(hc.accept(t.header, t.claim, NOW, &mut |s: &Hash| weights.epoch(s)).is_err());

    // bodies along the header chain are accepted without recomputing the claims
    let mut dst = Chain::new(Network::regtest(), 1);
    for id in hc.best_ids(1, hc.height()) {
        let b = src.block(&id).unwrap();
        assert!(dst.accept_prevalidated((*b).clone(), NOW).is_ok());
    }
    assert_eq!(dst.tip(), src.tip());

    // a heavier branch from height 18 moves the best header chain; marking it invalid moves it back
    let fork_at = src.active_id(18).unwrap();
    let s1 = block_on(&mut src, &fork_at, &addr(&key(2)), vec![]);
    let s1_id = s1.id(&src.net);
    src.accept(s1.clone(), NOW).unwrap();
    let s2 = block_on(&mut src, &s1_id, &addr(&key(2)), vec![]);
    src.accept(s2.clone(), NOW).unwrap();
    let s2_id = s2.id(&src.net);
    let s3 = block_on(&mut src, &s2_id, &addr(&key(2)), vec![]);
    src.accept(s3.clone(), NOW).unwrap();
    for b in [&s1, &s2, &s3] {
        assert_eq!(hc.accept(b.header, b.claim.clone(), NOW, &mut |s: &Hash| weights.epoch(s)), Ok(true));
    }
    assert_eq!(hc.height(), 21);
    assert_eq!(hc.tip(), s3.id(&src.net));
    hc.mark_invalid(&s1_id);
    assert_eq!(hc.height(), 20);
    assert_eq!(hc.tip(), blocks[19].id(&src.net));
    assert!(!hc.contains(&s3.id(&src.net)));

    // headers of blocks accepted elsewhere can be added without verification
    let mut hc2 = HeaderChain::new(Network::regtest(), 1);
    for b in &blocks {
        hc2.add_valid(&b.header, &b.claim);
    }
    assert_eq!(hc2.tip(), blocks[19].id(&src.net));
}

/// Two chained transfers inside one block: A pays bob, B spends A's output.
fn chained_pair(chain: &Chain, alice: &SigningKey, bob: &SigningKey, op: OutPoint) -> (Tx, Tx) {
    let a = spend(chain, alice, op, &addr(bob), 50_000);
    let mut b = Tx::Transfer {
        inputs: vec![Input { prev: OutPoint { txid: a.txid(), vout: 0 }, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![Output { value: 40_000, pkh: addr(&key(3)) }],
    };
    b.sign(&chain.net.chain_id, &[bob]);
    (a, b)
}

#[test]
fn undo_restores_exactly_after_reorg_and_failed_connect() {
    let mut chain = Chain::new(Network::regtest(), 1);
    let (alice, bob) = (key(1), key(2));
    let first = extend(&mut chain, &addr(&alice), vec![]);
    extend(&mut chain, &addr(&alice), vec![]);
    let op = OutPoint { txid: first.txs[0].txid(), vout: 0 };
    let before: Vec<_> = [addr(&alice), addr(&bob), addr(&key(3))].iter().map(|o| chain.coins_of(o)).collect();
    let fork_point = chain.tip();

    // failed connect: [coinbase, A, B, C with a missing input] must leave the UTXO set untouched
    let (a, b) = chained_pair(&chain, &alice, &bob, op);
    let mut c = Tx::Transfer {
        inputs: vec![Input { prev: OutPoint { txid: [7; 32], vout: 0 }, pubkey: [0; 32], sig: [0; 64] }],
        outputs: vec![Output { value: 1, pkh: addr(&bob) }],
    };
    c.sign(&chain.net.chain_id, &[&bob]);
    let bad = block_on(&mut chain, &fork_point, &addr(&alice), vec![a.clone(), b.clone(), c]);
    assert!(chain.accept(bad, NOW).is_err());
    assert!(chain.coin(&OutPoint { txid: a.txid(), vout: 0 }).is_none(), "phantom output after a failed connect");
    let after: Vec<_> = [addr(&alice), addr(&bob), addr(&key(3))].iter().map(|o| chain.coins_of(o)).collect();
    assert_eq!(before, after);

    // reorg: a block with A and B is disconnected by a heavier branch without them
    let good = block_on(&mut chain, &fork_point, &addr(&alice), vec![a.clone(), b]);
    assert_eq!(chain.accept(good, NOW), Ok(Accepted::NewTip));
    let s1 = block_on(&mut chain, &fork_point, &addr(&key(4)), vec![]);
    let s1_id = s1.id(&chain.net);
    chain.accept(s1, NOW).unwrap();
    let s2 = block_on(&mut chain, &s1_id, &addr(&key(4)), vec![]);
    assert!(matches!(chain.accept(s2, NOW), Ok(Accepted::Reorg { disconnected: 1 })));
    assert!(chain.coin(&OutPoint { txid: a.txid(), vout: 0 }).is_none(), "phantom output after a reorg");
    assert!(chain.coin(&op).is_some(), "the spent coin is back");
    assert!(chain.coins_of(&addr(&key(3))).is_empty());
}

#[test]
fn supply_audit_and_utxo_hash() {
    let (mut a, mut b) = (Chain::new(Network::regtest(), 1), Chain::new(Network::regtest(), 1));
    let alice = addr(&key(1));
    for _ in 0..5 {
        let blk = extend(&mut a, &alice, vec![]);
        assert!(b.accept(blk, NOW).is_ok());
    }
    // the same blocks give the same set, hash and total, within what the schedule issued
    let (total, count, hash) = a.utxo_audit();
    assert_eq!(b.utxo_audit(), (total, count, hash));
    assert!(total > 0 && total <= a.issued());
    extend(&mut a, &alice, vec![]);
    assert_ne!(a.utxo_audit().2, hash);
}

/// Bodies kept apart, as a node's block file would.
struct MapBodies(std::sync::Mutex<std::collections::HashMap<Hash, Block>>);

impl requant_consensus::chain::BodySource for MapBodies {
    fn load(&self, id: &Hash) -> Option<Block> {
        self.0.lock().unwrap().get(id).cloned()
    }
}

#[test]
fn old_bodies_leave_memory_and_a_deep_reorg_reads_them_back() {
    let src = std::sync::Arc::new(MapBodies(Default::default()));
    let mut chain = Chain::new(Network::regtest(), 1);
    let mut full = Chain::new(Network::regtest(), 1); // keeps everything in memory, for comparison
    chain.set_body_source(src.clone(), 5);
    let (alice, bob) = (addr(&key(1)), addr(&key(2)));
    let mut ids = vec![chain.tip()];
    for _ in 0..12 {
        let tip = chain.tip();
        let b = block_on(&mut chain, &tip, &alice, vec![]);
        src.0.lock().unwrap().insert(b.id(&chain.net), b.clone());
        ids.push(b.id(&chain.net));
        assert_eq!(full.accept(b.clone(), NOW), Ok(Accepted::NewTip));
        assert_eq!(chain.accept(b, NOW), Ok(Accepted::NewTip));
    }
    // genesis and the last five keep their bodies; older ones come back from the source
    assert!(chain.bodies_in_memory() <= 6, "{} bodies in memory", chain.bodies_in_memory());
    assert_eq!(chain.block(&ids[2]).unwrap().header.height, 2);
    // a branch from height 3 overtakes the tip: nine blocks are disconnected, most of them read back
    let mut parent = ids[3];
    let mut last = Accepted::SideChain;
    for _ in 0..10 {
        let b = block_on(&mut chain, &parent, &bob, vec![]);
        parent = b.id(&chain.net);
        src.0.lock().unwrap().insert(parent, b.clone());
        full.accept(b.clone(), NOW).unwrap();
        last = chain.accept(b, NOW).unwrap();
    }
    assert_eq!(last, Accepted::Reorg { disconnected: 9 });
    assert_eq!(chain.tip(), full.tip());
    assert_eq!(chain.utxo_audit(), full.utxo_audit(), "same UTXO set as a chain holding every body");
}

#[test]
fn a_restored_snapshot_equals_the_chain_and_keeps_working() {
    let src = std::sync::Arc::new(MapBodies(Default::default()));
    let mut chain = Chain::new(Network::regtest(), 1);
    let (alice, bob) = (key(1), key(2));
    let mut ids = vec![chain.tip()];
    for i in 0..8 {
        let tip = chain.tip();
        let txs = if i == 4 {
            let op = OutPoint { txid: chain.block(&ids[1]).unwrap().txs[0].txid(), vout: 0 };
            vec![spend(&chain, &alice, op, &addr(&bob), ATOMS_PER_RQT)]
        } else {
            vec![]
        };
        let b = block_on(&mut chain, &tip, &addr(&alice), txs);
        src.0.lock().unwrap().insert(b.id(&chain.net), b.clone());
        ids.push(b.id(&chain.net));
        assert_eq!(chain.accept(b, NOW), Ok(Accepted::NewTip));
    }
    // a side branch is part of the index too
    let side = block_on(&mut chain, &ids[6], &addr(&bob), vec![]);
    src.0.lock().unwrap().insert(side.id(&chain.net), side.clone());
    assert_eq!(chain.accept(side.clone(), NOW), Ok(Accepted::SideChain));

    let snap = chain.snapshot();
    let mut back = Chain::restore(Network::regtest(), 1, &snap).unwrap();
    back.set_body_source(src.clone(), 3);
    assert_eq!((back.tip(), back.height(), back.issued()), (chain.tip(), chain.height(), chain.issued()));
    assert_eq!(back.utxo_audit(), chain.utxo_audit());
    assert_eq!(back.snapshot().len(), snap.len());
    assert_eq!(back.best_headers().len() as u64, back.height());
    assert_eq!(back.block(&ids[2]).unwrap().header.height, 2, "old bodies come from the source");

    // both grow the same way, including a reorg onto the side branch read back from the source
    let mut parent = side.id(&chain.net);
    for _ in 0..3 {
        let b = block_on(&mut chain, &parent, &addr(&bob), vec![]);
        parent = b.id(&chain.net);
        src.0.lock().unwrap().insert(parent, b.clone());
        let r = chain.accept(b.clone(), NOW).unwrap();
        assert_eq!(back.accept(b, NOW).unwrap(), r);
    }
    assert_eq!(back.tip(), chain.tip());
    assert_eq!(back.utxo_audit(), chain.utxo_audit());

    // damage is refused, not half-loaded
    assert!(Chain::restore(Network::regtest(), 1, &snap[..snap.len() - 1]).is_err());
    let mut other = snap.clone();
    other[0] ^= 1;
    assert!(Chain::restore(Network::regtest(), 1, &other).is_err());
}
