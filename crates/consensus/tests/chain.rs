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
