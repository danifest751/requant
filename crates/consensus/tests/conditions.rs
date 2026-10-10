//! Spending conditions and time locks (CHAIN.md §4.1) on regtest: encodings, 2-of-2, HTLC claim and
//! refund, relative locks, the activation height, and a one-way payment channel built from them.

use ed25519_dalek::SigningKey;
use requant_consensus::block::Block;
use requant_consensus::chain::{mine, Accepted, Chain};
use requant_consensus::codec::Writer;
use requant_consensus::params::Network;
use requant_consensus::tx::{multi2_owner, pkh, Hash, Htlc, Input, OutPoint, Output, Tx, Unlock};
use requant_consensus::Error;

const NOW: u64 = u64::MAX / 2;

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

fn pubkey(k: &SigningKey) -> [u8; 32] {
    k.verifying_key().to_bytes()
}

fn addr(k: &SigningKey) -> Hash {
    pkh(&pubkey(k))
}

fn block_on(chain: &mut Chain, parent: &Hash, payee: &Hash, txs: Vec<Tx>) -> Block {
    let h = chain.block(parent).unwrap().header.height + 1;
    let mut b = chain.template_on(parent, payee, txs, chain.net.genesis_time + 60 * h);
    let seed = chain.epoch_seed(&b.header.prev, b.header.height);
    let epoch = chain.epoch(&seed);
    b.claim = mine(&chain.net, &epoch, &b.header, 0, 1000).expect("regtest ticket");
    b
}

fn extend(chain: &mut Chain, txs: Vec<Tx>) -> Result<Accepted, Error> {
    let tip = chain.tip();
    let b = block_on(chain, &tip, &addr(&key(1)), txs);
    chain.accept(b, NOW)
}

/// A chain whose first coinbase (paying key 1) is mature; returns it and that coin.
fn funded(net: Network) -> (Chain, OutPoint) {
    let mut chain = Chain::new(net, 1);
    let first = {
        let tip = chain.tip();
        let b = block_on(&mut chain, &tip, &addr(&key(1)), vec![]);
        let op = OutPoint { txid: b.txs[0].txid(), vout: 0 };
        chain.accept(b, NOW).unwrap();
        op
    };
    for _ in 0..chain.net.maturity {
        extend(&mut chain, vec![]).unwrap();
    }
    (chain, first)
}

/// Half of a coin (the regtest reward is small).
fn half(chain: &Chain, op: OutPoint) -> u64 {
    chain.coin(&op).unwrap().output.value / 2
}

/// Key 1 pays `value` of `op` to `owner` (a plain version-1 transfer: locking a coin under a condition
/// needs no new rule), change back; returns the transaction and the locked outpoint.
fn lock_to(chain: &Chain, op: OutPoint, owner: Hash, value: u64) -> (Tx, OutPoint) {
    let coin = chain.coin(&op).unwrap();
    let outputs =
        vec![Output { value, pkh: owner }, Output { value: coin.output.value - value - 1000, pkh: addr(&key(1)) }];
    let mut tx = Tx::Transfer { inputs: vec![Input::new(op)], outputs };
    tx.sign(&chain.net.chain_id, &[&key(1)]);
    assert!(!tx.is_v2());
    let locked = OutPoint { txid: tx.txid(), vout: 0 };
    (tx, locked)
}

/// A one-input transfer of `input` paying `outputs`, signed by `first` (and `second` for 2-of-2).
fn spend(chain: &Chain, input: Input, outputs: Vec<Output>, first: &SigningKey, second: Option<&SigningKey>) -> Tx {
    let mut tx = Tx::Transfer { inputs: vec![input], outputs };
    tx.sign(&chain.net.chain_id, &[first]);
    if let Some(k) = second {
        tx.sign_second(&chain.net.chain_id, 0, k);
    }
    tx
}

fn multi2_input(op: OutPoint, second: &SigningKey) -> Input {
    Input { unlock: Unlock::Multi2 { pubkey2: pubkey(second), sig2: [0; 64] }, ..Input::new(op) }
}

#[test]
fn encodings_are_canonical_and_txids_exclude_signatures() {
    let op = OutPoint { txid: [3; 32], vout: 1 };
    let htlc = Htlc { hash: [4; 32], claim: [5; 32], refund: [6; 32], timeout: 77 };
    let unlocks = [
        Unlock::Key,
        Unlock::Multi2 { pubkey2: [7; 32], sig2: [8; 64] },
        Unlock::HtlcClaim { htlc, preimage: [9; 32] },
        Unlock::HtlcRefund { htlc },
    ];
    for (k, unlock) in unlocks.into_iter().enumerate() {
        let inp =
            Input { pubkey: [1; 32], sig: [2; 64], after_height: 5, after_blocks: k as u32, unlock, ..Input::new(op) };
        let tx = Tx::Transfer { inputs: vec![inp], outputs: vec![Output { value: 1, pkh: [0; 32] }] };
        let bytes = tx.encode();
        assert_eq!(bytes[4], 2, "kind 2");
        assert_eq!(Tx::decode_exact(&bytes), Ok(tx.clone()));
        // signatures (both of a 2-of-2) do not change the txid; locks and the preimage do
        let with = |f: &dyn Fn(&mut Input)| {
            let mut other = tx.clone();
            let Tx::Transfer { inputs, .. } = &mut other else { unreachable!() };
            f(&mut inputs[0]);
            other
        };
        let resigned = with(&|i| {
            i.sig = [0xee; 64];
            if let Unlock::Multi2 { sig2, .. } = &mut i.unlock {
                *sig2 = [0xee; 64];
            }
        });
        assert_eq!(resigned.txid(), tx.txid());
        assert_ne!(resigned.wtxid(), tx.wtxid());
        assert_ne!(with(&|i| i.after_height = 6).txid(), tx.txid());
    }
    // a plain transfer stays kind 1, byte for byte as before
    let plain = Tx::Transfer { inputs: vec![Input::new(op)], outputs: vec![Output { value: 1, pkh: [0; 32] }] };
    assert_eq!(plain.encode()[4], 1);
    // kind 2 with nothing that needs it is refused (one encoding per transaction), as is an unknown unlock
    let kind2 = |unlock_kind: u8| {
        let mut w = Writer::default();
        w.u32(1);
        w.u8(2);
        w.varint(1);
        w.raw(&op.txid);
        w.u32(op.vout);
        w.raw(&[1; 32]);
        w.raw(&[2; 64]);
        w.u64(0);
        w.u32(0);
        w.u8(unlock_kind);
        w.varint(1);
        w.u64(1);
        w.raw(&[0; 32]);
        w.0
    };
    assert!(Tx::decode_exact(&kind2(0)).is_err());
    assert!(Tx::decode_exact(&kind2(9)).is_err());
}

#[test]
fn two_of_two_needs_both_keys_in_order() {
    let (mut chain, coin) = funded(Network::regtest());
    let v = half(&chain, coin);
    let (a, b) = (key(2), key(3));
    let owner = multi2_owner(&pubkey(&a), &pubkey(&b));
    let (lock, locked) = lock_to(&chain, coin, owner, v);
    assert_eq!(extend(&mut chain, vec![lock]), Ok(Accepted::NewTip));
    let out = vec![Output { value: v - 1000, pkh: addr(&key(4)) }];

    // one signature is not enough
    let one = spend(&chain, multi2_input(locked, &b), out.clone(), &a, None);
    assert_eq!(one.check_signatures(&chain.net.chain_id), Err(Error::Invalid("bad signature")));
    // the keys in the other order are another owner
    let swapped = spend(&chain, multi2_input(locked, &a), out.clone(), &b, Some(&a));
    swapped.check_signatures(&chain.net.chain_id).unwrap();
    assert_eq!(chain.check_spend(&swapped), Err(Error::Invalid("input key does not match the output")));
    // both, in order
    let both = spend(&chain, multi2_input(locked, &b), out, &a, Some(&b));
    both.check_standalone(&chain.net.chain_id).unwrap();
    assert_eq!(chain.check_spend(&both), Ok(1000));
    assert_eq!(extend(&mut chain, vec![both]), Ok(Accepted::NewTip));
    assert!(chain.coin(&locked).is_none());
}

#[test]
fn htlc_claim_with_the_preimage_refund_after_the_timeout() {
    let (mut chain, coin) = funded(Network::regtest());
    let v = half(&chain, coin);
    let (claimer, refunder) = (key(5), key(6));
    let preimage = [42u8; 32];
    let timeout = chain.height() + 6;
    let htlc = Htlc { hash: tnet::sha256::sha256(&preimage), claim: addr(&claimer), refund: addr(&refunder), timeout };
    let (lock, locked) = lock_to(&chain, coin, htlc.owner(), v);
    assert_eq!(extend(&mut chain, vec![lock]), Ok(Accepted::NewTip));
    let out = |to: &SigningKey| vec![Output { value: v - 1000, pkh: addr(to) }];
    let claim = |preimage: [u8; 32], by: &SigningKey| {
        let inp = Input { unlock: Unlock::HtlcClaim { htlc, preimage }, ..Input::new(locked) };
        spend(&chain, inp, out(by), by, None)
    };
    let refund = |after_height: u64| {
        let inp = Input { after_height, unlock: Unlock::HtlcRefund { htlc }, ..Input::new(locked) };
        spend(&chain, inp, out(&refunder), &refunder, None)
    };

    // claim: the right preimage and the claim key, at any time
    assert_eq!(chain.check_spend(&claim([41; 32], &claimer)), Err(Error::Invalid("htlc preimage does not match")));
    assert_eq!(chain.check_spend(&claim(preimage, &refunder)), Err(Error::Invalid("htlc claim by another key")));
    assert_eq!(chain.check_spend(&claim(preimage, &claimer)), Ok(1000));
    // refund: must commit to a height at or after the timeout, and that height must have come
    assert_eq!(chain.check_spend(&refund(timeout - 1)), Err(Error::Invalid("htlc refund before its timeout")));
    let early = refund(timeout);
    assert_eq!(chain.check_spend(&early), Err(Error::Invalid("input time lock not yet passed")));
    assert!(extend(&mut chain, vec![early.clone()]).is_err(), "a block cannot contain it yet");
    while chain.height() + 1 < timeout {
        extend(&mut chain, vec![]).unwrap();
    }
    assert_eq!(chain.check_spend(&early), Ok(1000));
    assert_eq!(extend(&mut chain, vec![early]), Ok(Accepted::NewTip));
    assert!(chain.coin(&locked).is_none());
}

#[test]
fn relative_lock_counts_from_the_coins_block() {
    let (mut chain, coin) = funded(Network::regtest());
    let v = half(&chain, coin);
    let (lock, locked) = lock_to(&chain, coin, addr(&key(7)), v);
    assert_eq!(extend(&mut chain, vec![lock]), Ok(Accepted::NewTip));
    let coin_height = chain.height();
    let inp = Input { after_blocks: 3, ..Input::new(locked) };
    let tx = spend(&chain, inp, vec![Output { value: v - 1000, pkh: addr(&key(8)) }], &key(7), None);
    assert!(tx.is_v2());
    while chain.height() + 1 < coin_height + 3 {
        assert_eq!(chain.check_spend(&tx), Err(Error::Invalid("input time lock not yet passed")));
        assert!(extend(&mut chain, vec![tx.clone()]).is_err());
        extend(&mut chain, vec![]).unwrap();
    }
    assert_eq!(chain.check_spend(&tx), Ok(1000));
    assert_eq!(extend(&mut chain, vec![tx]), Ok(Accepted::NewTip));
}

#[test]
fn kind_2_waits_for_the_activation_height() {
    let mut net = Network::regtest();
    net.conditions_height = 8;
    let (mut chain, coin) = funded(net);
    assert!(chain.height() + 1 < 8);
    // the smallest kind-2 transfer: a plain key spend with an already-passed absolute lock
    let inp = Input { after_height: 1, ..Input::new(coin) };
    let value = chain.coin(&coin).unwrap().output.value;
    let tx = spend(&chain, inp, vec![Output { value: value - 1000, pkh: addr(&key(9)) }], &key(1), None);
    let inactive = Err(Error::Invalid("conditions and time locks are not active at this height"));
    while chain.height() + 1 < 8 {
        assert_eq!(chain.check_spend(&tx), inactive);
        assert!(extend(&mut chain, vec![tx.clone()]).is_err());
        extend(&mut chain, vec![]).unwrap();
    }
    assert_eq!(chain.check_spend(&tx), Ok(1000));
    assert_eq!(extend(&mut chain, vec![tx]), Ok(Accepted::NewTip));
}

/// A one-way channel (MagnetGate paying for traffic): the client locks coins under 2-of-2 with the
/// server, the server signs a refund to the client that waits for an expiry height, the client signs
/// ever larger payments to the server, and the server publishes the last one before the expiry.
#[test]
fn one_way_payment_channel() {
    let (mut chain, coin) = funded(Network::regtest());
    let v = half(&chain, coin);
    let (client, server) = (key(1), key(10));
    let deposit = v;
    let owner = multi2_owner(&pubkey(&client), &pubkey(&server));
    let (fund, channel) = lock_to(&chain, coin, owner, deposit);
    assert_eq!(extend(&mut chain, vec![fund]), Ok(Accepted::NewTip));
    let expiry = chain.height() + 20;

    // the refund, signed by both now, valid only from the expiry
    let refund_in = Input { after_height: expiry, ..multi2_input(channel, &server) };
    let refund =
        spend(&chain, refund_in, vec![Output { value: deposit - 1000, pkh: addr(&client) }], &client, Some(&server));
    assert_eq!(chain.check_spend(&refund), Err(Error::Invalid("input time lock not yet passed")));

    // payments: each state pays the server more; the client signs first, the server countersigns
    let state = |paid: u64| {
        let outputs = vec![
            Output { value: paid, pkh: addr(&server) },
            Output { value: deposit - paid - 1000, pkh: addr(&client) },
        ];
        spend(&chain, multi2_input(channel, &server), outputs, &client, Some(&server))
    };
    let states: Vec<Tx> = (1..=3).map(|k| state(k * (deposit / 10))).collect();
    for s in &states {
        assert_eq!(chain.check_spend(s), Ok(1000));
    }
    // the server closes with the last state; the refund can then never be used
    assert_eq!(extend(&mut chain, vec![states[2].clone()]), Ok(Accepted::NewTip));
    let paid = OutPoint { txid: states[2].txid(), vout: 0 };
    assert_eq!(chain.coin(&paid).unwrap().output.value, 3 * (deposit / 10));
    assert_eq!(chain.check_spend(&refund), Err(Error::Invalid("missing or spent input")));
}
