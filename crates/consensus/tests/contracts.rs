//! Revocable outputs, revocable HTLCs and anyone-can-pay signatures (CHAIN.md §4.2) on regtest:
//! encodings, every spending path with its delays, adding inputs to an anyone-can-pay transfer, and the
//! activation height.

use ed25519_dalek::SigningKey;
use requant_consensus::block::Block;
use requant_consensus::chain::{mine, Accepted, Chain};
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Delayed, Hash, HtlcRevocable, Input, OutPoint, Output, Tx, Unlock};
use requant_consensus::Error;

const NOW: u64 = u64::MAX / 2;

fn key(b: u8) -> SigningKey {
    SigningKey::from_bytes(&[b; 32])
}

fn addr(k: &SigningKey) -> Hash {
    pkh(&k.verifying_key().to_bytes())
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

/// A chain with `n` mature coinbases paying key 1; returns it and those coins.
fn funded(net: Network, n: usize) -> (Chain, Vec<OutPoint>) {
    let mut chain = Chain::new(net, 1);
    let mut coins = Vec::new();
    for _ in 0..n {
        let tip = chain.tip();
        let b = block_on(&mut chain, &tip, &addr(&key(1)), vec![]);
        coins.push(OutPoint { txid: b.txs[0].txid(), vout: 0 });
        chain.accept(b, NOW).unwrap();
    }
    for _ in 0..chain.net.maturity {
        extend(&mut chain, vec![]).unwrap();
    }
    (chain, coins)
}

/// Key 1 locks half of `op` under `owner` with an ordinary transfer; returns it, the locked outpoint and
/// its value.
fn lock_to(chain: &Chain, op: OutPoint, owner: Hash) -> (Tx, OutPoint, u64) {
    let value = chain.coin(&op).unwrap().output.value / 2;
    let change = chain.coin(&op).unwrap().output.value - value - 1000;
    let mut tx = Tx::Transfer {
        inputs: vec![Input::new(op)],
        outputs: vec![Output { value, pkh: owner }, Output { value: change, pkh: addr(&key(1)) }],
    };
    tx.sign(&chain.net.chain_id, &[&key(1)]);
    let locked = OutPoint { txid: tx.txid(), vout: 0 };
    (tx, locked, value)
}

fn spend(id: &Hash, input: Input, value: u64, by: &SigningKey) -> Tx {
    let mut tx = Tx::Transfer { inputs: vec![input], outputs: vec![Output { value: value - 1000, pkh: addr(by) }] };
    tx.sign(id, &[by]);
    tx
}

fn delayed() -> Delayed {
    Delayed { owner: addr(&key(2)), revoke: addr(&key(3)), delay: 5 }
}

fn revocable(preimage: &[u8; 32], timeout: u64) -> HtlcRevocable {
    HtlcRevocable {
        hash: tnet::sha256::sha256(preimage),
        claim: addr(&key(4)),
        refund: addr(&key(5)),
        revoke: addr(&key(6)),
        timeout,
        claim_delay: 2,
        refund_delay: 3,
    }
}

#[test]
fn encodings_round_trip_and_flags_ride_in_the_unlock_byte() {
    let op = OutPoint { txid: [3; 32], vout: 1 };
    let h = revocable(&[9; 32], 77);
    let unlocks = [
        Unlock::DelayedOwner { d: delayed() },
        Unlock::DelayedRevoke { d: delayed() },
        Unlock::RevocableClaim { h, preimage: [9; 32] },
        Unlock::RevocableRefund { h },
        Unlock::RevocableRevoke { h },
        Unlock::Key,
    ];
    for (k, unlock) in unlocks.into_iter().enumerate() {
        for acp in [false, true] {
            if unlock == Unlock::Key && !acp {
                continue; // a plain input: kind 1
            }
            let inp = Input {
                pubkey: [1; 32],
                sig: [2; 64],
                after_blocks: k as u32,
                unlock,
                anyone_can_pay: acp,
                ..Input::new(op)
            };
            let tx = Tx::Transfer { inputs: vec![inp], outputs: vec![Output { value: 1, pkh: [0; 32] }] };
            let bytes = tx.encode();
            assert_eq!(bytes[4], 2, "kind 2");
            assert_eq!(Tx::decode_exact(&bytes), Ok(tx.clone()));
            assert!(tx.uses_contracts());
        }
    }
    // the first conditions keep their exact encoding and do not count as the later contracts
    let old = Input {
        unlock: Unlock::HtlcRefund {
            htlc: requant_consensus::tx::Htlc { hash: [1; 32], claim: [2; 32], refund: [3; 32], timeout: 4 },
        },
        ..Input::new(op)
    };
    let tx = Tx::Transfer { inputs: vec![old], outputs: vec![Output { value: 1, pkh: [0; 32] }] };
    assert!(tx.is_v2() && !tx.uses_contracts());
    // owners differ from each other and from every parameter change
    let d = delayed();
    assert_ne!(d.owner_hash(), Delayed { delay: 6, ..d }.owner_hash());
    assert_ne!(d.owner_hash(), Delayed { owner: d.revoke, revoke: d.owner, ..d }.owner_hash());
    assert_ne!(h.owner(), HtlcRevocable { claim_delay: 9, ..h }.owner());
}

#[test]
fn revocable_output_owner_waits_revoker_does_not() {
    let (mut chain, coins) = funded(Network::regtest(), 1);
    let d = delayed();
    let (lock, locked, v) = lock_to(&chain, coins[0], d.owner_hash());
    let id = chain.net.chain_id;
    assert_eq!(extend(&mut chain, vec![lock]), Ok(Accepted::NewTip));

    // the owner must commit to the delay, and the delay must have passed
    let owner = |after_blocks: u32| {
        spend(&id, Input { after_blocks, unlock: Unlock::DelayedOwner { d }, ..Input::new(locked) }, v, &key(2))
    };
    assert_eq!(chain.check_spend(&owner(4)), Err(Error::Invalid("delayed output spent before its delay")));
    assert_eq!(chain.check_spend(&owner(5)), Err(Error::Invalid("input time lock not yet passed")));
    // another key on the owner path, or on the revocation path
    let wrong =
        spend(&id, Input { after_blocks: 5, unlock: Unlock::DelayedOwner { d }, ..Input::new(locked) }, v, &key(3));
    assert_eq!(chain.check_spend(&wrong), Err(Error::Invalid("delayed output spent by another key")));
    let wrong = spend(&id, Input { unlock: Unlock::DelayedRevoke { d }, ..Input::new(locked) }, v, &key(2));
    assert_eq!(chain.check_spend(&wrong), Err(Error::Invalid("revocation by another key")));
    // the revocation key takes it at once: the penalty for publishing a revoked channel state
    let revoke = spend(&id, Input { unlock: Unlock::DelayedRevoke { d }, ..Input::new(locked) }, v, &key(3));
    assert_eq!(chain.check_spend(&revoke), Ok(1000));
    // the owner, once the coin is deep enough
    for _ in 0..4 {
        extend(&mut chain, vec![]).unwrap();
    }
    let late = owner(5);
    assert_eq!(chain.check_spend(&late), Ok(1000));
    assert_eq!(extend(&mut chain, vec![late]), Ok(Accepted::NewTip));
    assert!(chain.coin(&locked).is_none());
}

#[test]
fn revocable_htlc_paths_and_their_delays() {
    let (mut chain, coins) = funded(Network::regtest(), 1);
    let preimage = [42u8; 32];
    let timeout = chain.height() + 4;
    let h = revocable(&preimage, timeout);
    let (lock, locked, v) = lock_to(&chain, coins[0], h.owner());
    let id = chain.net.chain_id;
    assert_eq!(extend(&mut chain, vec![lock]), Ok(Accepted::NewTip));
    let input = |after_height: u64, after_blocks: u32, unlock: Unlock| Input {
        after_height,
        after_blocks,
        unlock,
        ..Input::new(locked)
    };

    // claim: preimage, claim key, claim delay
    let claim =
        |preimage, after_blocks| spend(&id, input(0, after_blocks, Unlock::RevocableClaim { h, preimage }), v, &key(4));
    assert_eq!(chain.check_spend(&claim([1; 32], 2)), Err(Error::Invalid("htlc preimage does not match")));
    assert_eq!(chain.check_spend(&claim(preimage, 1)), Err(Error::Invalid("htlc claim before its delay")));
    assert_eq!(chain.check_spend(&claim(preimage, 2)), Err(Error::Invalid("input time lock not yet passed")));
    // refund: timeout and refund delay
    let refund = |after_height, after_blocks| {
        spend(&id, input(after_height, after_blocks, Unlock::RevocableRefund { h }), v, &key(5))
    };
    assert_eq!(chain.check_spend(&refund(timeout - 1, 3)), Err(Error::Invalid("htlc refund before its timeout")));
    assert_eq!(chain.check_spend(&refund(timeout, 2)), Err(Error::Invalid("htlc refund before its delay")));
    // revoke: any time, revocation key only
    let revoke = spend(&id, input(0, 0, Unlock::RevocableRevoke { h }), v, &key(6));
    assert_eq!(chain.check_spend(&revoke), Ok(1000));
    let wrong = spend(&id, input(0, 0, Unlock::RevocableRevoke { h }), v, &key(4));
    assert_eq!(chain.check_spend(&wrong), Err(Error::Invalid("revocation by another key")));
    // after the delays and the timeout, claim and refund both work
    for _ in 0..4 {
        extend(&mut chain, vec![]).unwrap();
    }
    assert_eq!(chain.check_spend(&claim(preimage, 2)), Ok(1000));
    assert_eq!(chain.check_spend(&refund(timeout, 3)), Ok(1000));
}

#[test]
fn anyone_can_pay_lets_others_add_inputs_but_not_change_outputs() {
    let (mut chain, coins) = funded(Network::regtest(), 2);
    let id = chain.net.chain_id;
    let (a, b) = (chain.coin(&coins[0]).unwrap().output.value, chain.coin(&coins[1]).unwrap().output.value);
    let payee = addr(&key(7));
    // key 1 signs its coin anyone-can-pay towards one output, leaving a large fee
    let mut tx = Tx::Transfer {
        inputs: vec![Input { anyone_can_pay: true, ..Input::new(coins[0]) }],
        outputs: vec![Output { value: a - 5000, pkh: payee }],
    };
    tx.sign(&id, &[&key(1)]);
    tx.check_standalone(&id).unwrap();
    assert_eq!(chain.check_spend(&tx), Ok(5000));
    // someone adds a second input (here the same key's other coin, plainly signed): the first signature
    // still holds, and the fee grows by the whole added coin
    let mut bumped = tx.clone();
    if let Tx::Transfer { inputs, .. } = &mut bumped {
        inputs.push(Input::new(coins[1]));
    }
    bumped.sign_input(&id, 1, &key(1));
    bumped.check_standalone(&id).unwrap();
    assert_eq!(chain.check_spend(&bumped), Ok(5000 + b));
    // changing an output breaks the anyone-can-pay signature
    let mut changed = bumped.clone();
    if let Tx::Transfer { outputs, .. } = &mut changed {
        outputs[0].value -= 1;
    }
    assert_eq!(changed.check_signatures(&id), Err(Error::Invalid("bad signature")));
    // a plain signature does not survive an added input
    let mut plain =
        Tx::Transfer { inputs: vec![Input::new(coins[0])], outputs: vec![Output { value: a - 5000, pkh: payee }] };
    plain.sign(&id, &[&key(1)]);
    if let Tx::Transfer { inputs, .. } = &mut plain {
        inputs.push(Input::new(coins[1]));
    }
    plain.sign_input(&id, 1, &key(1));
    assert_eq!(plain.check_signatures(&id), Err(Error::Invalid("bad signature")));
    assert_eq!(extend(&mut chain, vec![bumped]), Ok(Accepted::NewTip));
}

#[test]
fn contracts_wait_for_their_activation_height() {
    let mut net = Network::regtest();
    net.contracts_height = 8;
    let (mut chain, coins) = funded(net, 1);
    assert!(chain.height() + 1 < 8);
    let mut tx = Tx::Transfer {
        inputs: vec![Input { anyone_can_pay: true, ..Input::new(coins[0]) }],
        outputs: vec![Output { value: 1000, pkh: addr(&key(7)) }],
    };
    tx.sign(&chain.net.chain_id, &[&key(1)]);
    assert_eq!(
        extend(&mut chain, vec![tx.clone()]),
        Err(Error::Invalid("revocable outputs and anyone-can-pay are not active at this height"))
    );
    while chain.height() + 1 < 8 {
        extend(&mut chain, vec![]).unwrap();
    }
    assert_eq!(extend(&mut chain, vec![tx]), Ok(Accepted::NewTip));
}
