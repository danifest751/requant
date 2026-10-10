//! One-way payment channels (SWAPS.md §3): a client pays a server in many small steps from one deposit,
//! with two transactions on the chain.
//!
//! 1. The client locks a deposit under 2-of-2 (client, server) with a funding transfer it signs but does
//!    not send yet. The channel file carries that transfer without signatures (the txid does not cover
//!    them), so the server cannot lock the client's coins before it signs the refund.
//! 2. The server signs the refund: the whole deposit back to the client, valid from the expiry height.
//! 3. The client sends the funding transfer.
//! 4. Each payment is a new state signed by the client: a transfer from the deposit paying the server the
//!    total so far and the client the rest. A newer state always pays the server more.
//! 5. Before the expiry the server countersigns the last state and sends it. If it does not, the client
//!    sends the refund at the expiry.
//!
//! The file holds no secrets: public keys, destinations, the deposit, the expiry and the two transfers.

use crate::contracts::who;
use ed25519_dalek::{Signature, VerifyingKey};
use requant_consensus::address::address;
use requant_consensus::params::Network;
use requant_consensus::tx::{multi2_owner, Hash, Input, OutPoint, Output, Tx, Unlock};
use requant_node::rpc::{hex, unhex};
use serde_json::{json, Value};

/// The fee of the refund and of every state (they are about 300 bytes: above the minimum rate). With
/// package relay a child of either can add to it.
pub const CHANNEL_FEE: u64 = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    /// Public keys: the client signs first, the server second.
    pub client: [u8; 32],
    pub server: [u8; 32],
    /// Where the refund and the client's change from each state go.
    pub client_to: Hash,
    /// Where the payments go.
    pub server_to: Hash,
    pub deposit: u64,
    /// The refund is valid from this height; the server must close before it.
    pub expiry: u64,
    /// The funding transfer, without signatures, and the output that holds the deposit.
    pub funding: Tx,
    pub vout: u32,
    /// The key hash of each funding input, for the client to sign it later.
    pub funding_owners: Vec<Hash>,
    /// The refund, signed by the client (and by the server once it accepted).
    pub refund: Tx,
    /// The total the client has paid so far (the client's own record).
    pub paid: u64,
}

fn h32(v: &Value, what: &str) -> Result<[u8; 32], String> {
    v.as_str()
        .and_then(|s| unhex(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or(format!("{what}: expected 64 hex digits"))
}

fn tx_of(v: &Value, what: &str) -> Result<Tx, String> {
    let b = v.as_str().and_then(|s| unhex(s).ok()).ok_or(format!("{what}: expected hex"))?;
    Tx::decode_exact(&b).map_err(|e| format!("{what}: {e}"))
}

/// A copy of `tx` without signatures (same txid).
pub fn without_signatures(tx: &Tx) -> Tx {
    let mut t = tx.clone();
    if let Tx::Transfer { inputs, .. } = &mut t {
        for i in inputs {
            i.sig = [0; 64];
            if let Unlock::Multi2 { sig2, .. } = &mut i.unlock {
                *sig2 = [0; 64];
            }
        }
    }
    t
}

fn verify(key: &[u8; 32], msg: &Hash, sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|k| k.verify_strict(msg, &Signature::from_bytes(sig)).is_ok())
}

impl Channel {
    /// The hash the deposit pays: 2-of-2 of the client and the server.
    pub fn owner(&self) -> Hash {
        multi2_owner(&self.client, &self.server)
    }

    pub fn outpoint(&self) -> OutPoint {
        OutPoint { txid: self.funding.txid(), vout: self.vout }
    }

    /// The input spending the deposit (client key first, the server's second; no signatures yet).
    fn input(&self) -> Input {
        Input {
            pubkey: self.client,
            unlock: Unlock::Multi2 { pubkey2: self.server, sig2: [0; 64] },
            ..Input::new(self.outpoint())
        }
    }

    /// The refund as it must be: the deposit less the fee to the client, from the expiry height.
    pub fn refund_template(&self) -> Tx {
        Tx::Transfer {
            inputs: vec![Input { after_height: self.expiry, ..self.input() }],
            outputs: vec![Output { value: self.deposit - CHANNEL_FEE, pkh: self.client_to }],
        }
    }

    /// The state paying the server `paid` in total (the client gets the rest, if any), unsigned.
    pub fn state(&self, paid: u64) -> Result<Tx, String> {
        let most = self.deposit - CHANNEL_FEE;
        if paid == 0 || paid > most {
            return Err(format!("a payment total from 0.00000001 to {} RQT", crate::format_amount(most)));
        }
        let mut outputs = vec![Output { value: paid, pkh: self.server_to }];
        if paid < most {
            outputs.push(Output { value: most - paid, pkh: self.client_to });
        }
        Ok(Tx::Transfer { inputs: vec![self.input()], outputs })
    }

    /// Open a channel: `funding` is the client's signed funding transfer, whose output `vout` pays the
    /// deposit to the 2-of-2; `refund` gets the client's signature by the caller.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: [u8; 32],
        server: [u8; 32],
        client_to: Hash,
        server_to: Hash,
        expiry: u64,
        funding: &Tx,
        vout: u32,
        funding_owners: Vec<Hash>,
    ) -> Result<Channel, String> {
        let out = funding.outputs().get(vout as usize).ok_or("the funding output is missing")?;
        if out.pkh != multi2_owner(&client, &server) {
            return Err("the funding output does not pay the channel's 2-of-2".into());
        }
        if out.value <= 2 * CHANNEL_FEE {
            return Err("the deposit must be more than the fees".into());
        }
        let mut c = Channel {
            client,
            server,
            client_to,
            server_to,
            deposit: out.value,
            expiry,
            funding: without_signatures(funding),
            vout,
            funding_owners,
            refund: Tx::Transfer { inputs: vec![], outputs: vec![] },
            paid: 0,
        };
        c.refund = c.refund_template();
        Ok(c)
    }

    /// Whether the client's signature on input 0 of `tx` is valid.
    fn client_signed(&self, net: &Network, tx: &Tx) -> bool {
        let Tx::Transfer { inputs, .. } = tx else { return false };
        inputs.len() == 1 && verify(&self.client, &tx.input_sighash(&net.chain_id, &tx.txid(), 0), &inputs[0].sig)
    }

    /// Whether the server's signature on the refund is there and valid.
    pub fn refund_accepted(&self, net: &Network) -> bool {
        self.refund.check_standalone(&net.chain_id).is_ok()
    }

    /// The checks every party makes on a channel file: the deposit pays the 2-of-2, the refund is exactly
    /// the deposit back to the client from the expiry, and the client signed it.
    pub fn check(&self, net: &Network) -> Result<(), String> {
        let out = self.funding.outputs().get(self.vout as usize).ok_or("the funding output is missing")?;
        if out.pkh != self.owner() || out.value != self.deposit {
            return Err("the funding output does not pay the deposit to the channel's 2-of-2".into());
        }
        if self.deposit <= 2 * CHANNEL_FEE {
            return Err("the deposit must be more than the fees".into());
        }
        if self.funding_owners.len() != self.funding.inputs_len() {
            return Err("one owner per funding input".into());
        }
        if self.refund.txid() != self.refund_template().txid() {
            return Err("the refund is not the deposit back to the client from the expiry".into());
        }
        if !self.client_signed(net, &self.refund) {
            return Err("the client's signature on the refund is missing or wrong".into());
        }
        if self.paid > self.deposit - CHANNEL_FEE {
            return Err("paid exceeds the deposit".into());
        }
        Ok(())
    }

    /// What a state signed by the client pays the server; refused unless it is a state of this channel
    /// with a valid client signature.
    pub fn paid_by(&self, net: &Network, state: &Tx) -> Result<u64, String> {
        let paid = state.outputs().first().map(|o| o.value).ok_or("not a channel state")?;
        let want = self.state(paid)?;
        if state.txid() != want.txid() {
            return Err("not a state of this channel".into());
        }
        if !self.client_signed(net, state) {
            return Err("the client's signature on the state is missing or wrong".into());
        }
        Ok(paid)
    }

    pub fn to_json(&self, net: &Network) -> Value {
        json!({
            "requant_channel": 1,
            "network": net.name,
            "client": hex(&self.client),
            "server": hex(&self.server),
            "client_to": address(net, &self.client_to),
            "server_to": address(net, &self.server_to),
            "deposit": self.deposit,
            "expiry": self.expiry,
            "address": address(net, &self.owner()),
            "funding": hex(&self.funding.encode()),
            "funding_txid": hex(&self.funding.txid()),
            "vout": self.vout,
            "funding_owners": self.funding_owners.iter().map(|o| hex(o)).collect::<Vec<_>>(),
            "refund": hex(&self.refund.encode()),
            "accepted": self.refund_accepted(net),
            "paid": self.paid,
        })
    }

    /// Read a channel file and make the checks of [`Channel::check`].
    pub fn from_json(net: &Network, v: &Value) -> Result<Channel, String> {
        if v["requant_channel"] != json!(1) {
            return Err("not a channel file".into());
        }
        if v["network"] != json!(net.name) {
            return Err(format!("a channel of the {} network", v["network"].as_str().unwrap_or("?")));
        }
        let addr = |k: &str| who(net, v[k].as_str().ok_or(format!("{k} missing"))?);
        let num = |k: &str| v[k].as_u64().ok_or(format!("{k}: expected a number"));
        let c = Channel {
            client: h32(&v["client"], "client")?,
            server: h32(&v["server"], "server")?,
            client_to: addr("client_to")?,
            server_to: addr("server_to")?,
            deposit: num("deposit")?,
            expiry: num("expiry")?,
            funding: without_signatures(&tx_of(&v["funding"], "funding")?),
            vout: u32::try_from(num("vout")?).map_err(|_| "vout: too large")?,
            funding_owners: v["funding_owners"]
                .as_array()
                .ok_or("funding_owners missing")?
                .iter()
                .map(|o| h32(o, "funding owner"))
                .collect::<Result<_, _>>()?,
            refund: tx_of(&v["refund"], "refund")?,
            paid: num("paid")?,
        };
        c.check(net)?;
        Ok(c)
    }
}

trait InputsLen {
    fn inputs_len(&self) -> usize;
}

impl InputsLen for Tx {
    fn inputs_len(&self) -> usize {
        match self {
            Tx::Transfer { inputs, .. } => inputs.len(),
            Tx::Coinbase { .. } => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use requant_consensus::tx::pkh;

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn pk(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    /// A channel of 10 RQT between client key 1 and server key 2, funded from a coin of key 3.
    fn open(net: &Network) -> (Channel, Tx) {
        let (client, server, payer) = (key(1), key(2), key(3));
        let mut funding = Tx::Transfer {
            inputs: vec![Input::new(OutPoint { txid: [9; 32], vout: 0 })],
            outputs: vec![
                Output { value: 5, pkh: pkh(&pk(&payer)) },
                Output { value: 1_000_000_000, pkh: multi2_owner(&pk(&client), &pk(&server)) },
            ],
        };
        funding.sign(&net.chain_id, &[&payer]);
        let mut c = Channel::new(
            pk(&client),
            pk(&server),
            pkh(&pk(&client)),
            [7; 32],
            500,
            &funding,
            1,
            vec![pkh(&pk(&payer))],
        )
        .unwrap();
        c.refund.sign(&net.chain_id, &[&client]);
        (c, funding)
    }

    #[test]
    fn a_channel_from_opening_to_closing() {
        let net = Network::regtest();
        let (mut c, funding) = open(&net);
        // the shared copy of the funding has no signatures and the same txid
        assert_eq!(c.funding.txid(), funding.txid());
        assert!(c.funding.check_standalone(&net.chain_id).is_err());
        assert!(c.check(&net).is_ok() && !c.refund_accepted(&net));
        // the server countersigns the refund; the file round-trips
        c.refund.sign_second(&net.chain_id, 0, &key(2));
        assert!(c.refund_accepted(&net));
        let back = Channel::from_json(&net, &c.to_json(&net)).unwrap();
        assert_eq!(back, c);
        // states: the client signs, the server reads the total and countersigns the last
        let mut last = None;
        for paid in [100_000, 2_500_000, 999_999_000] {
            let mut s = c.state(paid).unwrap();
            s.sign(&net.chain_id, &[&key(1)]);
            assert_eq!(c.paid_by(&net, &s), Ok(paid));
            last = Some(s);
        }
        let mut close = last.unwrap();
        assert_eq!(close.outputs().len(), 1, "everything to the server: no change output");
        close.sign_second(&net.chain_id, 0, &key(2));
        assert!(close.check_standalone(&net.chain_id).is_ok());
        assert!(c.state(999_999_001).is_err() && c.state(0).is_err());
    }

    #[test]
    fn forged_files_and_states_are_refused() {
        let net = Network::regtest();
        let (c, _) = open(&net);
        // a refund to someone else, or valid earlier than the expiry
        let mut v = c.to_json(&net);
        let mut early = c.clone();
        early.expiry = 400;
        let mut r = early.refund_template();
        r.sign(&net.chain_id, &[&key(1)]);
        v["refund"] = json!(hex(&r.encode()));
        assert!(Channel::from_json(&net, &v).is_err());
        // a deposit that is not in the funding output
        let mut v = c.to_json(&net);
        v["deposit"] = json!(2_000_000_000u64);
        assert!(Channel::from_json(&net, &v).is_err());
        // a refund the client did not sign
        let mut v = c.to_json(&net);
        v["refund"] = json!(hex(&c.refund_template().encode()));
        assert_eq!(
            Channel::from_json(&net, &v),
            Err("the client's signature on the refund is missing or wrong".into())
        );
        // a state signed by another key, or paying another address
        let mut s = c.state(5000).unwrap();
        s.sign(&net.chain_id, &[&key(4)]);
        assert!(c.paid_by(&net, &s).is_err());
        let mut other = c.clone();
        other.server_to = [8; 32];
        let mut s = other.state(5000).unwrap();
        s.sign(&net.chain_id, &[&key(1)]);
        assert_eq!(c.paid_by(&net, &s), Err("not a state of this channel".into()));
        // another network
        assert!(Channel::from_json(&Network::test(), &c.to_json(&net)).is_err());
    }
}
