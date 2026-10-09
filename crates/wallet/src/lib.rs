//! Requant wallet library: keys, bech32m addresses (BIP 350), amounts, and building signed transfers from
//! the node's UTXO listing.

use ed25519_dalek::SigningKey;
pub use requant_consensus::address::*;
use requant_consensus::params::Network;
use requant_consensus::tx::{pkh, Hash, Input, OutPoint, Output, Tx};

pub fn owner_of(key: &SigningKey) -> Hash {
    pkh(&key.verifying_key().to_bytes())
}

/// A spendable coin as listed by the node.
#[derive(Clone, Copy, Debug)]
pub struct Spendable {
    pub op: OutPoint,
    pub value: u64,
}

/// Pay `amount` to `to` from `coins` (largest first), change back to the key, `fee` to the miner.
pub fn build_transfer(
    net: &Network,
    key: &SigningKey,
    coins: &[Spendable],
    to: &Hash,
    amount: u64,
    fee: u64,
) -> Result<Tx, String> {
    if amount == 0 {
        return Err("amount must be positive".into());
    }
    let need = amount.checked_add(fee).ok_or("amount too large")?;
    let mut sorted = coins.to_vec();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.value));
    let (mut chosen, mut total) = (Vec::new(), 0u64);
    for c in sorted {
        if total >= need {
            break;
        }
        total += c.value;
        chosen.push(c);
    }
    if total < need {
        return Err(format!("insufficient funds: {} spendable, {} needed", format_amount(total), format_amount(need)));
    }
    let mut outputs = vec![Output { value: amount, pkh: *to }];
    if total > need {
        outputs.push(Output { value: total - need, pkh: owner_of(key) });
    }
    let inputs = chosen.iter().map(|c| Input { prev: c.op, pubkey: [0; 32], sig: [0; 64] }).collect();
    let mut tx = Tx::Transfer { inputs, outputs };
    let keys: Vec<&SigningKey> = chosen.iter().map(|_| key).collect();
    tx.sign(&net.chain_id, &keys);
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_building() {
        let net = Network::regtest();
        let key = SigningKey::from_bytes(&[5; 32]);
        let coins = [
            Spendable { op: OutPoint { txid: [1; 32], vout: 0 }, value: 300 },
            Spendable { op: OutPoint { txid: [2; 32], vout: 1 }, value: 1000 },
        ];
        let tx = build_transfer(&net, &key, &coins, &[9; 32], 900, 50).unwrap();
        tx.check_standalone(&net.chain_id).unwrap();
        let Tx::Transfer { inputs, outputs } = &tx else { panic!() };
        assert_eq!(inputs.len(), 1);
        assert_eq!(outputs.iter().map(|o| o.value).collect::<Vec<_>>(), [900, 50]);
        assert!(build_transfer(&net, &key, &coins, &[9; 32], 1300, 1).is_err());
    }
}

#[cfg(test)]
mod fund {
    #[test]
    fn test_network_fund_address() {
        let net = requant_consensus::params::Network::test();
        assert_eq!(
            super::address(&net, &net.dev_fund),
            "trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems"
        );
    }
}
