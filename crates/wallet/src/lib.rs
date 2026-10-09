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

/// Default fee rate in atoms per byte, and the smallest fee the wallet pays.
pub const DEFAULT_FEE_RATE: u64 = 5;
pub const MIN_FEE: u64 = 1000;
/// Inputs per transaction (a node accepts transactions up to 100 kB; an input takes 132 bytes).
pub const MAX_INPUTS: usize = 600;

/// Serialized size of a transfer with `inputs` inputs and `outputs` outputs (varints counted at 3 bytes).
pub fn transfer_size(inputs: usize, outputs: usize) -> u64 {
    (4 + 1 + 3 + 132 * inputs + 3 + 40 * outputs) as u64
}

/// Fee for that size at `rate` atoms per byte, at least `MIN_FEE`.
pub fn fee_for(inputs: usize, outputs: usize, rate: u64) -> u64 {
    transfer_size(inputs, outputs).saturating_mul(rate).max(MIN_FEE)
}

fn signed(net: &Network, key: &SigningKey, chosen: &[Spendable], outputs: Vec<Output>) -> Tx {
    let inputs = chosen.iter().map(|c| Input { prev: c.op, pubkey: [0; 32], sig: [0; 64] }).collect();
    let mut tx = Tx::Transfer { inputs, outputs };
    let keys: Vec<&SigningKey> = chosen.iter().map(|_| key).collect();
    tx.sign(&net.chain_id, &keys);
    tx
}

/// Pay every `(to, amount)` of `payments` from `coins` (largest first), change back to the key, a fee of
/// `rate` atoms per byte to the miner. Returns the transaction and its fee.
pub fn build_payment(
    net: &Network,
    key: &SigningKey,
    coins: &[Spendable],
    payments: &[(Hash, u64)],
    rate: u64,
) -> Result<(Tx, u64), String> {
    if payments.is_empty() || payments.iter().any(|p| p.1 == 0) {
        return Err("every amount must be positive".into());
    }
    let pay = payments.iter().try_fold(0u64, |s, p| s.checked_add(p.1)).ok_or("amount too large")?;
    let mut sorted = coins.to_vec();
    sorted.sort_by_key(|c| std::cmp::Reverse(c.value));
    let (mut chosen, mut total) = (Vec::new(), 0u64);
    // with change, the fee covers one more output
    let need = |n: usize| pay.saturating_add(fee_for(n, payments.len() + 1, rate));
    for c in sorted {
        if chosen.len() == MAX_INPUTS || total >= need(chosen.len()) {
            break;
        }
        total += c.value;
        chosen.push(c);
    }
    let fee = fee_for(chosen.len(), payments.len() + 1, rate);
    if total < pay.saturating_add(fee) {
        let what = if chosen.len() == MAX_INPUTS { " (too many small coins: run consolidate first)" } else { "" };
        return Err(format!(
            "insufficient funds: {} spendable, {} needed{what}",
            format_amount(total),
            format_amount(pay.saturating_add(fee))
        ));
    }
    let mut outputs: Vec<Output> = payments.iter().map(|(to, v)| Output { value: *v, pkh: *to }).collect();
    let change = total - pay - fee;
    if change > 0 {
        outputs.push(Output { value: change, pkh: owner_of(key) });
    }
    Ok((signed(net, key, &chosen, outputs), fee))
}

/// The first `MAX_INPUTS` of `coins`, in the order given, to `to` in one output, minus the fee. Returns the
/// transaction, the amount sent and the fee. Largest first sends the most; smallest first, to one's own
/// address, merges the dust.
pub fn build_sweep(
    net: &Network,
    key: &SigningKey,
    coins: &[Spendable],
    to: &Hash,
    rate: u64,
) -> Result<(Tx, u64, u64), String> {
    let chosen: Vec<Spendable> = coins.iter().take(MAX_INPUTS).copied().collect();
    if chosen.is_empty() {
        return Err("nothing spendable".into());
    }
    let total: u64 = chosen.iter().map(|c| c.value).sum();
    let fee = fee_for(chosen.len(), 1, rate);
    if total <= fee {
        return Err(format!("{} spendable does not cover the fee {}", format_amount(total), format_amount(fee)));
    }
    let tx = signed(net, key, &chosen, vec![Output { value: total - fee, pkh: *to }]);
    Ok((tx, total - fee, fee))
}

/// Pay `amount` to `to` with a fixed `fee` (kept for callers that set the fee themselves).
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
    Ok(signed(net, key, &chosen, outputs))
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

    fn many(n: usize, value: u64) -> Vec<Spendable> {
        (0..n).map(|k| Spendable { op: OutPoint { txid: [(k % 251) as u8; 32], vout: k as u32 }, value }).collect()
    }

    #[test]
    fn payments_fees_and_sweeps() {
        let net = Network::regtest();
        let key = SigningKey::from_bytes(&[5; 32]);
        // two recipients, fee from the size, change back
        let coins = many(10, 100_000);
        let (tx, fee) = build_payment(&net, &key, &coins, &[([1; 32], 150_000), ([2; 32], 20_000)], 5).unwrap();
        tx.check_standalone(&net.chain_id).unwrap();
        let Tx::Transfer { inputs, outputs } = &tx else { panic!() };
        assert_eq!(inputs.len(), 2);
        assert_eq!(fee, fee_for(2, 3, 5));
        assert!(tx.encode().len() as u64 <= transfer_size(2, 3));
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>() + fee, 200_000);
        // the size estimate never undercounts, whatever the shape
        for (i, o) in [(1, 1), (1, 2), (50, 1), (MAX_INPUTS, 1)] {
            let (tx, _, _) = build_sweep(&net, &key, &many(i, 10_000_000), &[3; 32], 5).unwrap();
            assert!(tx.encode().len() as u64 <= transfer_size(i, o), "{i} inputs");
        }
        // everything: one output of the total minus the fee, at most MAX_INPUTS coins per transaction
        let (tx, sent, fee) = build_sweep(&net, &key, &many(700, 10_000), &[3; 32], 5).unwrap();
        let Tx::Transfer { inputs, .. } = &tx else { panic!() };
        assert_eq!(inputs.len(), MAX_INPUTS);
        assert_eq!(sent + fee, MAX_INPUTS as u64 * 10_000);
        assert!(tx.encode().len() < 100_000);
        // too little for the amount plus the fee
        assert!(build_payment(&net, &key, &many(1, 1000), &[([1; 32], 900)], 5).is_err());
        assert!(build_sweep(&net, &key, &many(1, 500), &[3; 32], 5).is_err());
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

// ---- key files -------------------------------------------------------------------------------------
//
// A key file holds either the 32-byte secret as 64 hex digits (unencrypted) or one line
// `requant-key:1:argon2id:<m_kib>:<t>:<p>:<salt hex>:<nonce hex>:<ciphertext hex>`: the secret encrypted
// with XChaCha20-Poly1305 under a key derived from a passphrase with Argon2id; the header up to the salt
// is authenticated as associated data.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const KEY_TAG: &str = "requant-key:1:argon2id";
/// Argon2id cost: 64 MiB, 3 passes, 1 lane.
const KDF: (u32, u32, u32) = (65536, 3, 1);

fn kdf(pass: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<[u8; 32], &'static str> {
    let params = argon2::Params::new(m, t, p, Some(32)).map_err(|_| "bad key-derivation parameters")?;
    let mut out = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, &mut out)
        .map_err(|_| "key derivation failed")?;
    Ok(out)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhexs(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).ok()).collect()
}

pub fn is_encrypted(file_text: &str) -> bool {
    file_text.trim().starts_with(KEY_TAG)
}

/// Encrypt a secret under `pass`; `salt` (16 bytes) and `nonce` (24 bytes) must be random.
pub fn encrypt_key(secret: &[u8; 32], pass: &str, salt: &[u8; 16], nonce: &[u8; 24]) -> Result<String, &'static str> {
    let (m, t, p) = KDF;
    let header = format!("{KEY_TAG}:{m}:{t}:{p}");
    let cipher = XChaCha20Poly1305::new(&kdf(pass, salt, m, t, p)?.into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: secret, aad: header.as_bytes() })
        .map_err(|_| "encryption failed")?;
    Ok(format!("{header}:{}:{}:{}", hexs(salt), hexs(nonce), hexs(&ct)))
}

/// The secret of a key file: plain hex, or encrypted (then `pass` is needed).
pub fn decrypt_key(file_text: &str, pass: Option<&str>) -> Result<[u8; 32], &'static str> {
    let text = file_text.trim();
    if !is_encrypted(text) {
        return unhexs(text).and_then(|v| v.try_into().ok()).ok_or("key file must hold 64 hex digits");
    }
    let parts: Vec<&str> = text.split(':').collect();
    let [_, _, _, m, t, p, salt, nonce, ct] = parts.as_slice() else { return Err("malformed key file") };
    let num = |s: &str| s.parse::<u32>().map_err(|_| "malformed key file");
    let (m, t, p) = (num(m)?, num(t)?, num(p)?);
    let (salt, nonce, ct) = (
        unhexs(salt).ok_or("malformed key file")?,
        unhexs(nonce).ok_or("malformed key file")?,
        unhexs(ct).ok_or("malformed key file")?,
    );
    if nonce.len() != 24 || salt.len() < 8 {
        return Err("malformed key file");
    }
    let header = format!("{KEY_TAG}:{m}:{t}:{p}");
    let pass = pass.ok_or("this key file is encrypted: a passphrase is needed")?;
    let cipher = XChaCha20Poly1305::new(&kdf(pass, &salt, m, t, p)?.into());
    let secret = cipher
        .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ct, aad: header.as_bytes() })
        .map_err(|_| "wrong passphrase or damaged key file")?;
    secret.try_into().map_err(|_| "malformed key file")
}

#[cfg(test)]
mod keyfile {
    use super::*;

    #[test]
    fn encrypted_key_files() {
        let secret = [7u8; 32];
        let f = encrypt_key(&secret, "correct horse", &[1; 16], &[2; 24]).unwrap();
        assert!(is_encrypted(&f));
        assert_eq!(decrypt_key(&f, Some("correct horse")), Ok(secret));
        assert_eq!(decrypt_key(&f, Some("wrong")), Err("wrong passphrase or damaged key file"));
        assert!(decrypt_key(&f, None).is_err());
        // tampering with the cost parameters or the ciphertext is detected
        assert!(decrypt_key(&f.replacen(":65536:", ":65537:", 1), Some("correct horse")).is_err());
        let mut bad = f.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == '0' { '1' } else { '0' });
        assert!(decrypt_key(&bad, Some("correct horse")).is_err());
        // unencrypted files still load
        assert_eq!(decrypt_key(&format!("{}\n", hexs(&secret)), None), Ok(secret));
    }
}
