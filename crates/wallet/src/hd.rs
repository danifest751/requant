//! Hierarchical keys from one backup phrase: BIP 39 phrases (24 English words for 256 bits of entropy, the
//! seed by PBKDF2-HMAC-SHA512) and SLIP-0010 derivation for ed25519 (hardened children only, as SLIP-0010
//! requires for ed25519). Secrets live in `Zeroizing` buffers and are wiped when dropped.
//!
//! Requant keys sit at `m/44'/1'/account'/chain'/index'`: chain 0 receives, chain 1 takes change. Coin
//! type 1 is SLIP-0044's "testnet (all coins)"; a main network would need its own registered number.

use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// The BIP 39 English word list (sha256 2f5eed53…24dbda, checked in the tests).
const WORDS: &str = include_str!("bip39-english.txt");

pub const PURPOSE: u32 = 44;
pub const COIN_TYPE: u32 = 1;
pub const RECEIVE: u32 = 0;
pub const CHANGE: u32 = 1;
const HARDENED: u32 = 0x8000_0000;

fn words() -> Vec<&'static str> {
    WORDS.lines().collect()
}

pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut k = Zeroizing::new([0u8; 128]);
    if key.len() > 128 {
        k[..64].copy_from_slice(&Sha512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = (Zeroizing::new([0x36u8; 128]), Zeroizing::new([0x5cu8; 128]));
    for i in 0..128 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha512::new().chain_update(&ipad[..]).chain_update(msg).finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&Sha512::new().chain_update(&opad[..]).chain_update(inner).finalize());
    out
}

/// PBKDF2-HMAC-SHA512 with a 64-byte output (one block).
fn pbkdf2_sha512(pass: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 64]> {
    let mut first = salt.to_vec();
    first.extend_from_slice(&1u32.to_be_bytes());
    let mut u = Zeroizing::new(hmac_sha512(pass, &first));
    let mut t = Zeroizing::new(*u);
    for _ in 1..rounds {
        let next = hmac_sha512(pass, &u[..]);
        u.copy_from_slice(&next);
        for (a, b) in t.iter_mut().zip(u.iter()) {
            *a ^= b;
        }
    }
    t
}

/// The 24-word phrase of 32 bytes of entropy.
pub fn phrase_of(entropy: &[u8; 32]) -> Zeroizing<String> {
    let list = words();
    let check = Sha256::digest(entropy)[0];
    let mut bits = Zeroizing::new([0u8; 33]);
    bits[..32].copy_from_slice(entropy);
    bits[32] = check;
    let bit = |i: usize| (bits[i / 8] >> (7 - i % 8)) & 1;
    let mut out = Zeroizing::new(String::new());
    for w in 0..24 {
        let idx = (0..11).fold(0usize, |acc, j| (acc << 1) | bit(w * 11 + j) as usize);
        if w > 0 {
            out.push(' ');
        }
        out.push_str(list[idx]);
    }
    out
}

/// The entropy behind a 24-word phrase. Words may be given by their first four letters (unique in the
/// English list); case and extra spaces do not matter. The checksum word must match.
pub fn entropy_of(phrase: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let list = words();
    let given: Vec<String> = phrase.split_whitespace().map(|w| w.to_lowercase()).collect();
    if given.len() != 24 {
        return Err(format!("a backup phrase has 24 words, this one has {}", given.len()));
    }
    let mut bits = Zeroizing::new([0u8; 33]);
    for (w, word) in given.iter().enumerate() {
        let idx = match list.iter().position(|x| x == word) {
            Some(i) => i,
            None if word.len() >= 4 => {
                let m: Vec<usize> = (0..list.len()).filter(|&i| list[i].starts_with(word.as_str())).collect();
                match m.as_slice() {
                    [i] => *i,
                    _ => return Err(format!("word {} (\"{word}\") is not in the word list", w + 1)),
                }
            }
            None => return Err(format!("word {} (\"{word}\") is not in the word list", w + 1)),
        };
        for j in 0..11 {
            if (idx >> (10 - j)) & 1 == 1 {
                let i = w * 11 + j;
                bits[i / 8] |= 1 << (7 - i % 8);
            }
        }
    }
    let mut entropy = Zeroizing::new([0u8; 32]);
    entropy.copy_from_slice(&bits[..32]);
    if Sha256::digest(&entropy[..])[0] != bits[32] {
        return Err("the phrase's checksum does not match: a word is wrong or out of order".into());
    }
    Ok(entropy)
}

/// The BIP 39 seed of a phrase and an optional passphrase (ASCII; the wallet itself uses none).
pub fn seed_of(entropy: &[u8; 32], passphrase: &str) -> Zeroizing<[u8; 64]> {
    let phrase = phrase_of(entropy);
    let mut salt = format!("mnemonic{passphrase}");
    let seed = pbkdf2_sha512(phrase.as_bytes(), salt.as_bytes(), 2048);
    salt.zeroize();
    seed
}

/// A SLIP-0010 ed25519 node: private key and chain code.
pub struct Node {
    pub key: Zeroizing<[u8; 32]>,
    pub chain: Zeroizing<[u8; 32]>,
}

impl Node {
    pub fn master(seed: &[u8]) -> Node {
        Node::split(Zeroizing::new(hmac_sha512(b"ed25519 seed", seed)))
    }

    fn split(i: Zeroizing<[u8; 64]>) -> Node {
        let (mut key, mut chain) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        Node { key, chain }
    }

    /// The hardened child `index` (the hardening bit is added here).
    pub fn child(&self, index: u32) -> Node {
        let mut data = Zeroizing::new([0u8; 37]);
        data[1..33].copy_from_slice(&self.key[..]);
        data[33..].copy_from_slice(&(index | HARDENED).to_be_bytes());
        Node::split(Zeroizing::new(hmac_sha512(&self.chain[..], &data[..])))
    }

    pub fn derive(seed: &[u8], path: &[u32]) -> Node {
        path.iter().fold(Node::master(seed), |n, &i| n.child(i))
    }
}

/// The signing key at `m/44'/1'/account'/chain'/index'`.
pub fn key_at(seed: &[u8; 64], account: u32, chain: u32, index: u32) -> ed25519_dalek::SigningKey {
    let node = Node::derive(seed, &[PURPOSE, COIN_TYPE, account, chain, index]);
    ed25519_dalek::SigningKey::from_bytes(&node.key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|k| u8::from_str_radix(&s[2 * k..2 * k + 2], 16).unwrap()).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn word_list_is_the_bip39_one() {
        let joined: String = words().iter().map(|w| format!("{w}\n")).collect();
        assert_eq!(words().len(), 2048);
        assert_eq!(
            hex(&Sha256::digest(joined.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_case_2() {
        assert_eq!(
            hex(&hmac_sha512(b"Jefe", b"what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        );
    }

    /// BIP 39 vectors for 256-bit entropy (trezor/python-mnemonic vectors.json, passphrase "TREZOR").
    #[test]
    fn bip39_vectors() {
        let v = [
            ("0000000000000000000000000000000000000000000000000000000000000000",
             "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
             "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"),
            ("8080808080808080808080808080808080808080808080808080808080808080",
             "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
             "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f"),
            ("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
             "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
             "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440"),
            ("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
             "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
             "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998"),
        ];
        for (e, phrase, seed) in v {
            let e: [u8; 32] = unhex(e).try_into().unwrap();
            assert_eq!(phrase_of(&e).as_str(), phrase);
            assert_eq!(*entropy_of(phrase).unwrap(), e);
            assert_eq!(hex(&seed_of(&e, "TREZOR")[..]), seed);
        }
    }

    #[test]
    fn phrases_are_checked_and_forgiving_about_form() {
        let p = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        let e = entropy_of(p).unwrap();
        // four-letter prefixes, case and spacing
        let short: Vec<String> = p.split(' ').map(|w| w.chars().take(4).collect::<String>().to_uppercase()).collect();
        assert_eq!(entropy_of(&format!("  {}  ", short.join("   "))).unwrap(), e);
        // a swapped pair breaks the checksum, an unknown word is named, a short phrase is refused
        let mut w: Vec<&str> = p.split(' ').collect();
        w.swap(0, 1);
        assert!(entropy_of(&w.join(" ")).unwrap_err().contains("checksum"));
        assert!(entropy_of(&p.replace("razor", "razer")).unwrap_err().contains("word 11"));
        assert!(entropy_of("abandon about").is_err());
    }

    /// SLIP-0010 test vector 1 for ed25519.
    #[test]
    fn slip10_ed25519_vector_1() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        let cases: [(&[u32], &str, &str); 4] = [
            (
                &[],
                "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
            ),
            (
                &[0],
                "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
            ),
            (
                &[0, 1, 2],
                "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
            ),
            (
                &[0, 1, 2, 2, 1_000_000_000],
                "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
            ),
        ];
        for (path, chain, key) in cases {
            let n = Node::derive(&seed, path);
            assert_eq!((hex(&n.chain[..]), hex(&n.key[..])), (chain.to_string(), key.to_string()), "{path:?}");
        }
        // and the public key of m/0H/1H/2H/2H/1000000000H
        let n = Node::derive(&seed, &[0, 1, 2, 2, 1_000_000_000]);
        let pk = ed25519_dalek::SigningKey::from_bytes(&n.key).verifying_key().to_bytes();
        assert_eq!(hex(&pk), "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a");
    }
}
