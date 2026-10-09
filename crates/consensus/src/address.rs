//! Addresses (bech32m, BIP 350: `rq1`, `trq1`, `rqrt1` + version 0 + key hash) and amounts in RQT.

use crate::params::{Network, ATOMS_PER_RQT};
use crate::tx::Hash;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut v: Vec<u8> = b.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(b.iter().map(|c| c & 31));
    v
}

/// bech32m string of `hrp` and 5-bit `data`.
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    let mut s = format!("{hrp}1");
    for &d in data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

/// `(hrp, 5-bit data)` of a valid bech32m string.
pub fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), &'static str> {
    if s.len() > 90 {
        return Err("too long");
    }
    if s.chars().any(|c| c.is_ascii_lowercase()) && s.chars().any(|c| c.is_ascii_uppercase()) {
        return Err("mixed case");
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1').ok_or("no separator")?;
    let (hrp, rest) = (&s[..sep], &s[sep + 1..]);
    if hrp.is_empty() || rest.len() < 6 || hrp.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err("bad format");
    }
    let data: Vec<u8> = rest
        .bytes()
        .map(|c| CHARSET.iter().position(|&x| x == c).map(|p| p as u8).ok_or("bad character"))
        .collect::<Result<_, _>>()?;
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    if polymod(&values) != BECH32M_CONST {
        return Err("bad checksum");
    }
    Ok((hrp.to_string(), data[..data.len() - 6].to_vec()))
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits) = (0u32, 0u32);
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &v in data {
        if (v as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | v as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

pub fn hrp(net: &Network) -> &'static str {
    match net.name {
        "test" => "trq",
        "regtest" => "rqrt",
        _ => "rq",
    }
}

/// Address of a key hash: bech32m with the network's prefix, version 0.
pub fn address(net: &Network, owner: &Hash) -> String {
    let mut data = vec![0u8];
    data.extend(convert_bits(owner, 8, 5, true).unwrap());
    bech32m_encode(hrp(net), &data)
}

pub fn parse_address(net: &Network, s: &str) -> Result<Hash, &'static str> {
    let (h, data) = bech32m_decode(s)?;
    if h != hrp(net) {
        return Err("address is for another network");
    }
    if data.first() != Some(&0) {
        return Err("unknown address version");
    }
    convert_bits(&data[1..], 5, 8, false).and_then(|v| v.try_into().ok()).ok_or("bad address payload")
}

/// `"1.5"` -> 150,000,000 atoms; at most 8 decimals.
pub fn parse_amount(s: &str) -> Result<u64, &'static str> {
    let (int, frac) = s.split_once('.').unwrap_or((s, ""));
    if int.is_empty() && frac.is_empty()
        || frac.len() > 8
        || !int.bytes().chain(frac.bytes()).all(|c| c.is_ascii_digit())
    {
        return Err("bad amount");
    }
    let i: u64 = if int.is_empty() { 0 } else { int.parse().map_err(|_| "bad amount")? };
    let f: u64 = if frac.is_empty() { 0 } else { format!("{frac:0<8}").parse().map_err(|_| "bad amount")? };
    i.checked_mul(ATOMS_PER_RQT).and_then(|x| x.checked_add(f)).ok_or("amount too large")
}

pub fn format_amount(atoms: u64) -> String {
    format!("{}.{:08}", atoms / ATOMS_PER_RQT, atoms % ATOMS_PER_RQT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::pkh;

    fn owner_of(key: &ed25519_dalek::SigningKey) -> Hash {
        pkh(&key.verifying_key().to_bytes())
    }

    #[test]
    fn bip350_vectors() {
        for valid in ["A1LQFN3A", "a1lqfn3a", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa"] {
            assert!(bech32m_decode(valid).is_ok(), "{valid}");
        }
        // bech32 (not m) checksum, mixed case, bad character
        for invalid in ["a12uel5l", "A1lqfn3a", "a1lqfn3b", "a1lqfbn3a"] {
            assert!(bech32m_decode(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn addresses() {
        let net = Network::regtest();
        let owner = owner_of(&ed25519_dalek::SigningKey::from_bytes(&[5; 32]));
        let a = address(&net, &owner);
        assert!(a.starts_with("rqrt1q"));
        assert_eq!(parse_address(&net, &a), Ok(owner));
        assert_eq!(parse_address(&net, &a.to_uppercase()), Ok(owner));
        assert_eq!(parse_address(&Network::test(), &a), Err("address is for another network"));
        let mut typo = a.clone().into_bytes();
        typo[10] = if typo[10] == b'q' { b'p' } else { b'q' };
        assert!(parse_address(&net, std::str::from_utf8(&typo).unwrap()).is_err());
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("1"), Ok(ATOMS_PER_RQT));
        assert_eq!(parse_amount("1.5"), Ok(150_000_000));
        assert_eq!(parse_amount("0.00000001"), Ok(1));
        assert_eq!(parse_amount(".25"), Ok(25_000_000));
        for bad in ["", ".", "1.000000001", "-1", "1e3", "1.2.3"] {
            assert!(parse_amount(bad).is_err(), "{bad}");
        }
        assert_eq!(format_amount(150_000_001), "1.50000001");
    }
}
