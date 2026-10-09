//! Peer-to-peer messages. Frame: `magic[4] || cmd u8 || LE32 len || SHA256(payload)[..4] || payload`,
//! `magic` = first four bytes of the chain id.

use requant_consensus::codec::{Reader, Writer};
use requant_consensus::tx::Hash;
use std::io::{self, Read, Write};
use tnet::sha256::sha256;

pub const PROTOCOL: u32 = 1;
pub const MAX_PAYLOAD: usize = 2 << 20;
pub const MAX_INV: usize = 500;
pub const MAX_LOCATOR: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Hello { protocol: u32, height: u64, tip: Hash },
    GetBlocks(Vec<Hash>),
    Inv(Vec<Hash>),
    GetData(Vec<Hash>),
    Block(Vec<u8>),
    Tx(Vec<u8>),
    Ping(u64),
    Pong(u64),
}

fn hashes(w: &mut Writer, v: &[Hash]) {
    w.varint(v.len() as u64);
    for h in v {
        w.raw(h);
    }
}

fn read_hashes(r: &mut Reader, max: usize) -> Result<Vec<Hash>, requant_consensus::Error> {
    let n = r.varint(max as u64)?;
    (0..n).map(|_| r.arr32()).collect()
}

impl Msg {
    fn encode(&self) -> (u8, Vec<u8>) {
        let mut w = Writer::default();
        let cmd = match self {
            Msg::Hello { protocol, height, tip } => {
                w.u32(*protocol);
                w.u64(*height);
                w.raw(tip);
                0
            }
            Msg::GetBlocks(v) => {
                hashes(&mut w, v);
                1
            }
            Msg::Inv(v) => {
                hashes(&mut w, v);
                2
            }
            Msg::GetData(v) => {
                hashes(&mut w, v);
                3
            }
            Msg::Block(b) => {
                w.raw(b);
                4
            }
            Msg::Tx(b) => {
                w.raw(b);
                5
            }
            Msg::Ping(n) => {
                w.u64(*n);
                6
            }
            Msg::Pong(n) => {
                w.u64(*n);
                7
            }
        };
        (cmd, w.0)
    }

    fn decode(cmd: u8, p: &[u8]) -> Result<Msg, requant_consensus::Error> {
        let mut r = Reader::new(p);
        let m = match cmd {
            0 => Msg::Hello { protocol: r.u32()?, height: r.u64()?, tip: r.arr32()? },
            1 => Msg::GetBlocks(read_hashes(&mut r, MAX_LOCATOR)?),
            2 => Msg::Inv(read_hashes(&mut r, MAX_INV)?),
            3 => Msg::GetData(read_hashes(&mut r, MAX_INV)?),
            4 => return Ok(Msg::Block(p.to_vec())),
            5 => return Ok(Msg::Tx(p.to_vec())),
            6 => Msg::Ping(r.u64()?),
            7 => Msg::Pong(r.u64()?),
            _ => return Err(requant_consensus::Error::Decode("unknown command")),
        };
        r.finish()?;
        Ok(m)
    }
}

pub fn write_msg(w: &mut impl Write, magic: &[u8; 4], m: &Msg) -> io::Result<()> {
    let (cmd, p) = m.encode();
    let mut frame = Vec::with_capacity(p.len() + 13);
    frame.extend_from_slice(magic);
    frame.push(cmd);
    frame.extend_from_slice(&(p.len() as u32).to_le_bytes());
    frame.extend_from_slice(&sha256(&p)[..4]);
    frame.extend_from_slice(&p);
    w.write_all(&frame)?;
    w.flush()
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

pub fn read_msg(r: &mut impl Read, magic: &[u8; 4]) -> io::Result<Msg> {
    let mut head = [0u8; 13];
    r.read_exact(&mut head)?;
    if head[..4] != magic[..] {
        return Err(bad("wrong network magic"));
    }
    let len = u32::from_le_bytes(head[5..9].try_into().unwrap()) as usize;
    if len > MAX_PAYLOAD {
        return Err(bad("oversized message"));
    }
    let mut p = vec![0u8; len];
    r.read_exact(&mut p)?;
    if sha256(&p)[..4] != head[9..13] {
        return Err(bad("checksum"));
    }
    Msg::decode(head[4], &p).map_err(|_| bad("malformed message"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rejections() {
        let magic = *b"RQ01";
        let msgs = vec![
            Msg::Hello { protocol: 1, height: 7, tip: [3; 32] },
            Msg::GetBlocks(vec![[1; 32], [2; 32]]),
            Msg::Inv(vec![[4; 32]]),
            Msg::GetData(vec![]),
            Msg::Block(vec![1, 2, 3]),
            Msg::Tx(vec![]),
            Msg::Ping(9),
            Msg::Pong(9),
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_msg(&mut buf, &magic, m).unwrap();
        }
        let mut r = &buf[..];
        for m in &msgs {
            assert_eq!(&read_msg(&mut r, &magic).unwrap(), m);
        }
        let mut wrong = &buf[..];
        assert!(read_msg(&mut wrong, b"XXXX").is_err());
        let mut corrupt = buf.clone();
        corrupt[13] ^= 1;
        assert!(read_msg(&mut &corrupt[..], &magic).is_err());
    }
}
