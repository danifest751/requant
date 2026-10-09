//! Peer-to-peer messages. Frame: `magic[4] || cmd u8 || LE32 len || SHA256(payload)[..4] || payload`,
//! `magic` = first four bytes of the chain id.

use requant_consensus::codec::{Reader, Writer};
use requant_consensus::tx::Hash;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tnet::sha256::sha256;

/// Protocol 2: `Hello` carries a node id, the listening port and a user agent (later fields may follow and
/// are ignored); `GetAddr`/`Addr` exchange peer addresses.
/// Protocol 3 adds headers-first sync (`GetHeaders`/`Headers`); peers below 3 are synced block by block.
pub const PROTOCOL: u32 = 3;
pub const HEADERS_PROTOCOL: u32 = 3;
pub const MAX_HEADERS: usize = 2000;
pub const MIN_PROTOCOL: u32 = 2;
pub const MAX_ADDR: usize = 100;
pub const MAX_AGENT: usize = 64;
pub const MAX_PAYLOAD: usize = 2 << 20;
pub const MAX_INV: usize = 500;
pub const MAX_LOCATOR: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Msg {
    Hello {
        protocol: u32,
        height: u64,
        tip: Hash,
        node_id: u64,
        listen_port: u16,
        agent: String,
    },
    GetBlocks(Vec<Hash>),
    Inv(Vec<Hash>),
    GetData(Vec<Hash>),
    Block(Vec<u8>),
    Tx(Vec<u8>),
    Ping(u64),
    Pong(u64),
    GetAddr,
    Addr(Vec<SocketAddr>),
    GetHeaders(Vec<Hash>),
    /// `varint n || (header || claim)*`, decoded by the node (the claim size depends on the network).
    Headers(Vec<u8>),
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
            Msg::Hello { protocol, height, tip, node_id, listen_port, agent } => {
                w.u32(*protocol);
                w.u64(*height);
                w.raw(tip);
                w.u64(*node_id);
                w.0.extend_from_slice(&listen_port.to_le_bytes());
                w.bytes(&agent.as_bytes()[..agent.len().min(MAX_AGENT)]);
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
            Msg::GetAddr => 8,
            Msg::GetHeaders(v) => {
                hashes(&mut w, v);
                10
            }
            Msg::Headers(b) => {
                w.raw(b);
                11
            }
            Msg::Addr(v) => {
                w.varint(v.len() as u64);
                for a in v {
                    match a.ip() {
                        IpAddr::V4(ip) => {
                            w.u8(4);
                            w.raw(&ip.octets());
                        }
                        IpAddr::V6(ip) => {
                            w.u8(6);
                            w.raw(&ip.octets());
                        }
                    }
                    w.0.extend_from_slice(&a.port().to_le_bytes());
                }
                9
            }
        };
        (cmd, w.0)
    }

    fn decode(cmd: u8, p: &[u8]) -> Result<Msg, requant_consensus::Error> {
        let mut r = Reader::new(p);
        let m = match cmd {
            0 => {
                // Fields after the tip are read when present; anything after them is ignored, so later
                // protocol versions can extend the greeting.
                let (protocol, height, tip) = (r.u32()?, r.u64()?, r.arr32()?);
                let (mut node_id, mut listen_port, mut agent) = (0, 0, String::new());
                if let Ok(id) = r.u64() {
                    node_id = id;
                    listen_port = r.u16()?;
                    agent = String::from_utf8_lossy(r.bytes(MAX_AGENT)?).into_owned();
                }
                return Ok(Msg::Hello { protocol, height, tip, node_id, listen_port, agent });
            }
            1 => Msg::GetBlocks(read_hashes(&mut r, MAX_LOCATOR)?),
            2 => Msg::Inv(read_hashes(&mut r, MAX_INV)?),
            3 => Msg::GetData(read_hashes(&mut r, MAX_INV)?),
            4 => return Ok(Msg::Block(p.to_vec())),
            5 => return Ok(Msg::Tx(p.to_vec())),
            6 => Msg::Ping(r.u64()?),
            7 => Msg::Pong(r.u64()?),
            8 => Msg::GetAddr,
            10 => Msg::GetHeaders(read_hashes(&mut r, MAX_LOCATOR)?),
            11 => return Ok(Msg::Headers(p.to_vec())),
            9 => {
                let n = r.varint(MAX_ADDR as u64)?;
                let mut v = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let ip = match r.u8()? {
                        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(r.take(4)?).unwrap())),
                        6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(r.take(16)?).unwrap())),
                        _ => return Err(requant_consensus::Error::Decode("address family")),
                    };
                    v.push(SocketAddr::new(ip, r.u16()?));
                }
                Msg::Addr(v)
            }
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
            Msg::Hello {
                protocol: 2,
                height: 7,
                tip: [3; 32],
                node_id: 99,
                listen_port: 19333,
                agent: "requantd/test".into(),
            },
            Msg::GetAddr,
            Msg::GetHeaders(vec![[5; 32]]),
            Msg::Headers(vec![0]),
            Msg::Addr(vec!["1.2.3.4:19333".parse().unwrap(), "[2001:db8::1]:7".parse().unwrap()]),
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

#[cfg(test)]
mod compat {
    use super::*;

    #[test]
    fn hello_tolerates_extensions() {
        let magic = *b"RQ01";
        // a greeting from a later version with an extra trailing field
        let mut w = Writer::default();
        w.u32(3);
        w.u64(5);
        w.raw(&[1; 32]);
        w.u64(7);
        w.0.extend_from_slice(&19333u16.to_le_bytes());
        w.bytes(b"requantd/9.9");
        w.raw(b"future field");
        let p = w.0;
        let mut frame = magic.to_vec();
        frame.push(0);
        frame.extend_from_slice(&(p.len() as u32).to_le_bytes());
        frame.extend_from_slice(&sha256(&p)[..4]);
        frame.extend_from_slice(&p);
        let m = read_msg(&mut &frame[..], &magic).unwrap();
        assert_eq!(
            m,
            Msg::Hello {
                protocol: 3,
                height: 5,
                tip: [1; 32],
                node_id: 7,
                listen_port: 19333,
                agent: "requantd/9.9".into()
            }
        );
    }
}
