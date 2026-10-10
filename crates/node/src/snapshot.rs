//! Quick start. `chainstate.bin` holds what replaying `blocks.dat` would rebuild: the chain's index, best
//! chain, UTXO set and undo data ([`Chain::snapshot`]), the transaction index, and where each block's
//! record is in the block file. With it a node starts by reading the snapshot and replaying only the
//! records appended after it, instead of every block since genesis.
//!
//! Layout: `"RQSNAP01" || LE64 offset || LE32 len` of the last block record covered (checked against the
//! block file on load), then the sections, then `sha256` of everything before. Any mismatch (checksum,
//! network, a covered record not where the snapshot says, an inconsistent state) discards the snapshot
//! and the node replays the whole file as before. Written to a temporary file and renamed into place.

use crate::index::TxIndex;
use crate::store::Bodies;
use requant_consensus::chain::Chain;
use requant_consensus::codec::{Reader, Writer};
use requant_consensus::params::Network;
use requant_consensus::tx::Hash;
use std::io;
use std::path::Path;
use tnet::sha256::sha256;

const MAGIC: &[u8; 8] = b"RQSNAP01";

/// A snapshot read back: the state, and the last block record it covers.
pub struct Loaded {
    pub chain: Chain,
    pub index: TxIndex,
    pub bodies: Vec<(Hash, u64, u32)>,
    pub last: (u64, u32),
}

fn section(w: &mut Writer, bytes: &[u8]) {
    w.u64(bytes.len() as u64);
    w.raw(bytes);
}

/// The snapshot bytes of a consistent state (taken under the node's lock); `last` is the block file's
/// last record.
pub fn encode(chain: &Chain, index: &TxIndex, bodies: &Bodies, last: (u64, u32)) -> Vec<u8> {
    let mut w = Writer::default();
    w.raw(MAGIC);
    w.u64(last.0);
    w.u32(last.1);
    section(&mut w, &chain.snapshot());
    let mut iw = Writer::default();
    index.snapshot(&mut iw);
    section(&mut w, &iw.0);
    let entries = bodies.entries();
    w.u64(entries.len() as u64);
    for (id, at, len) in entries {
        w.raw(&id);
        w.u64(at);
        w.u32(len);
    }
    let sum = sha256(&w.0);
    w.raw(&sum);
    w.0
}

/// Write `bytes` to `path` atomically.
pub fn save(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

fn take_section<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], String> {
    let n = r.u64().map_err(|e| e.to_string())?;
    r.take(usize::try_from(n).map_err(|_| "section too long")?).map_err(|e| e.to_string())
}

/// Read and check a snapshot. The covered record is checked by the caller against the block file.
pub fn load(path: &Path, net: &Network, threads: usize) -> Result<Loaded, String> {
    let all = std::fs::read(path).map_err(|e| e.to_string())?;
    if all.len() < MAGIC.len() + 12 + 32 || &all[..8] != MAGIC {
        return Err("not a snapshot".into());
    }
    let (body, sum) = all.split_at(all.len() - 32);
    if sha256(body)[..] != sum[..] {
        return Err("checksum mismatch".into());
    }
    let mut r = Reader::new(&body[8..]);
    let e = |e: requant_consensus::Error| e.to_string();
    let last = (r.u64().map_err(e)?, r.u32().map_err(e)?);
    let chain = Chain::restore(net.clone(), threads, take_section(&mut r)?).map_err(e)?;
    let mut ir = Reader::new(take_section(&mut r)?);
    let index = TxIndex::restore(&mut ir).map_err(e)?;
    ir.finish().map_err(e)?;
    let n = r.u64().map_err(e)?;
    let mut bodies = Vec::new();
    for _ in 0..n {
        bodies.push((r.arr32().map_err(e)?, r.u64().map_err(e)?, r.u32().map_err(e)?));
    }
    r.finish().map_err(e)?;
    // the parts agree with each other, and the coins do not exceed what the schedule issued
    if index.tip() != Some(chain.tip()) {
        return Err("transaction index and chain disagree".into());
    }
    let (total, _, _) = chain.utxo_audit();
    if total > chain.issued() {
        return Err("more coins than issued".into());
    }
    Ok(Loaded { chain, index, bodies, last })
}
