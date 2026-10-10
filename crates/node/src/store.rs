//! Append-only block file: `LE32 len || first 4 bytes of SHA256(data) || data` per accepted block, in
//! acceptance order (parents before children). A torn or corrupt tail is cut off on open. Records are found
//! again by their offset ([`Bodies`]), so the chain can drop old bodies from memory.

use requant_consensus::block::Block;
use requant_consensus::chain::BodySource;
use requant_consensus::params::Network;
use requant_consensus::tx::Hash;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tnet::sha256::sha256;

pub struct Store {
    file: File,
    path: PathBuf,
    /// Where the next record goes.
    end: u64,
    /// Offset and length of the last record's data.
    last: Option<(u64, u32)>,
}

/// A stored record: the offset of its data in the file, and the data.
pub struct Record {
    pub offset: u64,
    pub data: Vec<u8>,
}

impl Store {
    /// Open (or create) `dir/blocks.dat` and return the stored records.
    pub fn open(dir: &Path) -> io::Result<(Store, Vec<Record>)> {
        Ok(Store::open_after(dir, None)?.expect("no covered record to check"))
    }

    /// Open `dir/blocks.dat` and return only the records after `after`, the data offset and length of a
    /// record a snapshot covers; `None` if that record is not in the file as described (then nothing is
    /// changed and the caller opens the whole file).
    pub fn open_after(dir: &Path, after: Option<(u64, u32)>) -> io::Result<Option<(Store, Vec<Record>)>> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("blocks.dat");
        // write (not append) mode, so that a torn tail can be truncated on every platform
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        let start = match after {
            None => 0,
            Some((at, len)) => {
                let size = file.metadata()?.len();
                if at < 8 || at + len as u64 > size {
                    return Ok(None);
                }
                let (mut head, mut data) = ([0u8; 8], vec![0u8; len as usize]);
                crate::epochs::read_at(&file, &mut head, at - 8)?;
                crate::epochs::read_at(&file, &mut data, at)?;
                if u32::from_le_bytes(head[..4].try_into().unwrap()) != len || sha256(&data)[..4] != head[4..] {
                    return Ok(None);
                }
                at + len as u64
            }
        };
        let mut all = Vec::new();
        file.seek(SeekFrom::Start(start))?;
        file.read_to_end(&mut all)?;
        let mut records = Vec::new();
        let mut last = after;
        let mut pos = 0usize;
        while all.len() - pos >= 8 {
            let len = u32::from_le_bytes(all[pos..pos + 4].try_into().unwrap()) as usize;
            if all.len() - pos - 8 < len {
                break;
            }
            let data = &all[pos + 8..pos + 8 + len];
            if sha256(data)[..4] != all[pos + 4..pos + 8] {
                break;
            }
            let offset = start + (pos + 8) as u64;
            records.push(Record { offset, data: data.to_vec() });
            last = Some((offset, len as u32));
            pos += 8 + len;
        }
        let end = start + pos as u64;
        if pos != all.len() {
            file.set_len(end)?;
        }
        file.seek(SeekFrom::Start(end))?;
        Ok(Some((Store { file, path, end, last }, records)))
    }

    /// Offset and length of the last record's data (what a snapshot taken now covers).
    pub fn last(&self) -> Option<(u64, u32)> {
        self.last
    }

    /// Append a record; returns the offset of its data.
    pub fn append(&mut self, data: &[u8]) -> io::Result<u64> {
        let mut rec = Vec::with_capacity(data.len() + 8);
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
        rec.extend_from_slice(&sha256(data)[..4]);
        rec.extend_from_slice(data);
        self.file.write_all(&rec)?;
        self.file.sync_data()?;
        let at = self.end + 8;
        self.end += rec.len() as u64;
        self.last = Some((at, data.len() as u32));
        Ok(at)
    }

    /// A reader of this file's records by block id (see [`Bodies`]).
    pub fn bodies(&self, net: Network) -> io::Result<Bodies> {
        Ok(Bodies { file: File::open(&self.path)?, net, index: RwLock::new(HashMap::new()) })
    }
}

/// Block bodies read back from `blocks.dat` by id: the offset and length of each block's record.
pub struct Bodies {
    file: File,
    net: Network,
    index: RwLock<HashMap<Hash, (u64, u32)>>,
}

impl Bodies {
    pub fn insert(&self, id: Hash, offset: u64, len: usize) {
        self.index.write().unwrap().insert(id, (offset, len as u32));
    }

    /// Every known record: id, offset, length (for the start-up snapshot).
    pub fn entries(&self) -> Vec<(Hash, u64, u32)> {
        self.index.read().unwrap().iter().map(|(id, &(at, len))| (*id, at, len)).collect()
    }
}

impl BodySource for Bodies {
    fn load(&self, id: &Hash) -> Option<Block> {
        let (at, len) = *self.index.read().unwrap().get(id)?;
        let mut buf = vec![0u8; len as usize];
        crate::epochs::read_at(&self.file, &mut buf, at).ok()?;
        Block::decode(&buf, &self.net).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_survive_reopen_and_torn_tail_is_cut() {
        let dir = std::env::temp_dir().join(format!("requant-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let (mut s, r) = Store::open(&dir).unwrap();
            assert!(r.is_empty());
            assert_eq!(s.append(b"one").unwrap(), 8);
            assert_eq!(s.append(b"two").unwrap(), 8 + 3 + 8);
        }
        // a torn third record
        OpenOptions::new().append(true).open(dir.join("blocks.dat")).unwrap().write_all(&[9, 0, 0, 0, 1]).unwrap();
        let (mut s, r) = Store::open(&dir).unwrap();
        let data: Vec<&[u8]> = r.iter().map(|x| x.data.as_slice()).collect();
        assert_eq!(data, vec![b"one".as_slice(), b"two".as_slice()]);
        assert_eq!(r[1].offset, 19);
        s.append(b"three").unwrap();
        assert_eq!(s.last(), Some((19 + 3 + 8, 5)));
        drop(s);
        let (_, r) = Store::open(&dir).unwrap();
        assert_eq!(r.len(), 3);
        // only the records after a covered one; a record that is not there as described is refused
        let (s, r) = Store::open_after(&dir, Some((19, 3))).unwrap().unwrap();
        assert_eq!(r.iter().map(|x| x.data.as_slice()).collect::<Vec<_>>(), vec![b"three".as_slice()]);
        assert_eq!(s.last(), Some((30, 5)));
        drop(s);
        assert!(Store::open_after(&dir, Some((19, 4))).unwrap().is_none());
        assert!(Store::open_after(&dir, Some((20, 3))).unwrap().is_none());
        assert!(Store::open_after(&dir, Some((30, 50))).unwrap().is_none());
        let (_, r) = Store::open_after(&dir, Some((30, 5))).unwrap().unwrap();
        assert!(r.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bodies_read_back_by_id() {
        let dir = std::env::temp_dir().join(format!("requant-bodies-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let net = Network::regtest();
        let g = requant_consensus::block::genesis(&net);
        let (mut s, _) = Store::open(&dir).unwrap();
        s.append(b"something else first").unwrap();
        let bytes = g.encode();
        let at = s.append(&bytes).unwrap();
        let bodies = s.bodies(net.clone()).unwrap();
        bodies.insert(g.id(&net), at, bytes.len());
        assert_eq!(bodies.load(&g.id(&net)), Some(g));
        assert_eq!(bodies.load(&[0; 32]), None);
        drop((s, bodies));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
