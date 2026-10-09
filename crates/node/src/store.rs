//! Append-only block file: `LE32 len || first 4 bytes of SHA256(data) || data` per accepted block, in
//! acceptance order (parents before children). A torn or corrupt tail is cut off on open.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use tnet::sha256::sha256;

pub struct Store {
    file: File,
}

impl Store {
    /// Open (or create) `dir/blocks.dat` and return the stored records.
    pub fn open(dir: &Path) -> io::Result<(Store, Vec<Vec<u8>>)> {
        std::fs::create_dir_all(dir)?;
        // write (not append) mode, so that a torn tail can be truncated on every platform
        let mut file =
            OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join("blocks.dat"))?;
        let mut all = Vec::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut all)?;
        let mut records = Vec::new();
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
            records.push(data.to_vec());
            pos += 8 + len;
        }
        if pos != all.len() {
            file.set_len(pos as u64)?;
        }
        file.seek(SeekFrom::Start(pos as u64))?;
        Ok((Store { file }, records))
    }

    pub fn append(&mut self, data: &[u8]) -> io::Result<()> {
        let mut rec = Vec::with_capacity(data.len() + 8);
        rec.extend_from_slice(&(data.len() as u32).to_le_bytes());
        rec.extend_from_slice(&sha256(data)[..4]);
        rec.extend_from_slice(data);
        self.file.write_all(&rec)?;
        self.file.sync_data()
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
            s.append(b"one").unwrap();
            s.append(b"two").unwrap();
        }
        // a torn third record
        OpenOptions::new().append(true).open(dir.join("blocks.dat")).unwrap().write_all(&[9, 0, 0, 0, 1]).unwrap();
        let (mut s, r) = Store::open(&dir).unwrap();
        assert_eq!(r, vec![b"one".to_vec(), b"two".to_vec()]);
        s.append(b"three").unwrap();
        drop(s);
        let (_, r) = Store::open(&dir).unwrap();
        assert_eq!(r.len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
