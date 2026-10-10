//! Epoch weights on disk. TNet v1 weights are 512 MiB per epoch; held in the process they pin that much
//! memory. Written once per epoch to `<datadir>/<network>/epochs/<seed>.tnet` (the transposed layers, layer
//! after layer) and read back at every check, they live in the operating system's file cache instead: as
//! fast while cached, and reclaimable when other programs need the memory (then a check reads from disk).
//! A checksum file guards against a damaged or partly written weights file.

use requant_consensus::tx::Hash;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tnet::{Epoch, LayerSource, Params};

/// Bytes hashed per checksum chunk.
const CHUNK: usize = 1 << 20;

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The weights file, kept open: positional reads from any thread, and still readable after the file is
/// replaced or removed (on Unix; Windows refuses to remove an open file).
struct FileSource {
    file: File,
    path: PathBuf,
    n: usize,
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], at: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(f, buf, at)
}

#[cfg(windows)]
fn read_at(f: &File, mut buf: &mut [u8], mut at: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match std::os::windows::fs::FileExt::seek_read(f, buf, at)? {
            0 => return Err(io::ErrorKind::UnexpectedEof.into()),
            k => {
                buf = &mut buf[k..];
                at += k as u64;
            }
        }
    }
    Ok(())
}

impl LayerSource for FileSource {
    fn read(&self, l: usize, j0: usize, out: &mut [i8]) -> io::Result<()> {
        // SAFETY: i8 and u8 have the same size and alignment, and every bit pattern is valid for both.
        let bytes = unsafe { std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, out.len()) };
        let r = read_at(&self.file, bytes, ((l * self.n + j0) * self.n) as u64);
        if let Err(e) = &r {
            // never verify with unreadable weights; a restart rebuilds the file
            eprintln!("epoch weights {}: {e}; stopping", self.path.display());
            std::process::exit(1);
        }
        r
    }
}

/// `sha256` of the concatenated `sha256` of every 1 MiB chunk of `path` (streamed, little memory).
fn checksum(path: &Path) -> io::Result<String> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; CHUNK];
    let mut hashes = Vec::new();
    loop {
        let mut got = 0;
        while got < CHUNK {
            let k = f.read(&mut buf[got..])?;
            if k == 0 {
                break;
            }
            got += k;
        }
        if got == 0 {
            break;
        }
        hashes.extend_from_slice(&tnet::sha256::sha256(&buf[..got]));
    }
    Ok(hexs(&tnet::sha256::sha256(&hashes)))
}

fn paths(dir: &Path, seed: &Hash) -> (PathBuf, PathBuf) {
    let name = hexs(seed);
    (dir.join(format!("{name}.tnet")), dir.join(format!("{name}.sum")))
}

/// The epoch for `seed` backed by its weights file in `dir`: an existing file whose checksum matches, or
/// a new one derived layer by layer (one layer in memory at a time). Files of other epochs than `keep`
/// are removed.
pub fn open_or_derive(dir: &Path, seed: &Hash, p: Params, keep: &[Hash]) -> io::Result<Epoch> {
    std::fs::create_dir_all(dir)?;
    // other epochs' files go first (the current one and the one being prepared stay), so the disk never
    // holds more than two epochs either
    for e in std::fs::read_dir(dir)?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let stem = name.split('.').next().unwrap_or("");
        let wanted = stem == hexs(seed) || keep.iter().any(|k| stem == hexs(k));
        if !wanted {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let (file, sum) = paths(dir, seed);
    let size = (p.layers * p.n * p.n) as u64;
    let good = std::fs::metadata(&file).is_ok_and(|m| m.len() == size)
        && std::fs::read_to_string(&sum).is_ok_and(|s| checksum(&file).is_ok_and(|c| c == s.trim()));
    if !good {
        let tmp = file.with_extension("tmp");
        {
            let mut f = io::BufWriter::new(File::create(&tmp)?);
            for l in 0..p.layers as u32 {
                let layer = tnet::transposed_layer(seed, p, l);
                f.write_all(&layer.iter().map(|&x| x as u8).collect::<Vec<u8>>())?;
            }
            f.into_inner().map_err(|e| e.into_error())?.sync_all()?;
        }
        let c = checksum(&tmp)?;
        std::fs::rename(&tmp, &file)?;
        std::fs::write(&sum, format!("{c}\n"))?;
    }
    Ok(Epoch::from_source(p, Box::new(FileSource { file: File::open(&file)?, path: file, n: p.n })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_file_checks_like_memory_and_is_rebuilt_when_damaged() {
        let dir = std::env::temp_dir().join(format!("requant-epochs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Params { n: 512, b: 4, layers: 3, w: 64, mult: tnet::default_mult(512) };
        let (seed, other) = ([4u8; 32], [5u8; 32]);
        let mem = Epoch::from_seed(&seed, p);
        let x = tnet::x0_seed(&[1; 32], 2);
        let disk = open_or_derive(&dir, &seed, p, &[]).unwrap();
        assert_eq!(disk.forward_row(&x, 1, 3), mem.forward_row(&x, 1, 1));
        drop(disk); // Windows does not replace an open file
                    // damage the file: the checksum notices and the file is derived again
        let (file, _) = paths(&dir, &seed);
        let mut bytes = std::fs::read(&file).unwrap();
        bytes[1000] ^= 1;
        std::fs::write(&file, &bytes).unwrap();
        let again = open_or_derive(&dir, &seed, p, &[]).unwrap();
        assert_eq!(again.forward_row(&x, 1, 2), mem.forward_row(&x, 1, 1));
        // preparing another epoch keeps only the epochs asked for
        open_or_derive(&dir, &other, p, &[seed]).unwrap();
        assert!(file.exists());
        drop(again); // Windows keeps open files
        open_or_derive(&dir, &other, p, &[]).unwrap();
        assert!(!file.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
