//! Signed releases and opt-in self-update.
//!
//! A release is a short text manifest signed with the release key, whose public half is built into the
//! node ([`RELEASE_KEY`]):
//!
//! ```text
//! requant-release 1
//! version 0.6.1
//! asset linux-x86_64 <sha256 hex> https://github.com/danifest751/requant/releases/download/v0.6.1/requantd-linux-x86_64
//! asset windows-x86_64 <sha256 hex> https://...
//! ```
//!
//! signed (ed25519, strict) over `H("requant/release", text)`. Nodes pass the newest release they have
//! verified to their peers (protocol 4), so every node learns of it; `getinfo` and the log say when this
//! node is older. With `--auto-update`, after a random delay (so a bad release cannot stop every node at
//! once) the node downloads its platform's binary with the system's `curl`, checks the signed SHA-256 and
//! that the new binary reports the announced version, replaces its own executable, and exits for the
//! service manager to start the new one. Only versions above the running one are taken: an old signed
//! manifest cannot downgrade a node.

use crate::node::{now, Shared, VERSION};
use ed25519_dalek::{Signature, VerifyingKey};
use requant_consensus::params::tagged;
use requant_consensus::tx::Hash;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Public key of the Requant release key (`48671c99…b72c`).
pub const RELEASE_KEY: [u8; 32] = [
    0x48, 0x67, 0x1c, 0x99, 0x65, 0x29, 0x23, 0x36, 0x73, 0x41, 0xd7, 0x4e, 0xe8, 0xdb, 0xef, 0x4b, 0x86, 0x18, 0x56,
    0xc0, 0xbf, 0x54, 0xfb, 0xb0, 0x8e, 0x6b, 0x8d, 0x94, 0x19, 0xdc, 0xb7, 0x2c,
];
pub const MAX_RELEASE_TEXT: usize = 4096;
/// Updates start at a random moment within this many seconds of learning of a release.
const SPREAD: u64 = 1800;
/// Download attempts per release.
const ATTEMPTS: u32 = 3;

pub type Version = (u32, u32, u32);

pub fn parse_version(s: &str) -> Option<Version> {
    let mut it = s.trim().split('.').map(|x| x.parse::<u32>().ok());
    let v = (it.next()??, it.next()??, it.next()??);
    it.next().is_none().then_some(v)
}

pub fn own_version() -> Version {
    parse_version(VERSION).expect("crate version is x.y.z")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    pub platform: String,
    pub sha256: Hash,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub text: String,
    pub sig: [u8; 64],
    pub version: Version,
    pub assets: Vec<Asset>,
}

/// The message a release signature covers.
pub fn signed_message(text: &str) -> Hash {
    tagged("requant/release", &[text.as_bytes()])
}

/// This build's platform name in manifests.
pub fn platform() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "linux-x86_64",
        ("windows", "x86_64") => "windows-x86_64",
        ("linux", "aarch64") => "linux-aarch64",
        ("macos", "aarch64") => "macos-aarch64",
        _ => "other",
    }
}

fn unhex32(s: &str) -> Option<Hash> {
    crate::rpc::unhex(s).ok()?.try_into().ok()
}

impl Release {
    /// Parse and verify a manifest against `key` (normally [`RELEASE_KEY`]).
    pub fn verify_with(text: &str, sig: &[u8; 64], key: &[u8; 32]) -> Result<Release, &'static str> {
        if text.len() > MAX_RELEASE_TEXT {
            return Err("release manifest too long");
        }
        let vk = VerifyingKey::from_bytes(key).map_err(|_| "bad release key")?;
        vk.verify_strict(&signed_message(text), &Signature::from_bytes(sig)).map_err(|_| "bad release signature")?;
        let mut lines = text.lines();
        if lines.next() != Some("requant-release 1") {
            return Err("not a release manifest");
        }
        let (mut version, mut assets) = (None, Vec::new());
        for l in lines {
            let f: Vec<&str> = l.split_whitespace().collect();
            match f.as_slice() {
                ["version", v] => version = parse_version(v),
                ["asset", platform, sha, url] => {
                    if !url.starts_with("https://") {
                        return Err("release asset url must be https");
                    }
                    let sha256 = unhex32(sha).ok_or("bad asset hash")?;
                    assets.push(Asset { platform: platform.to_string(), sha256, url: url.to_string() });
                }
                [] => {}
                _ => return Err("unknown manifest line"),
            }
        }
        Ok(Release { text: text.to_string(), sig: *sig, version: version.ok_or("no version")?, assets })
    }

    pub fn version_string(&self) -> String {
        format!("{}.{}.{}", self.version.0, self.version.1, self.version.2)
    }

    pub fn asset(&self) -> Option<&Asset> {
        self.assets.iter().find(|a| a.platform == platform())
    }

    /// `LE16 text length || text || signature`, for the peer message and `release.txt`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = (self.text.len() as u16).to_le_bytes().to_vec();
        v.extend_from_slice(self.text.as_bytes());
        v.extend_from_slice(&self.sig);
        v
    }

    pub fn decode(b: &[u8], key: &[u8; 32]) -> Result<Release, &'static str> {
        let n = u16::from_le_bytes(b.get(..2).ok_or("short")?.try_into().unwrap()) as usize;
        if b.len() != 2 + n + 64 {
            return Err("release message length");
        }
        let text = std::str::from_utf8(&b[2..2 + n]).map_err(|_| "release text is not utf-8")?;
        Release::verify_with(text, b[2 + n..].try_into().unwrap(), key)
    }
}

/// The newest verified release in `datadir`, if any.
pub fn load(path: &Path, key: &[u8; 32]) -> Option<Release> {
    Release::decode(&std::fs::read(path).ok()?, key).ok()
}

fn sha256_file(path: &Path) -> std::io::Result<Hash> {
    Ok(tnet::sha256::sha256(&std::fs::read(path)?))
}

/// Download, check and install `r`'s binary for this platform in place of the running executable.
fn install(r: &Release, dir: &Path) -> Result<PathBuf, String> {
    let asset = r.asset().ok_or("no binary for this platform")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let new = dir.join(if cfg!(windows) { "requantd.new.exe" } else { "requantd.new" });
    let _ = std::fs::remove_file(&new);
    let out = Command::new("curl")
        .args(["-fsSL", "--max-time", "600", "-o"])
        .arg(&new)
        .arg(&asset.url)
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("download failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    if sha256_file(&new).map_err(|e| e.to_string())? != asset.sha256 {
        return Err("downloaded binary does not match the signed hash".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    let v = Command::new(&new).arg("--version").output().map_err(|e| format!("new binary does not run: {e}"))?;
    let said = String::from_utf8_lossy(&v.stdout).trim().to_string();
    if said != format!("requantd/{}", r.version_string()) {
        return Err(format!("new binary reports {said:?}"));
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let prev = exe.with_extension(if cfg!(windows) { "prev.exe" } else { "prev" });
    let _ = std::fs::remove_file(&prev);
    // a running executable can be renamed (also on Windows), then the new one takes its place
    std::fs::rename(&exe, &prev).map_err(|e| format!("cannot replace {}: {e}", exe.display()))?;
    if let Err(e) = std::fs::rename(&new, &exe).or_else(|_| std::fs::copy(&new, &exe).map(|_| ())) {
        let _ = std::fs::rename(&prev, &exe);
        return Err(format!("cannot install {}: {e}", exe.display()));
    }
    Ok(exe)
}

/// With `--auto-update`: wait for a newer release, then install it at a random moment within `SPREAD`
/// seconds and exit (the service manager starts the new binary). Failures are logged and retried a few
/// times; the node keeps running meanwhile.
pub fn updater(shared: Shared, dir: PathBuf) {
    let mut due: Option<(Version, u64)> = None;
    let mut tries = 0u32;
    loop {
        std::thread::sleep(Duration::from_secs(20));
        let r = shared.lock().unwrap().release.clone();
        let Some(r) = r.filter(|r| r.version > own_version() && r.asset().is_some()) else { continue };
        match due {
            Some((v, _)) if v == r.version => {}
            _ => {
                let delay = crate::node::random_u64() % SPREAD;
                eprintln!("update to {} scheduled in {} min", r.version_string(), delay / 60);
                due = Some((r.version, now() + delay));
                tries = 0;
            }
        }
        let (_, at) = due.unwrap();
        if now() < at || tries >= ATTEMPTS {
            continue;
        }
        tries += 1;
        match install(&r, &dir) {
            Ok(exe) => {
                eprintln!("updated to requantd {} ({}); restarting", r.version_string(), exe.display());
                shared.lock().unwrap().book.save();
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("update to {} failed (attempt {tries} of {ATTEMPTS}): {e}", r.version_string());
                due = Some((r.version, now() + 600));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(key: &SigningKey, text: &str) -> [u8; 64] {
        key.sign(&signed_message(text)).to_bytes()
    }

    #[test]
    fn manifests_verify_and_roundtrip() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let pk = key.verifying_key().to_bytes();
        let text =
            format!("requant-release 1\nversion 1.2.3\nasset linux-x86_64 {} https://example.org/a\n", "ab".repeat(32));
        let r = Release::verify_with(&text, &signed(&key, &text), &pk).unwrap();
        assert_eq!(r.version, (1, 2, 3));
        assert_eq!(r.assets[0].sha256, [0xab; 32]);
        // another key, another text, plain http: refused
        let other = SigningKey::from_bytes(&[4; 32]);
        assert!(Release::verify_with(&text, &signed(&other, &text), &pk).is_err());
        assert!(Release::verify_with(&text.replace("1.2.3", "1.2.4"), &signed(&key, &text), &pk).is_err());
        let http = text.replace("https://", "http://");
        assert!(Release::verify_with(&http, &signed(&key, &http), &pk).is_err());
        assert_eq!(parse_version("0.6.0"), Some((0, 6, 0)));
        assert_eq!(parse_version("0.6"), None);
        assert!(parse_version("10.0.0") > parse_version("9.9.9"));
    }
}
