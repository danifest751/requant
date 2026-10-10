"""Publish a signed requantd release (maintainers).

    python scripts/release.py VERSION --linux requantd --windows requantd.exe --key release.key [--publish]

Writes `release-VERSION.txt` (the manifest: version, and per platform the binary's SHA-256 and download
URL on the GitHub release `vVERSION`) and `release-VERSION.sig` (its signature by the release key, made
with `requant-wallet sign-release`). With `--publish`, creates the GitHub release with the binaries and
those two files (`gh` CLI). Announce it by passing the manifest and signature to any node:
`submitrelease` over its JSON-RPC; peers spread it, and nodes started with `--auto-update` install it.
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

REPO = "requant-network/requant"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--linux", type=Path, help="requantd for linux-x86_64 (static musl build)")
    ap.add_argument("--windows", type=Path, help="requantd.exe for windows-x86_64")
    ap.add_argument("--key", type=Path, required=True, help="release key file")
    ap.add_argument("--wallet", default="target/release/requant-wallet", help="requant-wallet that signs")
    ap.add_argument("--wallet-linux", type=Path, help="requant-wallet for linux-x86_64, attached for download")
    ap.add_argument("--wallet-windows", type=Path, help="requant-wallet.exe for windows-x86_64, attached for download")
    ap.add_argument("--out", type=Path, default=Path("."))
    ap.add_argument("--publish", action="store_true", help="create the GitHub release")
    a = ap.parse_args()

    v = a.version
    if len(v.split(".")) != 3 or not all(p.isdigit() for p in v.split(".")):
        sys.exit("version must be x.y.z")
    assets = []
    for platform, path, name in [
        ("linux-x86_64", a.linux, "requantd-linux-x86_64"),
        ("windows-x86_64", a.windows, "requantd-windows-x86_64.exe"),
    ]:
        if path:
            url = f"https://github.com/{REPO}/releases/download/v{v}/{name}"
            assets.append((platform, path, name, url))
    if not assets:
        sys.exit("give at least one binary")
    text = f"requant-release 1\nversion {v}\n" + "".join(
        f"asset {platform} {sha256(path)} {url}\n" for platform, path, _, url in assets
    )
    manifest = a.out / f"release-{v}.txt"
    manifest.write_bytes(text.encode())
    wallet = a.wallet + (".exe" if sys.platform == "win32" and not a.wallet.endswith(".exe") else "")
    sig = subprocess.run(
        [str(Path(wallet).resolve()), "sign-release", str(a.key), str(manifest)], capture_output=True, text=True, check=True
    ).stdout.strip()
    sig_file = a.out / f"release-{v}.sig"
    sig_file.write_text(sig + "\n")
    print(text, end="")
    print(f"signature {sig}")

    if a.publish:
        # each binary is uploaded under its asset name (a copy with that name, then the upload)
        staged = []
        for _, path, name, _ in assets:
            dst = a.out / name
            if path.resolve() != dst.resolve():
                dst.write_bytes(path.read_bytes())
            staged.append(str(dst))
        # wallets are downloads only: nodes update requantd from the manifest, never the wallet
        for path, name in [(a.wallet_linux, "requant-wallet-linux-x86_64"),
                           (a.wallet_windows, "requant-wallet-windows-x86_64.exe")]:
            if path:
                dst = a.out / name
                if path.resolve() != dst.resolve():
                    dst.write_bytes(path.read_bytes())
                staged.append(str(dst))
        notes = (f"requantd {v} (node) and requant-wallet for Linux and Windows. Signed release manifest for "
                 f"auto-updating nodes: release-{v}.txt, signature release-{v}.sig. See TESTNET.md.")
        subprocess.run(
            ["gh", "release", "create", f"v{v}", "--repo", REPO, "--title", f"requantd {v}", "--notes", notes,
             *staged, str(manifest), str(sig_file)],
            check=True,
        )
        print(f"published https://github.com/{REPO}/releases/tag/v{v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
