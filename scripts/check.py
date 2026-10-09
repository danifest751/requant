"""Local gate: pytest, rustfmt, clippy (warnings as errors), cargo test. Run before every commit."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(name: str, cmd: list[str]) -> bool:
    print(f"== {name}: {' '.join(cmd)}", flush=True)
    ok = subprocess.run(cmd, cwd=ROOT).returncode == 0
    print(f"== {name}: {'OK' if ok else 'FAILED'}", flush=True)
    return ok


def main() -> int:
    results = [run("pytest", [sys.executable, "-m", "pytest", "tests", "-q"])]
    cargo = shutil.which("cargo")
    if cargo is None:
        print("cargo not found: Rust checks skipped")
    else:
        results.append(run("cargo fmt", [cargo, "fmt", "--all", "--check"]))
        results.append(run("cargo clippy", [cargo, "clippy", "--workspace", "--all-targets", "--quiet", "--", "-D", "warnings"]))
        results.append(run("cargo test", [cargo, "test", "--workspace", "--quiet"]))
    ok = all(results)
    print("ALL CHECKS PASSED" if ok else "CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
