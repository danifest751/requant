"""Python reference vs committed vectors and vs the Rust ``tnet`` binary."""

import json
import os
import shutil
import subprocess

import pytest

from reference import tnet_ref as t

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = "tnet.exe" if os.name == "nt" else "tnet"


def _check(g):
    n, w, mult, layers = g["n"], g["w"], g["mult"], g["L"]
    epoch, hd, nonce, i = bytes.fromhex(g["epoch"]), bytes.fromhex(g["hd"]), g["nonce"], g["i"]
    weights = [t.layer_weights(epoch, n, l) for l in range(layers)]
    assert g["weights_sha256"] == [t.sha256(t.encode(wl)).hex() for wl in weights]
    seed = t.x0_seed(hd, nonce)
    assert g["x0_sha256"] == t.sha256(t.encode(t.x0_row(seed, n, i))).hex()
    row = t.forward_row(weights, n, mult, seed, i)
    assert g["row"] == t.encode(row).hex()
    assert g["row_sha256"] == t.sha256(t.encode(row)).hex()
    assert g["tickets"] == [t.ticket_hash(row[c * w:(c + 1) * w], hd, nonce, i, c).hex() for c in range(n // w)]


def test_committed_small_vectors():
    with open(os.path.join(ROOT, "vectors", "tnet-v1-small.jsonl"), encoding="utf-8") as f:
        for line in f:
            _check(json.loads(line))


CASES = [
    (64, 16, 4, 16, t.default_mult(64), b"\x06" * 32, b"\x07" * 32, 0, [0, 15]),
    (128, 64, 3, 32, t.default_mult(128), bytes(range(32)), bytes(range(32, 64)), 2**64 - 1, [1, 63]),
    (64, 8, 2, 64, 1 << 20, b"\x00" * 32, b"\xff" * 32, 12345, [7]),  # coarse scale: saturates
]


@pytest.mark.parametrize("case", CASES)
def test_rust_binary_matches(case):
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo not found")
    subprocess.run([cargo, "build", "--quiet", "--bin", "tnet"], cwd=ROOT, check=True)
    exe = os.path.join(ROOT, "target", "debug", EXE)
    n, b, layers, w, mult, epoch, hd, nonce, rows = case
    args = [str(n), str(b), str(layers), str(w), str(mult), epoch.hex(), hd.hex(), str(nonce), *map(str, rows)]
    out = subprocess.run([exe, "vectors", *args], capture_output=True, text=True, check=True).stdout
    got = [json.loads(line) for line in out.splitlines()]
    assert [g["i"] for g in got] == rows
    for g in got:
        _check(g)


def test_constants_and_targets():
    assert t.default_mult(8192) == 2505 and t.default_mult(4096) == 3542
    m = 1 << 20
    assert [t.requant(y, m) for y in (0, 7, 8, -8, -9, 1 << 20, -(1 << 20))] == [0, 0, 1, 0, -1, 127, -128]
    target = bytes([0x00, 0x0F]) + b"\xff" * 30
    assert t.meets_target(bytes([0x00, 0x0F]) + b"\xff" * 30, target)
    assert not t.meets_target(bytes([0x00, 0x10]) + b"\x00" * 30, target)
