"""TNet v1 reference in pure Python (standard library only), written from SPEC.md.

Independent of the Rust crate; ``tests/test_reference.py`` checks it against ``vectors/`` and the
``tnet`` binary. Slow: meant for small parameters.
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence

DOM_EXPAND = b"abacus/expand"
DOM_W = b"abacus/tnet-w"
DOM_X0 = b"abacus/tnet-x0"
TICKET_TAG = 0x54
REQ_SHIFT = 24


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def le32(x: int) -> bytes:
    return x.to_bytes(4, "little")


def le64(x: int) -> bytes:
    return x.to_bytes(8, "little")


def expand(seed: bytes, start: int, length: int) -> bytes:
    """Bytes [start, start + length) of SHA256(DOM_EXPAND || seed || LE32(k)), k = 0, 1, ..."""
    out = bytearray()
    k = start // 32
    while len(out) < (start % 32) + length:
        out += sha256(DOM_EXPAND, seed, le32(k))
        k += 1
    return bytes(out[start % 32:start % 32 + length])


def to_i8(data: bytes) -> List[int]:
    return [x - 256 if x >= 128 else x for x in data]


def encode(v: Sequence[int]) -> bytes:
    return bytes(x & 0xFF for x in v)


def default_mult(n: int) -> int:
    return round((1 << REQ_SHIFT) / (74.0 * n ** 0.5))


def layer_weights(epoch_seed: bytes, n: int, l: int) -> List[int]:
    return to_i8(expand(sha256(DOM_W, epoch_seed, le32(l)), 0, n * n))


def x0_seed(header_digest: bytes, nonce: int) -> bytes:
    return sha256(DOM_X0, header_digest, le64(nonce))


def x0_row(seed: bytes, n: int, i: int) -> List[int]:
    return to_i8(expand(seed, i * n, n))


def requant(y: int, mult: int) -> int:
    return max(-128, min(127, (y * mult + (1 << (REQ_SHIFT - 1))) >> REQ_SHIFT))


def forward_row(weights, n: int, mult: int, seed: bytes, i: int) -> List[int]:
    x = x0_row(seed, n, i)
    for w in weights:
        x = [requant(sum(x[k] * w[k * n + j] for k in range(n)), mult) for j in range(n)]
    return x


def ticket_hash(piece: Sequence[int], header_digest: bytes, nonce: int, i: int, c: int) -> bytes:
    return sha256(encode(piece), bytes([TICKET_TAG]), header_digest, le64(nonce), le32(i), le32(c))


def meets_target(h: bytes, target: bytes) -> bool:
    return int.from_bytes(h, "big") <= int.from_bytes(target, "big")
