# Requant chain rules (draft v0)

Status: **draft for the test network** (2026-10-09). Values may change until the main network launches;
every change updates this file, the consensus crate (`crates/consensus`) and its tests together. The work
function is `SPEC.md` (TNet v1), unchanged.

## 1. Conventions

- Integers are little-endian unless stated. `H(tag, x)` is `SHA256(tag || x)` with `tag` an ASCII string
  without terminator; all tags start with `requant/`.
- `varint` is Bitcoin's CompactSize (`< 0xfd`: 1 byte; `0xfd` + LE16; `0xfe` + LE32; `0xff` + LE64);
  only the shortest encoding is valid.
- `bytes` is `varint(len) || data`.
- Decoders reject trailing data, non-canonical encodings and lengths above the limits of section 9.
- 1 RQT = 10^8 atoms. Amounts are `u64` atoms.

## 2. Networks

| | main | test | regtest |
|---|---|---|---|
| name (for `chain_id`) | `main` | `test` | `regtest` |
| work function | TNet v1 | TNet v1 | TNet `n = 256, B = 64, L = 4, w = 64, M = 14170` |
| target spacing `T` | 60 s | 60 s | 60 s |
| ASERT half-life `tau` | 7200 s | 7200 s | 7200 s |
| epoch length `E` / look-back `K` | 1440 / 60 | 1440 / 60 | 16 / 4 |
| `pow_limit` (largest target) | `2^240 - 1` | `2^248 - 1` | `2^255 - 1` |
| genesis target | set at launch | `pow_limit` | `pow_limit` |
| coinbase maturity | 100 | 100 | 2 |
| development fund (§8) | 6%, heights 1..2^21, key set at launch | same, `trq1qvfkg4mygtgkcthzsnjdpgqdujda8vm92cg62vas08aylluhf5gqsezeems` | 6%, heights 1..8, public test key |

`chain_id = H("requant/chain", name)`. Regtest exists for tests and local development; its small work
function makes CPU mining instant. The main network's genesis target is chosen at launch from the
test network's hashrate so that ASERT does not start from a trivially easy target (an instamine).

## 3. Block header and work claim

```
header (116 bytes) = LE32 version || LE64 height || prev_id[32] || tx_root[32] || LE64 time || target[32]
claim  (272 bytes) = LE64 nonce || LE32 i || LE32 c || piece[256]           (piece[w] on regtest)
header_digest      = H("requant/header", chain_id || header)
block_id           = H("requant/block", header_digest || claim)
```

`target` is a 256-bit big-endian integer. `header_digest` is the `header_digest` of `SPEC.md`; the claim
is checked against `target` as in `SPEC.md` §7, with the epoch weights of section 6.

## 4. Transactions

```
tx       = LE32 version || LE8 kind || body
coinbase (kind 0): LE64 height || bytes extra (<= 64) || varint n_out || output*
transfer (kind 1): varint n_in || input* || varint n_out || output*
input    = prev_txid[32] || LE32 vout || pubkey[32] || signature[64]
output   = LE64 value || pkh[32]                    pkh = H("requant/pkh", pubkey)
```

- `txid = H("requant/txid", tx with every signature omitted)`; `wtxid = H("requant/wtxid", tx)`.
  Outputs are referenced by `(txid, vout)`, so signatures cannot change a reference.
- Input `k` carries an ed25519 signature (RFC 8032, strict verification: canonical `S`, no small-order
  keys) of `H("requant/sighash", chain_id || txid || LE32 k)` by `pubkey`, and `H("requant/pkh", pubkey)`
  must equal the `pkh` of the output it spends.
- `version` is 1. A transfer has at least one input and one output, no repeated outpoint, outputs
  of at least 1 atom, and `sum(outputs) <= sum(inputs)`; the difference is the fee.

## 5. Blocks

```
block = header || claim || varint n_tx || tx*
tx_root = H("requant/txroot", LE32 n_tx || M(wtxid_0 .. wtxid_{n-1}))
M(x) = x for one leaf;  M(l || r) = H("requant/node", M(l) || M(r)),  splitting n leaves into the
       largest power of two below n and the rest (RFC 6962 tree, no duplicated leaves)
```

A block is valid when, against its parent:

1. `version = 1`, `height = parent.height + 1`, `prev_id = parent.block_id`;
2. `time > median(time of the last 11 blocks)`; nodes also refuse blocks with `time > now + 7200` until
   that time (not a consensus rule);
3. `target = next_target(parent)` (section 7);
4. the claim is valid (`SPEC.md` §7) for `header_digest` and the epoch of `height`;
5. `tx_root` matches; the serialized block is at most 1 MiB; the first transaction, and only it, is a
   coinbase with `height` equal to the block height;
6. every transfer is valid (section 4) against the outputs created by earlier blocks and earlier
   transactions of the same block, spends each output once, and spends coinbase outputs only after
   `maturity` blocks (`spending height - creating height >= maturity`);
7. coinbase outputs total at most `reward(height) + fees`.

The best chain is the valid chain with the greatest cumulative work, `work(target) = floor(2^256 /
(target + 1))`; on a tie the first seen is kept.

## 6. Epochs

`epoch(height) = floor(height / E)`. The epoch seed is `H("requant/epoch0", chain_id)` for epoch 0 and
`H("requant/epoch", LE64 e || block_id(e E - K))` for epoch `e >= 1`. Nodes derive the next epoch's
weights after block `e E - K` (about 7 s on one CPU core for TNet v1).

## 7. Difficulty (ASERT, anchored at genesis)

For the block after `parent` (BCH's aserti3-2d with the genesis block as anchor):

```
exponent = trunc( ((parent.time - genesis.time) - T * parent.height) * 65536 / tau )   (signed, toward zero)
shifts   = exponent >> 16                                                              (arithmetic, floor)
frac     = exponent & 0xffff
factor   = 65536 + ((195766423245049 frac + 971821376 frac^2 + 5127 frac^3 + 2^47) >> 48)
target   = (genesis.target * factor) shifted left by (shifts - 16) bits (right if negative), computed
           without overflow; then 0 becomes 1 and anything above pow_limit becomes pow_limit
```

The target halves (difficulty doubles) for every `tau` of lag behind schedule and doubles for every `tau`
ahead.

## 8. Emission

```
reward(height) = max( TAIL, max(0, S - generated(height)) >> 22 ),   for height >= 1
S = 2^24 * 10^8 atoms,  TAIL = 25,000,000 atoms
generated(1) = 0,  generated(h + 1) = generated(h) + reward(h)
```

The genesis block (height 0) issues nothing. The first reward (height 1) is 4 RQT; half of the main emission (`2^24 RQT`) is issued in about 5.5
years at one block per minute; the tail of 0.25 RQT per block starts after about 22 years and adds about
131,400 RQT per year from then on. Fees go to the miner in addition. No premine.

**Development fund.** For heights `1 ..= 2^21` (about four years) the coinbase must pay at least
`floor(reward(height) * 6 / 100)` to the network's fund key hash: 0.24 RQT of the first 4 RQT, about
396,000 RQT in total (2.4% of `S`, 6% of the 6.6 million RQT issued in those four years). Fees are never
shared. From height `2^21 + 1` the rule ends by itself. The fund is created only by mined blocks, like
every other coin; there is no premine. Its owner publishes the fund's spending regularly.

## 9. Limits

| | |
|---|---|
| serialized block | 1 MiB |
| inputs or outputs per transaction | 10,000 |
| coinbase `extra` | 64 bytes |
| sum of any amounts | must not exceed `2^63` atoms |

## 10. Genesis

The genesis block of each network is fixed in the consensus crate: height 0, `prev_id` zero, an empty
claim (not checked), one coinbase without outputs, `time` the launch time and `target = pow_limit`.
