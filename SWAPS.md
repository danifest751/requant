# Swaps and payment channels

Status: **consensus primitives, pool policy and wallet commands; no protocol software yet.** Since
node 0.15.0 the chain has 2-of-2 conditions, hash/time-locked contracts (HTLCs) and absolute and
relative time locks ([CHAIN.md §4.1](CHAIN.md)); since node 0.16.0 also revocable outputs, revocable
HTLCs and anyone-can-pay signatures ([§4.2](CHAIN.md)), and a pool that ranks packages (child pays for
parent) and replaces by fee ([§4.3](CHAIN.md)). On the test network they are active from heights 1400
and 4700, on the main network from genesis. `requant-wallet` describes conditions, locks coins under
them and spends them along each path (`condition`, `spend-condition`, `cosign`). The protocols below
are built in software on top of them, and **that software does not exist yet:** there is no swap tool,
maker bot or channel implementation. The point of having the primitives now is that adding these
protocols later needs no hard fork.

## The primitives

| Primitive | In consensus as |
|---|---|
| Hash lock | HTLC claim path: the 32-byte SHA-256 preimage and the claim key |
| Time lock | HTLC refund path (absolute height); `after_height` and `after_blocks` on any input |
| 2-of-2 | Multi2 condition: two ed25519 keys sign the same transaction |
| Revocable output | `delayed`: the owner after a relative delay, the revocation key at any time |
| Revocable HTLC | as an HTLC, with delays on claim and refund and a revocation path |
| Anyone-can-pay | a signature over its own input and all outputs, so others may add inputs |
| k-of-n | off chain: FROST or MuSig2 aggregate ed25519 keys into one ordinary key |

A locked coin pays a hash like any address, so locking is an ordinary transfer. The spending input
reveals the condition. Txids exclude signatures, so a transfer can be signed by both parties before
its parent is even confirmed, and its reference stays valid. Every protocol below depends on this.

## 1. HTLC swaps (Bitcoin family, EVM)

Party A picks a secret `s` and publishes `H = SHA256(s)`.

1. A locks RQT in an HTLC: hash `H`, claim key B, refund key A, timeout `t_RQT`.
2. B locks the other coin under the same `H`, refundable to B at an earlier timeout `t_other`.
   On Bitcoin, Litecoin, Bitcoin Cash and Dogecoin this is the standard `OP_SHA256` +
   `OP_CHECKLOCKTIMEVERIFY` script; on EVM chains it is a contract.
3. A claims the other coin, which reveals `s` on that chain.
4. B claims the RQT with `s`.

If either side stops, both refund after their timeouts. The RQT timeout must be the later one
(`t_RQT` well after `t_other`), so that B always has time to use `s` once A reveals it.

**Privacy: weak, and it should be said so.** The same `H` appears on both chains, and the amounts and
timing match. Anyone watching both chains can link the two halves. The HTLC is also visible on RQT
when it is spent: its claim or refund path is revealed.

## 2. Swaps with Monero (adaptor signatures)

Monero has no scripts and no hash locks. A swap with it uses adaptor signatures plus time locks on
the other chain, which RQT now has. The usual design (as in the Bitcoin–Monero swaps):

1. **Lock.** The RQT side locks coins under 2-of-2 (A, B). Before broadcasting, both sign:
   - a *cancel* transfer of the lock coin to a new 2-of-2, valid `after_blocks = t1` after the lock;
   - a *refund* transfer from the cancel output back to the RQT seller;
   - a *punish* transfer from the cancel output to the buyer, valid `after_blocks = t2` after the
     cancel.
2. **Monero side.** The XMR is sent to an address whose spend key is shared between the parties.
3. **Redeem.** Redeeming the RQT completes an adaptor signature. The completed signature reveals the
   secret half of the Monero key, so the other party can sweep the XMR.
4. **Refund or punish.** If a party stops, the cancel, refund and punish paths with their relative
   locks settle the coins without trust.

RQT and Monero use the same curve (ed25519). The adaptor secret is therefore one scalar on both
sides, and no cross-curve proof of equal discrete logarithms is needed (Bitcoin–Monero swaps need
one).

**What has to be built:**
- ed25519 adaptor signatures, which need random nonces: the deterministic nonce of plain ed25519
  does not apply;
- the swap state machine and a maker bot;
- an external cryptographic review before real money.

**Privacy.**
- If the 2-of-2 is the consensus Multi2 condition, it is visible when spent. Swaps whose RQT side
  looks like an ordinary transfer need the two keys aggregated off-chain into one (MuSig2 on
  ed25519). The result is checked by the ordinary single-key rule, so no consensus change is needed.
  Until that exists, say the swap is visible.
- The Monero side keeps Monero's privacy.
- Amounts and timing can still correlate the two halves.

## 3. Payment channels (MagnetGate)

Paying for traffic is one-way, client to server, and needs only 2-of-2 and an absolute lock:

1. The client locks a deposit under 2-of-2 (client, server).
2. The server signs a *refund* of the whole deposit to the client, valid from an expiry height.
3. For each piece of traffic, the client signs a new transfer from the deposit that pays the server
   more and itself the rest. The server keeps the last one.
4. Before the expiry, the server publishes the last state; that spends the deposit, and the refund
   can never be used. If the server disappears, the client takes the refund at the expiry.

There is no revocation and no penalty: a newer state always pays the server more, so the server never
wants to publish an older one. The consensus test `one_way_payment_channel` walks through exactly
this.

**Two-way channels** use the revocable templates of §4.2, as Lightning does. Each party holds its own
version of the latest commitment transfer from the 2-of-2 deposit, in which its own balance pays a
revocable output (`delayed`: itself after `delay` blocks, or the other party's revocation key at once)
and the other party's balance pays the other party directly. Moving to a new state, each side hands
over the secret of its revocation key for the old one. Publishing a revoked state then lets the other
side take the publisher's balance through the revocation path before the delay ends. Payments routed
through channels sit in revocable HTLCs (claim with the preimage, refund after the timeout, both after
a delay; revocation at once). The templates are in consensus; the channel software is large and
needs review.

## Before any of this carries real value

- **Finality.** A swap is only as safe as the depth of reorganisation it can survive. A small
  proof-of-work chain can be rewritten by an attacker with enough hashrate; the attacker could undo
  the RQT side after receiving the other coin. Swap software must wait for confirmations scaled to
  the amount and the network's hashrate, and say so to users. TNet hashrate cannot be rented on the
  usual GPU markets, which helps but does not remove this risk.
- **Fees on pre-signed transfers.** Refunds and cancels are signed long before they are sent. If fees
  rise in between, there are three ways to get them in: a child spending one of their outputs pays
  for both (packages are ranked together, and since node 0.17.0 relayed together, so the pre-signed
  parent may pay nothing); a signer who used anyone-can-pay lets anyone add an input that raises the
  fee; and a single-signer transfer can be replaced by fee. A pre-signed transfer therefore only
  needs an output its owner can spend with a child.
- **Review.** The consensus rules are small, fixed templates with tests
  (`crates/consensus/tests/conditions.rs`). The protocols need their own review, the Monero one most
  of all.
