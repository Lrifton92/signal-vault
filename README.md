# Signal Vault

**Sell a trading signal without revealing it, then prove your track record when it expires.**

A Tari Ootle template implementing one primitive: *pay to unlock now, verify publicly later*.

Built for the September 2026 Tari Developer Showcase.

## The problem

Signal sellers cannot publish their edge, because publishing it destroys it. So the market runs on
screenshots and trust: Telegram groups, deleted losing calls, track records nobody can audit. The
buyer has no way to check a seller's history, and the seller has no way to prove one without giving
the signal away for free.

## What the template does

A provider seals a signal as `commitment_of(publisher key, payload, nonce)`: Blake2b-256 over a
domain tag and those three parts, each length-prefixed. They compute it off-chain and publish only
the digest, together with a price and a reveal epoch. The payload never touches the chain while it
is tradeable: never put payload and nonce in a transaction before expiry, that would publish them.
Because the key is part of the hash, a commitment only opens in a vault signed by the key that
sealed it: copying a competitor's commitment into your own vault gets you a signal you can never
open.

1. **`publish(commitment, reveal_at_epoch, price, payment_resource)`** creates the component.
   Payment must be TARI: the engine lets the issuer of any other resource recall or freeze it in any
   vault, which would let a provider pricing in their own coin take the escrow back. The
   component has no owner, so nobody, the publisher included, can change its code or its rules
   afterwards. `reveal_at_epoch` must be at most 10,000 epochs away, and the publication is
   emitted as a `signal_published` event, so a provider's unopened vaults stay visible.
2. **`purchase(payment) -> (badge, change)`** takes payment into the vault and mints a
   non-fungible access badge carrying the commitment and the epoch of purchase (`change` is `None`
   on an exact payment). Only the vault itself can mint badges, and badge data is immutable. The provider
   delivers the payload off-chain to badge holders. Sales close automatically at the reveal epoch.
3. **`reveal(payload, nonce)`** is callable by *anyone* during the reveal window (10 epochs from
   the reveal epoch). The template re-hashes, rejects anything that does not open the commitment,
   refuses payloads with control, bidi or zero-width characters (a payload must read the way it
   hashes), and requires a 16 to 64-byte nonce (use 32 random bytes: a short one lets anyone brute-force a
   guessable payload from the public digest).
4. **`refund(badges)`**: if the window closes without a reveal, any badge holder burns their badges
   and gets the price back. An unopened signal is a refunded loss, never a quiet one.
5. **`withdraw(amount)` / `withdraw_confidential(proof)`** pay the provider out, only with the
   publishing key and only after the reveal: until then the money backs the refunds.

## Why the Ootle specifically

- **Native TARI is a stealth resource**: what a buyer holds and where the provider sends the
  proceeds can stay private. The price and the number of badges sold are public, so gross revenue is
  too (`price × sold`).
- **Templates** make the escrow-and-reveal logic small enough to audit in one sitting. The whole
  contract is under 400 lines.
- **Epochs** give the reveal deadline a consensus-level clock instead of a trusted timestamp.

## What it guarantees, and what it does not

Guaranteed by the template:

- A payload cannot be read on-chain before the reveal epoch, so a buyer cannot be front-run by
  someone watching state.
- A commitment can be opened exactly one way. Parts are length-prefixed before hashing, so
  `("ab", "c")` and `("a", "bc")` are different digests and a provider cannot open one commitment
  with two payloads and keep whichever aged better.
- The digest was fixed before the outcome existed, so a revealed record is a real record.

Not guaranteed, and deliberately out of scope:

- **Off-chain delivery.** The template proves *what* was sealed, not that the provider actually
  sent it to a buyer. Delivery is a separate problem; encrypting to the badge holder's key is the
  natural next layer.
- **Signal quality.** Verifiability is not profitability. The contract makes a bad provider
  *legible*, not absent.
- **Reveal liveness.** If the provider vanishes and no buyer keeps the preimage, the commitment
  stays sealed. Buyers then get their money back, but the payload itself is lost.
- **Selective publishing across keys.** Every publication is an event, but a provider with several
  keys can still hide the vaults signed by the others.

## The same primitive elsewhere

Anything shaped like "sell information now, prove it later": research calls, oracle
pre-commitments, sealed-bid auctions, bug-bounty disclosure windows.

## Build

```
rustup target add wasm32-unknown-unknown
cargo test --lib                                  # commitment scheme, native
cargo test --tests                                # engine scenarios, Linux/macOS only
cargo build --release --target wasm32-unknown-unknown
```

Output: `target/wasm32-unknown-unknown/release/signal_vault.wasm` (182 KB), plus the template
metadata CBOR generated by `build.rs`.

Built against the published crates `tari_template_lib 0.31.1` and `tari_template_abi 0.19.1`, so
the build reproduces without a checkout of the Ootle repository. Blake2b-256 is computed in-template
by the pure-Rust `blake2` crate rather than by an engine intrinsic, for the same reason.

## Deployed

The September contest version is live on the **esmeralda** testnet. It predates both audit passes
and has none of their fixes (no refunds, owner-controlled vault): do not use it for real value.

```
template_06b9882e4d8e26551752ef0b1c5d300ec0b9a6db8a85705e34934f6dc858a61d
```

Published with `tari publish` through a local wallet daemon against the public indexer at
`ootle-indexer-a.tari.com`. The on-chain ABI carries all fourteen functions — `publish`,
`purchase`, `reveal`, `withdraw`, `withdraw_confidential` and the nine getters — under the
template name `SignalVault`.

## Checked with the official tooling

`tari lint` (from `tari-ootle-cli 0.26.0`) reports **0 errors, 0 warnings**, and
`cargo clippy --target wasm32-unknown-unknown -- -D warnings` is clean. What the linter changed
here, and why it was right:

- `crate-type` is exactly `["cdylib"]`. Dropping `rlib` took the binary from 245 KB to 182 KB. The
  integration tests therefore keep their own copy of `commitment_of` (`tests/common`), and every
  successful reveal checks it against the template's.
- Every `Vec<u8>` crossing the template boundary is now `Bytes` from `tari_template_lib::prelude`.
  A `Vec<u8>` CBOR-encodes as an array of integers rather than a byte string, up to twice the size.
- `build.rs` and `tari_ootle_template_build` generate the on-chain template metadata, and
  `[package.metadata.tari-template]` carries the tags, category and links.

The one remaining suggestion is `logo_url`, left empty on purpose rather than pointed at a
placeholder image.

## Licence

BSD-3-Clause, matching the Tari codebase. See `LICENSE`.
