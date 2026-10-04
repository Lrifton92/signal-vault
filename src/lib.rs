// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! # Signal Vault
//!
//! A sealed-bid marketplace primitive for the Tari Ootle: **pay to unlock, verify after expiry**.
//!
//! A signal provider publishes only `commitment_of(publisher, payload, nonce)` — the signal itself never touches
//! the chain while it is tradeable. Buyers pay into a vault and receive an access badge; the
//! provider delivers the payload off-chain to badge holders. Once the reveal epoch is reached,
//! anybody may open the commitment, and from then on the payload is public and permanently bound
//! to the epoch at which it was sealed.
//!
//! That ordering is what the contract buys you:
//!
//! * a buyer cannot be front-run, because the payload is not readable on-chain before expiry;
//! * a provider cannot fabricate a track record afterwards, because the commitment was fixed
//!   before the outcome was known, the hash is checked on reveal, and the component has no owner
//!   who could swap its code;
//! * a provider is only paid for a signal they open: proceeds stay locked until the reveal, and if
//!   the reveal window closes without one, every badge holder can burn their badge for a refund.
//!
//! Payment is in TARI only. The engine lets a resource's issuer recall or freeze it in any vault,
//! so a coin the provider issued would let them take the escrow back before revealing.
//!
//! What stays private: the payload until expiry. What does not: the price and the number of
//! badges sold are public, so gross revenue is `price × sold`.
//!
//! The same primitive fits any "sell information now, prove it later" market: research calls,
//! oracle pre-commitments, sealed-bid auctions.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use tari_template_lib::prelude::*;
use tari_template_lib::types::Hash32;

/// Domain separator, so a digest produced here can never be mistaken for one produced by another
/// protocol that happens to hash the same bytes.
const DOMAIN: &[u8] = b"tari.ootle.signal_vault.commitment.v2";

type Blake2b256 = Blake2b<U32>;

/// Epochs after `reveal_at_epoch` during which the signal can still be opened. Once they have
/// passed without a reveal, the vault switches to refunds, and the two never overlap.
pub const REVEAL_WINDOW_EPOCHS: u64 = 10;

/// Furthest `reveal_at_epoch` a vault may be published with, counted from the current epoch. Without
/// a bound, a vault sealed for `u64::MAX` would never reach judgement nor refunds.
pub const MAX_REVEAL_HORIZON_EPOCHS: u64 = 10_000;

/// A short nonce lets anyone brute-force a guessable payload ("long" / "short") from the public
/// commitment before expiry. The chain cannot check entropy, but it can refuse to open a commitment
/// that was sealed with a nonce too short to have had any: use 32 bytes from a CSPRNG.
pub const MIN_NONCE_LEN: usize = 16;
pub const MAX_NONCE_LEN: usize = 64;
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// The commitment a provider seals, and the value `reveal` checks against.
///
/// Every part is length-prefixed before hashing, so `("ab", "c")` and `("a", "bc")` produce
/// different digests. Without that, a provider could open one commitment with two different
/// payload/nonce splits and pick whichever one aged better.
///
/// The publisher's public key is part of the hash, so a commitment only opens in a vault published
/// by the key that sealed it: copying a competitor's commitment into your own vault gets you a
/// signal you can never open.
///
/// Compute it off-chain, never in a transaction: payload and nonce in a transaction are public. It
/// is an ordinary Rust function, outside the template, so it can be tested natively.
pub fn commitment_of(publisher: &[u8], payload: &str, nonce: &[u8]) -> Hash32 {
    let mut hasher = Blake2b256::new();
    for part in [DOMAIN, publisher, payload.as_bytes(), nonce] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Hash32::from_array(hasher.finalize().into())
}

/// Whether a payload reads the way it hashes. Control characters, bidi overrides and zero-width
/// characters let a provider show one call and hold another, then pick after the fact.
pub fn payload_is_canonical(payload: &str) -> bool {
    !payload.chars().any(|c| {
        c.is_control() ||
            matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}')
    })
}

/// Data carried by an access badge. Kept deliberately small: everything a buyer needs to prove
/// which sealed signal their badge unlocks.
#[derive(Debug, Clone, minicbor::Encode, minicbor::Decode, minicbor::CborLen)]
pub struct BadgeData {
    /// The commitment this badge grants access to.
    #[n(0)]
    pub commitment: [u8; 32],
    /// Epoch in which the badge was bought. Proves when it was paid for, not when the payload was
    /// delivered.
    #[n(1)]
    pub bought_at_epoch: u64,
}

#[template]
mod signal_vault {
    use super::*;

    pub struct SignalVault {
        /// `commitment_of(payload, nonce)`. Fixed at publish time and never mutated.
        commitment: Hash32,
        /// First epoch at which `reveal` is allowed.
        reveal_at_epoch: u64,
        /// Price of one access badge, in the payment resource.
        price: Amount,
        /// Proceeds. Confidential when the payment resource is.
        earnings: Vault,
        /// Access badges handed to buyers.
        badges: ResourceManager,
        /// The opened payload. `None` until `reveal` succeeds.
        payload: Option<String>,
        /// The nonce that opens the commitment. Published with the payload so anyone can re-hash.
        nonce: Option<Bytes>,
        /// Epoch at which the reveal actually happened.
        revealed_at_epoch: Option<u64>,
        /// Number of badges sold. The provider can buy their own, so this is not a reputation metric.
        sold: u64,
        /// Badges burned for a refund.
        refunded: u64,
        /// Key that signed `publish`. The only key allowed to withdraw, since the component has no
        /// owner.
        publisher: RistrettoPublicKeyBytes,
    }

    impl SignalVault {
        /// Seals a signal.
        ///
        /// `commitment` must be `commitment_of(signer's public key, payload, nonce)` — the template
        /// checks that on reveal, so a provider who commits to nothing simply can never reveal.
        ///
        /// `payment_resource` must be TARI.
        pub fn publish(
            commitment: Hash32,
            reveal_at_epoch: u64,
            price: Amount,
            payment_resource: ResourceAddress,
        ) -> Component<Self> {
            let now = Consensus::current_epoch();
            assert!(
                reveal_at_epoch > now,
                "reveal_at_epoch {} must be in the future (current epoch {})",
                reveal_at_epoch,
                now
            );
            assert!(
                reveal_at_epoch - now <= MAX_REVEAL_HORIZON_EPOCHS,
                "reveal_at_epoch {} is more than {} epochs away",
                reveal_at_epoch,
                MAX_REVEAL_HORIZON_EPOCHS
            );
            assert!(price.is_positive(), "price must be positive");
            // Any other resource has an issuer, and the engine lets an issuer recall or freeze it
            // in any vault: the escrow would only be as good as the issuer's goodwill.
            assert!(payment_resource == TARI_TOKEN, "payment must be in TARI");

            // The vault's address is reserved up front so the badge resource can name it: only code
            // running inside this component (`purchase` and `refund`) may mint or burn a badge.
            let allocation = CallerContext::allocate_component_address(None);
            let vault_address = allocation.get_address();
            let publisher = CallerContext::transaction_signer_public_key();

            // No owner, and every rule locked: an owner bypasses mint rules, so the publisher could
            // otherwise mint free badges or freeze the buyers' ones. Badge data is immutable.
            let badges = ResourceBuilder::non_fungible()
                .with_owner_rule(OwnerRule::None)
                .with_token_symbol("SIGV")
                .add_metadata("name", "Signal Vault access badge")
                .mintable(rule!(component(vault_address)), LOCKED)
                .burnable(rule!(component(vault_address)), LOCKED)
                .update_non_fungible_data(rule!(deny_all), LOCKED)
                .build();

            emit_event("signal_published", metadata! {
                "vault" => vault_address.to_string(),
                "publisher" => publisher.to_string(),
                "commitment" => commitment.to_string(),
                "reveal_at_epoch" => reveal_at_epoch.to_string(),
                "price" => price.to_string(),
            });

            Component::new(Self {
                commitment,
                reveal_at_epoch,
                price,
                earnings: Vault::new_empty(payment_resource),
                badges: badges.into(),
                payload: None,
                nonce: None,
                revealed_at_epoch: None,
                sold: 0,
                refunded: 0,
                publisher,
            })
            .with_address_allocation(allocation)
            // No owner: an owner passes every method rule and may replace the component's template,
            // which would let the publisher rewrite the commitment after the fact.
            .with_owner_rule(OwnerRule::None)
            .with_access_rules(
                ComponentAccessRules::new()
                    .method("purchase", rule!(allow_all))
                    .method("reveal", rule!(allow_all))
                    .method("refund", rule!(allow_all))
                    .method("withdraw", rule!(public_key(publisher)))
                    .method("withdraw_confidential", rule!(public_key(publisher)))
                    .method("commitment", rule!(allow_all))
                    .method("reveal_at_epoch", rule!(allow_all))
                    .method("price", rule!(allow_all))
                    .method("sold", rule!(allow_all))
                    .method("payload", rule!(allow_all))
                    .method("nonce", rule!(allow_all))
                    .method("revealed_at_epoch", rule!(allow_all))
                    .method("earnings_balance", rule!(allow_all))
                    .method("refunded", rule!(allow_all))
                    .default(rule!(deny_all)),
            )
            .create()
        }

        /// Buys one access badge.
        ///
        /// Returns the badge, plus the change when more than the price was paid (`None` on an exact
        /// payment: the engine does not allow an empty bucket). Selling stops at the reveal epoch:
        /// past that point the payload is public, so charging for it would be selling nothing.
        pub fn purchase(&mut self, mut payment: Bucket) -> (Bucket, Option<Bucket>) {
            assert!(self.payload.is_none(), "signal already revealed; nothing left to sell");
            assert!(
                Consensus::current_epoch() < self.reveal_at_epoch,
                "sale closed: the reveal epoch has been reached"
            );
            assert!(
                payment.resource_address() == self.earnings.resource_address(),
                "wrong payment resource"
            );
            // The template only sees the revealed part of a confidential bucket. Hidden commitments
            // would be deposited uncounted and stuck: the provider cannot spend them without the
            // buyer's masks. Pay the price as a revealed amount.
            payment.assert_contains_no_confidential_funds();

            let paid = payment.amount();
            assert!(paid >= self.price, "paid {} but the price is {}", paid, self.price);

            let change = (paid > self.price).then(|| payment.take(paid - self.price));
            self.earnings.deposit(payment);

            let badge = self.badges.mint_non_fungible(
                NonFungibleId::random(),
                &BadgeData {
                    commitment: self.commitment.into_array(),
                    bought_at_epoch: Consensus::current_epoch(),
                },
                &(),
            );
            self.sold += 1;
            (badge, change)
        }

        /// Opens the commitment. Callable by anyone during the reveal window — a provider who goes
        /// quiet cannot bury a losing call if a buyer was given the payload and the nonce. After
        /// the window, an unopened signal counts as a loss and its buyers are refunded.
        pub fn reveal(&mut self, payload: String, nonce: Bytes) {
            let now = Consensus::current_epoch();
            assert!(
                now >= self.reveal_at_epoch,
                "too early: reveal opens at epoch {} (current {})",
                self.reveal_at_epoch,
                now
            );
            assert!(
                now < self.refund_from_epoch(),
                "reveal window closed at epoch {}; the vault is refunding",
                self.refund_from_epoch()
            );
            assert!(self.payload.is_none(), "already revealed");
            assert!(payload.len() <= MAX_PAYLOAD_LEN, "payload longer than {} bytes", MAX_PAYLOAD_LEN);
            assert!(payload_is_canonical(&payload), "payload contains control or bidi characters");
            assert!(
                (MIN_NONCE_LEN..=MAX_NONCE_LEN).contains(&nonce.len()),
                "nonce must be {} to {} bytes",
                MIN_NONCE_LEN,
                MAX_NONCE_LEN
            );
            assert!(
                commitment_of(self.publisher.as_bytes(), &payload, &nonce) == self.commitment,
                "payload and nonce do not open this commitment"
            );

            emit_event("signal_revealed", metadata! {
                "commitment" => self.commitment.to_string(),
                "epoch" => now.to_string(),
                "sold" => self.sold.to_string(),
            });

            self.payload = Some(payload);
            self.nonce = Some(nonce);
            self.revealed_at_epoch = Some(now);
        }

        /// Refunds unopened signals: burns the badges and returns their price. Allowed once the
        /// reveal window has closed without a reveal.
        pub fn refund(&mut self, badges: Bucket) -> Bucket {
            assert!(self.payload.is_none(), "signal revealed; nothing to refund");
            let now = Consensus::current_epoch();
            assert!(
                now >= self.refund_from_epoch(),
                "refunds open at epoch {} (current {})",
                self.refund_from_epoch(),
                now
            );
            assert!(
                badges.resource_address() == self.badges.resource_address(),
                "not a badge of this vault"
            );
            let count = badges.amount();
            assert!(count.is_positive(), "no badge to refund");
            let due = self.price.checked_mul(count).expect("refund amount overflows");

            badges.burn();
            self.refunded += count.to_u64_checked().expect("badge count fits in u64");
            self.earnings.withdraw(due)
        }

        /// Withdraws proceeds. Publisher only, and only once the signal is open: until then the
        /// money backs the refunds.
        pub fn withdraw(&mut self, amount: Amount) -> Bucket {
            assert!(self.payload.is_some(), "proceeds are locked until the signal is revealed");
            self.earnings.withdraw(amount)
        }

        /// Withdraws proceeds into a confidential output. The amount leaving the vault is still
        /// visible in the proof; only where it goes is hidden.
        pub fn withdraw_confidential(&mut self, proof: ConfidentialWithdrawProof) -> Bucket {
            assert!(self.payload.is_some(), "proceeds are locked until the signal is revealed");
            self.earnings.withdraw_confidential(proof)
        }

        /// Badges burned for a refund.
        pub fn refunded(&self) -> u64 {
            self.refunded
        }

        fn refund_from_epoch(&self) -> u64 {
            self.reveal_at_epoch.saturating_add(REVEAL_WINDOW_EPOCHS)
        }

        /// The sealed commitment.
        pub fn commitment(&self) -> Hash32 {
            self.commitment
        }

        /// The epoch from which `reveal` is allowed.
        pub fn reveal_at_epoch(&self) -> u64 {
            self.reveal_at_epoch
        }

        /// Price of one badge.
        pub fn price(&self) -> Amount {
            self.price
        }

        /// Badges sold so far.
        pub fn sold(&self) -> u64 {
            self.sold
        }

        /// The opened payload, or `None` while the signal is still sealed.
        pub fn payload(&self) -> Option<String> {
            self.payload.clone()
        }

        /// The nonce that opens the commitment, published alongside the payload.
        pub fn nonce(&self) -> Option<Bytes> {
            self.nonce.clone()
        }

        /// Epoch at which the reveal happened.
        pub fn revealed_at_epoch(&self) -> Option<u64> {
            self.revealed_at_epoch
        }

        /// Balance of the earnings vault. Purchases only accept revealed funds, so this is always
        /// `price × (sold − refunded)` minus withdrawals, confidential resource or not.
        pub fn earnings_balance(&self) -> Amount {
            self.earnings.balance()
        }
    }
}

#[cfg(test)]
mod tests {
    //! The commitment scheme is the only part of the vault that has to be right before anything else
    //! matters: if two different payloads can open the same commitment, the whole "you cannot fake a
    //! track record" claim collapses. These run natively, no engine needed.

    use super::{commitment_of, payload_is_canonical};

    const KEY: &[u8] = &[7u8; 32];

    #[test]
    fn same_input_gives_same_commitment() {
        let a = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-1");
        assert_eq!(a, b, "the digest must be deterministic");
    }

    #[test]
    fn a_different_payload_gives_a_different_commitment() {
        let a = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of(KEY, "BTCUSDT short 62000 sl 63500", b"nonce-1");
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_nonce_gives_a_different_commitment() {
        let a = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-2");
        assert_ne!(
            a, b,
            "the nonce is what stops a guessable payload from being brute-forced before reveal"
        );
    }

    #[test]
    fn a_different_publisher_gives_a_different_commitment() {
        // What stops a copier from reselling someone else's sealed signal.
        let a = commitment_of(KEY, "BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of(&[8u8; 32], "BTCUSDT long 62000 sl 60500", b"nonce-1");
        assert_ne!(a, b);
    }

    #[test]
    fn shifting_bytes_between_parts_does_not_collide() {
        // The attack the length prefix exists to stop: without it, hashing payload||nonce would let a
        // provider open one commitment two ways and claim whichever call turned out right.
        assert_ne!(commitment_of(KEY, "ab", b"c"), commitment_of(KEY, "a", b"bc"));
        assert_ne!(commitment_of(b"k", "ab", b""), commitment_of(b"ka", "b", b""));
    }

    #[test]
    fn empty_payload_and_empty_nonce_are_distinguished() {
        let a = commitment_of(KEY, "", b"");
        let b = commitment_of(KEY, "", b"\x00");
        let c = commitment_of(KEY, "\u{0}", b"");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn commitment_is_32_bytes() {
        assert_eq!(commitment_of(KEY, "x", b"y").as_slice().len(), 32);
    }

    #[test]
    fn payloads_that_read_differently_than_they_hash_are_not_canonical() {
        assert!(payload_is_canonical("BTCUSDT long 62000 sl 60500 — entrée à 62k"));
        assert!(!payload_is_canonical("BTC \u{202E}trohs"));
        assert!(!payload_is_canonical("BTC long\0short"));
        assert!(!payload_is_canonical("BTC long\u{200B}"));
        assert!(!payload_is_canonical("BTC long\nshort"));
    }
}
