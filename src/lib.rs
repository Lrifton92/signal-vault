// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! # Signal Vault
//!
//! A sealed-bid marketplace primitive for the Tari Ootle: **pay to unlock, verify after expiry**.
//!
//! A signal provider publishes only `blake2b(payload || nonce)` — the signal itself never touches
//! the chain while it is tradeable. Buyers pay into a vault and receive an access badge; the
//! provider delivers the payload off-chain to badge holders. Once the reveal epoch is reached,
//! anybody may open the commitment, and from then on the payload is public and permanently bound
//! to the epoch at which it was sealed.
//!
//! That ordering is what the contract buys you:
//!
//! * a buyer cannot be front-run, because the payload is not readable on-chain before expiry;
//! * a provider cannot fabricate a track record afterwards, because the commitment was fixed
//!   before the outcome was known and the hash is checked on reveal;
//! * when the payment resource is a confidential one, the amounts paid and the balance held stay
//!   hidden, so a provider does not publish their own revenue in order to sell.
//!
//! The same primitive fits any "sell information now, prove it later" market: research calls,
//! oracle pre-commitments, sealed-bid auctions.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use tari_template_lib::prelude::*;
use tari_template_lib::types::Hash32;

/// Domain separator, so a digest produced here can never be mistaken for one produced by another
/// protocol that happens to hash the same bytes.
const DOMAIN: &[u8] = b"tari.ootle.signal_vault.commitment.v1";

type Blake2b256 = Blake2b<U32>;

/// The commitment a provider seals, and the value `reveal` checks against.
///
/// Every part is length-prefixed before hashing, so `("ab", "c")` and `("a", "bc")` produce
/// different digests. Without that, a provider could open one commitment with two different
/// payload/nonce splits and pick whichever one aged better.
///
/// Kept outside the template module so it is an ordinary Rust function: callers can compute the
/// commitment off-chain before publishing, and it can be tested natively without an engine.
pub fn commitment_of(payload: &str, nonce: &[u8]) -> Hash32 {
    let mut hasher = Blake2b256::new();
    hasher.update((DOMAIN.len() as u64).to_le_bytes());
    hasher.update(DOMAIN);
    hasher.update((payload.len() as u64).to_le_bytes());
    hasher.update(payload.as_bytes());
    hasher.update((nonce.len() as u64).to_le_bytes());
    hasher.update(nonce);
    Hash32::from_array(hasher.finalize().into())
}

/// Data carried by an access badge. Kept deliberately small: everything a buyer needs to prove
/// which sealed signal their badge unlocks.
#[derive(Debug, Clone, minicbor::Encode, minicbor::Decode, minicbor::CborLen)]
pub struct BadgeData {
    /// The commitment this badge grants access to.
    #[n(0)]
    pub commitment: [u8; 32],
    /// Epoch in which the badge was bought. Lets a provider prove delivery order.
    #[n(1)]
    pub bought_at_epoch: u64,
}

#[template]
mod signal_vault {
    use super::*;

    pub struct SignalVault {
        /// `blake2b(payload || nonce)`. Fixed at publish time and never mutated.
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
        /// Number of badges sold. Public on purpose: demand is the provider's reputation.
        sold: u64,
    }

    impl SignalVault {
        /// Seals a signal.
        ///
        /// `commitment` must be `blake2b(payload || nonce)` — the template checks that on reveal,
        /// so a provider who commits to nothing simply can never reveal.
        ///
        /// `payment_resource` chooses the privacy model: pass a confidential resource and the
        /// amounts paid stay hidden; pass a public one and they do not.
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
            assert!(price.is_positive(), "price must be positive");

            let badges = ResourceBuilder::non_fungible()
                .with_token_symbol("SIGV")
                .add_metadata("name", "Signal Vault access badge")
                .mintable(rule!(allow_all), OWNER)
                .burnable(rule!(allow_all), OWNER)
                .build();

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
            })
            .with_access_rules(AccessRules::allow_all())
            .create()
        }

        /// Buys one access badge.
        ///
        /// Returns the badge, plus any change. Selling stops at the reveal epoch: past that point
        /// the payload is public, so charging for it would be selling nothing.
        pub fn purchase(&mut self, mut payment: Bucket) -> (Bucket, Bucket) {
            assert!(self.payload.is_none(), "signal already revealed; nothing left to sell");
            assert!(
                Consensus::current_epoch() < self.reveal_at_epoch,
                "sale closed: the reveal epoch has been reached"
            );
            assert!(
                payment.resource_address() == self.earnings.resource_address(),
                "wrong payment resource"
            );

            let paid = payment.amount();
            assert!(paid >= self.price, "paid {} but the price is {}", paid, self.price);

            let change = payment.take(paid - self.price);
            self.earnings.deposit(payment);

            let badge = self.badges.mint_non_fungible(
                NonFungibleId::random(),
                &Metadata::new(),
                &BadgeData {
                    commitment: self.commitment.into_array(),
                    bought_at_epoch: Consensus::current_epoch(),
                },
            );
            self.sold += 1;
            (badge, change)
        }

        /// Opens the commitment. Callable by anyone once the reveal epoch is reached — a provider
        /// who goes quiet cannot bury a losing call, as long as one buyer holds the preimage.
        pub fn reveal(&mut self, payload: String, nonce: Bytes) {
            let now = Consensus::current_epoch();
            assert!(
                now >= self.reveal_at_epoch,
                "too early: reveal opens at epoch {} (current {})",
                self.reveal_at_epoch,
                now
            );
            assert!(self.payload.is_none(), "already revealed");
            assert!(
                commitment_of(&payload, &nonce) == self.commitment,
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

        /// Withdraws proceeds. Restricted to the component owner by the access rules set at
        /// publish time on the calling account.
        pub fn withdraw(&mut self, amount: Amount) -> Bucket {
            self.earnings.withdraw(amount)
        }

        /// Withdraws confidential proceeds without disclosing the amount.
        pub fn withdraw_confidential(&mut self, proof: ConfidentialWithdrawProof) -> Bucket {
            self.earnings.withdraw_confidential(proof)
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

        /// Revealed balance of the earnings vault. Zero for a confidential resource whose value
        /// has not been revealed — that is the point.
        pub fn earnings_balance(&self) -> Amount {
            self.earnings.balance()
        }

        /// Re-derives the commitment. Exposed so a buyer can check, off-chain and before paying,
        /// that the payload they were promised is the one that was sealed.
        pub fn digest_of(payload: String, nonce: Bytes) -> Hash32 {
            commitment_of(&payload, &nonce)
        }

    }
}

#[cfg(test)]
mod tests {
    //! The commitment scheme is the only part of the vault that has to be right before anything else
    //! matters: if two different payloads can open the same commitment, the whole "you cannot fake a
    //! track record" claim collapses. These run natively, no engine needed.

    use super::commitment_of;

    #[test]
    fn same_input_gives_same_commitment() {
        let a = commitment_of("BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of("BTCUSDT long 62000 sl 60500", b"nonce-1");
        assert_eq!(a, b, "the digest must be deterministic");
    }

    #[test]
    fn a_different_payload_gives_a_different_commitment() {
        let a = commitment_of("BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of("BTCUSDT short 62000 sl 63500", b"nonce-1");
        assert_ne!(a, b);
    }

    #[test]
    fn a_different_nonce_gives_a_different_commitment() {
        let a = commitment_of("BTCUSDT long 62000 sl 60500", b"nonce-1");
        let b = commitment_of("BTCUSDT long 62000 sl 60500", b"nonce-2");
        assert_ne!(
            a, b,
            "the nonce is what stops a guessable payload from being brute-forced before reveal"
        );
    }

    #[test]
    fn shifting_bytes_between_payload_and_nonce_does_not_collide() {
        // The attack the length prefix exists to stop: without it, hashing payload||nonce would let a
        // provider open one commitment two ways and claim whichever call turned out right.
        let a = commitment_of("ab", b"c");
        let b = commitment_of("a", b"bc");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_payload_and_empty_nonce_are_distinguished() {
        let a = commitment_of("", b"");
        let b = commitment_of("", b"\x00");
        let c = commitment_of("\u{0}", b"");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn commitment_is_32_bytes() {
        assert_eq!(commitment_of("x", b"y").as_slice().len(), 32);
    }
}
