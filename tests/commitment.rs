// Copyright 2026 Soufian J (OG Boy)
// SPDX-License-Identifier: BSD-3-Clause

//! The commitment scheme is the only part of the vault that has to be right before anything else
//! matters: if two different payloads can open the same commitment, the whole "you cannot fake a
//! track record" claim collapses. These run natively, no engine needed.

use signal_vault::commitment_of;

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
