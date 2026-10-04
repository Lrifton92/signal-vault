//! Regression tests for the October hardening pass: who can mint, who can swap the code, who can
//! open, and when the money may leave. Every rejection is checked for its reason, so a test cannot
//! pass because the transaction failed for something unrelated.
//!
//! Linux/macOS only, like `end_to_end.rs`.

mod common;

use tari_template_lib_types::{bytes::Bytes, constants::TARI_TOKEN, Amount, ComponentAddress, Hash32, NonFungibleAddress, ResourceAddress};
use tari_template_test_tooling::{
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    transaction::{args, Transaction},
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
/// 32 bytes, as a provider should use.
const NONCE: &[u8] = b"demo-nonce-0123456789abcdefghijk";
const PRICE: u64 = 1_000;
const REVEAL_AT_EPOCH: u64 = 5;

fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

fn digest(test: &mut TemplateTest, payload: &str, nonce: &[u8]) -> Hash32 {
    common::digest(test, payload, nonce)
}

/// Publishes a vault signed by the test's default key (the publisher).
fn publish(test: &mut TemplateTest, commitment: Hash32, reveal_at: u64) -> (ComponentAddress, ResourceAddress) {
    let template = test.get_template_address("SignalVault");
    let result = test.execute_expect_success(
        test.transaction()
            .call_function(template, "publish", args![commitment, reveal_at, Amount::from_u64(PRICE), TARI_TOKEN])
            .build_and_seal(test.secret_key()),
        vec![],
    );
    let diff = result.finalize.accept().expect("publish must commit");
    let vault = diff.up_iter().find_map(|(id, _)| id.as_component_address()).expect("vault component");
    let badges = diff.up_iter().find_map(|(id, _)| id.as_resource_address()).expect("badge resource");
    (vault, badges)
}

fn setup() -> (TemplateTest, ComponentAddress, ResourceAddress) {
    let mut test = TemplateTest::new_cwd([".", "tests/badge_forger"]);
    set_epoch(&mut test, 1);
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let (vault, badges) = publish(&mut test, commitment, REVEAL_AT_EPOCH);
    (test, vault, badges)
}

/// Asserts the transaction is rejected, and rejected for `needle` (case-insensitive).
#[track_caller]
fn expect_reject(test: &mut TemplateTest, tx: Transaction, proofs: Vec<NonFungibleAddress>, needle: &str) {
    let reason = format!("{:?}", test.execute_expect_failure(tx, proofs));
    assert!(
        reason.to_lowercase().contains(&needle.to_lowercase()),
        "rejected for the wrong reason (wanted {needle:?}): {reason}"
    );
}

fn buy(test: &mut TemplateTest, vault: ComponentAddress) -> ComponentAddress {
    let (buyer, proof, key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(&key);
    test.execute_expect_success(tx, vec![proof]);
    buyer
}

#[test]
fn the_publisher_cannot_mint_a_badge_outside_purchase() {
    // The publisher signed the transaction that created the badge resource. If that makes them its
    // owner, the engine lets them past the mint rule.
    let (mut test, _vault, badges) = setup();
    let owner_proof = test.owner_proof();
    let owner_account = test.create_account(test.to_public_key_bytes(), None, vec![owner_proof.clone()]);
    let forger = test.get_template_address("BadgeForger");
    let tx = test
        .transaction()
        .call_function(forger, "forge", args![badges])
        .put_last_instruction_output_on_workspace("badge")
        .call_method(owner_account, "deposit", args![Workspace("badge")])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![owner_proof], "denied");
}

#[test]
fn the_publisher_cannot_swap_the_vault_code() {
    // A component owner may move it to another template, which could rewrite the commitment.
    let (mut test, vault, _) = setup();
    let other = test.get_template_address("BadgeForger");
    let tx = test
        .transaction()
        .update_component_template(vault, other)
        .build_and_seal(test.secret_key());
    let owner_proof = test.owner_proof();
    expect_reject(&mut test, tx, vec![owner_proof], "denied");
}

#[test]
fn a_non_owner_can_reveal() {
    let (mut test, vault, _) = setup();
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    let (_, proof, key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(vault, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())])
        .build_and_seal(&key);
    test.execute_expect_success(tx, vec![proof]);
    assert_eq!(
        test.call_method::<Option<String>>(vault, "payload", args![], vec![]).as_deref(),
        Some(PAYLOAD)
    );
}

#[test]
fn the_sale_closes_at_the_reveal_epoch_even_before_a_reveal() {
    let (mut test, vault, _) = setup();
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    let (buyer, proof, key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(&key);
    expect_reject(&mut test, tx, vec![proof], "sale closed");
}

#[test]
fn the_publisher_cannot_withdraw_before_the_reveal() {
    // Otherwise a provider can seal nothing, sell, cash out and vanish.
    let (mut test, vault, _) = setup();
    buy(&mut test, vault);
    let owner_proof = test.owner_proof();
    let owner_account = test.create_account(test.to_public_key_bytes(), None, vec![owner_proof.clone()]);
    let tx = test
        .transaction()
        .call_method(vault, "withdraw", args![Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("proceeds")
        .call_method(owner_account, "deposit", args![Workspace("proceeds")])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![owner_proof], "locked until the signal is revealed");
}

#[test]
fn publish_rejects_a_reveal_epoch_beyond_the_horizon() {
    let mut test = TemplateTest::new_cwd([".", "tests/badge_forger"]);
    set_epoch(&mut test, 1);
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let template = test.get_template_address("SignalVault");
    let tx = test
        .transaction()
        .call_function(template, "publish", args![commitment, u64::MAX, Amount::from_u64(PRICE), TARI_TOKEN])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "epochs away");
}

#[test]
fn a_commitment_sealed_with_a_short_nonce_cannot_be_opened() {
    let mut test = TemplateTest::new_cwd([".", "tests/badge_forger"]);
    set_epoch(&mut test, 1);
    let commitment = digest(&mut test, "long", b"1234");
    let (vault, _) = publish(&mut test, commitment, REVEAL_AT_EPOCH);
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    let tx = test
        .transaction()
        .call_method(vault, "reveal", args!["long".to_string(), Bytes::from_vec(b"1234".to_vec())])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "nonce must be");
}

/// Epoch from which an unopened vault refunds. Mirrors `REVEAL_WINDOW_EPOCHS` in the template.
const REFUND_FROM_EPOCH: u64 = REVEAL_AT_EPOCH + 10;

/// Burns every badge `buyer` holds for a refund and deposits the money back.
fn refund_tx(test: &mut TemplateTest, vault: ComponentAddress, badges: ResourceAddress, buyer: ComponentAddress, key: &tari_template_test_tooling::crypto::RistrettoSecretKey) -> Transaction {
    test.transaction()
        .call_method(buyer, "withdraw", args![badges, Amount::from_u64(1)])
        .put_last_instruction_output_on_workspace("badge")
        .call_method(vault, "refund", args![Workspace("badge")])
        .put_last_instruction_output_on_workspace("money")
        .call_method(buyer, "deposit", args![Workspace("money")])
        .build_and_seal(key)
}

#[test]
fn an_unopened_signal_refunds_its_buyers() {
    let (mut test, vault, badges) = setup();
    let (buyer, proof, key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(&key);
    test.execute_expect_success(tx, vec![proof.clone()]);

    // Not before the reveal window has closed.
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    let early = refund_tx(&mut test, vault, badges, buyer, &key);
    expect_reject(&mut test, early, vec![proof.clone()], "refunds open at epoch");

    set_epoch(&mut test, REFUND_FROM_EPOCH);
    let tx = refund_tx(&mut test, vault, badges, buyer, &key);
    test.execute_expect_success(tx, vec![proof]);

    assert_eq!(test.call_method::<u64>(vault, "refunded", args![], vec![]), 1);
    assert_eq!(test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]), Amount::zero());

    // And the signal can no longer be opened: reveal and refund never overlap.
    let tx = test
        .transaction()
        .call_method(vault, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "reveal window closed");
}

#[test]
fn an_opened_signal_does_not_refund() {
    let (mut test, vault, badges) = setup();
    let (buyer, proof, key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(&key);
    test.execute_expect_success(tx, vec![proof.clone()]);

    set_epoch(&mut test, REVEAL_AT_EPOCH);
    test.call_method::<()>(vault, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())], vec![]);

    set_epoch(&mut test, REFUND_FROM_EPOCH);
    let tx = refund_tx(&mut test, vault, badges, buyer, &key);
    expect_reject(&mut test, tx, vec![proof], "nothing to refund");
}
