//! Second audit pass on the hardened vault: the escrow against the payment resource's issuer, a
//! commitment copied into someone else's vault, payloads that read differently than they hash, and
//! the access checks the first pass only covered by accident.
//!
//! Linux/macOS only, like `end_to_end.rs`.

mod common;

use tari_template_lib_types::{
    bytes::Bytes,
    constants::TARI_TOKEN,
    Amount,
    ComponentAddress,
    Hash32,
    NonFungibleAddress,
    ResourceAddress,
};
use tari_template_test_tooling::{
    crypto::RistrettoSecretKey,
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    transaction::{args, Transaction},
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const NONCE: &[u8] = b"demo-nonce-0123456789abcdefghijk";
const PRICE: u64 = 1_000;
const SUPPLY: u64 = 10_000;
const REVEAL_AT_EPOCH: u64 = 5;
const REFUND_FROM_EPOCH: u64 = REVEAL_AT_EPOCH + 10;

fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

fn new_test() -> TemplateTest {
    let mut test = TemplateTest::new_cwd([".", "tests/rug_coin"]);
    set_epoch(&mut test, 1);
    test
}

fn digest(test: &mut TemplateTest, payload: &str, nonce: &[u8]) -> Hash32 {
    common::digest(test, payload, nonce)
}

/// Publishes a vault, signed by `key`, and returns its address, badge resource and earnings vault.
fn publish_as(
    test: &mut TemplateTest,
    key: &RistrettoSecretKey,
    proofs: Vec<NonFungibleAddress>,
    commitment: Hash32,
    payment: ResourceAddress,
) -> (ComponentAddress, ResourceAddress, tari_template_lib_types::VaultId) {
    let template = test.get_template_address("SignalVault");
    let result = test.execute_expect_success(
        test.transaction()
            .call_function(template, "publish", args![commitment, REVEAL_AT_EPOCH, Amount::from_u64(PRICE), payment])
            .build_and_seal(key),
        proofs,
    );
    let diff = result.finalize.accept().expect("publish must commit");
    let vault = diff.up_iter().find_map(|(id, _)| id.as_component_address()).expect("vault component");
    let badges = diff.up_iter().find_map(|(id, _)| id.as_resource_address()).expect("badge resource");
    let earnings = diff.up_iter().find_map(|(id, _)| id.as_vault_id()).expect("earnings vault");
    (vault, badges, earnings)
}

fn publish(test: &mut TemplateTest, commitment: Hash32) -> (ComponentAddress, ResourceAddress) {
    let key = test.secret_key().clone();
    let (vault, badges, _) = publish_as(test, &key, vec![], commitment, TARI_TOKEN);
    (vault, badges)
}

#[track_caller]
fn expect_reject(test: &mut TemplateTest, tx: Transaction, proofs: Vec<NonFungibleAddress>, needle: &str) {
    let reason = format!("{:?}", test.execute_expect_failure(tx, proofs));
    assert!(
        reason.to_lowercase().contains(&needle.to_lowercase()),
        "rejected for the wrong reason (wanted {needle:?}): {reason}"
    );
}

fn buy_as(test: &mut TemplateTest, vault: ComponentAddress, buyer: ComponentAddress, proof: &NonFungibleAddress, key: &RistrettoSecretKey) {
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(key);
    test.execute_expect_success(tx, vec![proof.clone()]);
}

fn buy(test: &mut TemplateTest, vault: ComponentAddress) {
    let (buyer, proof, key) = test.create_funded_account();
    buy_as(test, vault, buyer, &proof, &key);
}

fn refund_tx(test: &mut TemplateTest, vault: ComponentAddress, badges: ResourceAddress, count: u64, buyer: ComponentAddress, key: &RistrettoSecretKey) -> Transaction {
    test.transaction()
        .call_method(buyer, "withdraw", args![badges, Amount::from_u64(count)])
        .put_last_instruction_output_on_workspace("badges")
        .call_method(vault, "refund", args![Workspace("badges")])
        .put_last_instruction_output_on_workspace("money")
        .call_method(buyer, "deposit", args![Workspace("money")])
        .build_and_seal(key)
}

#[test]
fn a_recallable_payment_coin_is_refused() {
    // The engine checks a recall against the resource's rules only, never against who owns the
    // vault: a publisher who priced the signal in a coin they can recall took the escrow back before
    // revealing (CI run 37245086143 on the previous commit). Only TARI is accepted now.
    let mut test = new_test();
    let coin: ComponentAddress = test.call_function("RugCoin", "issue", args![Amount::from_u64(SUPPLY)], vec![]);
    let rug: ResourceAddress = test.call_method(coin, "resource", args![], vec![]);
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let template = test.get_template_address("SignalVault");
    let tx = test
        .transaction()
        .call_function(template, "publish", args![commitment, REVEAL_AT_EPOCH, Amount::from_u64(PRICE), rug])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "payment must be in TARI");
}

#[test]
fn a_copied_commitment_cannot_be_opened_in_the_copier_vault() {
    // Nothing tied a commitment to its publisher: a copier could resell anyone's sealed signal,
    // open it once the original is revealed, and let the losers refund at no cost to themselves.
    let mut test = new_test();
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let (original, _) = publish(&mut test, commitment);

    let (_, copier_proof, copier_key) = test.create_funded_account();
    let (copy, _, _) = publish_as(&mut test, &copier_key, vec![copier_proof], commitment, TARI_TOKEN);
    buy(&mut test, copy);

    set_epoch(&mut test, REVEAL_AT_EPOCH);
    test.call_method::<()>(original, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())], vec![]);

    let tx = test
        .transaction()
        .call_method(copy, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "do not open this commitment");
}

#[test]
fn a_payload_that_reads_differently_than_it_hashes_cannot_be_opened() {
    // A right-to-left override makes "BTC long" render while the bytes say otherwise, so a provider
    // could pick the reading after the fact.
    let mut test = new_test();
    let payload = "BTC \u{202E}gnol trohs";
    let commitment = digest(&mut test, payload, NONCE);
    let (vault, _) = publish(&mut test, commitment);
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    let tx = test
        .transaction()
        .call_method(vault, "reveal", args![payload.to_string(), Bytes::from_vec(NONCE.to_vec())])
        .build_and_seal(test.secret_key());
    expect_reject(&mut test, tx, vec![], "control or bidi");
}

#[test]
fn a_stranger_cannot_withdraw_even_after_the_reveal() {
    // Before the reveal the proceeds are locked anyway, so only this proves the access rule.
    let mut test = new_test();
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let (vault, _) = publish(&mut test, commitment);
    buy(&mut test, vault);
    set_epoch(&mut test, REVEAL_AT_EPOCH);
    test.call_method::<()>(vault, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())], vec![]);

    let (thief, thief_proof, thief_key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(vault, "withdraw", args![Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("loot")
        .call_method(thief, "deposit", args![Workspace("loot")])
        .build_and_seal(&thief_key);
    expect_reject(&mut test, tx, vec![thief_proof], "call component method 'withdraw'");
    assert_eq!(test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]), Amount::from_u64(PRICE));
}

#[test]
fn a_badge_from_another_vault_is_not_refunded() {
    let mut test = new_test();
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let (vault_a, _) = publish(&mut test, commitment);
    buy(&mut test, vault_a);
    let other = digest(&mut test, "ETHUSDT short 3000", b"other-nonce-0123456789abcdefghij");
    let (vault_b, badges_b) = publish(&mut test, other);
    let (buyer, proof, key) = test.create_funded_account();
    buy_as(&mut test, vault_b, buyer, &proof, &key);

    set_epoch(&mut test, REFUND_FROM_EPOCH);
    let tx = refund_tx(&mut test, vault_a, badges_b, 1, buyer, &key);
    expect_reject(&mut test, tx, vec![proof], "not a badge of this vault");
    assert_eq!(test.call_method::<Amount>(vault_a, "earnings_balance", args![], vec![]), Amount::from_u64(PRICE));
}

#[test]
fn several_badges_refund_at_once() {
    let mut test = new_test();
    let commitment = digest(&mut test, PAYLOAD, NONCE);
    let (vault, badges) = publish(&mut test, commitment);
    let (buyer, proof, key) = test.create_funded_account();
    buy_as(&mut test, vault, buyer, &proof, &key);
    buy_as(&mut test, vault, buyer, &proof, &key);

    set_epoch(&mut test, REFUND_FROM_EPOCH);
    let tx = refund_tx(&mut test, vault, badges, 2, buyer, &key);
    test.execute_expect_success(tx, vec![proof]);
    assert_eq!(test.call_method::<u64>(vault, "refunded", args![], vec![]), 2);
    assert_eq!(test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]), Amount::zero());
}
