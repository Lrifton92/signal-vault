//! Regression tests for the issues reported on the September contest submission:
//! who can take the proceeds, who can mint badges, and whether paying the exact price works.
//!
//! Linux/macOS only, like `end_to_end.rs`: the engine pulls a Cranelift JIT that does not build on
//! Windows.

mod common;

use tari_template_lib_types::{bytes::Bytes, constants::TARI_TOKEN, Amount, ComponentAddress, Hash32, ResourceAddress};
use tari_template_test_tooling::{
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    transaction::args,
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const NONCE: &[u8] = b"demo-nonce-0123456789abcdefghijk";
const PRICE: u64 = 1_000;
const REVEAL_AT_EPOCH: u64 = 5;

/// Publishes a vault signed by the test's default key, the publisher (the vault itself has no owner).
fn setup() -> (TemplateTest, ComponentAddress, ResourceAddress) {
    let mut test = TemplateTest::new_cwd([".", "tests/badge_forger"]);
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(1));

    let commitment: Hash32 = common::digest(&test, PAYLOAD, NONCE);
    let template = test.get_template_address("SignalVault");
    let result = test.execute_expect_success(
        test.transaction()
            .call_function(template, "publish", args![commitment, REVEAL_AT_EPOCH, Amount::from_u64(PRICE), TARI_TOKEN])
            .build_and_seal(test.secret_key()),
        vec![],
    );
    let diff = result.finalize.accept().expect("publish must commit");
    let vault = diff.up_iter().find_map(|(id, _)| id.as_component_address()).expect("vault component");
    let badges = diff.up_iter().find_map(|(id, _)| id.as_resource_address()).expect("badge resource");
    (test, vault, badges)
}

/// One buyer pays `amount` and deposits the badge, plus the change when there is some. Panics,
/// with the engine's reason, if the transaction is rejected.
fn buy(test: &mut TemplateTest, vault: ComponentAddress, amount: u64) {
    let (buyer, proof, key) = test.create_funded_account();
    let mut builder = test
        .transaction()
        .call_method(buyer, "withdraw", args![TARI_TOKEN, Amount::from_u64(amount)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")]);
    if amount > PRICE {
        builder = builder.call_method(buyer, "deposit", args![Workspace("out.1")]);
    }
    test.execute_expect_success(builder.build_and_seal(&key), vec![proof]);
}

#[test]
fn a_stranger_cannot_withdraw_the_proceeds() {
    let (mut test, vault, _) = setup();
    buy(&mut test, vault, PRICE + 1);

    let (thief, thief_proof, thief_key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(vault, "withdraw", args![Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("loot")
        .call_method(thief, "deposit", args![Workspace("loot")])
        .build_and_seal(&thief_key);
    test.execute_expect_failure(tx, vec![thief_proof]);

    assert_eq!(
        test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]),
        Amount::from_u64(PRICE),
        "the proceeds must still be in the vault"
    );
}

#[test]
fn the_publisher_can_withdraw_the_proceeds_once_revealed() {
    let (mut test, vault, _) = setup();
    buy(&mut test, vault, PRICE + 1);

    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(REVEAL_AT_EPOCH));
    test.call_method::<()>(vault, "reveal", args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())], vec![]);

    let owner_proof = test.owner_proof();
    let owner_account = test.create_account(test.to_public_key_bytes(), None, vec![owner_proof.clone()]);
    let tx = test
        .transaction()
        .call_method(vault, "withdraw", args![Amount::from_u64(PRICE)])
        .put_last_instruction_output_on_workspace("proceeds")
        .call_method(owner_account, "deposit", args![Workspace("proceeds")])
        .build_and_seal(test.secret_key());
    test.execute_expect_success(tx, vec![owner_proof]);

    assert_eq!(test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]), Amount::zero());
}

#[test]
fn a_badge_cannot_be_minted_without_purchase() {
    let (mut test, _vault, badges) = setup();

    let (forger, forger_proof, forger_key) = test.create_funded_account();
    let forger_template = test.get_template_address("BadgeForger");
    let tx = test
        .transaction()
        .call_function(forger_template, "forge", args![badges])
        .put_last_instruction_output_on_workspace("badge")
        .call_method(forger, "deposit", args![Workspace("badge")])
        .build_and_seal(&forger_key);
    test.execute_expect_failure(tx, vec![forger_proof]);
}

#[test]
fn paying_the_exact_price_works() {
    let (mut test, vault, _) = setup();
    buy(&mut test, vault, PRICE);
    assert_eq!(test.call_method::<u64>(vault, "sold", args![], vec![]), 1);
}
