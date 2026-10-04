//! Paying with a confidential resource. The template only sees the revealed part of a bucket, so
//! hidden commitments would be deposited uncounted and stuck in the vault: nobody but the buyer knows
//! their masks, and only the publisher may withdraw. Purchases must refuse them.
//!
//! Linux/macOS only, like `end_to_end.rs`.

use tari_template_lib_types::{bytes::Bytes, Amount, ComponentAddress, Hash32, ResourceAddress};
use tari_template_test_tooling::{
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::{
        confidential::{generate_confidential_output_statement, generate_reveal_proof, generate_withdraw_proof},
        value_proof::value_proofs_for_commitment,
    },
    transaction::args,
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const NONCE: &[u8] = b"demo-nonce-0123456789abcdefghijk";
const PRICE: u64 = 1_000;
const SUPPLY: u64 = 10_000;
const REVEAL_AT_EPOCH: u64 = 5;

/// A faucet holding `SUPPLY` in one hidden commitment, and a vault priced in that resource.
fn setup() -> (TemplateTest, ComponentAddress, ComponentAddress, tari_template_test_tooling::crypto::RistrettoSecretKey) {
    let mut test = TemplateTest::new_cwd([".", "tests/confidential_faucet"]);
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(1));

    let (supply, mask, _) = generate_confidential_output_statement(SUPPLY, None);
    let faucet: ComponentAddress = test.call_function(
        "ConfidentialFaucet",
        "mint",
        args![supply, value_proofs_for_commitment(SUPPLY, &mask)],
        vec![],
    );
    let resource: ResourceAddress = test.call_method(faucet, "resource", args![], vec![]);

    let commitment: Hash32 = test.call_function(
        "SignalVault",
        "digest_of",
        args![PAYLOAD.to_string(), Bytes::from_vec(NONCE.to_vec())],
        vec![],
    );
    let vault: ComponentAddress = test.call_function(
        "SignalVault",
        "publish",
        args![commitment, REVEAL_AT_EPOCH, Amount::from_u64(PRICE), resource],
        vec![],
    );
    (test, faucet, vault, mask)
}

#[test]
fn a_payment_with_hidden_commitments_is_refused() {
    let (mut test, faucet, vault, mask) = setup();
    let (buyer, proof, key) = test.create_funded_account();

    // The price revealed, plus 500 hidden in a commitment: before the fix the 500 was swallowed.
    let withdraw = generate_withdraw_proof(&mask, 500, Some(SUPPLY - 500 - PRICE), PRICE);
    let tx = test
        .transaction()
        .call_method(faucet, "take", args![withdraw.proof])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .build_and_seal(&key);
    let reason = format!("{:?}", test.execute_expect_failure(tx, vec![proof]));
    assert!(reason.contains("confidential commitments"), "rejected for the wrong reason: {reason}");
    assert_eq!(test.call_method::<u64>(vault, "sold", args![], vec![]), 0);
}

#[test]
fn a_fully_revealed_confidential_payment_is_accepted() {
    let (mut test, faucet, vault, mask) = setup();
    let (buyer, proof, key) = test.create_funded_account();

    // Everything revealed: the price goes to the vault and the rest comes back as change.
    let tx = test
        .transaction()
        .call_method(faucet, "take", args![generate_reveal_proof(&mask, SUPPLY)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .call_method(buyer, "deposit", args![Workspace("out.1")])
        .build_and_seal(&key);
    test.execute_expect_success(tx, vec![proof]);

    assert_eq!(test.call_method::<u64>(vault, "sold", args![], vec![]), 1);
    assert_eq!(
        test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]),
        Amount::from_u64(PRICE)
    );
}
