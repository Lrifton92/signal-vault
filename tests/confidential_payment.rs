//! Payment resources other than TARI. A confidential resource used to let hidden commitments be
//! deposited uncounted and stuck; any issued resource lets its issuer recall or freeze the escrow
//! (see `audit_second_wave.rs`). Both are now refused at publish.
//!
//! Linux/macOS only, like `end_to_end.rs`.

mod common;

use tari_template_lib_types::{Amount, ComponentAddress, ResourceAddress};
use tari_template_test_tooling::{
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    support::{confidential::generate_confidential_output_statement, value_proof::value_proofs_for_commitment},
    transaction::args,
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const NONCE: &[u8] = b"demo-nonce-0123456789abcdefghijk";
const PRICE: u64 = 1_000;
const SUPPLY: u64 = 10_000;
const REVEAL_AT_EPOCH: u64 = 5;

#[test]
fn a_confidential_payment_resource_is_refused() {
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

    let commitment = common::digest(&test, PAYLOAD, NONCE);
    let template = test.get_template_address("SignalVault");
    let tx = test
        .transaction()
        .call_function(template, "publish", args![commitment, REVEAL_AT_EPOCH, Amount::from_u64(PRICE), resource])
        .build_and_seal(test.secret_key());
    let reason = format!("{:?}", test.execute_expect_failure(tx, vec![]));
    assert!(reason.contains("payment must be in TARI"), "rejected for the wrong reason: {reason}");
}
