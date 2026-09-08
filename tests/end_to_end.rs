//! The full life of one signal, against a simulated Ootle ledger.
//!
//! The unit tests in `src/lib.rs` cover the commitment function in isolation. They cannot cover the
//! part that actually carries the product claim: that a buyer pays for something sealed, that the
//! provider cannot open it early or open it as something else, and that the sale closes on its own
//! at expiry. Those are properties of the component, not of a hash, so they need a ledger.
//!
//! Runs on Linux/macOS only: `tari_template_test_tooling` pulls the engine, which pulls a Cranelift
//! JIT that refuses to compile on Windows. CI runs it.

use tari_engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId};
use tari_template_lib::{
    args,
    models::{Amount, ComponentAddress},
    prelude::XTR,
};
use tari_template_lib_types::Hash32;
use tari_template_test_tooling::TemplateTest;

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const NONCE: &[u8] = b"demo-nonce-01";
const PRICE: i64 = 1_000;
const REVEAL_AT_EPOCH: u64 = 5;

fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

/// publish -> purchase -> (early reveal rejected) -> (wrong payload rejected) -> reveal -> readable
#[test]
fn a_sealed_signal_is_sold_then_opened_only_at_expiry_and_only_as_committed() {
    let mut test = TemplateTest::new(["."]);
    set_epoch(&mut test, 1);

    // The digest is computed by the template itself, so the test commits to exactly what the
    // template will re-hash on reveal. Recomputing it here would test the test.
    let commitment: Hash32 = test.call_function(
        "SignalVault",
        "digest_of",
        args![PAYLOAD.to_string(), NONCE.to_vec()],
        vec![],
    );

    let vault: ComponentAddress = test.call_function(
        "SignalVault",
        "publish",
        args![commitment, REVEAL_AT_EPOCH, Amount(PRICE), XTR],
        vec![],
    );

    // Sealed: the payload is not on-chain before expiry.
    let sealed: Option<String> = test.call_method(vault, "payload", args![], vec![]);
    assert!(sealed.is_none(), "the payload must not be readable before the reveal epoch");
    assert_eq!(test.call_method::<u64>(vault, "sold", args![], vec![]), 0);

    // --- a buyer pays and receives an access badge -------------------------------------------
    let (buyer, buyer_proof, buyer_key) = test.create_funded_account();
    test.execute_expect_success(
        test.transaction()
            .call_method(buyer, "withdraw", args![XTR, Amount(PRICE)])
            .put_last_instruction_output_on_workspace("payment")
            .call_method(vault, "purchase", args![Workspace("payment")])
            .put_last_instruction_output_on_workspace("out")
            .call_method(buyer, "deposit", args![Workspace("out.0")])
            .call_method(buyer, "deposit", args![Workspace("out.1")])
            .build_and_seal(&buyer_key),
        vec![buyer_proof.clone()],
    );
    assert_eq!(
        test.call_method::<u64>(vault, "sold", args![], vec![]),
        1,
        "the purchase must be recorded"
    );
    assert_eq!(
        test.call_method::<Amount>(vault, "earnings_balance", args![], vec![]),
        Amount(PRICE),
        "the payment must land in the vault"
    );

    // --- the provider cannot open it early ----------------------------------------------------
    test.execute_expect_failure(
        test.transaction()
            .call_method(vault, "reveal", args![PAYLOAD.to_string(), NONCE.to_vec()])
            .build_and_seal(&test.secret_key().clone()),
        vec![],
    );

    set_epoch(&mut test, REVEAL_AT_EPOCH);

    // --- and cannot open it as something else -------------------------------------------------
    // The whole track-record claim rests on this failing.
    test.execute_expect_failure(
        test.transaction()
            .call_method(
                vault,
                "reveal",
                args!["BTCUSDT short 62000 sl 63500".to_string(), NONCE.to_vec()],
            )
            .build_and_seal(&test.secret_key().clone()),
        vec![],
    );

    // Nothing was written by the failed attempts.
    let still_sealed: Option<String> = test.call_method(vault, "payload", args![], vec![]);
    assert!(still_sealed.is_none(), "a rejected reveal must not mutate state");

    // --- the real reveal, callable by anyone --------------------------------------------------
    test.call_method::<()>(
        vault,
        "reveal",
        args![PAYLOAD.to_string(), NONCE.to_vec()],
        vec![],
    );

    let opened: Option<String> = test.call_method(vault, "payload", args![], vec![]);
    assert_eq!(opened.as_deref(), Some(PAYLOAD), "the committed payload must be readable");
    assert_eq!(
        test.call_method::<Option<u64>>(vault, "revealed_at_epoch", args![], vec![]),
        Some(REVEAL_AT_EPOCH)
    );

    // --- and the sale is closed, because the payload is public now -----------------------------
    let (late_buyer, late_proof, late_key) = test.create_funded_account();
    test.execute_expect_failure(
        test.transaction()
            .call_method(late_buyer, "withdraw", args![XTR, Amount(PRICE)])
            .put_last_instruction_output_on_workspace("payment")
            .call_method(vault, "purchase", args![Workspace("payment")])
            .build_and_seal(&late_key),
        vec![late_proof],
    );
    assert_eq!(
        test.call_method::<u64>(vault, "sold", args![], vec![]),
        1,
        "selling must stop once the signal is public"
    );
}
