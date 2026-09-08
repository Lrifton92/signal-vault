//! The full life of one signal, against a simulated Ootle ledger.
//!
//! The unit tests in `src/lib.rs` cover the commitment function in isolation. They cannot cover the
//! part that actually carries the product claim: that a buyer pays for something sealed, that the
//! provider cannot open it early or open it as something else, and that the sale closes on its own
//! at expiry. Those are properties of the component, not of a hash, so they need a ledger.
//!
//! Linux/macOS only: `tari_template_test_tooling` pulls the engine, which pulls a Cranelift JIT
//! that refuses to compile on Windows (tari-project/tari-cli#205). CI runs it.

use tari_template_lib_types::{constants::XTR, Amount, ComponentAddress, Hash32};
use tari_template_test_tooling::{
    engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId},
    transaction::args,
    TemplateTest,
};

const PAYLOAD: &str = "BTCUSDT long 62000 sl 60500 tp 67000";
const WRONG_PAYLOAD: &str = "BTCUSDT short 62000 sl 63500";
const NONCE: &[u8] = b"demo-nonce-01";
const PRICE: i64 = 1_000;
const REVEAL_AT_EPOCH: u64 = 5;

fn set_epoch(test: &mut TemplateTest, epoch: u64) {
    test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
}

/// publish -> purchase -> (early reveal rejected) -> (wrong payload rejected) -> reveal -> closed
#[test]
fn a_sealed_signal_is_sold_then_opened_only_at_expiry_and_only_as_committed() {
    let mut test = TemplateTest::new(["."]);
    set_epoch(&mut test, 1);

    // The digest comes from the template's own `digest_of`, so the test commits to exactly what the
    // template will re-hash on reveal. Recomputing it here would only test the test.
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

    // Sealed: nothing readable before the reveal epoch.
    assert!(
        test.call_method::<Option<String>>(vault, "payload", args![], vec![]).is_none(),
        "the payload must not be readable before the reveal epoch"
    );
    assert_eq!(test.call_method::<u64>(vault, "sold", args![], vec![]), 0);

    // --- a buyer pays and receives an access badge --------------------------------------------
    let (buyer, buyer_proof, buyer_key) = test.create_funded_account();
    let tx = test
        .transaction()
        .call_method(buyer, "withdraw", args![XTR, Amount(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .put_last_instruction_output_on_workspace("out")
        .call_method(buyer, "deposit", args![Workspace("out.0")])
        .call_method(buyer, "deposit", args![Workspace("out.1")])
        .build_and_seal(&buyer_key);
    test.execute_expect_success(tx, vec![buyer_proof]);

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
    let key = test.secret_key().clone();
    let too_early = test
        .transaction()
        .call_method(vault, "reveal", args![PAYLOAD.to_string(), NONCE.to_vec()])
        .build_and_seal(&key);
    test.execute_expect_failure(too_early, vec![]);

    set_epoch(&mut test, REVEAL_AT_EPOCH);

    // --- and cannot open it as a different call -----------------------------------------------
    // The whole track-record claim rests on this failing.
    let wrong = test
        .transaction()
        .call_method(vault, "reveal", args![WRONG_PAYLOAD.to_string(), NONCE.to_vec()])
        .build_and_seal(&key);
    test.execute_expect_failure(wrong, vec![]);

    assert!(
        test.call_method::<Option<String>>(vault, "payload", args![], vec![]).is_none(),
        "a rejected reveal must not mutate state"
    );

    // --- the real reveal ----------------------------------------------------------------------
    test.call_method::<()>(vault, "reveal", args![PAYLOAD.to_string(), NONCE.to_vec()], vec![]);

    assert_eq!(
        test.call_method::<Option<String>>(vault, "payload", args![], vec![]).as_deref(),
        Some(PAYLOAD),
        "the committed payload must be readable once opened"
    );
    assert_eq!(
        test.call_method::<Option<u64>>(vault, "revealed_at_epoch", args![], vec![]),
        Some(REVEAL_AT_EPOCH)
    );

    // --- and the sale is closed, because the payload is public now -----------------------------
    let (late_buyer, late_proof, late_key) = test.create_funded_account();
    let too_late = test
        .transaction()
        .call_method(late_buyer, "withdraw", args![XTR, Amount(PRICE)])
        .put_last_instruction_output_on_workspace("payment")
        .call_method(vault, "purchase", args![Workspace("payment")])
        .build_and_seal(&late_key);
    test.execute_expect_failure(too_late, vec![late_proof]);

    assert_eq!(
        test.call_method::<u64>(vault, "sold", args![], vec![]),
        1,
        "selling must stop once the signal is public"
    );
}
