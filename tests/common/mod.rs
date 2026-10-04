//! Off-chain helpers shared by the integration tests.

use blake2::{digest::consts::U32, Blake2b, Digest};
use tari_template_lib_types::Hash32;
use tari_template_test_tooling::TemplateTest;

/// `commitment_of` from the template, computed off-chain the way a provider must: payload and nonce
/// in a transaction would be public. The crate is a `cdylib` only (the Ootle linter's rule), so the
/// tests cannot import it; every successful reveal checks this copy against the template's.
pub fn commitment_of(publisher: &[u8], payload: &str, nonce: &[u8]) -> Hash32 {
    let mut hasher = Blake2b::<U32>::new();
    for part in [b"tari.ootle.signal_vault.commitment.v2".as_slice(), publisher, payload.as_bytes(), nonce] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Hash32::from_array(hasher.finalize().into())
}

/// The commitment for a vault published with the test's default key.
pub fn digest(test: &TemplateTest, payload: &str, nonce: &[u8]) -> Hash32 {
    commitment_of(test.to_public_key_bytes().as_bytes(), payload, nonce)
}
