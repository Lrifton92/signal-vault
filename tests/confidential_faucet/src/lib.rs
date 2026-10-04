//! Test-only template: mints a confidential resource and pays out of it, so tests can hand Signal
//! Vault a bucket with hidden commitments in it.

use tari_template_lib::prelude::*;

#[template]
mod confidential_faucet {
    use super::*;

    pub struct ConfidentialFaucet {
        vault: Vault,
    }

    impl ConfidentialFaucet {
        pub fn mint(supply: ConfidentialOutputStatement) -> Component<Self> {
            let coins = ResourceBuilder::confidential()
                .mintable(rule!(allow_all), OWNER)
                .initial_supply(supply);
            Component::new(Self { vault: Vault::from_bucket(coins) })
                .with_access_rules(ComponentAccessRules::new().default(rule!(allow_all)))
                .create()
        }

        pub fn resource(&self) -> ResourceAddress {
            self.vault.resource_address()
        }

        pub fn take(&mut self, proof: ConfidentialWithdrawProof) -> Bucket {
            self.vault.withdraw_confidential(proof)
        }
    }
}
