//! Test-only template: a fungible coin whose issuer can recall it out of any vault, including a
//! Signal Vault's escrow.

use tari_template_lib::prelude::*;

#[template]
mod rug_coin {
    use super::*;

    pub struct RugCoin {
        supply: Vault,
    }

    impl RugCoin {
        pub fn issue(amount: Amount) -> Component<Self> {
            let issuer = CallerContext::transaction_signer_public_key();
            let coins = ResourceBuilder::public_fungible()
                .with_token_symbol("RUG")
                .recallable(rule!(public_key(issuer)), LOCKED)
                .initial_supply(amount);
            Component::new(Self { supply: Vault::from_bucket(coins) })
                .with_access_rules(ComponentAccessRules::new().default(rule!(allow_all)))
                .create()
        }

        pub fn take(&mut self, amount: Amount) -> Bucket {
            self.supply.withdraw(amount)
        }

        pub fn resource(&self) -> ResourceAddress {
            self.supply.resource_address()
        }

        pub fn recall(resource: ResourceAddress, vault: VaultId, amount: Amount) -> Bucket {
            ResourceManager::get(resource).recall_fungible_amount(vault, amount)
        }
    }
}
