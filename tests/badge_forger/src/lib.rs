//! Test-only template: mints a badge of any resource it is pointed at, without going through
//! `purchase`. Signal Vault must refuse it.

use tari_template_lib::prelude::*;

#[template]
mod badge_forger {
    use super::*;

    pub struct BadgeForger {}

    impl BadgeForger {
        pub fn forge(badges: ResourceAddress) -> Bucket {
            ResourceManager::get(badges).mint_non_fungible(NonFungibleId::random(), &Metadata::new(), &())
        }
    }
}
