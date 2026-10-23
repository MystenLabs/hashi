// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The hBTC supply: the `total_supply` of Hashi's `TreasuryCap<BTC>`.
//!
//! Why it exists: the auditor compares the supply with the value of its UTXO
//! pool. More hBTC than the pool holds means that Bitcoin does not back every
//! hBTC.
//!
//! How it works:
//! 1. At startup, `find_hbtc_treasury_cap` reads the Hashi object for the id
//!    of its treasury `ObjectBag`.
//! 2. Derive the id of the bag's `Key<TreasuryCap<BTC>>` field the same way
//!    Move does. Read the field for the id of the cap.
//! 3. Each check reads the cap and decodes its supply.
//!
//! Assumptions:
//! - The cap stays in the treasury bag under the original package's `Key`,
//!   so its id does not change.
//! - Only `GetObject` is used. An archive node does not serve `GetCoinInfo`
//!   or `ListDynamicFields`.

use std::str::FromStr;

use anyhow::Context;
use hashi_types::move_types::Field;
use hashi_types::move_types::Hashi;
use hashi_types::move_types::TreasuryCap;
use serde::de::DeserializeOwned;
use sui_rpc::field::FieldMask;
use sui_rpc::field::FieldMaskUtil;
use sui_rpc::proto::sui::rpc::v2::GetObjectRequest;
use sui_rpc::proto::sui::rpc::v2::Object;
use sui_sdk_types::Address;
use sui_sdk_types::Identifier;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;

use super::SuiPoller;

/// The id of the dynamic object field that holds `TreasuryCap<BTC>` in the
/// treasury bag `bag_id`.
pub fn treasury_cap_field_id(bag_id: Address, package_id: Address) -> Address {
    let btc = struct_tag(package_id, "btc", "BTC", vec![]);
    let cap = struct_tag(Address::TWO, "coin", "TreasuryCap", vec![btc]);
    let key = struct_tag(package_id, "treasury", "Key", vec![cap]);
    let wrapper = struct_tag(Address::TWO, "dynamic_object_field", "Wrapper", vec![key]);
    // `Key` has no fields, so Move gives it one `dummy_field: bool`.
    bag_id.derive_dynamic_child_id(&wrapper, &[0])
}

impl SuiPoller {
    /// Find Hashi's `TreasuryCap<BTC>` through the Hashi object
    /// `hashi_object_id`. Call once, before `hbtc_supply`.
    pub async fn find_hbtc_treasury_cap(&mut self, hashi_object_id: Address) -> anyhow::Result<()> {
        let package_id = Address::from_str(&self.package_id)
            .with_context(|| format!("invalid Hashi package ID {}", self.package_id))?;
        let hashi: Hashi =
            read_object(&mut self.client, hashi_object_id, "the Hashi object").await?;
        let field_id = treasury_cap_field_id(hashi.treasury.objects.id, package_id);
        let field: Field<bool, Address> =
            read_object(&mut self.client, field_id, "the hBTC TreasuryCap field").await?;
        self.hbtc_treasury_cap_id = field.value;
        tracing::info!(hbtc_treasury_cap_id = %field.value, "found the hBTC TreasuryCap");
        Ok(())
    }

    /// The `total_supply` of Hashi's `TreasuryCap<BTC>`, in satoshis.
    pub async fn hbtc_supply(&mut self) -> anyhow::Result<u64> {
        let id = self.hbtc_treasury_cap_id;
        let cap: TreasuryCap = read_object(&mut self.client, id, "the hBTC TreasuryCap").await?;
        Ok(cap.supply)
    }
}

fn struct_tag(address: Address, module: &str, name: &str, type_params: Vec<TypeTag>) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag::new(
        address,
        Identifier::new(module).expect("valid module name"),
        Identifier::new(name).expect("valid type name"),
        type_params,
    )))
}

/// The BCS contents of object `id`, decoded as `T`.
async fn read_object<T: DeserializeOwned>(
    client: &mut sui_rpc::Client,
    id: Address,
    what: &str,
) -> anyhow::Result<T> {
    let request =
        GetObjectRequest::new(&id).with_read_mask(FieldMask::from_paths([Object::path_builder()
            .contents()
            .finish()]));
    client
        .ledger_client()
        .get_object(request)
        .await
        .with_context(|| format!("failed to fetch {what} {id}"))?
        .into_inner()
        .object
        .with_context(|| format!("Sui GetObject response is missing {what} {id}"))?
        .contents()
        .deserialize()
        .with_context(|| format!("failed to decode {what} {id}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_field_id_matches_testnet() {
        // Read from testnet on 2026-10-22: the cap's owner is this field, and
        // the field's owner is the treasury bag.
        let package_id =
            Address::from_str("0x5e0b99c31f691742acea5de4ca1bf53c398d5639fed6503a51ffe8035dc68485")
                .unwrap();
        let bag_id =
            Address::from_str("0xe4029de51c3972ce6f0b2be70b6bff52f1f54ece7ad27e26b383bc328fc9e38d")
                .unwrap();
        assert_eq!(
            treasury_cap_field_id(bag_id, package_id).to_string(),
            "0x8ef8a4b5f9826796f896896624c0817ac232eccda18e3872420b7504524130f7"
        );
    }
}
