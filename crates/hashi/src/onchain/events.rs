#![allow(unused)]

use crate::onchain::move_types::UtxoId;

use super::MoveType;
use std::collections::BTreeSet;
use sui_rpc::proto::sui::rpc::v2::Bcs;
use sui_sdk_types::Address;
use sui_sdk_types::StructTag;
use sui_sdk_types::TypeTag;
use sui_sdk_types::bcs::FromBcs;

#[derive(Debug)]
pub enum HashiEvent {
    ValidatorRegistered(ValidatorRegistered),
    ValidatorUpdated(ValidatorUpdated),
    VoteCastEvent(VoteCastEvent),
    VoteRemovedEvent(VoteRemovedEvent),
    ProposalDeletedEvent(ProposalDeletedEvent),
    ProposalExecutedEvent(ProposalExecutedEvent),
    QuorumReachedEvent(QuorumReachedEvent),
    PackageUpgradedEvent(PackageUpgradedEvent),
    MintEvent(MintEvent),
    BurnEvent(BurnEvent),
    DepositRequestedEvent(DepositRequestedEvent),
    DepositConfirmedEvent(DepositConfirmedEvent),
}

impl HashiEvent {
    pub fn try_parse(
        package_ids: &BTreeSet<Address>,
        bcs: &Bcs,
    ) -> Result<Option<Self>, anyhow::Error> {
        let event_type = bcs.name().parse::<StructTag>()?;

        // If this isn't from a package we care about we can skip
        if !package_ids.contains(event_type.address()) {
            return Ok(None);
        }

        let event = match (event_type.module().as_str(), event_type.name().as_str()) {
            ValidatorRegistered::MODULE_NAME => ValidatorRegistered::from_bcs(bcs.value())?.into(),
            ValidatorUpdated::MODULE_NAME => ValidatorUpdated::from_bcs(bcs.value())?.into(),
            VoteCastEvent::MODULE_NAME => VoteCastEvent::from_bcs(bcs.value())?.into(),
            VoteRemovedEvent::MODULE_NAME => VoteRemovedEvent::from_bcs(bcs.value())?.into(),
            ProposalDeletedEvent::MODULE_NAME => {
                ProposalDeletedEvent::from_bcs(bcs.value())?.into()
            }
            ProposalExecutedEvent::MODULE_NAME => {
                ProposalExecutedEvent::from_bcs(bcs.value())?.into()
            }
            QuorumReachedEvent::MODULE_NAME => QuorumReachedEvent::from_bcs(bcs.value())?.into(),
            MintEvent::MODULE_NAME => MintEvent::new(&event_type, bcs.value())?.into(),
            BurnEvent::MODULE_NAME => BurnEvent::new(&event_type, bcs.value())?.into(),
            DepositRequestedEvent::MODULE_NAME => {
                DepositRequestedEvent::from_bcs(bcs.value())?.into()
            }
            DepositConfirmedEvent::MODULE_NAME => {
                DepositConfirmedEvent::from_bcs(bcs.value())?.into()
            }
            _ => {
                return Ok(None);
            }
        };

        Ok(Some(event))
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ValidatorRegistered {
    pub validator: Address,
}

impl MoveType for ValidatorRegistered {
    const MODULE: &'static str = "validator";
    const NAME: &'static str = "ValidatorRegistered";
}

impl From<ValidatorRegistered> for HashiEvent {
    fn from(value: ValidatorRegistered) -> Self {
        Self::ValidatorRegistered(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ValidatorUpdated {
    pub validator: Address,
}

impl MoveType for ValidatorUpdated {
    const MODULE: &'static str = "validator";
    const NAME: &'static str = "ValidatorUpdated";
}

impl From<ValidatorUpdated> for HashiEvent {
    fn from(value: ValidatorUpdated) -> Self {
        Self::ValidatorUpdated(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct VoteCastEvent {
    pub proposal_id: Address,
    pub voter: Address,
}

impl MoveType for VoteCastEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteCastEvent";
}

impl From<VoteCastEvent> for HashiEvent {
    fn from(value: VoteCastEvent) -> Self {
        Self::VoteCastEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct VoteRemovedEvent {
    pub proposal_id: Address,
    pub voter: Address,
}

impl MoveType for VoteRemovedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "VoteRemovedEvent";
}

impl From<VoteRemovedEvent> for HashiEvent {
    fn from(value: VoteRemovedEvent) -> Self {
        Self::VoteRemovedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ProposalDeletedEvent {
    pub proposal_id: Address,
}

impl MoveType for ProposalDeletedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalDeletedEvent";
}

impl From<ProposalDeletedEvent> for HashiEvent {
    fn from(value: ProposalDeletedEvent) -> Self {
        Self::ProposalDeletedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct ProposalExecutedEvent {
    pub proposal_id: Address,
}

impl MoveType for ProposalExecutedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "ProposalExecutedEvent";
}

impl From<ProposalExecutedEvent> for HashiEvent {
    fn from(value: ProposalExecutedEvent) -> Self {
        Self::ProposalExecutedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct QuorumReachedEvent {
    pub proposal_id: Address,
}

impl MoveType for QuorumReachedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "QuorumReachedEvent";
}

impl From<QuorumReachedEvent> for HashiEvent {
    fn from(value: QuorumReachedEvent) -> Self {
        Self::QuorumReachedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct PackageUpgradedEvent {
    pub package: Address,
    pub version: u64,
}

impl MoveType for PackageUpgradedEvent {
    const MODULE: &'static str = "proposal_events";
    const NAME: &'static str = "PackageUpgradedEvent";
}

impl From<PackageUpgradedEvent> for HashiEvent {
    fn from(value: PackageUpgradedEvent) -> Self {
        Self::PackageUpgradedEvent(value)
    }
}

#[derive(Debug)]
pub struct MintEvent {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for MintEvent {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "MintEvent";
}

impl MintEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        if event_type.module() == Self::MODULE
            && event_type.name() == Self::NAME
            && let [coin_type] = event_type.type_params()
        {
            Ok(Self {
                coin_type: coin_type.to_owned(),
                amount: bcs::from_bytes(bcs)?,
            })
        } else {
            Err(anyhow::anyhow!("invalid MintEvent"))
        }
    }
}

impl From<MintEvent> for HashiEvent {
    fn from(value: MintEvent) -> Self {
        Self::MintEvent(value)
    }
}

#[derive(Debug)]
pub struct BurnEvent {
    pub coin_type: TypeTag,
    pub amount: u64,
}

impl MoveType for BurnEvent {
    const MODULE: &'static str = "treasury";
    const NAME: &'static str = "BurnEvent";
}

impl BurnEvent {
    fn new(event_type: &StructTag, bcs: &[u8]) -> Result<Self, anyhow::Error> {
        if event_type.module() == Self::MODULE
            && event_type.name() == Self::NAME
            && let [coin_type] = event_type.type_params()
        {
            Ok(Self {
                coin_type: coin_type.to_owned(),
                amount: bcs::from_bytes(bcs)?,
            })
        } else {
            Err(anyhow::anyhow!("invalid BurnEvent"))
        }
    }
}

impl From<BurnEvent> for HashiEvent {
    fn from(value: BurnEvent) -> Self {
        Self::BurnEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositRequestedEvent {
    pub request_id: Address,
    pub utxo_id: UtxoId,
    pub amount: u64,
    pub derivation_path: Option<Address>,
    pub timestamp_ms: u64,
}

impl MoveType for DepositRequestedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositRequestedEvent";
}

impl From<DepositRequestedEvent> for HashiEvent {
    fn from(value: DepositRequestedEvent) -> Self {
        Self::DepositRequestedEvent(value)
    }
}

#[derive(Debug, serde_derive::Deserialize)]
pub struct DepositConfirmedEvent {
    pub request_id: Address,
    pub utxo_id: UtxoId,
    pub amount: u64,
    pub derivation_path: Option<Address>,
    // signature: XXX
}

impl MoveType for DepositConfirmedEvent {
    const MODULE: &'static str = "deposit";
    const NAME: &'static str = "DepositConfirmedEvent";
}

impl From<DepositConfirmedEvent> for HashiEvent {
    fn from(value: DepositConfirmedEvent) -> Self {
        Self::DepositConfirmedEvent(value)
    }
}
