// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::ops::Bound;

use hashi_types::committee::RuntimeCommittee;
use prometheus::IntCounterVec;
use sui_sdk_types::Address;
use tonic::Status;

const REFUSAL_TAG: &str = "caller-membership:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    NotMember,
    CommitteeUnknown,
}

impl Refusal {
    fn label(self) -> &'static str {
        match self {
            Self::NotMember => "not_member",
            Self::CommitteeUnknown => "committee_unknown",
        }
    }
}

pub(super) fn check_member(committee: &RuntimeCommittee, caller: &Address) -> Result<(), Refusal> {
    committee
        .index_of(caller)
        .map(|_| ())
        .ok_or(Refusal::NotMember)
}

pub(super) fn check_current_or_previous(
    caller: &Address,
    request_epoch: u64,
    current_epoch: u64,
    current: &RuntimeCommittee,
    previous: Option<&RuntimeCommittee>,
) -> Result<(), Refusal> {
    let committee = if request_epoch == current_epoch {
        current
    } else {
        let Some(previous) = previous else {
            return Ok(());
        };
        previous
    };
    check_member(committee, caller)
}

pub(super) fn check_epoch_or_successor(
    committees: &BTreeMap<u64, RuntimeCommittee>,
    epoch: u64,
    caller: &Address,
) -> Result<(), Refusal> {
    if committees
        .get(&epoch)
        .is_some_and(|committee| check_member(committee, caller).is_ok())
    {
        return Ok(());
    }
    committees
        .range((Bound::Excluded(epoch), Bound::Unbounded))
        .next()
        .map_or(Err(Refusal::CommitteeUnknown), |(_, successor)| {
            check_member(successor, caller)
        })
}

pub(super) fn check_epoch(
    committees: &BTreeMap<u64, RuntimeCommittee>,
    epoch: u64,
    caller: &Address,
) -> Result<(), Refusal> {
    committees
        .get(&epoch)
        .map_or(Err(Refusal::CommitteeUnknown), |committee| {
            check_member(committee, caller)
        })
}

pub(super) fn refuse(
    refused: &IntCounterVec,
    handler: &str,
    caller: &Address,
    checked: &str,
    refusal: Refusal,
) -> Status {
    refused
        .with_label_values(&[handler, &caller.to_string(), refusal.label()])
        .inc();
    Status::permission_denied(format!(
        "{REFUSAL_TAG} {caller} not admitted for {checked} ({})",
        refusal.label()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashi_types::committee::Bls12381PrivateKey;
    use hashi_types::committee::Committee;
    use hashi_types::committee::CommitteeMember;
    use hashi_types::committee::EncryptionPrivateKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn address(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    fn committee(epoch: u64, members: &[u8]) -> RuntimeCommittee {
        let mut rng = StdRng::seed_from_u64(epoch);
        let members = members
            .iter()
            .map(|&byte| {
                CommitteeMember::new(
                    address(byte),
                    Bls12381PrivateKey::generate(&mut rng).public_key(),
                    EncryptionPrivateKey::new(&mut rng).public_key(),
                    1,
                )
            })
            .collect();
        Committee::new(members, epoch, 0u16, 3333u16).into()
    }

    #[test]
    fn caller_membership_rules() {
        let committees = BTreeMap::from([
            (10, committee(10, &[1])),
            (20, committee(20, &[2])),
            (30, committee(30, &[3])),
        ]);
        let before_pending = BTreeMap::from([(10, committee(10, &[1])), (20, committee(20, &[2]))]);
        let current = committee(20, &[2]);
        let previous = committee(10, &[1]);
        let cases = [
            (
                check_epoch_or_successor(&committees, 10, &address(1)),
                Ok(()),
            ),
            (
                check_epoch_or_successor(&committees, 10, &address(2)),
                Ok(()),
            ),
            (
                check_epoch_or_successor(&committees, 10, &address(3)),
                Err(Refusal::NotMember),
            ),
            (
                check_epoch_or_successor(&committees, 10, &address(9)),
                Err(Refusal::NotMember),
            ),
            (
                check_epoch_or_successor(&before_pending, 20, &address(3)),
                Err(Refusal::CommitteeUnknown),
            ),
            (
                check_epoch_or_successor(&committees, 30, &address(3)),
                Ok(()),
            ),
            (check_epoch(&committees, 20, &address(2)), Ok(())),
            (
                check_epoch(&committees, 20, &address(1)),
                Err(Refusal::NotMember),
            ),
            (
                check_epoch(&committees, 25, &address(2)),
                Err(Refusal::CommitteeUnknown),
            ),
            (
                check_current_or_previous(&address(2), 20, 20, &current, Some(&previous)),
                Ok(()),
            ),
            (
                check_current_or_previous(&address(1), 20, 20, &current, Some(&previous)),
                Err(Refusal::NotMember),
            ),
            (
                check_current_or_previous(&address(1), 10, 20, &current, Some(&previous)),
                Ok(()),
            ),
            (
                check_current_or_previous(&address(2), 10, 20, &current, Some(&previous)),
                Err(Refusal::NotMember),
            ),
            (
                check_current_or_previous(&address(9), 10, 20, &current, None),
                Ok(()),
            ),
            (check_member(&current, &address(2)), Ok(())),
            (check_member(&current, &address(1)), Err(Refusal::NotMember)),
        ];
        for (index, (got, expected)) in cases.into_iter().enumerate() {
            assert_eq!(got, expected, "case {index}");
        }
    }
}
