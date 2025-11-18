pub use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::bls12381::{BLS_PRIVATE_KEY_LENGTH, min_pk};
use fastcrypto::traits::{
    AggregateAuthenticator, AllowedRng, KeyPair, Signer, ToFromBytes, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sui_crypto::SignatureError;
use sui_sdk_types::Address;

/// A thin wrapper around min_pk::BLS12381PrivateKey needed to implement Clone.
#[derive(Serialize, Deserialize, Debug)]
pub struct Bls12381PrivateKey(min_pk::BLS12381PrivateKey);

impl Clone for Bls12381PrivateKey {
    fn clone(&self) -> Self {
        // A bit of a hack since min_pk::BLS12381PrivateKey doesn't implement Clone
        Self(min_pk::BLS12381PrivateKey::from_bytes(self.0.as_bytes()).unwrap())
    }
}

impl Bls12381PrivateKey {
    /// The length of an BLS12381 private key in bytes.
    pub const LENGTH: usize = BLS_PRIVATE_KEY_LENGTH;

    pub fn from_bytes(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        min_pk::BLS12381PrivateKey::from_bytes(&bytes)
            .map_err(SignatureError::from_source)
            .map(Self)
    }

    pub fn public_key(&self) -> BLS12381PublicKey {
        min_pk::BLS12381PublicKey::from(&self.0)
    }

    pub fn generate(rng: &mut impl AllowedRng) -> Self {
        Self(min_pk::BLS12381KeyPair::generate(rng).private())
    }

    pub fn sign<T: Serialize>(&self, epoch: u64, address: Address, message: &T) -> MemberSignature {
        MemberSignature {
            epoch,
            address,
            signature: self.0.sign(&bcs::to_bytes(message).unwrap()),
        }
    }
}

#[derive(Debug)]
pub struct BlsCommittee {
    epoch: u64,
    members: Vec<BlsCommitteeMember>,
    address_to_index: BTreeMap<Address, usize>,
    total_weight: u64,
}

#[derive(Debug)]
#[allow(unused)]
pub struct BlsCommitteeMember {
    address: Address,
    public_key: BLS12381PublicKey,
    weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberSignature {
    epoch: u64,
    address: Address,
    signature: BLS12381Signature,
}

impl BlsCommittee {
    pub fn new(members: Vec<BlsCommitteeMember>, epoch: u64) -> Self {
        let total_weight = members.iter().map(|member| member.weight as u64).sum();
        let address_to_index = members
            .iter()
            .enumerate()
            .map(|(index, member)| (member.address, index))
            .collect();
        Self {
            epoch,
            members,
            address_to_index,
            total_weight,
        }
    }

    pub fn members(&self) -> &[BlsCommitteeMember] {
        &self.members
    }

    /// The total weight of the members of this committee.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    fn member(&self, address: &Address) -> Result<&BlsCommitteeMember, SignatureError> {
        let index = self
            .address_to_index
            .get(address)
            .ok_or_else(|| SignatureError::from_source(format!("unknown address {address}",)))?;
        Ok(&self.members[*index])
    }

    /// Verify a single signature provided by a [BlsCommitteeMember].
    fn verify<T: Serialize>(
        &self,
        message: &T,
        signature: &MemberSignature,
    ) -> Result<(), SignatureError> {
        if self.epoch != signature.epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch, self.epoch,
            )));
        }
        let message_bytes = bcs::to_bytes(message).map_err(SignatureError::from_source)?;
        self.member(&signature.address)?
            .public_key
            .verify(&message_bytes, &signature.signature)
            .map_err(SignatureError::from_source)
    }

    /// Verify an [CommitteeSignature]. If you also need to verify the weight, you can either
    /// get the weight of the signature with [CommitteeSignature::weight] or use the [verify_signature_and_weight]
    /// function.
    pub fn verify_signature<T: Serialize>(
        &self,
        signature: &CommitteeSignature<T>,
    ) -> Result<(), SignatureError> {
        let pks = signature
            .bitmap
            .iter()
            .map(|index| self.members[index].public_key.clone())
            .collect::<Vec<_>>();

        let message_bytes = bcs::to_bytes(&signature.message).map_err(SignatureError::from_source)?;
        signature
            .signature
            .verify(&pks, &message_bytes)
            .map_err(SignatureError::from_source)
    }

    /// Verify a signature and check that the weight of the signature is at least `required_weight`.
    pub fn verify_signature_and_weight<T: Serialize>(
        &self,
        signature: &CommitteeSignature<T>,
        required_weight: u64,
    ) -> Result<(), SignatureError> {
        let signed_weight = signature.weight(&self)?;
        if signed_weight < required_weight {
            return Err(SignatureError::from_source(format!(
                "insufficient signing weight {}; required weight threshold is {}",
                signed_weight, required_weight,
            )));
        }
        self.verify_signature(signature)
    }

    /// The number of members of this committee.
    fn size(&self) -> usize {
        self.members.len()
    }
}

impl BlsCommitteeMember {
    pub fn new(address: Address, public_key: BLS12381PublicKey, weight: u64) -> Self {
        Self {
            address,
            public_key,
            weight,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeSignature<T> {
    epoch: u64,
    signature: BLS12381AggregateSignature,
    bitmap: BitMap,
    pub(crate) message: T,
}

impl<T> CommitteeSignature<T> {
    /// The committee members included in this signature.
    pub fn signers(&self, committee: &BlsCommittee) -> Result<Vec<Address>, SignatureError> {
        if committee.epoch != self.epoch || self.bitmap.size != committee.members.len() {
            return Err(SignatureError::from_source(
                "committee signature does not match committee",
            ));
        }
        Ok(self
            .bitmap
            .iter()
            .map(|index| committee.members[index].address)
            .collect())
    }

    /// The total weight of the signers of this signature.
    pub fn weight(&self, committee: &BlsCommittee) -> Result<u64, SignatureError> {
        if committee.epoch != self.epoch || self.bitmap.size != committee.members.len() {
            return Err(SignatureError::from_source(
                "committee signature does not match committee",
            ));
        }
        Ok(self
            .bitmap
            .iter()
            .map(|index| committee.members[index].weight)
            .sum())
    }
}

#[derive(Debug)]
pub struct BLSSignatureAggregator<'a, T> {
    committee: &'a BlsCommittee,
    aggregate_signature: Option<BLS12381AggregateSignature>,
    bitmap: BitMap,
    signed_weight: u64,
    message: T,
}

impl<'a, T: Serialize + Clone> BLSSignatureAggregator<'a, T> {
    pub fn new(committee: &'a BlsCommittee, message: T) -> Self {
        Self {
            bitmap: BitMap::new(committee.size()),
            committee,
            aggregate_signature: None,
            signed_weight: 0,
            message,
        }
    }

    /// Add a signature to this aggregator.
    ///
    /// Returns an error if:
    ///  * a signature from the same member has already been added,
    ///  * if the signer is not a member of the committee,
    ///  * if the signature is not valid.
    pub fn add_signature(&mut self, signature: MemberSignature) -> Result<(), SignatureError> {
        self.committee.verify(&self.message, &signature)?;

        let index = self
            .committee
            .address_to_index
            .get(&signature.address)
            .ok_or_else(|| {
                SignatureError::from_source(format!("unknown address {}", &signature.address))
            })?;

        if self.bitmap.insert(*index)? {
            return Err(SignatureError::from_source(
                "duplicate signature from same committee member",
            ));
        }

        match self.aggregate_signature {
            None => self.aggregate_signature = Some(signature.signature.into()),
            Some(ref mut aggregate_signature) => aggregate_signature
                .add_signature(signature.signature)
                .map_err(SignatureError::from_source)?,
        }

        self.signed_weight += self.committee.members[*index].weight as u64;
        Ok(())
    }

    /// Add a raw [BLS12381Signature] from the given signer to this aggregator.
    ///
    /// Returns an error if:
    ///  * a signature from the same member has already been added,
    ///  * if the signer is not a member of the committee,
    ///  * if the signature is not valid.
    pub fn add_signature_from(
        &mut self,
        signer: Address,
        signature: BLS12381Signature,
    ) -> Result<(), SignatureError> {
        let member_signature = MemberSignature {
            epoch: self.committee.epoch,
            address: signer,
            signature,
        };
        self.add_signature(member_signature)
    }

    /// The total weight of the signatures aggregated so far.
    pub fn weight(&self) -> u64 {
        self.signed_weight
    }

    /// Return the aggregated signature from the signatures aggregated so far.
    /// Returns an error if no signatures have been added yet.
    pub fn finish(&self) -> Result<CommitteeSignature<T>, SignatureError> {
        match &self.aggregate_signature {
            None => Err(SignatureError::from_source(
                "signature map must have at least one entry",
            )),
            Some(signature) => {
                let aggregated_signature = CommitteeSignature {
                    epoch: self.committee.epoch,
                    signature: signature.clone(),
                    bitmap: self.bitmap.clone(),
                    message: self.message.clone(),
                };

                // Double check that the aggregated sig still verifies
                self.committee
                    .verify_signature(&aggregated_signature)?;

                Ok(aggregated_signature)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BitMap {
    size: usize,
    bitmap: Vec<u8>,
}

impl BitMap {
    fn new(size: usize) -> Self {
        Self {
            size,
            bitmap: Vec::new(),
        }
    }

    /// Set the given index in the bitmap and return the previous value.
    /// If an index larger than the committee size is given, nothing is changed and `false` is returned.
    fn insert(&mut self, b: usize) -> Result<bool, SignatureError> {
        if b >= self.size as usize {
            return Err(SignatureError::from_source(
                "index larger than committee size ({b} >= {self.committee_size})",
            ));
        }

        let byte_index = b / 8;
        let bit_index = b % 8;
        let bit_mask = 1 << (7 - bit_index);

        if byte_index >= self.bitmap.len() {
            self.bitmap.resize(byte_index + 1, 0);
        }
        let previous = self.bitmap[byte_index] & bit_mask != 0;
        self.bitmap[byte_index] |= bit_mask;
        Ok(previous)
    }

    fn iter(&self) -> impl Iterator<Item = usize> {
        self.bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_index, byte)| {
                (0..8).filter_map(move |bit_index| {
                    let bit = byte & (1 << (7 - bit_index)) != 0;
                    bit.then(|| byte_index * 8 + bit_index)
                })
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fastcrypto::groups::FiatShamirChallenge;
    use fastcrypto::groups::bls12381::Scalar;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use test_strategy::proptest;

    impl proptest::arbitrary::Arbitrary for Bls12381PrivateKey {
        type Parameters = ();
        fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
            use proptest::strategy::Strategy;

            proptest::arbitrary::any::<[u8; 48]>()
                .prop_map(|bytes| {
                    let sk = Scalar::fiat_shamir_reduction_to_group_element(&bytes);
                    let secret_key =
                        min_pk::BLS12381PrivateKey::from_bytes(&sk.to_byte_array()).unwrap();
                    Self(secret_key)
                })
                .boxed()
        }
        type Strategy = proptest::strategy::BoxedStrategy<Self>;
    }

    #[proptest]
    fn basic_aggregation(private_keys: [Bls12381PrivateKey; 4], message: Vec<u8>) {
        // Skip cases where we have the same keys
        {
            let mut pks: Vec<BLS12381PublicKey> =
                private_keys.iter().map(|key| key.public_key()).collect();
            pks.sort();
            pks.dedup();
            if pks.len() != 4 {
                return Ok(());
            }
        }

        let epoch = 7;

        let addresses = private_keys
            .iter()
            .enumerate()
            .map(|(i, _)| Address::new([i as u8; 32]))
            .collect::<Vec<_>>();

        let members = private_keys
            .iter()
            .enumerate()
            .map(|(i, key)| BlsCommitteeMember {
                address: addresses[i],
                public_key: key.public_key(),
                weight: 1,
            })
            .collect();
        let committee = BlsCommittee::new(members, epoch);

        let mut aggregator = BLSSignatureAggregator::new(&committee, message.clone());

        // Aggregating with no sigs fails
        aggregator.finish().unwrap_err();

        // Adding a signature with the wrong index fails
        aggregator
            .add_signature(private_keys[0].sign(epoch, addresses[1], &message))
            .unwrap_err();

        // Adding a signature with the wrong epoch fails
        aggregator
            .add_signature(private_keys[0].sign(4, addresses[0], &message))
            .unwrap_err();

        // This works
        aggregator
            .add_signature(private_keys[0].sign(epoch, addresses[0], &message))
            .unwrap();

        assert_eq!(aggregator.finish().unwrap().weight(&committee).unwrap(), 1);

        // Aggregating with a sig from the same committee member more than once fails
        aggregator
            .add_signature(private_keys[0].sign(epoch, addresses[0], &message))
            .unwrap_err();

        aggregator
            .add_signature(private_keys[1].sign(epoch, addresses[1], &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign(epoch, addresses[2], &message))
            .unwrap();

        assert_eq!(aggregator.finish().unwrap().weight(&committee).unwrap(), 3);

        // Aggregating with sufficient weight succeeds and verifies
        let signature = aggregator.finish().unwrap();
        aggregator
            .committee
            .verify_signature(&signature)
            .unwrap();

        committee
            .verify_signature_and_weight(&signature, 3)
            .unwrap();
        committee
            .verify_signature_and_weight(&signature, 2)
            .unwrap_err();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(private_keys[3].sign(epoch, addresses[3], &message))
            .unwrap();

        let signature = aggregator.finish().unwrap();
        aggregator
            .committee
            .verify_signature(&signature)
            .unwrap();
        assert_eq!(aggregator.finish().unwrap().weight(&committee).unwrap(), 4);
    }
}
