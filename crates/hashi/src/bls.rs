pub use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::bls12381::{BLS_PRIVATE_KEY_LENGTH, min_pk};
use fastcrypto::traits::{
    AggregateAuthenticator, AllowedRng, KeyPair, Signer, ToFromBytes, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
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

    pub fn sign<T: Serialize>(&self, epoch: u64, index: u64, message: &T) -> MemberSignature<T> {
        MemberSignature {
            epoch,
            index,
            signature: self.0.sign(&bcs::to_bytes(message).unwrap()),
            message: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct BlsCommittee {
    epoch: u64,
    members: Vec<BlsCommitteeMember>,
    total_weight: u64,
}

#[derive(Debug)]
#[allow(unused)]
pub struct BlsCommitteeMember {
    validator_address: Address,
    public_key: BLS12381PublicKey,
    weight: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberSignature<T> {
    epoch: u64,
    index: u64,
    signature: BLS12381Signature,
    message: PhantomData<T>,
}

impl BlsCommittee {
    pub fn new(members: Vec<BlsCommitteeMember>, epoch: u64) -> Self {
        let total_weight = members.iter().map(|member| member.weight as u64).sum();
        Self {
            epoch,
            members,
            total_weight,
        }
    }

    pub fn members(&self) -> &[BlsCommitteeMember] {
        &self.members
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    fn member(&self, idx: u64) -> Result<&BlsCommitteeMember, SignatureError> {
        let member = self.members.get(idx as usize).ok_or_else(|| {
            SignatureError::from_source(format!(
                "index {idx} out of bounds; committee has {} members",
                self.members.len(),
            ))
        })?;
        Ok(member)
    }

    /// Verify a single signature provided by a [BlsCommitteeMember].
    fn verify<T: Serialize>(
        &self,
        message: &T,
        signature: &MemberSignature<T>,
    ) -> Result<(), SignatureError> {
        if self.epoch != signature.epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch, self.epoch,
            )));
        }
        let message_bytes = bcs::to_bytes(message).map_err(SignatureError::from_source)?;
        self.member(signature.index)?
            .public_key
            .verify(&message_bytes, &signature.signature)
            .map_err(SignatureError::from_source)
    }

    /// Verify an [CommitteeSignature]. If you also need to verify the weight, you can either
    /// get that with the [signed_weight_of] function of by using [verify_signature_and_weight].
    pub fn verify_signature<T: Serialize>(
        &self,
        message: &T,
        signature: &CommitteeSignature<T>,
    ) -> Result<(), SignatureError> {
        let pks: Vec<BLS12381PublicKey> = signature
            .bitmap
            .iter()
            .map(|idx| {
                let member = self.member(idx)?;
                Ok(member.public_key.clone())
            })
            .collect::<Result<_, SignatureError>>()?;

        let message_bytes = bcs::to_bytes(message).map_err(SignatureError::from_source)?;
        signature
            .signature
            .verify(&pks, &message_bytes)
            .map_err(SignatureError::from_source)
    }

    pub fn verify_signature_and_weight<T: Serialize>(
        &self,
        message: &T,
        signature: &CommitteeSignature<T>,
        required_weight: u64,
    ) -> Result<(), SignatureError> {
        let signed_weight = self.signed_weight_of(signature)?;
        if signed_weight < required_weight {
            return Err(SignatureError::from_source(format!(
                "insufficient signing weight {}; required weight threshold is {}",
                signed_weight, required_weight,
            )));
        }
        self.verify_signature(message, signature)
    }

    pub fn signed_weight_of<T>(
        &self,
        committee_signature: &CommitteeSignature<T>,
    ) -> Result<u64, SignatureError> {
        if committee_signature.epoch != self.epoch
            || committee_signature.bitmap.committee_size != self.members.len() as u64
        {
            return Err(SignatureError::from_source(
                "committee signature does not match committee",
            ));
        }
        Ok(committee_signature
            .bitmap
            .iter()
            .map(|idx| self.member(idx).unwrap().weight as u64)
            .sum())
    }

    pub fn signers_of<T>(
        &self,
        committee_signature: &CommitteeSignature<T>,
    ) -> Result<Vec<Address>, SignatureError> {
        if committee_signature.epoch != self.epoch
            || committee_signature.bitmap.committee_size != self.members.len() as u64
        {
            return Err(SignatureError::from_source(
                "committee signature does not match committee",
            ));
        }
        Ok(committee_signature
            .bitmap
            .iter()
            .map(|idx| self.member(idx).unwrap().validator_address)
            .collect())
    }
}

impl BlsCommitteeMember {
    pub fn new(validator_address: Address, public_key: BLS12381PublicKey, weight: u16) -> Self {
        Self {
            validator_address,
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
            bitmap: BitMap::new(committee.members().len() as u64),
            committee,
            aggregate_signature: None,
            signed_weight: 0,
            message,
        }
    }

    pub fn committee(&self) -> &BlsCommittee {
        self.committee
    }

    pub fn add_signature(&mut self, signature: MemberSignature<T>) -> Result<(), SignatureError> {
        self.committee.verify(&self.message, &signature)?;

        if self.bitmap.insert(signature.index)? {
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

        let member = self.committee.member(signature.index)?;
        self.signed_weight += member.weight as u64;
        Ok(())
    }

    pub fn weight(&self) -> u64 {
        self.signed_weight
    }

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
                    .verify_signature(&self.message, &aggregated_signature)?;

                Ok(aggregated_signature)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BitMap {
    committee_size: u64,
    bitmap: Vec<u8>,
}

impl BitMap {
    fn new(committee_size: u64) -> Self {
        Self {
            committee_size,
            bitmap: Vec::new(),
        }
    }

    /// Set the given index in the bitmap and return the previous value.
    /// If an index larger than the committee size is given, nothing is changed and `false` is returned.
    fn insert(&mut self, b: u64) -> Result<bool, SignatureError> {
        if b >= self.committee_size {
            return Err(SignatureError::from_source(
                "index larger than committee size ({b} >= {self.committee_size})",
            ));
        }

        let byte_index = (b / 8) as usize;
        let bit_index = (b % 8) as usize;
        let bit_mask = 1 << (7 - bit_index);

        if byte_index >= self.bitmap.len() {
            self.bitmap.resize(byte_index + 1, 0);
        }
        let previous = self.bitmap[byte_index] & bit_mask != 0;
        self.bitmap[byte_index] |= bit_mask;
        Ok(previous)
    }

    fn iter(&self) -> impl Iterator<Item = u64> {
        self.bitmap
            .iter()
            .enumerate()
            .flat_map(|(byte_index, byte)| {
                (0..8).filter_map(move |bit_index| {
                    let bit = byte & (1 << (7 - bit_index)) != 0;
                    bit.then(|| (byte_index * 8 + bit_index) as u64)
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

        let members = private_keys
            .iter()
            .map(|key| BlsCommitteeMember {
                validator_address: Address::ZERO,
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
            .add_signature(private_keys[0].sign(epoch, 1, &message))
            .unwrap_err();

        // Adding a signature with the wrong epoch fails
        aggregator
            .add_signature(private_keys[0].sign(4, 0, &message))
            .unwrap_err();

        // This works
        aggregator
            .add_signature(private_keys[0].sign(epoch, 0, &message))
            .unwrap();

        assert_eq!(
            committee
                .signed_weight_of(&aggregator.finish().unwrap())
                .unwrap(),
            1
        );

        // Aggregating with a sig from the same committee member more than once fails
        aggregator
            .add_signature(private_keys[0].sign(epoch, 0, &message))
            .unwrap_err();

        aggregator
            .add_signature(private_keys[1].sign(epoch, 1, &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign(epoch, 2, &message))
            .unwrap();

        assert_eq!(
            committee
                .signed_weight_of(&aggregator.finish().unwrap())
                .unwrap(),
            3
        );

        // Aggregating with sufficient weight succeeds and verifies
        let signature = aggregator.finish().unwrap();
        aggregator
            .committee()
            .verify_signature(&message, &signature)
            .unwrap();

        committee
            .verify_signature_and_weight(&message, &signature, 3)
            .unwrap();
        committee
            .verify_signature_and_weight(&message, &signature, 2)
            .unwrap_err();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(private_keys[3].sign(epoch, 3, &message))
            .unwrap();

        let signature = aggregator.finish().unwrap();
        aggregator
            .committee()
            .verify_signature(&message, &signature)
            .unwrap();
        assert_eq!(committee.signed_weight_of(&signature).unwrap(), 4);
    }
}
