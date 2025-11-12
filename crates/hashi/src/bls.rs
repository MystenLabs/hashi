pub use fastcrypto::bls12381::min_pk::{
    BLS12381AggregateSignature, BLS12381PublicKey, BLS12381Signature,
};
use fastcrypto::bls12381::{BLS_PRIVATE_KEY_LENGTH, min_pk};
use fastcrypto::traits::{
    AggregateAuthenticator, AllowedRng, KeyPair, Signer, ToFromBytes, VerifyingKey,
};
use serde_derive::{Deserialize, Serialize};
use sui_crypto::SignatureError;
use sui_sdk_types::Address;

pub type Session = Vec<u8>;

/// A thin wrapper around min_pk::BLS12381PrivateKey needed to implement Clone.
#[derive(Serialize, Deserialize, Debug)]
pub struct BLSCommittePrivateKey(min_pk::BLS12381PrivateKey);

impl Clone for BLSCommittePrivateKey {
    fn clone(&self) -> Self {
        // A bit of a hack since min_pk::BLS12381PrivateKey doesn't implement Clone
        Self(min_pk::BLS12381PrivateKey::from_bytes(self.0.as_bytes()).unwrap())
    }
}

impl BLSCommittePrivateKey {
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

    pub fn sign(&self, message: &[u8]) -> BLS12381Signature {
        self.0.sign(message)
    }
}

/// The type of weight verification to perform.
#[derive(Copy, Clone, Debug)]
pub enum RequiredWeight {
    /// Verify that the signers form a quorum.
    Quorum,
    /// Verify that the signers include at least one correct node.
    OneCorrectNode,
    /// Verify that the signers include at least one node.
    OneNode,
    /// A custom, fixed threshold
    Custom(u64),
}

#[derive(Debug)]
pub struct BlsCommittee {
    members: Vec<BlsCommitteeMember>,
    total_weight: u64,
}

#[derive(Debug)]
#[allow(unused)]
pub struct BlsCommitteeMember {
    pub(crate) validator_address: Address,
    pub(crate) public_key: BLS12381PublicKey,
    pub(crate) weight: u16,
}

impl BlsCommittee {
    pub fn new(members: Vec<BlsCommitteeMember>) -> Self {
        let total_weight = members.iter().map(|member| member.weight as u64).sum();
        Self {
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

    fn member_by_idx(&self, idx: usize) -> Result<&BlsCommitteeMember, SignatureError> {
        let member = self.members.get(idx).ok_or_else(|| {
            SignatureError::from_source(format!(
                "index {idx} out of bounds; committee has {} members",
                self.members.len(),
            ))
        })?;
        Ok(member)
    }

    fn threshold(&self, required_weight: &RequiredWeight) -> u64 {
        let f = (self.total_weight - 1) / 3;
        match required_weight {
            RequiredWeight::Quorum => 2 * f + 1,
            RequiredWeight::OneCorrectNode => f + 1,
            RequiredWeight::OneNode => 1,
            RequiredWeight::Custom(t) => *t,
        }
    }

    fn verify(
        &self,
        message: &[u8],
        index: usize,
        signature: &BLS12381Signature,
    ) -> Result<(), SignatureError> {
        self.member_by_idx(index)?
            .public_key
            .verify(message, &signature)
            .map_err(SignatureError::from_source)
    }

    pub fn verify_aggregated_signature(
        &self,
        message: &[u8],
        signature: &BLSAggregatedSignature,
        required_weight: Option<RequiredWeight>,
    ) -> Result<(), SignatureError> {
        let mut signed_weight = 0u64;
        let mut pks = Vec::new();
        for idx in BitMap::new_iter(self.members().len(), &signature.bitmap)? {
            let member = self.member_by_idx(idx)?;
            signed_weight += member.weight as u64;
            pks.push(member.public_key.clone());
        }

        signature
            .signature
            .verify(&pks, message)
            .map_err(SignatureError::from_source)?;

        if let Some(required_weight) = required_weight {
            let threshold = self.threshold(&required_weight);
            return if signed_weight >= threshold {
                Ok(())
            } else {
                Err(SignatureError::from_source(format!(
                    "insufficient signing weight {}; required weight threshold is {}",
                    signed_weight, threshold,
                )))
            };
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BLSAggregatedSignature {
    signature: BLS12381AggregateSignature,
    bitmap: Vec<u8>,
}

#[derive(Debug)]
pub struct BLSSignatureAggregator {
    committee: BlsCommittee,
    aggregate_signature: Option<BLS12381AggregateSignature>,
    bitmap: BitMap,
    signed_weight: u64,
    message: Vec<u8>,
}

impl BLSSignatureAggregator {
    pub fn new(committee: BlsCommittee, message: Vec<u8>) -> Self {
        Self {
            bitmap: BitMap::new(committee.members().len()),
            committee,
            aggregate_signature: None,
            signed_weight: 0,
            message,
        }
    }

    pub fn committee(&self) -> &BlsCommittee {
        &self.committee
    }

    pub fn add_signature(
        &mut self,
        index: usize,
        signature: BLS12381Signature,
    ) -> Result<(), SignatureError> {
        let member = self.committee.member_by_idx(index)?;

        self.committee.verify(&self.message, index, &signature)?;

        if self.bitmap.insert(index) {
            return Err(SignatureError::from_source(
                "duplicate signature from same committee member",
            ));
        }

        match self.aggregate_signature {
            None => self.aggregate_signature = Some(signature.into()),
            Some(ref mut aggregate_signature) => aggregate_signature
                .add_signature(signature)
                .map_err(SignatureError::from_source)?,
        }
        self.signed_weight += member.weight as u64;
        Ok(())
    }

    pub fn has_weight(&self, required_weight: &RequiredWeight) -> bool {
        let threshold = self.committee().threshold(required_weight);
        self.signed_weight >= threshold
    }

    pub fn finish(
        &self,
        required_weight: RequiredWeight,
    ) -> Result<BLSAggregatedSignature, SignatureError> {
        if !self.has_weight(&required_weight) {
            return Err(SignatureError::from_source(format!(
                "signature weight of {} is insufficient to reach required weight threshold of {}",
                self.signed_weight,
                self.committee.threshold(&required_weight),
            )));
        }

        match &self.aggregate_signature {
            None => Err(SignatureError::from_source(
                "signature map must have at least one entry",
            )),
            Some(signature) => {
                let aggregated_signature = BLSAggregatedSignature {
                    signature: signature.clone(),
                    bitmap: self.bitmap.clone().into_inner(),
                };

                // Double check that the aggregated sig still verifies
                self.committee.verify_aggregated_signature(
                    &self.message,
                    &aggregated_signature,
                    Some(required_weight),
                )?;

                Ok(aggregated_signature)
            }
        }
    }
}

#[derive(Clone, Debug)]
struct BitMap {
    committee_size: usize,
    bitmap: Vec<u8>,
}

impl BitMap {
    fn new(committee_size: usize) -> Self {
        Self {
            committee_size,
            bitmap: Vec::new(),
        }
    }

    /// Set the given index in the bitmap and return the previous value.
    /// If an index larger than the committee size is given, nothing is changed and `false` is returned.
    fn insert(&mut self, b: usize) -> bool {
        if b >= self.committee_size {
            return false;
        }

        let byte_index = b / 8;
        let bit_index = b % 8;
        let bit_mask = 1 << (7 - bit_index);

        if byte_index >= self.bitmap.len() {
            self.bitmap.resize(byte_index + 1, 0);
        }
        let previous = self.bitmap[byte_index] & bit_mask != 0;
        self.bitmap[byte_index] |= bit_mask;
        previous
    }

    fn into_inner(self) -> Vec<u8> {
        self.bitmap
    }

    fn new_iter(
        committee_size: usize,
        bitmap: &[u8],
    ) -> Result<impl Iterator<Item = usize>, SignatureError> {
        let max_bitmap_len_bytes = committee_size.div_ceil(8);

        if bitmap.len() > max_bitmap_len_bytes {
            return Err(SignatureError::from_source("invalid bitmap"));
        }

        Ok(bitmap.iter().enumerate().flat_map(|(byte_index, byte)| {
            (0..8).filter_map(move |bit_index| {
                let bit = byte & (1 << (7 - bit_index)) != 0;
                bit.then(|| byte_index * 8 + bit_index)
            })
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use fastcrypto::groups::FiatShamirChallenge;
    use fastcrypto::groups::bls12381::Scalar;
    use fastcrypto::serde_helpers::ToFromByteArray;
    use test_strategy::proptest;

    impl proptest::arbitrary::Arbitrary for BLSCommittePrivateKey {
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
    fn basic_aggregation(private_keys: [BLSCommittePrivateKey; 4], message: Vec<u8>) {
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

        let required_weight = RequiredWeight::Quorum;
        let members = private_keys
            .iter()
            .map(|key| BlsCommitteeMember {
                validator_address: Address::ZERO,
                public_key: key.public_key(),
                weight: 1,
            })
            .collect();
        let committee = BlsCommittee::new(members);

        let mut aggregator = BLSSignatureAggregator::new(committee, message.clone());

        // Aggregating with no sigs fails
        aggregator.finish(required_weight).unwrap_err();

        aggregator
            .add_signature(0, private_keys[0].sign(&message))
            .unwrap();

        // Aggregating with a sig from the same committee member more than once fails
        aggregator
            .add_signature(0, private_keys[0].sign(&message))
            .unwrap_err();

        // Aggregating with insufficient weight fails
        aggregator.finish(required_weight).unwrap_err();

        aggregator
            .add_signature(1, private_keys[1].sign(&message))
            .unwrap();
        aggregator
            .add_signature(2, private_keys[2].sign(&message))
            .unwrap();

        // Aggregating with sufficient weight succeeds and verifies
        let signature = aggregator.finish(required_weight).unwrap();
        aggregator
            .committee()
            .verify_aggregated_signature(&message, &signature, Some(required_weight))
            .unwrap();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(3, private_keys[3].sign(&message))
            .unwrap();
        let signature = aggregator.finish(required_weight).unwrap();
        aggregator
            .committee()
            .verify_aggregated_signature(&message, &signature, Some(required_weight))
            .unwrap();
    }
}
