use fastcrypto::bls12381::BLS_PRIVATE_KEY_LENGTH;
use fastcrypto::bls12381::min_pk;
pub use fastcrypto::bls12381::min_pk::BLS12381AggregateSignature;
pub use fastcrypto::bls12381::min_pk::BLS12381PublicKey;
pub use fastcrypto::bls12381::min_pk::BLS12381Signature;
use fastcrypto::traits::AggregateAuthenticator;
use fastcrypto::traits::AllowedRng;
use fastcrypto::traits::KeyPair;
use fastcrypto::traits::Signer;
use fastcrypto::traits::ToFromBytes;
use fastcrypto::traits::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use sui_crypto::SignatureError;
use sui_sdk_types::Address;

pub type EncryptionPrivateKey =
    fastcrypto_tbls::ecies_v1::PrivateKey<crate::dkg::EncryptionGroupElement>;
pub type EncryptionPublicKey =
    fastcrypto_tbls::ecies_v1::PublicKey<crate::dkg::EncryptionGroupElement>;

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
        let signing_message = signing_message(epoch, message);
        MemberSignature {
            epoch,
            address,
            signature: self.0.sign(&signing_message),
        }
    }

    pub fn proof_of_possession(&self, epoch: u64, address: Address) -> MemberSignature {
        let public_key = self.public_key();
        self.sign(epoch, address, &(address, public_key))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Committee {
    epoch: u64,
    members: Vec<CommitteeMember>,
    address_to_index: HashMap<Address, usize>,
    total_weight: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommitteeMember {
    address: Address,
    public_key: BLS12381PublicKey,
    encryption_public_key: EncryptionPublicKey,
    weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberSignature {
    epoch: u64,
    address: Address,
    signature: BLS12381Signature,
}

impl MemberSignature {
    pub fn new(epoch: u64, address: Address, signature: BLS12381Signature) -> Self {
        Self {
            epoch,
            address,
            signature,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn signature(&self) -> &BLS12381Signature {
        &self.signature
    }
}

impl Committee {
    pub fn new(members: Vec<CommitteeMember>, epoch: u64) -> Self {
        let total_weight = members.iter().map(|member| member.weight).sum();
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

    pub fn members(&self) -> &[CommitteeMember] {
        &self.members
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The total weight of the members of this committee.
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    fn member(&self, address: &Address) -> Result<&CommitteeMember, SignatureError> {
        let index = self
            .address_to_index
            .get(address)
            .ok_or_else(|| SignatureError::from_source(format!("unknown address {address}",)))?;
        Ok(&self.members[*index])
    }

    pub fn weight_of(&self, member: &Address) -> Result<u64, SignatureError> {
        self.member(member).map(|m| m.weight)
    }

    /// Returns the index of a member by address, or None if not found.
    pub fn index_of(&self, address: &Address) -> Option<usize> {
        self.address_to_index.get(address).copied()
    }

    /// Verify a single signature provided by a [CommitteeMember].
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
        let message_bytes = signing_message(signature.epoch, message);
        self.member(&signature.address)?
            .public_key
            .verify(&message_bytes, &signature.signature)
            .map_err(SignatureError::from_source)
    }

    /// Verify an [CommitteeSignature]. If you also need to verify the weight, you can either
    /// get the weight of the signature with [CommitteeSignature::weight] or use the [Self::verify_signature_and_weight]
    /// function.
    pub fn verify_signature<T: Serialize>(
        &self,
        signed_message: &SignedMessage<T>,
    ) -> Result<(), SignatureError> {
        let pks = signed_message
            .signature
            .signers_bitmap
            .iter()
            .map(|index| self.members[index].public_key.clone())
            .collect::<Vec<_>>();

        let message_bytes =
            signing_message(signed_message.signature.epoch, &signed_message.message);
        signed_message
            .signature
            .signature
            .verify(&pks, &message_bytes)
            .map_err(SignatureError::from_source)
    }

    /// Verify a signature and check that the weight of the signature is at least `required_weight`.
    pub fn verify_signature_and_weight<T: Serialize>(
        &self,
        signed_message: &SignedMessage<T>,
        required_weight: u64,
    ) -> Result<(), SignatureError> {
        let signed_weight = signed_message.signature.weight(self)?;
        if signed_weight < required_weight {
            return Err(SignatureError::from_source(format!(
                "insufficient signing weight {}; required weight threshold is {}",
                signed_weight, required_weight,
            )));
        }
        self.verify_signature(signed_message)
    }

    /// The number of members of this committee.
    fn size(&self) -> usize {
        self.members.len()
    }
}

impl CommitteeMember {
    pub fn new(
        address: Address,
        public_key: BLS12381PublicKey,
        encryption_public_key: EncryptionPublicKey,
        weight: u64,
    ) -> Self {
        Self {
            address,
            public_key,
            encryption_public_key,
            weight,
        }
    }

    pub fn validator_address(&self) -> Address {
        self.address
    }

    pub fn public_key(&self) -> &BLS12381PublicKey {
        &self.public_key
    }

    pub fn encryption_public_key(&self) -> &EncryptionPublicKey {
        &self.encryption_public_key
    }

    pub fn weight(&self) -> u64 {
        self.weight
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeSignature {
    epoch: u64,
    signature: BLS12381AggregateSignature,
    signers_bitmap: BitMap,
}

impl CommitteeSignature {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }

    pub fn signers_bitmap_bytes(&self) -> &[u8] {
        self.signers_bitmap.as_bytes()
    }

    /// Verify that the committee could be used to verify this certificate, e.g., that the epoch and
    /// the number of signers match.
    fn verify_committee(&self, committee: &Committee) -> Result<(), SignatureError> {
        if committee.epoch != self.epoch
            || self.signers_bitmap.iter().any(|i| i >= committee.size())
        {
            return Err(SignatureError::from_source(
                "committee signature does not match committee",
            ));
        }
        Ok(())
    }

    /// The committee members included in this signature.
    pub fn signers(&self, committee: &Committee) -> Result<Vec<Address>, SignatureError> {
        self.verify_committee(committee)?;
        Ok(self
            .signers_bitmap
            .iter()
            .map(|index| committee.members[index].address)
            .collect())
    }

    /// The total weight of the signers of this signature.
    pub fn weight(&self, committee: &Committee) -> Result<u64, SignatureError> {
        self.verify_committee(committee)?;
        Ok(self
            .signers_bitmap
            .iter()
            .map(|index| committee.members[index].weight)
            .sum())
    }

    /// Check if the given address is a signer of this certificate. O(1) operation.
    pub fn is_signer(
        &self,
        address: &Address,
        committee: &Committee,
    ) -> Result<bool, SignatureError> {
        self.verify_committee(committee)?;
        let index = committee
            .address_to_index
            .get(address)
            .ok_or_else(|| SignatureError::from_source(format!("unknown address {address}")))?;
        Ok(self.signers_bitmap.contains(*index))
    }
}

#[derive(Debug, Clone)]
pub struct SignedMessage<T> {
    signature: CommitteeSignature,
    pub(crate) message: T,
}

impl<T> SignedMessage<T> {
    pub fn epoch(&self) -> u64 {
        self.signature.epoch()
    }

    pub fn message(&self) -> &T {
        &self.message
    }

    pub fn signature_bytes(&self) -> &[u8] {
        self.signature.signature_bytes()
    }

    pub fn signers_bitmap_bytes(&self) -> &[u8] {
        self.signature.signers_bitmap_bytes()
    }

    /// The committee members included in this signature.
    pub fn signers(&self, committee: &Committee) -> Result<Vec<Address>, SignatureError> {
        self.signature.signers(committee)
    }

    /// The total weight of the signers of this signature.
    pub fn weight(&self, committee: &Committee) -> Result<u64, SignatureError> {
        self.signature.weight(committee)
    }

    /// Check if the given address is a signer of this certificate. O(1) operation.
    pub fn is_signer(
        &self,
        address: &Address,
        committee: &Committee,
    ) -> Result<bool, SignatureError> {
        self.signature.is_signer(address, committee)
    }

    /// Get a reference to the committee signature.
    pub(crate) fn committee_signature(&self) -> &CommitteeSignature {
        &self.signature
    }
}

impl<T: Serialize> SignedMessage<T> {
    pub fn try_from_parts(
        epoch: u64,
        message: T,
        signature_bytes: &[u8],
        signers_bitmap_bytes: &[u8],
        committee: &Committee,
        threshold: u64,
    ) -> Result<Self, SignatureError> {
        let signature = BLS12381AggregateSignature::from_bytes(signature_bytes)
            .map_err(SignatureError::from_source)?;
        let signers_bitmap = BitMap::from_bytes(signers_bitmap_bytes);
        let committee_signature = CommitteeSignature {
            epoch,
            signature,
            signers_bitmap,
        };
        let signed_message = SignedMessage {
            signature: committee_signature,
            message,
        };
        committee.verify_signature_and_weight(&signed_message, threshold)?;
        Ok(signed_message)
    }
}

#[derive(Debug)]
pub struct BlsSignatureAggregator<'a, T> {
    committee: &'a Committee,
    aggregate_signature: Option<BLS12381AggregateSignature>,
    bitmap: BitMap,
    signed_weight: u64,
    message: T,
}

impl<'a, T: Serialize + Clone> BlsSignatureAggregator<'a, T> {
    pub fn new(committee: &'a Committee, message: T) -> Self {
        Self {
            bitmap: BitMap::new(),
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

        self.signed_weight += self.committee.members[*index].weight;
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
    pub fn finish(&self) -> Result<SignedMessage<T>, SignatureError> {
        match &self.aggregate_signature {
            None => Err(SignatureError::from_source(
                "signature map must have at least one entry",
            )),
            Some(signature) => {
                let signed_message = SignedMessage {
                    signature: CommitteeSignature {
                        epoch: self.committee.epoch,
                        signature: signature.clone(),
                        signers_bitmap: self.bitmap.clone(),
                    },
                    message: self.message.clone(),
                };

                // Double check that the aggregated sig still verifies
                self.committee.verify_signature(&signed_message)?;

                Ok(signed_message)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BitMap {
    bitmap: Vec<u8>,
}

impl BitMap {
    fn new() -> Self {
        Self { bitmap: Vec::new() }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bitmap
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bitmap: bytes.to_vec(),
        }
    }

    /// Set the given index in the bitmap and return the previous value.
    fn insert(&mut self, b: usize) -> Result<bool, SignatureError> {
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

    /// Check if the given index is set in the bitmap. Returns false if index is out of bounds.
    fn contains(&self, b: usize) -> bool {
        let byte_index = b / 8;
        let bit_index = b % 8;
        let bit_mask = 1 << (7 - bit_index);
        byte_index < self.bitmap.len() && (self.bitmap[byte_index] & bit_mask != 0)
    }
}

fn signing_message<T: Serialize>(epoch: u64, message: &T) -> Vec<u8> {
    bcs::to_bytes(&(epoch, message)).unwrap()
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

        let mut rng = rand::thread_rng();
        let encryption_public_keys: Vec<EncryptionPublicKey> = private_keys
            .iter()
            .enumerate()
            .map(|_| EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(&mut rng)))
            .collect();

        let members = private_keys
            .iter()
            .enumerate()
            .map(|(i, key)| CommitteeMember {
                address: addresses[i],
                public_key: key.public_key(),
                encryption_public_key: encryption_public_keys[i].clone(),
                weight: 1,
            })
            .collect();
        let committee = Committee::new(members, epoch);

        let mut aggregator = BlsSignatureAggregator::new(&committee, message.clone());

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
        aggregator.committee.verify_signature(&signature).unwrap();

        committee
            .verify_signature_and_weight(&signature, 3)
            .unwrap();
        committee
            .verify_signature_and_weight(&signature, 4)
            .unwrap_err();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(private_keys[3].sign(epoch, addresses[3], &message))
            .unwrap();

        let signature = aggregator.finish().unwrap();
        aggregator.committee.verify_signature(&signature).unwrap();
        assert_eq!(aggregator.finish().unwrap().weight(&committee).unwrap(), 4);
    }

    #[proptest]
    fn test_is_signer(private_keys: [Bls12381PrivateKey; 4], message: Vec<u8>) {
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

        let mut rng = rand::thread_rng();
        let encryption_public_keys: Vec<EncryptionPublicKey> = private_keys
            .iter()
            .enumerate()
            .map(|_| EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(&mut rng)))
            .collect();

        let members = private_keys
            .iter()
            .enumerate()
            .map(|(i, key)| CommitteeMember {
                address: addresses[i],
                public_key: key.public_key(),
                encryption_public_key: encryption_public_keys[i].clone(),
                weight: 1,
            })
            .collect();
        let committee = Committee::new(members, epoch);

        let mut aggregator = BlsSignatureAggregator::new(&committee, message.clone());

        // Add signatures from validators 0, 1, and 2 (but not 3)
        aggregator
            .add_signature(private_keys[0].sign(epoch, addresses[0], &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[1].sign(epoch, addresses[1], &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign(epoch, addresses[2], &message))
            .unwrap();

        let certificate = aggregator.finish().unwrap();

        // Test is_signer returns true for signers
        assert!(certificate.is_signer(&addresses[0], &committee).unwrap());
        assert!(certificate.is_signer(&addresses[1], &committee).unwrap());
        assert!(certificate.is_signer(&addresses[2], &committee).unwrap());

        // Test is_signer returns false for non-signer
        assert!(!certificate.is_signer(&addresses[3], &committee).unwrap());

        // Test is_signer returns error for unknown address
        let unknown_address = Address::new([99; 32]);
        assert!(certificate.is_signer(&unknown_address, &committee).is_err());

        // Test is_signer returns error for wrong committee (different epoch)
        let wrong_committee = Committee::new(
            private_keys
                .iter()
                .enumerate()
                .map(|(i, key)| CommitteeMember {
                    address: addresses[i],
                    public_key: key.public_key(),
                    encryption_public_key: encryption_public_keys[i].clone(),
                    weight: 1,
                })
                .collect(),
            999, // Different epoch
        );
        assert!(
            certificate
                .is_signer(&addresses[0], &wrong_committee)
                .is_err()
        );
    }

    #[proptest]
    fn test_from_parts(private_keys: [Bls12381PrivateKey; 4], message: Vec<u8>) {
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
        let threshold = 3u64;

        let addresses = private_keys
            .iter()
            .enumerate()
            .map(|(i, _)| Address::new([i as u8; 32]))
            .collect::<Vec<_>>();

        let mut rng = rand::thread_rng();
        let encryption_public_keys: Vec<EncryptionPublicKey> = private_keys
            .iter()
            .enumerate()
            .map(|_| EncryptionPublicKey::from_private_key(&EncryptionPrivateKey::new(&mut rng)))
            .collect();

        let members = private_keys
            .iter()
            .enumerate()
            .map(|(i, key)| CommitteeMember {
                address: addresses[i],
                public_key: key.public_key(),
                encryption_public_key: encryption_public_keys[i].clone(),
                weight: 1,
            })
            .collect();
        let committee = Committee::new(members, epoch);

        // Create a certificate via aggregator
        let mut aggregator = BlsSignatureAggregator::new(&committee, message.clone());
        aggregator
            .add_signature(private_keys[0].sign(epoch, addresses[0], &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[1].sign(epoch, addresses[1], &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign(epoch, addresses[2], &message))
            .unwrap();

        let original_cert = aggregator.finish().unwrap();

        // Extract parts
        let signature_bytes = original_cert.signature_bytes();
        let bitmap_bytes = original_cert.signers_bitmap_bytes();

        // Reconstruct from parts
        let reconstructed = SignedMessage::try_from_parts(
            epoch,
            message.clone(),
            signature_bytes,
            bitmap_bytes,
            &committee,
            threshold,
        )
        .unwrap();

        // Verify reconstructed certificate matches original
        assert_eq!(reconstructed.epoch(), original_cert.epoch());
        assert_eq!(
            reconstructed.signature_bytes(),
            original_cert.signature_bytes()
        );
        assert_eq!(
            reconstructed.signers_bitmap_bytes(),
            original_cert.signers_bitmap_bytes()
        );
        assert_eq!(reconstructed.weight(&committee).unwrap(), 3);

        // Verify signers match
        assert!(reconstructed.is_signer(&addresses[0], &committee).unwrap());
        assert!(reconstructed.is_signer(&addresses[1], &committee).unwrap());
        assert!(reconstructed.is_signer(&addresses[2], &committee).unwrap());
        assert!(!reconstructed.is_signer(&addresses[3], &committee).unwrap());
    }
}
