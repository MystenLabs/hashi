use std::collections::BTreeMap;

use base64ct::Base64;
use base64ct::Encoding;
use blst::min_pk::AggregatePublicKey;
use blst::min_pk::AggregateSignature;
use blst::min_pk::PublicKey;
use blst::min_pk::SecretKey;
use blst::min_pk::Signature;
use sui_crypto::SignatureError;
use sui_crypto::Signer;
use sui_crypto::Verifier;
use sui_sdk_types::Address;
use sui_sdk_types::SignatureScheme;

const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

fn serialize_bytes_to_base64<S, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    use serde::Serialize;
    let b64 = Base64::encode_string(bytes);
    b64.serialize(serializer)
}

fn deserialize_base64_to_bytes<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let b64: std::borrow::Cow<'de, str> = serde::Deserialize::deserialize(deserializer)?;
    let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom(format!("invalid length, expected {} bytes", N)))
}

#[derive(Debug)]
#[allow(unused)]
struct BlstError(blst::BLST_ERROR);

impl std::fmt::Display for BlstError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BlstError {}

#[derive(Clone)]
pub struct Bls12381PrivateKey(SecretKey);

impl std::fmt::Debug for Bls12381PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Bls12381PrivateKey")
            .field(&"__elided__")
            .finish()
    }
}

impl serde::Serialize for Bls12381PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use base64ct::Base64;
        use base64ct::Encoding;

        let bytes = self.0.to_bytes();

        let b64 = Base64::encode_string(&bytes);
        b64.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Bls12381PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use base64ct::Base64;
        use base64ct::Encoding;

        let b64: std::borrow::Cow<'de, str> = serde::Deserialize::deserialize(deserializer)?;
        let bytes = Base64::decode_vec(&b64).map_err(serde::de::Error::custom)?;
        Self::new(
            bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid key length"))?,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
impl proptest::arbitrary::Arbitrary for Bls12381PrivateKey {
    type Parameters = ();
    type Strategy = proptest::strategy::BoxedStrategy<Self>;
    fn arbitrary_with(_: Self::Parameters) -> Self::Strategy {
        use proptest::strategy::Strategy;

        proptest::arbitrary::any::<[u8; Self::LENGTH]>()
            .prop_map(|bytes| {
                let secret_key = SecretKey::key_gen(&bytes, &[]).unwrap();
                Self(secret_key)
            })
            .boxed()
    }
}

impl Bls12381PrivateKey {
    /// The length of an bls12381 private key in bytes.
    pub const LENGTH: usize = 32;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        SecretKey::from_bytes(&bytes)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
            .map(Self)
    }

    pub fn scheme(&self) -> SignatureScheme {
        SignatureScheme::Bls12381
    }

    pub fn public_key(&self) -> Bls12381PublicKey {
        let public_key = self.0.sk_to_pk();
        Bls12381PublicKey {
            bytes: public_key.to_bytes(),
            public_key,
        }
    }

    pub fn generate<R>(mut rng: R) -> Self
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let mut buf: [u8; Self::LENGTH] = [0; Self::LENGTH];
        rng.fill_bytes(&mut buf);
        let secret_key = SecretKey::key_gen(&buf, &[]).unwrap();
        Self(secret_key)
    }

    #[cfg(test)]
    fn sign_hashi(&self, epoch: u64, message: &[u8]) -> HashiSignature {
        let signature = self.try_sign(message).unwrap();
        HashiSignature {
            epoch,
            public_key: self.public_key(),
            signature,
        }
    }
}

impl Signer<Bls12381Signature> for Bls12381PrivateKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Bls12381Signature, SignatureError> {
        let signature = self.0.sign(msg, DST_G2, &[]);
        Ok(Bls12381Signature(signature))
    }
}

#[derive(Debug, Clone, Eq)]
pub struct Bls12381PublicKey {
    bytes: [u8; Self::LENGTH],
    public_key: PublicKey,
}

impl Ord for Bls12381PublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.bytes.cmp(&other.bytes)
    }
}

impl PartialOrd for Bls12381PublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Bls12381PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl std::fmt::Display for Bls12381PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use base64ct::Base64;
        use base64ct::Encoding;
        let b64 = Base64::encode_string(&self.bytes);
        f.write_str(&b64)
    }
}

impl serde::Serialize for Bls12381PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serialize_bytes_to_base64(&self.bytes, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Bls12381PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserialize_base64_to_bytes::<D, { Self::LENGTH }>(deserializer)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

impl Bls12381PublicKey {
    /// The length of an bls12381 min_pk public key in bytes.
    pub const LENGTH: usize = 48;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        PublicKey::key_validate(&bytes)
            .map(|public_key| Self { bytes, public_key })
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
    }
}

#[derive(Debug, Clone)]
pub struct Bls12381Signature(pub(crate) Signature);

impl serde::Serialize for Bls12381Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.to_bytes();
        serialize_bytes_to_base64(&bytes, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Bls12381Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = deserialize_base64_to_bytes::<D, { Self::LENGTH }>(deserializer)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

impl Bls12381Signature {
    /// The length of a bls12381 min_pk signature in bytes.
    pub const LENGTH: usize = 96;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        Signature::sig_validate(&bytes, true)
            .map(Self)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
    }
}

impl Verifier<Bls12381Signature> for Bls12381PublicKey {
    fn verify(&self, message: &[u8], signature: &Bls12381Signature) -> Result<(), SignatureError> {
        let err = signature
            .0
            .verify(true, message, DST_G2, &[], &self.public_key, false);
        if err == blst::BLST_ERROR::BLST_SUCCESS {
            Ok(())
        } else {
            Err(SignatureError::from_source(BlstError(err)))
        }
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
}

#[derive(Debug)]
pub struct BlsCommittee {
    members: Vec<BlsCommitteeMember>,
    epoch: u64,
    public_key_to_index: BTreeMap<Bls12381PublicKey, usize>,
    total_weight: u64,
}

#[derive(Debug)]
#[allow(unused)]
pub struct BlsCommitteeMember {
    pub validator_address: Address,
    pub public_key: Bls12381PublicKey,
    pub weight: u16,
}

struct MemberInfo<'a> {
    member: &'a BlsCommitteeMember,
    index: usize,
}

impl BlsCommittee {
    pub fn new(members: Vec<BlsCommitteeMember>, epoch: u64) -> Self {
        let mut public_key_to_index = BTreeMap::new();

        let mut total_weight = 0u64;
        for (idx, member) in members.iter().enumerate() {
            public_key_to_index.insert(member.public_key.clone(), idx);
            total_weight += member.weight as u64;
        }

        Self {
            members,
            epoch,
            public_key_to_index,
            total_weight,
        }
    }

    pub fn members(&self) -> &[BlsCommitteeMember] {
        &self.members
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    fn member(&self, public_key: &Bls12381PublicKey) -> Result<MemberInfo<'_>, SignatureError> {
        self.public_key_to_index
            .get(public_key)
            .ok_or_else(|| {
                SignatureError::from_source(format!(
                    "signature from public_key {public_key} does not belong to this committee",
                ))
            })
            .and_then(|idx| self.member_by_idx(*idx))
    }

    fn member_by_idx(&self, idx: usize) -> Result<MemberInfo<'_>, SignatureError> {
        let member = self.members.get(idx).ok_or_else(|| {
            SignatureError::from_source(format!(
                "index {idx} out of bounds; committee has {} members",
                self.members.len(),
            ))
        })?;

        Ok(MemberInfo { member, index: idx })
    }

    fn threshold(&self, required_weight: &RequiredWeight) -> u64 {
        match required_weight {
            RequiredWeight::Quorum => ((self.total_weight - 1) / 3) * 2 + 1,
            RequiredWeight::OneCorrectNode => ((self.total_weight - 1) / 3) + 1,
            RequiredWeight::OneNode => 1,
        }
    }
}

#[derive(Debug)]
pub struct HashiSignature {
    pub epoch: u64,
    pub public_key: Bls12381PublicKey,
    pub signature: Bls12381Signature,
}

#[derive(Debug)]
pub struct HashiAggregatedSignature {
    pub epoch: u64,
    pub signature: Bls12381Signature,
    pub bitmap: Vec<u8>,
}

impl Verifier<HashiSignature> for BlsCommittee {
    fn verify(&self, message: &[u8], signature: &HashiSignature) -> Result<(), SignatureError> {
        if signature.epoch != self.epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch, self.epoch,
            )));
        }

        let member = self.member(&signature.public_key)?;
        member
            .member
            .public_key
            .verify(message, &signature.signature)
    }
}

impl Verifier<(&HashiAggregatedSignature, RequiredWeight)> for BlsCommittee {
    fn verify(
        &self,
        message: &[u8],
        (signature, required_weight): &(&HashiAggregatedSignature, RequiredWeight),
    ) -> Result<(), SignatureError> {
        if signature.epoch != self.epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch, self.epoch
            )));
        }

        let mut signed_weight = 0u64;
        let mut bitmap = BitMap::new_iter(self.members().len(), &signature.bitmap)?;

        let mut aggregated_public_key = {
            let idx = bitmap.next().ok_or_else(|| {
                SignatureError::from_source("signature bitmap must have at least one entry")
            })?;

            let member = self.member_by_idx(idx)?;

            signed_weight += member.member.weight as u64;
            AggregatePublicKey::from_public_key(&member.member.public_key.public_key)
        };

        for idx in bitmap {
            let member = self.member_by_idx(idx)?;

            signed_weight += member.member.weight as u64;
            aggregated_public_key
                .add_public_key(&member.member.public_key.public_key, false) // Keys are already verified
                .map_err(BlstError)
                .map_err(SignatureError::from_source)?;
        }

        let aggregated_public_key = aggregated_public_key.to_public_key();
        Bls12381PublicKey {
            bytes: aggregated_public_key.to_bytes(),
            public_key: aggregated_public_key,
        }
        .verify(message, &signature.signature)?;

        let required_weight = self.threshold(required_weight);
        if signed_weight >= required_weight {
            Ok(())
        } else {
            Err(SignatureError::from_source(format!(
                "insufficient signing weight {}; required weight threshold is {}",
                signed_weight, required_weight,
            )))
        }
    }
}

#[derive(Debug)]
pub struct HashiSignatureAggregator {
    committee: BlsCommittee,
    signatures: BTreeMap<usize, HashiSignature>,
    signed_weight: u64,
    message: Vec<u8>,
}

impl HashiSignatureAggregator {
    pub fn new(committee: BlsCommittee, message: Vec<u8>) -> Self {
        Self {
            committee,
            signatures: Default::default(),
            signed_weight: 0,
            message,
        }
    }

    pub fn committee(&self) -> &BlsCommittee {
        &self.committee
    }

    pub fn add_signature(&mut self, signature: HashiSignature) -> Result<(), SignatureError> {
        use std::collections::btree_map::Entry;

        if signature.epoch != self.committee().epoch {
            return Err(SignatureError::from_source(format!(
                "signature epoch {} does not match committee epoch {}",
                signature.epoch,
                self.committee().epoch
            )));
        }

        let member = self.committee.member(&signature.public_key)?;

        member
            .member
            .public_key
            .verify(&self.message, &signature.signature)?;

        match self.signatures.entry(member.index) {
            Entry::Vacant(v) => {
                v.insert(signature);
            }
            Entry::Occupied(_) => {
                return Err(SignatureError::from_source(
                    "duplicate signature from same committee member",
                ));
            }
        }

        self.signed_weight += member.member.weight as u64;

        Ok(())
    }

    pub fn finish(
        &self,
        required_weight: RequiredWeight,
    ) -> Result<HashiAggregatedSignature, SignatureError> {
        let threshold = self.committee().threshold(&required_weight);
        if self.signed_weight < threshold {
            return Err(SignatureError::from_source(format!(
                "signature weight of {} is insufficient to reach required weight threshold of {}",
                self.signed_weight, threshold,
            )));
        }

        let mut iter = self.signatures.iter();
        let (member_idx, signature) = iter.next().ok_or_else(|| {
            SignatureError::from_source("signature map must have at least one entry")
        })?;

        let mut bitmap = BitMap::new(self.committee().members().len());
        bitmap.insert(*member_idx);
        let agg_sig = AggregateSignature::from_signature(&signature.signature.0);

        let (agg_sig, bitmap) = iter.fold(
            (agg_sig, bitmap),
            |(mut agg_sig, mut bitmap), (member_idx, signature)| {
                bitmap.insert(*member_idx);
                agg_sig
                    .add_signature(&signature.signature.0, false)
                    .expect("signature was already verified");
                (agg_sig, bitmap)
            },
        );

        let aggregated_signature = HashiAggregatedSignature {
            epoch: self.committee().epoch,
            signature: Bls12381Signature(agg_sig.to_signature()),
            bitmap: bitmap.into_inner(),
        };

        // Double check that the aggregated sig still verifies
        self.committee
            .verify(&self.message, &(&aggregated_signature, required_weight))?;

        Ok(aggregated_signature)
    }
}

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

    fn insert(&mut self, b: usize) {
        if b >= self.committee_size {
            return;
        }

        let byte_index = b / 8;
        let bit_index = b % 8;
        let bit_mask = 1 << (7 - bit_index);

        if byte_index >= self.bitmap.len() {
            self.bitmap.resize(byte_index + 1, 0);
        }

        self.bitmap[byte_index] |= bit_mask;
    }

    fn into_inner(self) -> Vec<u8> {
        self.bitmap
    }

    fn new_iter(
        committee_size: usize,
        bitmap: &[u8],
    ) -> Result<impl Iterator<Item = usize>, SignatureError> {
        let max_bitmap_len_bytes = if committee_size.is_multiple_of(8) {
            committee_size / 8
        } else {
            (committee_size / 8) + 1
        };

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

pub fn sign_message_hash(
    message_hash: &[u8; 32],
    bls_signing_key: &Bls12381PrivateKey,
) -> Bls12381Signature {
    bls_signing_key
        .try_sign(message_hash)
        .expect("BLS signing should not fail")
}

pub fn verify_approval_signature(
    message_hash: &[u8; 32],
    signature: &Bls12381Signature,
    validator_address: &crate::types::ValidatorAddress,
    dkg_config: &crate::dkg::types::DkgConfig,
) -> Result<(), crate::dkg::types::DkgError> {
    let validator_info = dkg_config
        .validators
        .iter()
        .find(|v| v.address == *validator_address)
        .ok_or_else(|| crate::dkg::types::DkgError::InvalidMessage {
            sender: validator_address.clone(),
            reason: "Unknown validator address".to_string(),
        })?;
    validator_info
        .signature_verification_key
        .verify(message_hash, signature)
        .map_err(|e| {
            crate::dkg::types::DkgError::CryptoError(format!(
                "BLS signature verification failed: {}",
                e
            ))
        })
}

pub fn aggregate_approval_signatures(
    approvals: &[(crate::types::ValidatorAddress, Bls12381Signature)],
    dkg_config: &crate::dkg::types::DkgConfig,
    epoch: u64,
    message_hash: &[u8; 32],
) -> Result<(Bls12381Signature, Vec<u8>), crate::dkg::types::DkgError> {
    let members: Vec<BlsCommitteeMember> = dkg_config
        .validators
        .iter()
        .map(|v| BlsCommitteeMember {
            validator_address: Address::ZERO, // Not used in aggregation
            public_key: v.signature_verification_key.clone(),
            weight: v.weight,
        })
        .collect();
    let committee = BlsCommittee::new(members, epoch);
    let mut aggregator = HashiSignatureAggregator::new(committee, message_hash.to_vec());
    for (addr, sig) in approvals {
        let validator = dkg_config
            .validators
            .iter()
            .find(|v| v.address == *addr)
            .ok_or_else(|| crate::dkg::types::DkgError::InvalidMessage {
                sender: addr.clone(),
                reason: "Unknown validator".to_string(),
            })?;
        let hashi_sig = HashiSignature {
            epoch,
            public_key: validator.signature_verification_key.clone(),
            signature: sig.clone(),
        };
        aggregator.add_signature(hashi_sig).map_err(|e| {
            crate::dkg::types::DkgError::CryptoError(format!("Failed to add signature: {}", e))
        })?;
    }
    let aggregated = aggregator.finish(RequiredWeight::Quorum).map_err(|e| {
        crate::dkg::types::DkgError::CryptoError(format!("Failed to aggregate signatures: {}", e))
    })?;
    Ok((aggregated.signature, aggregated.bitmap))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::dkg::types::{DkgConfig, DkgError, ValidatorInfo};
    use crate::types::ValidatorAddress;
    use fastcrypto::groups::ristretto255::RistrettoPoint;
    use fastcrypto_tbls::ecies_v1::{PrivateKey, PublicKey};
    use test_strategy::proptest;

    fn create_test_validator(index: u8, bls_signing_key: Bls12381PrivateKey) -> ValidatorInfo {
        let ecies_private = PrivateKey::<RistrettoPoint>::new(&mut rand::thread_rng());
        let ecies_public = PublicKey::from_private_key(&ecies_private);
        ValidatorInfo {
            address: ValidatorAddress([index; 32]),
            party_id: index as u16,
            weight: 1,
            communication_key: ecies_public,
            signature_verification_key: bls_signing_key.public_key(),
        }
    }

    fn create_validators_with_keys(count: usize) -> (Vec<ValidatorInfo>, Vec<Bls12381PrivateKey>) {
        let mut validators = Vec::new();
        let mut bls_keys = Vec::new();
        for i in 0..count {
            let bls_signing_key = Bls12381PrivateKey::generate(rand::rngs::OsRng);
            let validator = create_test_validator(i as u8, bls_signing_key.clone());
            validators.push(validator);
            bls_keys.push(bls_signing_key);
        }
        (validators, bls_keys)
    }

    fn create_single_validator_config(
        bls_signing_key: Bls12381PrivateKey,
    ) -> (ValidatorAddress, DkgConfig) {
        let validator = create_test_validator(1, bls_signing_key);
        let validator_address = validator.address.clone();
        let dkg_config = DkgConfig::new(1, vec![validator], 1, 0).unwrap();
        (validator_address, dkg_config)
    }

    const TEST_MESSAGE_HASH: [u8; 32] = [42u8; 32];

    #[proptest]
    fn basic_signing(signer: Bls12381PrivateKey, message: Vec<u8>) {
        let signature = signer.sign(&message);
        signer.public_key().verify(&message, &signature).unwrap();
    }

    #[test]
    fn test_sign_message_hash() {
        let bls_signing_key = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        let bls_public_key = bls_signing_key.public_key();
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_signing_key);

        assert!(
            bls_public_key
                .verify(&TEST_MESSAGE_HASH, &signature)
                .is_ok(),
            "Signature should verify successfully"
        );

        // Verify that a different message produces a different signature
        let different_hash: [u8; 32] = [99u8; 32];
        let different_signature = sign_message_hash(&different_hash, &bls_signing_key);

        assert!(
            bls_public_key.verify(&different_hash, &signature).is_err(),
            "Original signature should not verify with different message"
        );
        assert!(
            bls_public_key
                .verify(&different_hash, &different_signature)
                .is_ok(),
            "Different signature should verify with its own message"
        );
    }

    #[test]
    fn test_verify_approval_signature_valid() {
        let bls_signing_key = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        let (validator_address, dkg_config) =
            create_single_validator_config(bls_signing_key.clone());
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_signing_key);

        let result = verify_approval_signature(
            &TEST_MESSAGE_HASH,
            &signature,
            &validator_address,
            &dkg_config,
        );

        assert!(result.is_ok(), "Valid signature should verify successfully");
    }

    #[test]
    fn test_verify_approval_signature_wrong_signer() {
        let bls_signing_key1 = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        let bls_signing_key2 = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        // Create a validator with public key 1
        let (validator_address, dkg_config) = create_single_validator_config(bls_signing_key1);
        // Sign with key 2 (wrong key)
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_signing_key2);

        // Verify should fail
        let result = verify_approval_signature(
            &TEST_MESSAGE_HASH,
            &signature,
            &validator_address,
            &dkg_config,
        );
        assert!(result.is_err(), "Wrong signature should fail verification");

        if let Err(DkgError::CryptoError(msg)) = result {
            assert!(msg.contains("BLS signature verification failed"));
        } else {
            panic!("Expected CryptoError");
        }
    }

    #[test]
    fn test_verify_approval_signature_unknown_validator() {
        let bls_signing_key = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        let (_, dkg_config) = create_single_validator_config(bls_signing_key.clone());
        // Try to verify with unknown validator address
        let unknown_address = ValidatorAddress([99u8; 32]);
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_signing_key);

        // Verify should fail
        let result = verify_approval_signature(
            &TEST_MESSAGE_HASH,
            &signature,
            &unknown_address,
            &dkg_config,
        );
        assert!(
            result.is_err(),
            "Unknown validator should fail verification"
        );

        if let Err(DkgError::InvalidMessage { reason, .. }) = result {
            assert!(reason.contains("Unknown validator address"));
        } else {
            panic!("Expected InvalidMessage error");
        }
    }

    #[test]
    fn test_aggregate_approval_signatures() {
        let (validators, bls_keys) = create_validators_with_keys(4);
        let mut approvals = Vec::new();
        let dkg_config = DkgConfig::new(1, validators.clone(), 2, 1).unwrap();
        for i in 0..3 {
            let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_keys[i]);
            approvals.push((validators[i].address.clone(), signature));
        }

        let result = aggregate_approval_signatures(&approvals, &dkg_config, 1, &TEST_MESSAGE_HASH);
        assert!(
            result.is_ok(),
            "Aggregation should succeed: {:?}",
            result.err()
        );

        let (aggregated_sig, bitmap) = result.unwrap();

        assert!(!bitmap.is_empty(), "Bitmap should not be empty");
        assert_eq!(aggregated_sig.0.to_bytes().len(), Bls12381Signature::LENGTH);
    }

    #[test]
    fn test_aggregate_approval_signatures_insufficient_weight() {
        let (validators, bls_keys) = create_validators_with_keys(4);
        let dkg_config = DkgConfig::new(1, validators.clone(), 2, 1).unwrap();
        // Only have 1 validator sign (insufficient)
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_keys[0]);
        let approvals = vec![(validators[0].address.clone(), signature)];

        let result = aggregate_approval_signatures(&approvals, &dkg_config, 1, &TEST_MESSAGE_HASH);
        assert!(
            result.is_err(),
            "Aggregation should fail with insufficient weight"
        );

        if let Err(DkgError::CryptoError(msg)) = result {
            assert!(
                msg.contains("insufficient") || msg.contains("weight") || msg.contains("threshold"),
                "Expected error about insufficient weight, got: {}",
                msg
            );
        } else {
            panic!(
                "Expected CryptoError about insufficient weight, got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_aggregate_approval_signatures_unknown_validator() {
        let bls_signing_key = Bls12381PrivateKey::generate(rand::rngs::OsRng);
        let (_, dkg_config) = create_single_validator_config(bls_signing_key.clone());
        // Create approval from unknown validator
        let unknown_address = ValidatorAddress([99u8; 32]);
        let signature = sign_message_hash(&TEST_MESSAGE_HASH, &bls_signing_key);
        let approvals = vec![(unknown_address, signature)];

        let result = aggregate_approval_signatures(&approvals, &dkg_config, 1, &TEST_MESSAGE_HASH);
        assert!(
            result.is_err(),
            "Aggregation should fail with unknown validator"
        );

        if let Err(DkgError::InvalidMessage { reason, .. }) = result {
            assert!(reason.contains("Unknown validator"));
        } else {
            panic!("Expected InvalidMessage error");
        }
    }

    #[proptest]
    fn basic_aggregation(private_keys: [Bls12381PrivateKey; 4], message: Vec<u8>) {
        // Skip cases where we have the same keys
        {
            let mut pks: Vec<Bls12381PublicKey> =
                private_keys.iter().map(|key| key.public_key()).collect();
            pks.sort();
            pks.dedup();
            if pks.len() != 4 {
                return Ok(());
            }
        }

        let required_weight = RequiredWeight::Quorum;
        let epoch = 123;
        let members = private_keys
            .iter()
            .map(|key| BlsCommitteeMember {
                validator_address: Address::ZERO,
                public_key: key.public_key(),
                weight: 1,
            })
            .collect();
        let committee = BlsCommittee::new(members, epoch);

        let mut aggregator = HashiSignatureAggregator::new(committee, message.clone());

        // Aggregating with no sigs fails
        aggregator.finish(required_weight).unwrap_err();

        aggregator
            .add_signature(private_keys[0].sign_hashi(epoch, &message))
            .unwrap();

        // Aggregating with a sig from the same committee member more than once fails
        aggregator
            .add_signature(private_keys[0].sign_hashi(epoch, &message))
            .unwrap_err();

        // Aggregating with insufficient weight fails
        aggregator.finish(required_weight).unwrap_err();

        aggregator
            .add_signature(private_keys[1].sign_hashi(epoch, &message))
            .unwrap();
        aggregator
            .add_signature(private_keys[2].sign_hashi(epoch, &message))
            .unwrap();

        // Aggregating with sufficient weight succeeds and verifies
        let signature = aggregator.finish(required_weight).unwrap();
        aggregator
            .committee()
            .verify(&message, &(&signature, required_weight))
            .unwrap();

        // We can add the last sig and still be successful
        aggregator
            .add_signature(private_keys[3].sign_hashi(epoch, &message))
            .unwrap();
        let signature = aggregator.finish(required_weight).unwrap();
        aggregator
            .committee()
            .verify(&message, &(&signature, required_weight))
            .unwrap();
    }

    #[proptest]
    fn roundtrip_public_key_serialization(private_key: Bls12381PrivateKey) {
        let public_key = private_key.public_key();
        let bytes = bcs::to_bytes(&public_key).unwrap();
        let deserialized: Bls12381PublicKey = bcs::from_bytes(&bytes).unwrap();

        assert_eq!(public_key, deserialized);
    }

    #[proptest]
    fn roundtrip_signature_serialization(private_key: Bls12381PrivateKey, message: Vec<u8>) {
        let signature = private_key.try_sign(&message).unwrap();
        let bytes = bcs::to_bytes(&signature).unwrap();
        let deserialized: Bls12381Signature = bcs::from_bytes(&bytes).unwrap();

        private_key
            .public_key()
            .verify(&message, &deserialized)
            .unwrap();
    }
}
