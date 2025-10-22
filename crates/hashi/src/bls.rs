use std::collections::BTreeMap;

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

#[derive(Debug)]
pub struct Bls12381Signature(Signature);

impl Bls12381Signature {
    /// The length of a bls12381 min_pk signature in bytes.
    pub const LENGTH: usize = 96;

    pub fn new(bytes: [u8; Self::LENGTH]) -> Result<Self, SignatureError> {
        Signature::sig_validate(&bytes, true)
            .map(Self)
            .map_err(BlstError)
            .map_err(SignatureError::from_source)
    }

    pub fn to_bytes(&self) -> [u8; Self::LENGTH] {
        self.0.to_bytes()
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
    validator_address: Address,
    public_key: Bls12381PublicKey,
    weight: u16,
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
    epoch: u64,
    public_key: Bls12381PublicKey,
    signature: Bls12381Signature,
}

#[derive(Debug)]
pub struct HashiAggregatedSignature {
    epoch: u64,
    signature: Bls12381Signature,
    bitmap: Vec<u8>,
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

#[cfg(test)]
mod test {
    use super::*;
    use test_strategy::proptest;

    #[proptest]
    fn basic_signing(signer: Bls12381PrivateKey, message: Vec<u8>) {
        let signature = signer.sign(&message);
        signer.public_key().verify(&message, &signature).unwrap();
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
}
