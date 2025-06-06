use crate::hash::CryptoHash;
use crate::types::{AccountId, EpochId};
use crate::validator_signer::ValidatorSigner;
use borsh::{BorshDeserialize, BorshSerialize};
use near_crypto::{PublicKey, Signature};
use near_schema_checker_lib::ProtocolSchema;
use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

/// Peer id is the public key.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    ProtocolSchema,
)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct PeerId(Arc<PublicKey>);

impl PeerId {
    pub fn new(key: PublicKey) -> Self {
        Self(Arc::new(key))
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.0
    }
}

impl PeerId {
    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        PeerId::new(near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519).public_key())
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Account announcement information
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Eq, Clone, Debug, Hash, ProtocolSchema)]
pub struct AnnounceAccount {
    /// AccountId to be announced.
    pub account_id: AccountId,
    /// PeerId from the owner of the account.
    pub peer_id: PeerId,
    /// This announcement is only valid for this `epoch`.
    pub epoch_id: EpochId,
    /// Signature using AccountId associated secret key.
    pub signature: Signature,
}

impl AnnounceAccount {
    pub fn new(signer: &ValidatorSigner, peer_id: PeerId, epoch_id: EpochId) -> Self {
        let signature = Self::sign(signer, &peer_id, &epoch_id);
        Self { account_id: signer.validator_id().clone(), peer_id: peer_id, epoch_id, signature }
    }

    pub fn hash(&self) -> CryptoHash {
        Self::build_header_hash(&self.account_id, &self.peer_id, &self.epoch_id)
    }

    fn sign(signer: &ValidatorSigner, peer_id: &PeerId, epoch_id: &EpochId) -> Signature {
        let hash = Self::build_header_hash(signer.validator_id(), peer_id, epoch_id);
        signer.sign_bytes(hash.as_ref())
    }

    /// We hash only (account_id, peer_id, epoch_id). There is no need hash the signature
    /// as it's uniquely determined the triple.
    fn build_header_hash(
        account_id: &AccountId,
        peer_id: &PeerId,
        epoch_id: &EpochId,
    ) -> CryptoHash {
        CryptoHash::hash_borsh((account_id, peer_id, epoch_id))
    }
}
