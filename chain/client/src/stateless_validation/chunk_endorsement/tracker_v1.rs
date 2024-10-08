use lru::LruCache;
use near_primitives::stateless_validation::chunk_endorsement::ChunkEndorsementV1;
use near_primitives::stateless_validation::validator_assignment::ChunkEndorsementsState;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use near_chain_primitives::Error;
use near_epoch_manager::EpochManagerAdapter;
use near_primitives::checked_feature;
use near_primitives::sharding::{ChunkHash, ShardChunkHeader};
use near_primitives::types::AccountId;

// This is the number of unique chunks for which we would track the chunk endorsements.
// Ideally, we should not be processing more than num_shards chunks at a time.
const NUM_CHUNKS_IN_CHUNK_ENDORSEMENTS_CACHE: usize = 100;

/// Module to track chunk endorsements received from chunk validators.
pub struct ChunkEndorsementTracker {
    epoch_manager: Arc<dyn EpochManagerAdapter>,
    inner: Mutex<ChunkEndorsementTrackerInner>,
}

struct ChunkEndorsementTrackerInner {
    epoch_manager: Arc<dyn EpochManagerAdapter>,
    /// We store the validated chunk endorsements received from chunk validators
    /// This is keyed on chunk_hash and account_id of validator to avoid duplicates.
    /// Chunk endorsements would later be used as a part of block production.
    chunk_endorsements:
        LruCache<ChunkHash, (ShardChunkHeader, HashMap<AccountId, ChunkEndorsementV1>)>,
    /// We store chunk endorsements to be processed later because we did not have
    /// chunks ready at the time we received that endorsements from validators.
    /// This is keyed on chunk_hash and account_id of validator to avoid duplicates.
    pending_chunk_endorsements: LruCache<ChunkHash, HashMap<AccountId, ChunkEndorsementV1>>,
}

impl ChunkEndorsementTracker {
    pub(crate) fn process_chunk_endorsement(
        &self,
        endorsement: ChunkEndorsementV1,
        chunk_header: Option<ShardChunkHeader>,
    ) -> Result<(), Error> {
        // We need the chunk header in order to process the chunk endorsement.
        // If we don't have the header, then queue it up for when we do have the header.
        // We must use the partial chunk (as opposed to the full chunk) in order to get
        // the chunk header, because we may not be tracking that shard.
        match chunk_header {
            Some(chunk_header) => {
                self.process_chunk_endorsement_with_chunk_header(&chunk_header, endorsement)
            }
            None => self.add_chunk_endorsement_to_pending_cache(endorsement),
        }
    }

    pub fn new(epoch_manager: Arc<dyn EpochManagerAdapter>) -> Self {
        Self {
            epoch_manager: epoch_manager.clone(),
            inner: Mutex::new(ChunkEndorsementTrackerInner {
                epoch_manager,
                chunk_endorsements: LruCache::new(
                    NonZeroUsize::new(NUM_CHUNKS_IN_CHUNK_ENDORSEMENTS_CACHE).unwrap(),
                ),
                // We can use a different cache size if needed, it does not have to be the same as for `chunk_endorsements`.
                pending_chunk_endorsements: LruCache::new(
                    NonZeroUsize::new(NUM_CHUNKS_IN_CHUNK_ENDORSEMENTS_CACHE).unwrap(),
                ),
            }),
        }
    }

    /// Process pending endorsements for the given chunk header.
    /// It removes these endorsements from the `pending_chunk_endorsements` cache.
    pub fn process_pending_endorsements(&self, chunk_header: &ShardChunkHeader) {
        self.inner.lock().unwrap().process_pending_endorsements(chunk_header);
    }

    /// Add the chunk endorsement to a cache of pending chunk endorsements (if not yet there).
    fn add_chunk_endorsement_to_pending_cache(
        &self,
        endorsement: ChunkEndorsementV1,
    ) -> Result<(), Error> {
        self.inner.lock().unwrap().process_chunk_endorsement_impl(endorsement, None, false)
    }

    /// Function to process an incoming chunk endorsement from chunk validators.
    /// We first verify the chunk endorsement and then store it in a cache.
    /// We would later include the endorsements in the block production.
    fn process_chunk_endorsement_with_chunk_header(
        &self,
        chunk_header: &ShardChunkHeader,
        endorsement: ChunkEndorsementV1,
    ) -> Result<(), Error> {
        let _span = tracing::debug_span!(target: "client", "process_chunk_endorsement", chunk_hash=?chunk_header.chunk_hash(), shard_id=chunk_header.shard_id()).entered();
        // Validate the endorsement before locking the mutex to improve performance.
        if !self.epoch_manager.verify_chunk_endorsement(&chunk_header, &endorsement)? {
            tracing::error!(target: "client", ?endorsement, "Invalid chunk endorsement.");
            return Err(Error::InvalidChunkEndorsement);
        }
        self.inner.lock().unwrap().process_chunk_endorsement_impl(
            endorsement,
            Some(chunk_header),
            true,
        )
    }

    /// This function is called by block producer potentially multiple times if there's not enough stake.
    /// For older protocol version, we return an empty array of chunk endorsements.
    pub fn collect_chunk_endorsements(
        &self,
        chunk_header: &ShardChunkHeader,
    ) -> Result<ChunkEndorsementsState, Error> {
        self.inner.lock().unwrap().compute_chunk_endorsements_impl(chunk_header)
    }
}

impl ChunkEndorsementTrackerInner {
    /// Process pending endorsements for the given chunk header.
    /// It removes these endorsements from the `pending_chunk_endorsements` cache.
    pub fn process_pending_endorsements(&mut self, chunk_header: &ShardChunkHeader) {
        let chunk_hash = &chunk_header.chunk_hash();
        let chunk_endorsements = self.pending_chunk_endorsements.pop(chunk_hash);
        let Some(chunk_endorsements) = chunk_endorsements else {
            return;
        };
        tracing::debug!(target: "client", ?chunk_hash, "Processing pending chunk endorsements.");
        for endorsement in chunk_endorsements.values() {
            if let Err(error) =
                self.process_chunk_endorsement_impl(endorsement.clone(), Some(chunk_header), false)
            {
                tracing::debug!(target: "client", ?endorsement, ?error, "Error processing pending chunk endorsement");
            }
        }
    }

    /// If the chunk header is available, we will verify the chunk endorsement and then store it in a cache.
    /// Otherwise, we store the endorsement in a separate cache of endorsements to be processed when the chunk is ready.
    fn process_chunk_endorsement_impl(
        &mut self,
        endorsement: ChunkEndorsementV1,
        chunk_header: Option<&ShardChunkHeader>,
        already_validated: bool,
    ) -> Result<(), Error> {
        let chunk_hash = endorsement.chunk_hash();
        let account_id = &endorsement.account_id;

        let existing_entry = self.chunk_endorsements.peek(chunk_hash);

        // If we have already processed this chunk endorsement, return early.
        if existing_entry.is_some_and(|(_, existing_endorsements)| {
            existing_endorsements.contains_key(account_id)
        }) {
            tracing::debug!(target: "client", ?endorsement, "Already received chunk endorsement.");
            return Ok(());
        }

        // If we are the current block producer, we store the chunk endorsement for each chunk which
        // would later be used during block production to check whether to include the chunk or not.
        // TODO(stateless_validation): It's possible for a malicious validator to send endorsements
        // for 100 unique chunks thus pushing out current valid endorsements from our cache.
        // Maybe add check to ensure we don't accept endorsements from chunks already included in some block?
        // Maybe add check to ensure we don't accept endorsements from chunks that have too old height_created?
        tracing::debug!(target: "client", ?endorsement, "Received and saved chunk endorsement.");

        // The header might be available in the endorsement cache, even if it isn't provided.
        // In such case it should be treated as a non-pending endorsement.
        let header = chunk_header.or_else(|| existing_entry.map(|(header, _)| header));

        if let Some(chunk_header) = header {
            if !already_validated
                && !self.epoch_manager.verify_chunk_endorsement(&chunk_header, &endorsement)?
            {
                tracing::error!(target: "client", ?endorsement, "Invalid chunk endorsement.");
                return Err(Error::InvalidChunkEndorsement);
            }

            if self.chunk_endorsements.peek(chunk_hash).is_none() {
                self.chunk_endorsements
                    .put(chunk_hash.clone(), (chunk_header.clone(), HashMap::new()));
            }
            self.chunk_endorsements
                .get_mut(chunk_hash)
                .unwrap()
                .1
                .insert(account_id.clone(), endorsement);
        } else {
            // Chunk header is not available, store the endorsement in the pending cache.
            self.pending_chunk_endorsements.get_or_insert(chunk_hash.clone(), || HashMap::new());
            self.pending_chunk_endorsements
                .get_mut(chunk_hash)
                .unwrap()
                .insert(account_id.clone(), endorsement);
        }

        Ok(())
    }

    pub fn compute_chunk_endorsements_impl(
        &mut self,
        chunk_header: &ShardChunkHeader,
    ) -> Result<ChunkEndorsementsState, Error> {
        let epoch_id =
            self.epoch_manager.get_epoch_id_from_prev_block(chunk_header.prev_block_hash())?;
        let protocol_version = self.epoch_manager.get_epoch_protocol_version(&epoch_id)?;
        if !checked_feature!("stable", StatelessValidation, protocol_version) {
            // Return an empty array of chunk endorsements for older protocol versions.
            return Ok(ChunkEndorsementsState {
                is_endorsed: true,
                ..ChunkEndorsementsState::default()
            });
        }

        let chunk_validator_assignments = self.epoch_manager.get_chunk_validator_assignments(
            &epoch_id,
            chunk_header.shard_id(),
            chunk_header.height_created(),
        )?;
        // Get the chunk_endorsements for the chunk from our cache.
        // Note that these chunk endorsements are already validated as part of process_chunk_endorsement.
        // We can safely rely on the following details
        //    1. The chunk endorsements are from valid chunk_validator for this chunk.
        //    2. The chunk endorsements signatures are valid.
        let Some((_header, chunk_endorsements)) =
            self.chunk_endorsements.get(&chunk_header.chunk_hash())
        else {
            // Early return if no chunk_endorsements found in our cache.
            return Ok(ChunkEndorsementsState::default());
        };

        let validator_signatures = chunk_endorsements
            .into_iter()
            .map(|(account_id, endorsement)| (account_id, endorsement.signature.clone()))
            .collect();

        Ok(chunk_validator_assignments.compute_endorsement_state(validator_signatures))
    }
}
