use crate::stateless_validation::chunk_validator::send_chunk_endorsement_to_block_producers;
use actix::Actor as ActixActor;
use near_async::actix_wrapper::ActixWrapper;
use near_async::futures::{AsyncComputationSpawner, AsyncComputationSpawnerExt};
use near_async::messaging::{Actor, Handler, Sender};
use near_async::{MultiSend, MultiSenderFrom};
use near_chain::chain::ChunkStateWitnessMessage;
use near_chain::stateless_validation::chunk_validation::{self, MainStateTransitionCache};
use near_chain::types::RuntimeAdapter;
use near_chain::validate::validate_chunk_with_chunk_extra;
use near_chain::{ChainStore, ChainStoreAccess, Error};
use near_chain_configs::MutableValidatorSigner;
use near_epoch_manager::EpochManagerAdapter;
use near_epoch_manager::shard_assignment::shard_id_to_uid;
use near_network::types::{NetworkRequests, PeerManagerMessageRequest};
use near_performance_metrics_macros::perf;
use near_primitives::block::Block;
use near_primitives::stateless_validation::state_witness::{
    ChunkStateWitness, ChunkStateWitnessAck,
};
use near_primitives::validator_signer::ValidatorSigner;
use std::sync::Arc;

pub type ChunkValidationActor = ActixWrapper<ChunkValidationActorInner>;

#[derive(Clone, MultiSend, MultiSenderFrom)]
pub struct ChunkValidationSenderForPartialWitness {
    pub chunk_state_witness: Sender<ChunkStateWitnessMessage>,
}

/// A standalone actor for validating chunk state witnesses.
/// This actor extracts chunk validation logic from the ClientActor to allow
/// for more focused and potentially parallelized chunk validation.
pub struct ChunkValidationActorInner {
    chain_store: ChainStore,
    genesis_block: Arc<Block>,
    epoch_manager: Arc<dyn EpochManagerAdapter>,
    runtime_adapter: Arc<dyn RuntimeAdapter>,
    network_adapter: Sender<PeerManagerMessageRequest>,
    validator_signer: MutableValidatorSigner,
    save_latest_witnesses: bool,
    validation_spawner: Arc<dyn AsyncComputationSpawner>,
    main_state_transition_result_cache: MainStateTransitionCache,
}

impl Actor for ChunkValidationActorInner {}

impl ChunkValidationActorInner {
    pub fn new(
        chain_store: ChainStore,
        genesis_block: Arc<Block>,
        epoch_manager: Arc<dyn EpochManagerAdapter>,
        runtime_adapter: Arc<dyn RuntimeAdapter>,
        network_adapter: Sender<PeerManagerMessageRequest>,
        validator_signer: MutableValidatorSigner,
        save_latest_witnesses: bool,
        validation_spawner: Arc<dyn AsyncComputationSpawner>,
    ) -> Self {
        Self {
            chain_store,
            genesis_block,
            epoch_manager,
            runtime_adapter,
            network_adapter,
            validator_signer,
            save_latest_witnesses,
            validation_spawner,
            main_state_transition_result_cache: MainStateTransitionCache::default(),
        }
    }

    pub fn spawn_actix_actor(self) -> actix::Addr<ChunkValidationActor> {
        let actix_wrapper = ActixWrapper::new(self);
        let arbiter = actix::Arbiter::new().handle();
        ActixActor::start_in_arbiter(&arbiter, |_| actix_wrapper)
    }

    fn send_state_witness_ack(&self, witness: &ChunkStateWitness) -> Result<(), Error> {
        let chunk_producer = self
            .epoch_manager
            .get_chunk_producer_info(&witness.chunk_production_key())?
            .account_id()
            .clone();

        // Skip sending ack to self.
        if let Some(validator_signer) = self.validator_signer.get() {
            if chunk_producer == *validator_signer.validator_id() {
                return Ok(());
            }
        }

        self.network_adapter.send(PeerManagerMessageRequest::NetworkRequests(
            NetworkRequests::ChunkStateWitnessAck(
                chunk_producer,
                ChunkStateWitnessAck::new(witness),
            ),
        ));
        Ok(())
    }

    /// Process chunk state witness - this is extracted from Client::process_chunk_state_witness
    fn process_chunk_state_witness_standalone(
        &mut self,
        witness: ChunkStateWitness,
    ) -> Result<(), Error> {
        let _span = tracing::debug_span!(
            target: "chunk_validation",
            "process_chunk_state_witness_standalone",
            chunk_hash = ?witness.chunk_header().chunk_hash(),
            height = %witness.chunk_header().height_created(),
            shard_id = %witness.chunk_header().shard_id(),
        )
        .entered();

        // Save the witness if configured to do so
        if self.save_latest_witnesses {
            if let Err(err) = self.chain_store.save_latest_chunk_state_witness(&witness) {
                tracing::error!(target: "chunk_validation", ?err, "Failed to save latest witness");
            }
        }

        // Get the previous block
        let prev_block_hash = *witness.chunk_header().prev_block_hash();
        let prev_block = self.chain_store.get_block(&prev_block_hash)?;

        // Validate that block hash matches
        if witness.chunk_header().prev_block_hash() != prev_block.hash() {
            return Err(Error::Other(format!(
                "Previous block hash mismatch: witness={}, block={}",
                witness.chunk_header().prev_block_hash(),
                prev_block.hash()
            )));
        }

        let Some(signer) = self.validator_signer.get() else {
            return Err(Error::Other("No validator signer available".to_string()));
        };

        // Start validating the chunk - this is extracted from ChunkValidator::start_validating_chunk
        self.start_validating_chunk_standalone(witness, &signer, false)
    }

    /// This is extracted from ChunkValidator::start_validating_chunk and made standalone
    fn start_validating_chunk_standalone(
        &self,
        state_witness: ChunkStateWitness,
        signer: &Arc<ValidatorSigner>,
        save_witness_if_invalid: bool,
    ) -> Result<(), Error> {
        let _span = tracing::debug_span!(
            target: "chunk_validation",
            "start_validating_chunk_standalone",
            height = %state_witness.chunk_production_key().height_created,
            shard_id = %state_witness.chunk_production_key().shard_id,
            validator = %signer.validator_id(),
            tag_block_production = true,
            tag_witness_distribution = true,
        )
        .entered();

        let prev_block_hash = *state_witness.chunk_header().prev_block_hash();
        let chunk_production_key = state_witness.chunk_production_key();
        let shard_id = state_witness.chunk_header().shard_id();
        let chunk_header = state_witness.chunk_header().clone();

        let network_sender = self.network_adapter.clone();
        let epoch_manager = self.epoch_manager.clone();
        let runtime_adapter = self.runtime_adapter.clone();
        let chain_store = self.chain_store.clone();
        let genesis_block = self.genesis_block.clone();
        let store = self.chain_store.store();
        let cache = self.main_state_transition_result_cache.clone();
        let signer = signer.clone();

        self.validation_spawner.spawn("stateless_validation", move || {
            let _span = tracing::debug_span!(
                target: "chunk_validation",
                "async_validating_chunk",
                height = %state_witness.chunk_production_key().height_created,
                shard_id = %state_witness.chunk_production_key().shard_id,
                validator = %signer.validator_id(),
                tag_block_production = true,
                tag_witness_distribution = true,
            )
            .entered();

            // Helper macro to avoid verbose error handling
            macro_rules! try_or_return {
                ($expr:expr) => {
                    match $expr {
                        Ok(val) => val,
                        Err(err) => {
                            tracing::error!(target: "chunk_validation", ?err, "Async stateless validation error");
                            return;
                        }
                    }
                };
            }

            // All expensive operations happen here in async task
            let expected_epoch_id = try_or_return!(epoch_manager.get_epoch_id_from_prev_block(&prev_block_hash));

            if expected_epoch_id != chunk_production_key.epoch_id {
                tracing::error!(
                    target: "chunk_validation",
                    "Invalid EpochId {:?} for previous block {}, expected {:?}",
                    chunk_production_key.epoch_id, prev_block_hash, expected_epoch_id
                );
                return;
            }

            let shard_uid = try_or_return!(shard_id_to_uid(epoch_manager.as_ref(), shard_id, &expected_epoch_id));
            let prev_block = try_or_return!(chain_store.get_block(&prev_block_hash));
            let last_header = try_or_return!(epoch_manager.get_prev_chunk_header(&prev_block, shard_id));
            let chunk_producer_name = try_or_return!(epoch_manager.get_chunk_producer_info(&chunk_production_key)).take_account_id();

            // First check if we can validate using existing chunk extra (fast path)
            if let Ok(prev_chunk_extra) = chain_store.get_chunk_extra(&prev_block_hash, &shard_uid) {
                match validate_chunk_with_chunk_extra(
                    &chain_store,
                    epoch_manager.as_ref(),
                    &prev_block_hash,
                    &prev_chunk_extra,
                    last_header.height_included(),
                    &chunk_header,
                ) {
                    Ok(()) => {
                        send_chunk_endorsement_to_block_producers(
                            &chunk_header,
                            epoch_manager.as_ref(),
                            signer.as_ref(),
                            &network_sender,
                        );
                        return;
                    }
                    Err(err) => {
                        tracing::error!(
                            target: "chunk_validation",
                            ?err,
                            ?chunk_producer_name,
                            ?chunk_production_key,
                            "Failed to validate chunk using existing chunk extra",
                        );
                        near_chain::stateless_validation::metrics::CHUNK_WITNESS_VALIDATION_FAILED_TOTAL
                            .with_label_values(&[&shard_id.to_string(), err.prometheus_label_value()])
                            .inc();
                        return;
                    }
                }
            }

            // If chunk extra validation failed or wasn't available, do full witness validation
            let pre_validation_result = match chunk_validation::pre_validate_chunk_state_witness(
                &state_witness,
                &chain_store,
                genesis_block,
                epoch_manager.as_ref(),
            ) {
                Ok(result) => result,
                Err(err) => {
                    near_chain::stateless_validation::metrics::CHUNK_WITNESS_VALIDATION_FAILED_TOTAL
                        .with_label_values(&[&shard_id.to_string(), err.prometheus_label_value()])
                        .inc();
                    tracing::error!(
                        target: "chunk_validation",
                        ?err,
                        ?chunk_producer_name,
                        ?chunk_production_key,
                        "Failed to pre-validate chunk state witness"
                    );
                    return;
                }
            };

            match chunk_validation::validate_chunk_state_witness(
                state_witness,
                pre_validation_result,
                epoch_manager.as_ref(),
                runtime_adapter.as_ref(),
                &cache,
                store,
                save_witness_if_invalid,
            ) {
                Ok(()) => {
                    send_chunk_endorsement_to_block_producers(
                        &chunk_header,
                        epoch_manager.as_ref(),
                        signer.as_ref(),
                        &network_sender,
                    );
                }
                Err(err) => {
                    near_chain::stateless_validation::metrics::CHUNK_WITNESS_VALIDATION_FAILED_TOTAL
                        .with_label_values(&[&shard_id.to_string(), err.prometheus_label_value()])
                        .inc();
                    tracing::error!(
                        target: "chunk_validation",
                        ?err,
                        ?chunk_producer_name,
                        ?chunk_production_key,
                        "Failed to validate chunk"
                    );
                }
            }
        });
        Ok(())
    }
}

impl Handler<ChunkStateWitnessMessage> for ChunkValidationActorInner {
    #[perf]
    fn handle(&mut self, msg: ChunkStateWitnessMessage) {
        let ChunkStateWitnessMessage { witness, raw_witness_size: _ } = msg;

        let _span = tracing::debug_span!(
            target: "chunk_validation",
            "handle_chunk_state_witness",
            chunk_hash = ?witness.chunk_header().chunk_hash(),
            height = %witness.chunk_header().height_created(),
            shard_id = %witness.chunk_header().shard_id(),
            tag_witness_distribution = true,
        )
        .entered();

        // Check if we're a validator
        if self.validator_signer.get().is_none() {
            tracing::warn!(
                target: "chunk_validation",
                "Received chunk state witness but this is not a validator node"
            );
            return;
        }

        // Send acknowledgement back to the chunk producer
        if let Err(err) = self.send_state_witness_ack(&witness) {
            tracing::error!(target: "chunk_validation", ?err, "Failed to send state witness ack");
            return;
        }

        // Process the witness
        match self.process_chunk_state_witness_standalone(witness) {
            Ok(()) => {
                tracing::debug!(target: "chunk_validation", "Chunk witness validation started successfully");
            }
            Err(Error::DBNotFoundErr(_)) => {
                // Previous block isn't available at the moment
                // TODO: Handle orphan state witness properly
                tracing::debug!(
                    target: "chunk_validation",
                    "Previous block not found - witness may be orphaned"
                );
            }
            Err(err) => {
                tracing::error!(target: "chunk_validation", ?err, "Failed to start chunk witness validation");
            }
        }
    }
}
