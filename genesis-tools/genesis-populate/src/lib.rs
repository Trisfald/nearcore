//! Tools for creating a genesis block.

pub mod state_dump;

use crate::state_dump::StateDump;
use indicatif::{ProgressBar, ProgressStyle};
use near_chain::genesis::get_genesis_congestion_infos;
use near_chain::types::RuntimeAdapter;
use near_chain::{Block, ChainStore};
use near_chain_configs::Genesis;
use near_crypto::InMemorySigner;
use near_epoch_manager::{EpochManager, EpochManagerAdapter, EpochManagerHandle};
use near_primitives::account::{AccessKey, Account, AccountContract};
use near_primitives::bandwidth_scheduler::BandwidthRequests;
use near_primitives::block::Tip;
use near_primitives::congestion_info::CongestionInfo;
use near_primitives::epoch_block_info::BlockInfo;
use near_primitives::genesis::{genesis_block, genesis_chunks};
use near_primitives::hash::{CryptoHash, hash};
use near_primitives::shard_layout::ShardUId;
use near_primitives::state_record::StateRecord;
use near_primitives::types::chunk_extra::ChunkExtra;
use near_primitives::types::{AccountId, Balance, EpochId, ShardId, StateChangeCause, StateRoot};
use near_primitives::utils::to_timestamp;
use near_store::adapter::StoreUpdateAdapter;
use near_store::genesis::{compute_storage_usage, initialize_genesis_state};
use near_store::trie::update::TrieUpdateResult;
use near_store::{
    Store, TrieUpdate, get_account, get_genesis_state_roots, set_access_key, set_account,
};
use near_time::Utc;
use near_vm_runner::ContractCode;
use nearcore::{NearConfig, NightshadeRuntime, NightshadeRuntimeExt};
pub use node_runtime::bootstrap_congestion_info;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Deterministically construct an account ID by index.
///
/// This is used by the estimator to fill a DB with many accounts for which the
/// name can be constructed again during estimations.
///
/// The ids are constructed to form a somewhat interesting shape in the trie. It
/// starts with a hash that will be different for each account, followed by a
/// string that is sufficiently long. The hash is supposed to produces a bunch
/// of branches, whereas the string after that will produce an extension.
///
/// If anyone has a reason to change the format, there is no strong reason to
/// keep it exactly as it is. But keeping the length of the accounts the same
/// would be desired to avoid breaking tests and estimations.
///
/// Note that existing estimator DBs need to be reconstructed when the format
/// changes. Daily estimations are not affected by this.
pub fn get_account_id(account_index: u64) -> AccountId {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    account_index.hash(&mut hasher);
    let hash = hasher.finish();
    // Some estimations rely on the account ID length being constant.
    // Pad booth numbers to length 20, the longest decimal representation of an u64.
    AccountId::try_from(format!("{hash:020}_near_{account_index:020}")).unwrap()
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct GenesisBuilder {
    home_dir: PathBuf,
    // We hold this temporary directory to avoid deletion through deallocation.
    #[allow(dead_code)]
    tmpdir: tempfile::TempDir,
    genesis: Arc<Genesis>,
    store: Store,
    epoch_manager: Arc<EpochManagerHandle>,
    runtime: Arc<NightshadeRuntime>,
    unflushed_records: HashMap<ShardId, Vec<StateRecord>>,
    roots: HashMap<ShardId, StateRoot>,
    state_updates: HashMap<ShardId, TrieUpdate>,

    // Things that can be set.
    additional_accounts_num: u64,
    additional_accounts_code: Option<Vec<u8>>,
    additional_accounts_code_hash: CryptoHash,

    print_progress: bool,
}

impl GenesisBuilder {
    pub fn from_config_and_store(home_dir: &Path, config: NearConfig, store: Store) -> Self {
        let tmpdir = tempfile::Builder::new().prefix("storage").tempdir().unwrap();
        initialize_genesis_state(store.clone(), &config.genesis, Some(tmpdir.path()));
        let epoch_manager =
            EpochManager::new_arc_handle(store.clone(), &config.genesis.config, None);
        let runtime = NightshadeRuntime::from_config(
            tmpdir.path(),
            store.clone(),
            &config,
            epoch_manager.clone(),
        )
        .expect("could not create the transaction runtime");
        Self {
            home_dir: home_dir.to_path_buf(),
            tmpdir,
            genesis: Arc::new(config.genesis),
            store,
            epoch_manager,
            runtime,
            unflushed_records: Default::default(),
            roots: Default::default(),
            state_updates: Default::default(),
            additional_accounts_num: 0,
            additional_accounts_code: None,
            additional_accounts_code_hash: CryptoHash::default(),
            print_progress: false,
        }
    }

    pub fn print_progress(mut self) -> Self {
        self.print_progress = true;
        self
    }

    pub fn add_additional_accounts(mut self, num: u64) -> Self {
        self.additional_accounts_num = num;
        self
    }

    pub fn add_additional_accounts_contract(mut self, contract_code: Vec<u8>) -> Self {
        self.additional_accounts_code_hash = hash(&contract_code);
        self.additional_accounts_code = Some(contract_code);
        self
    }

    pub fn build(mut self) -> Result<Self> {
        // First, apply whatever is defined by the genesis config.
        let roots = get_genesis_state_roots(self.runtime.store())?
            .expect("genesis state roots not initialized.");
        let shard_layout = &self.genesis.config.shard_layout;
        let genesis_shard_version = shard_layout.version();
        self.roots = roots
            .into_iter()
            .enumerate()
            .map(|(shard_index, state_root)| {
                (shard_layout.get_shard_id(shard_index).unwrap(), state_root)
            })
            .collect();
        self.state_updates = self
            .roots
            .iter()
            .map(|(&shard_id, root)| {
                (
                    shard_id,
                    self.runtime
                        .get_tries()
                        .new_trie_update(ShardUId::new(genesis_shard_version, shard_id), *root),
                )
            })
            .collect();
        self.unflushed_records =
            self.roots.keys().cloned().map(|shard_idx| (shard_idx, vec![])).collect();

        let shard_ids: Vec<_> = self.genesis.config.shard_layout.shard_ids().collect();
        let total_accounts_num = self.additional_accounts_num * shard_ids.len() as u64;
        let bar = ProgressBar::new(total_accounts_num as _);
        bar.set_style(ProgressStyle::default_bar().template(
            "[elapsed {elapsed_precise} remaining {eta_precise}] Writing into storage {bar} {pos:>7}/{len:7}",
        ).unwrap());
        // Add records in chunks of 3000 per shard for memory efficiency reasons.
        for i in 0..total_accounts_num {
            let account_id = get_account_id(i);
            self.add_additional_account(account_id)?;
            bar.inc(1);
        }

        for shard_id in shard_ids {
            self.flush_shard_records(shard_id)?;
        }
        bar.finish();
        self.write_genesis_block()?;
        Ok(self)
    }

    pub fn dump_state(self) -> Result<Self> {
        let state_dump =
            StateDump { store: self.store.clone(), roots: self.roots.values().cloned().collect() };
        state_dump.save_to_dir(self.home_dir.clone())?;
        Ok(self)
    }

    fn flush_shard_records(&mut self, shard_id: ShardId) -> Result<()> {
        let records = self.unflushed_records.insert(shard_id, vec![]).unwrap_or_default();
        if records.is_empty() {
            return Ok(());
        }
        let mut state_update =
            self.state_updates.remove(&shard_id).expect("State updates are always available");
        let protocol_config = self.runtime.get_protocol_config(&EpochId::default())?;
        let storage_usage_config = protocol_config.runtime_config.fees.storage_usage_config.clone();

        // Compute storage usage and update accounts.
        for (account_id, storage_usage) in compute_storage_usage(&records, &storage_usage_config) {
            let mut account =
                get_account(&state_update, &account_id)?.expect("We should've created account");
            account.set_storage_usage(storage_usage);
            set_account(&mut state_update, account_id, &account);
        }
        let tries = self.runtime.get_tries();
        state_update.commit(StateChangeCause::InitialState);
        let TrieUpdateResult { trie_changes, state_changes, .. } = state_update.finalize()?;
        let genesis_shard_version = self.genesis.config.shard_layout.version();
        let shard_uid = ShardUId::new(genesis_shard_version, shard_id);
        let mut store_update = tries.store_update();
        let root = tries.apply_all(&trie_changes, shard_uid, &mut store_update);
        near_store::flat::FlatStateChanges::from_state_changes(&state_changes)
            .apply_to_flat_state(&mut store_update.flat_store_update(), shard_uid);
        store_update.commit()?;

        self.roots.insert(shard_id, root);
        self.state_updates.insert(shard_id, tries.new_trie_update(shard_uid, root));
        Ok(())
    }

    fn write_genesis_block(&self) -> Result<()> {
        let shard_ids: Vec<_> = self.genesis.config.shard_layout.shard_ids().collect();

        let state_roots = self.roots.values().cloned().collect();
        let congestion_infos = get_genesis_congestion_infos(
            self.epoch_manager.as_ref(),
            self.runtime.as_ref(),
            &state_roots,
        )?;

        let genesis_chunks = genesis_chunks(
            state_roots,
            congestion_infos,
            &shard_ids,
            self.genesis.config.gas_limit,
            self.genesis.config.genesis_height,
            self.genesis.config.protocol_version,
        );
        let validator_stakes =
            self.epoch_manager.get_epoch_block_producers_ordered(&EpochId::default())?;
        let genesis = genesis_block(
            self.genesis.config.protocol_version,
            genesis_chunks.into_iter().map(|chunk| chunk.take_header()).collect(),
            Utc::from_unix_timestamp_nanos(to_timestamp(self.genesis.config.genesis_time) as i128)
                .unwrap(),
            self.genesis.config.genesis_height,
            self.genesis.config.min_gas_price,
            self.genesis.config.total_supply,
            &validator_stakes,
        );

        let mut store = ChainStore::new(
            self.store.clone(),
            true,
            self.genesis.config.transaction_validity_period,
        );
        let mut store_update = store.store_update();

        store_update.merge(
            self.epoch_manager
                .add_validator_proposals(
                    BlockInfo::from_header(genesis.header(), 0),
                    *genesis.header().random_value(),
                )
                .unwrap(),
        );
        store_update
            .save_block_header(genesis.header().clone())
            .expect("save genesis block header shouldn't fail");
        let genesis = Arc::new(genesis);
        store_update.save_block(Arc::clone(&genesis));

        for (chunk_header, &state_root) in genesis.chunks().iter().zip(self.roots.values()) {
            let shard_layout = &self.genesis.config.shard_layout;
            let shard_id = chunk_header.shard_id();
            let shard_uid = ShardUId::from_shard_id_and_layout(shard_id, &shard_layout);

            let congestion_info = self.get_congestion_info(&genesis, shard_id, state_root)?;

            let chunk_extra = ChunkExtra::new(
                &state_root,
                CryptoHash::default(),
                vec![],
                0,
                self.genesis.config.gas_limit,
                0,
                Some(congestion_info),
                chunk_header.bandwidth_requests().cloned().unwrap_or_else(BandwidthRequests::empty),
            );
            store_update.save_chunk_extra(genesis.hash(), &shard_uid, chunk_extra.into());
        }

        let head = Tip::from_header(genesis.header());
        store_update.save_head(&head).unwrap();
        store_update.save_final_head(&head).unwrap();
        store_update.commit().unwrap();

        Ok(())
    }

    fn get_congestion_info(
        &self,
        genesis: &Block,
        shard_id: ShardId,
        state_root: CryptoHash,
    ) -> Result<CongestionInfo> {
        let prev_hash = genesis.header().prev_hash();
        let trie = self.runtime.get_trie_for_shard(shard_id, prev_hash, state_root, true)?;
        let protocol_config = self.runtime.get_protocol_config(genesis.header().epoch_id())?;
        let runtime_config = protocol_config.runtime_config;
        let congestion_info = bootstrap_congestion_info(&trie, &runtime_config, shard_id)?;
        Ok(congestion_info)
    }

    fn add_additional_account(&mut self, account_id: AccountId) -> Result<()> {
        let testing_init_balance: Balance = 10u128.pow(30);
        let testing_init_stake: Balance = 0;
        let shard_id = self.genesis.config.shard_layout.account_id_to_shard_id(&account_id);
        let mut records = self.unflushed_records.remove(&shard_id).unwrap_or_default();
        let mut state_update =
            self.state_updates.remove(&shard_id).expect("State update should have been added");

        let signer = InMemorySigner::test_signer(&account_id);
        let account = Account::new(
            testing_init_balance,
            testing_init_stake,
            AccountContract::from_local_code_hash(self.additional_accounts_code_hash),
            0,
        );
        set_account(&mut state_update, account_id.clone(), &account);
        let account_record = StateRecord::Account { account_id: account_id.clone(), account };
        records.push(account_record);
        let access_key_record = StateRecord::AccessKey {
            account_id: account_id.clone(),
            public_key: signer.public_key(),
            access_key: AccessKey::full_access(),
        };
        set_access_key(
            &mut state_update,
            account_id.clone(),
            signer.public_key(),
            &AccessKey::full_access(),
        );
        records.push(access_key_record);
        if let Some(wasm_binary) = self.additional_accounts_code.as_ref() {
            let code = ContractCode::new(wasm_binary.clone(), None);
            state_update.set_code(account_id.clone(), &code);
            let contract_record = StateRecord::Contract { account_id, code: wasm_binary.clone() };
            records.push(contract_record);
        }

        // Add records in chunks of 3000 per shard for memory efficiency reasons.
        const CHUNK_SIZE: usize = 3000;
        let num_records_to_flush = records.len();
        let needs_flush = num_records_to_flush >= CHUNK_SIZE;
        self.unflushed_records.insert(shard_id, records);
        self.state_updates.insert(shard_id, state_update);

        if needs_flush {
            self.flush_shard_records(shard_id)?;
        }
        Ok(())
    }
}
