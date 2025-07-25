use super::TrieRefcountSubtraction;
use super::mem::memtries::MemTries;
use super::state_snapshot::{StateSnapshot, StateSnapshotConfig};
use crate::adapter::StoreAdapter;
use crate::adapter::trie_store::{TrieStoreAdapter, TrieStoreUpdateAdapter};
use crate::flat::FlatStorageManager;
use crate::trie::TrieRefcountAddition;
use crate::trie::config::TrieConfig;
use crate::trie::mem::loading::load_trie_from_flat_state_and_delta;
use crate::trie::prefetching_trie_storage::PrefetchingThreadsHandle;
use crate::trie::trie_storage::{TrieCache, TrieCachingStorage};
use crate::{DBCol, PrefetchApi, Store, TrieDBStorage, TrieStorage, metrics};
use crate::{Trie, TrieChanges, TrieUpdate};
use itertools::Itertools;
use near_primitives::errors::StorageError;
use near_primitives::hash::CryptoHash;
use near_primitives::shard_layout::ShardUId;
use near_primitives::trie_key::TrieKey;
use near_primitives::types::{
    BlockHeight, RawStateChange, RawStateChangesWithTrieKey, StateChangeCause, StateRoot,
};
use parking_lot::{Mutex, RwLock};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

struct ShardTriesInner {
    store: TrieStoreAdapter,
    trie_config: TrieConfig,
    memtries: RwLock<HashMap<ShardUId, Arc<RwLock<MemTries>>>>,
    /// Cache reserved for client actor to use
    caches: Mutex<HashMap<ShardUId, TrieCache>>,
    /// Cache for readers.
    view_caches: Mutex<HashMap<ShardUId, TrieCache>>,
    flat_storage_manager: FlatStorageManager,
    /// Prefetcher state, such as IO threads, per shard.
    prefetchers: RwLock<HashMap<ShardUId, (PrefetchApi, PrefetchingThreadsHandle)>>,
    /// Provides access to the snapshot of the DB at the beginning of an epoch.
    // Needs a synchronization primitive because it can be concurrently accessed:
    // * writes by StateSnapshotActor
    // * reads by ViewClientActor
    state_snapshot: Arc<RwLock<Option<StateSnapshot>>>,
    /// Configures how to make state snapshots.
    state_snapshot_config: StateSnapshotConfig,
    /// Details on which shards are split into which shards.
    /// The mapping is from parent_shard_uid to a list of child_shard_uids.
    /// This mapping is only maintained for parent memtries that have split and
    /// converted to hybrid memtries for the children.
    ///
    /// Once the child memtrie is recreated, we can remove it from this mapping.
    ///
    /// In super rare cases it's possible that we see forks close to the resharding boundary.
    /// We would like to apply the same set of trie changes to the child memtrie to keep
    /// a consistent view across forks.
    temp_split_shard_map: RwLock<HashMap<ShardUId, Vec<ShardUId>>>,
}

#[derive(Clone)]
pub struct ShardTries(Arc<ShardTriesInner>);

impl ShardTries {
    pub fn new(
        store: TrieStoreAdapter,
        trie_config: TrieConfig,
        shard_uids: &[ShardUId],
        flat_storage_manager: FlatStorageManager,
        state_snapshot_config: StateSnapshotConfig,
    ) -> Self {
        let caches = Self::create_initial_caches(&trie_config, &shard_uids, false);
        let view_caches = Self::create_initial_caches(&trie_config, &shard_uids, true);
        metrics::HAS_STATE_SNAPSHOT.set(0);
        ShardTries(Arc::new(ShardTriesInner {
            store,
            trie_config,
            memtries: Default::default(),
            caches: Mutex::new(caches),
            view_caches: Mutex::new(view_caches),
            flat_storage_manager,
            prefetchers: Default::default(),
            state_snapshot: Default::default(),
            state_snapshot_config,
            temp_split_shard_map: Default::default(),
        }))
    }

    /// Create caches for all shards according to the trie config.
    fn create_initial_caches(
        config: &TrieConfig,
        shard_uids: &[ShardUId],
        is_view: bool,
    ) -> HashMap<ShardUId, TrieCache> {
        shard_uids
            .iter()
            .map(|&shard_uid| (shard_uid, TrieCache::new(config, shard_uid, is_view)))
            .collect()
    }

    pub fn new_trie_update(&self, shard_uid: ShardUId, state_root: StateRoot) -> TrieUpdate {
        TrieUpdate::new(self.get_trie_for_shard(shard_uid, state_root))
    }

    pub fn new_trie_update_view(&self, shard_uid: ShardUId, state_root: StateRoot) -> TrieUpdate {
        TrieUpdate::new(self.get_view_trie_for_shard(shard_uid, state_root))
    }

    #[tracing::instrument(
        level = "trace",
        target = "store::trie::shard_tries",
        "ShardTries::get_trie_cache_for",
        skip_all,
        fields(is_view)
    )]
    pub(crate) fn get_trie_cache_for(
        &self,
        shard_uid: ShardUId,
        is_view: bool,
    ) -> Option<TrieCache> {
        self.trie_cache_enabled(shard_uid, is_view).then(|| {
            let caches_to_use = if is_view { &self.0.view_caches } else { &self.0.caches };
            let mut caches = caches_to_use.lock();
            caches
                .entry(shard_uid)
                .or_insert_with(|| TrieCache::new(&self.0.trie_config, shard_uid, is_view))
                .clone()
        })
    }

    fn trie_cache_enabled(&self, shard_uid: ShardUId, is_view: bool) -> bool {
        is_view || self.get_memtries(shard_uid).is_none()
    }

    fn get_trie_for_shard_internal(
        &self,
        shard_uid: ShardUId,
        state_root: StateRoot,
        is_view: bool,
        block_hash: Option<CryptoHash>,
    ) -> Trie {
        let storage: Arc<dyn TrieStorage> =
            if let Some(cache) = self.get_trie_cache_for(shard_uid, is_view) {
                Arc::new(self.create_caching_storage(cache, shard_uid, is_view))
            } else {
                Arc::new(TrieDBStorage::new(self.0.store.clone(), shard_uid))
            };
        let flat_storage_chunk_view = block_hash
            .and_then(|block_hash| self.0.flat_storage_manager.chunk_view(shard_uid, block_hash));
        // Do not use memtries for view queries, for two reasons: memtries do not provide historical state,
        // and also this can introduce lock contention on memtries.
        if is_view {
            Trie::new_with_memtries(
                storage,
                None,
                Default::default(),
                state_root,
                flat_storage_chunk_view,
            )
        } else {
            let memtries = self.get_memtries(shard_uid);
            let split_shard_map_guard = self.0.temp_split_shard_map.read();
            let children_shard_uid =
                split_shard_map_guard.get(&shard_uid).cloned().unwrap_or_default();
            let mut children_memtries = HashMap::new();
            for shard_uid in children_shard_uid {
                if let Some(memtrie) = self.get_memtries(shard_uid) {
                    children_memtries.insert(shard_uid, memtrie);
                }
            }
            Trie::new_with_memtries(
                storage,
                memtries,
                children_memtries,
                state_root,
                flat_storage_chunk_view,
            )
        }
    }

    pub fn get_trie_for_shard(&self, shard_uid: ShardUId, state_root: StateRoot) -> Trie {
        self.get_trie_for_shard_internal(shard_uid, state_root, false, None)
    }

    pub fn get_trie_with_block_hash_for_shard(
        &self,
        shard_uid: ShardUId,
        state_root: StateRoot,
        block_hash: &CryptoHash,
        is_view: bool,
    ) -> Trie {
        self.get_trie_for_shard_internal(shard_uid, state_root, is_view, Some(*block_hash))
    }

    pub fn get_view_trie_for_shard(&self, shard_uid: ShardUId, state_root: StateRoot) -> Trie {
        self.get_trie_for_shard_internal(shard_uid, state_root, true, None)
    }

    pub fn store_update(&self) -> TrieStoreUpdateAdapter<'static> {
        self.0.store.store_update()
    }

    pub fn store(&self) -> TrieStoreAdapter {
        self.0.store.clone()
    }

    pub fn get_flat_storage_manager(&self) -> FlatStorageManager {
        self.0.flat_storage_manager.clone()
    }

    pub fn state_snapshot_config(&self) -> &StateSnapshotConfig {
        &self.0.state_snapshot_config
    }

    pub fn state_snapshots_dir(&self) -> Option<&Path> {
        self.state_snapshot_config().state_snapshots_dir()
    }

    pub(crate) fn state_snapshot(&self) -> &Arc<RwLock<Option<StateSnapshot>>> {
        &self.0.state_snapshot
    }

    #[tracing::instrument(
        level = "trace",
        target = "store::trie::shard_tries",
        "ShardTries::update_cache",
        skip_all,
        fields(ops.len = ops.len()),
    )]
    pub fn update_cache(&self, ops: Vec<(&CryptoHash, Option<&[u8]>)>, shard_uid: ShardUId) {
        if let Some(cache) = self.get_trie_cache_for(shard_uid, false) {
            cache.update_cache(ops);
        }
    }

    fn create_caching_storage(
        &self,
        cache: TrieCache,
        shard_uid: ShardUId,
        is_view: bool,
    ) -> TrieCachingStorage {
        // Do not enable prefetching on view caches.
        // 1) Performance of view calls is not crucial.
        // 2) A lot of the prefetcher code assumes there is only one "main-thread" per shard active.
        //    If you want to enable it for view calls, at least make sure they don't share
        //    the `PrefetchApi` instances with the normal calls.
        let prefetch_enabled = !is_view && self.0.trie_config.prefetch_enabled();
        let prefetch_api = prefetch_enabled.then(|| {
            self.0
                .prefetchers
                .write()
                .entry(shard_uid)
                .or_insert_with(|| {
                    PrefetchApi::new(
                        self.0.store.clone(),
                        cache.clone(),
                        shard_uid,
                        &self.0.trie_config,
                    )
                })
                .0
                .clone()
        });
        TrieCachingStorage::new(self.0.store.clone(), cache, shard_uid, is_view, prefetch_api)
    }

    fn apply_deletions_inner(
        &self,
        deletions: &[TrieRefcountSubtraction],
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        let mut ops = Vec::with_capacity(deletions.len());
        for TrieRefcountSubtraction { trie_node_or_value_hash, rc, .. } in deletions {
            store_update.decrement_refcount_by(shard_uid, trie_node_or_value_hash, *rc);
            ops.push((trie_node_or_value_hash, None));
        }

        self.update_cache(ops, shard_uid);
    }

    fn apply_insertions_inner(
        &self,
        insertions: &[TrieRefcountAddition],
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        let mut ops = Vec::with_capacity(insertions.len());
        for TrieRefcountAddition { trie_node_or_value_hash, trie_node_or_value, rc } in insertions {
            store_update.increment_refcount_by(
                shard_uid,
                trie_node_or_value_hash,
                trie_node_or_value,
                *rc,
            );
            ops.push((trie_node_or_value_hash, Some(trie_node_or_value.as_slice())));
        }
        self.update_cache(ops, shard_uid);
    }

    fn apply_all_inner(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        apply_deletions: bool,
        store_update: &mut TrieStoreUpdateAdapter,
    ) -> StateRoot {
        self.apply_insertions_inner(&trie_changes.insertions, shard_uid, store_update);
        if apply_deletions {
            self.apply_deletions_inner(&trie_changes.deletions, shard_uid, store_update);
        }
        trie_changes.new_root
    }

    #[tracing::instrument(
        level = "trace",
        target = "store::trie::shard_tries",
        "ShardTries::apply_insertions",
        fields(num_insertions = trie_changes.insertions().len(), shard_id = %shard_uid.shard_id()),
        skip_all,
    )]
    pub fn apply_insertions(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        // `itoa` is much faster for printing shard_id to a string than trivial alternatives.
        let mut buffer = itoa::Buffer::new();
        let shard_id = buffer.format(shard_uid.shard_id);

        metrics::APPLIED_TRIE_INSERTIONS
            .with_label_values(&[&shard_id])
            .inc_by(trie_changes.insertions.len() as u64);
        self.apply_insertions_inner(&trie_changes.insertions, shard_uid, store_update)
    }

    #[tracing::instrument(
        level = "trace",
        target = "store::trie::shard_tries",
        "ShardTries::apply_deletions",
        fields(num_deletions = trie_changes.deletions().len(), shard_id = %shard_uid.shard_id()),
        skip_all,
    )]
    pub fn apply_deletions(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        // `itoa` is much faster for printing shard_id to a string than trivial alternatives.
        let mut buffer = itoa::Buffer::new();
        let shard_id = buffer.format(shard_uid.shard_id);

        metrics::APPLIED_TRIE_DELETIONS
            .with_label_values(&[&shard_id])
            .inc_by(trie_changes.deletions.len() as u64);
        self.apply_deletions_inner(&trie_changes.deletions, shard_uid, store_update)
    }

    pub fn revert_insertions(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        // `itoa` is much faster for printing shard_id to a string than trivial alternatives.
        let mut buffer = itoa::Buffer::new();
        let shard_id = buffer.format(shard_uid.shard_id);

        metrics::REVERTED_TRIE_INSERTIONS
            .with_label_values(&[&shard_id])
            .inc_by(trie_changes.insertions.len() as u64);
        self.apply_deletions_inner(
            &trie_changes.insertions.iter().map(|insertion| insertion.revert()).collect::<Vec<_>>(),
            shard_uid,
            store_update,
        )
    }

    /// NOTE: This method does not update memtries, thus if memtries could be enabled, also call `apply_memtrie_changes`.
    /// TODO: Consider calling apply_memtrie_changes in this function or adding a new function to call both.
    pub fn apply_all(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        store_update: &mut TrieStoreUpdateAdapter,
    ) -> StateRoot {
        self.apply_all_inner(trie_changes, shard_uid, true, store_update)
    }

    pub fn apply_memtrie_changes(
        &self,
        trie_changes: &TrieChanges,
        shard_uid: ShardUId,
        block_height: BlockHeight,
    ) -> Option<StateRoot> {
        // Apply children memtrie changes in case of forks on parent. Most of the time children_memtrie_changes
        // will be empty. Lookup children_memtrie_changes for more context.
        let split_shard_map_guard = self.0.temp_split_shard_map.read();
        let children_shard_uid = split_shard_map_guard.get(&shard_uid).cloned().unwrap_or_default();
        for (shard_uid, memtrie_changes) in &trie_changes.children_memtrie_changes {
            // Note that we should only be writing the changes to the child memtrie iff the child and parent
            // share the frozen memtrie base.
            // It's possible that while processing the block, the child memtrie was recreated and no longer
            // shares the base with parent, in which case we skip writing the changes.
            if children_shard_uid.contains(&shard_uid) {
                let memtrie = self.get_memtries(*shard_uid).expect("Memtrie must exist");
                memtrie.write().apply_memtrie_changes(block_height, memtrie_changes);
            }
        }

        if let Some(memtries) = self.get_memtries(shard_uid) {
            let changes = trie_changes
                .memtrie_changes
                .as_ref()
                .expect("Memtrie changes must be present if memtrie is loaded");
            Some(memtries.write().apply_memtrie_changes(block_height, changes))
        } else {
            assert!(
                trie_changes.memtrie_changes.is_none(),
                "Memtrie changes must not be present if memtrie is not loaded"
            );
            None
        }
    }

    /// Retains in-memory tries for given shards, i.e. unload tries from memory for shards that are NOT
    /// in the given list. Should be called to unload obsolete tries from memory.
    pub fn retain_memtries(&self, shard_uids: &[ShardUId]) {
        tracing::info!(target: "memtrie", "Current memtries: {:?}. Keeping memtries for shards {:?}...",
            self.0.memtries.read().keys(), shard_uids);
        self.0.memtries.write().retain(|shard_uid, _| shard_uids.contains(shard_uid));
        tracing::info!(target: "memtrie", "Memtries retaining complete for shards {:?}", shard_uids);
    }

    /// Remove trie from memory for given shard.
    pub fn unload_memtrie(&self, shard_uid: &ShardUId) {
        tracing::info!(target: "memtrie", "Unloading trie from memory for shard {:?}...", shard_uid);
        self.0.memtries.write().remove(shard_uid);
        tracing::info!(target: "memtrie", "Memtrie unloading complete for shard {:?}", shard_uid);
    }

    /// Loads in-memory-trie for given shard and state root (if given).
    pub fn load_memtrie(
        &self,
        shard_uid: &ShardUId,
        state_root: Option<StateRoot>,
        parallelize: bool,
    ) -> Result<(), StorageError> {
        tracing::info!(target: "memtrie", "Loading trie to memory for shard {:?}...", shard_uid);
        let memtries = load_trie_from_flat_state_and_delta(
            &self.0.store.store(),
            *shard_uid,
            state_root,
            parallelize,
        )?;
        self.0.memtries.write().insert(*shard_uid, Arc::new(RwLock::new(memtries)));
        tracing::info!(target: "memtrie", "Memtrie loading complete for shard {:?}", shard_uid);
        Ok(())
    }

    /// Loads in-memory trie upon catchup, if it is enabled.
    /// Requires state root because `ChunkExtra` is not available at the time mem-trie is being loaded.
    /// Mem-tries of shards that are pending resharding must be loaded in any case.
    pub fn load_memtrie_on_catchup(
        &self,
        shard_uid: &ShardUId,
        state_root: &StateRoot,
        shard_uids_pending_resharding: &HashSet<ShardUId>,
    ) -> Result<(), StorageError> {
        if !self.0.trie_config.load_memtries_for_tracked_shards
            && !shard_uids_pending_resharding.contains(shard_uid)
        {
            return Ok(());
        }
        // It should not happen that memtrie is already loaded for a shard
        // for which we just did state sync.
        debug_assert!(!self.0.memtries.read().contains_key(shard_uid));
        self.load_memtrie(shard_uid, Some(*state_root), false)
    }

    /// Loads in-memory tries upon startup. The given shard_uids are possible candidates to load,
    /// but which exact shards to load depends on configuration. This may only be called when flat
    /// storage is ready.
    ///
    /// The `shard_uids_pending_resharding` parameter is used to load memtries
    /// for shards that are not configured to be loaded but should be loaded
    /// anyway. This is used when a shard is about to be resharded and we need
    /// to have the memtries loaded for it.
    pub fn load_memtries_for_enabled_shards(
        &self,
        tracked_shards: &[ShardUId],
        shard_uids_pending_resharding: &HashSet<ShardUId>,
        parallelize: bool,
    ) -> Result<(), StorageError> {
        let trie_config = &self.0.trie_config;
        let shard_uids_to_load = tracked_shards
            .iter()
            .filter(|shard_uid| {
                trie_config.load_memtries_for_tracked_shards
                    || trie_config.load_memtries_for_shards.contains(shard_uid)
                    || shard_uids_pending_resharding.contains(shard_uid)
            })
            .collect_vec();

        tracing::debug!(
            target: "memtrie",
            ?tracked_shards,
            load_memtries_for_tracked_shards=?trie_config.load_memtries_for_tracked_shards,
            load_memtries_for_shards=?trie_config.load_memtries_for_shards,
            ?shard_uids_pending_resharding,
            "Loading tries config"
        );
        tracing::info!(target: "memtrie", "Loading tries to memory for shards {:?}...", shard_uids_to_load);
        shard_uids_to_load
            .par_iter()
            .map(|shard_uid| self.load_memtrie(shard_uid, None, parallelize))
            .collect::<Result<(), StorageError>>()?;

        tracing::info!(target: "memtrie", "Memtries loading complete for shards {:?}", shard_uids_to_load);
        Ok(())
    }

    /// Retrieves the in-memory tries for the shard.
    pub fn get_memtries(&self, shard_uid: ShardUId) -> Option<Arc<RwLock<MemTries>>> {
        let guard = self.0.memtries.read();
        guard.get(&shard_uid).cloned()
    }

    /// Garbage collects the in-memory tries for the shard up to (and including) the given
    /// height.
    pub fn delete_memtrie_roots_up_to_height(&self, shard_uid: ShardUId, height: BlockHeight) {
        if let Some(memtries) = self.get_memtries(shard_uid) {
            memtries.write().delete_until_height(height);
        }
    }

    /// Freezes in-memory trie for parent shard and copies reference from it to children shards.
    /// This is needed to serve queries for these shards just after resharding, before proper
    /// memtries are loaded.
    /// Note that this function is idempotent. It's possible for us to call this function multiple
    /// times for the same parent shard in case of fork handling at the resharding boundary.
    pub fn freeze_parent_memtrie(
        &self,
        parent_shard_uid: ShardUId,
        children_shard_uids: Vec<ShardUId>,
    ) -> Result<(), StorageError> {
        let mut split_shard_map_guard = self.0.temp_split_shard_map.write();
        if split_shard_map_guard.contains_key(&parent_shard_uid) {
            // If the parent has already been split, then we don't do anything here.
            return Ok(());
        }

        tracing::info!(
            target: "memtrie",
            ?parent_shard_uid,
            ?children_shard_uids,
            "Freezing parent memtrie, creating children memtries...",
        );
        let mut outer_guard = self.0.memtries.write();
        let Some(memtries) = outer_guard.remove(&parent_shard_uid) else {
            return Err(StorageError::MemTrieLoadingError(format!(
                "On freezing parent memtrie, memtrie not loaded for shard {:?}",
                parent_shard_uid
            )));
        };
        let mut guard = memtries.write();
        let memtries = std::mem::replace(&mut *guard, MemTries::new(parent_shard_uid));
        let frozen_memtries = memtries.freeze();

        // Create hybrid memtrie for both parent and children shards.
        for shard_uid in [vec![parent_shard_uid], children_shard_uids.clone()].concat() {
            outer_guard.insert(
                shard_uid,
                Arc::new(RwLock::new(MemTries::from_frozen_memtries(
                    shard_uid,
                    frozen_memtries.clone(),
                ))),
            );
        }

        // Insert the mapping from parent to children shards.
        split_shard_map_guard.insert(parent_shard_uid, children_shard_uids);

        tracing::info!(target: "memtrie", "Memtries freezing complete");
        Ok(())
    }
}

#[derive(Clone)]
pub struct WrappedTrieChanges {
    tries: ShardTries,
    shard_uid: ShardUId,
    trie_changes: TrieChanges,
    state_changes: Vec<RawStateChangesWithTrieKey>,
    block_height: BlockHeight,
}

// Partial implementation. Skips `tries` due to its complexity and
// `trie_changes` and `state_changes` due to their large volume.
impl std::fmt::Debug for WrappedTrieChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedTrieChanges")
            .field("tries", &"<not shown>")
            .field("shard_uid", &self.shard_uid)
            .field("trie_changes", &"<not shown>")
            .field("state_changes", &"<not shown>")
            .field("block_height", &self.block_height)
            .finish()
    }
}

impl WrappedTrieChanges {
    pub fn new(
        tries: ShardTries,
        shard_uid: ShardUId,
        trie_changes: TrieChanges,
        state_changes: Vec<RawStateChangesWithTrieKey>,
        block_height: BlockHeight,
    ) -> Self {
        WrappedTrieChanges { tries, shard_uid, trie_changes, state_changes, block_height }
    }

    pub fn state_changes(&self) -> &[RawStateChangesWithTrieKey] {
        &self.state_changes
    }

    pub fn apply_mem_changes(&self) {
        self.tries.apply_memtrie_changes(&self.trie_changes, self.shard_uid, self.block_height);
    }

    /// Save insertions of trie nodes into Store.
    pub fn insertions_into(&self, store_update: &mut TrieStoreUpdateAdapter) {
        self.tries.apply_insertions(&self.trie_changes, self.shard_uid, store_update)
    }

    /// Save deletions of trie nodes into Store.
    pub fn deletions_into(&self, store_update: &mut TrieStoreUpdateAdapter) {
        self.tries.apply_deletions(&self.trie_changes, self.shard_uid, store_update)
    }

    /// Save state changes into Store.
    ///
    /// NOTE: the changes are drained from `self`.
    #[tracing::instrument(
        level = "debug",
        target = "store::trie::shard_tries",
        "ShardTries::state_changes_into",
        fields(num_state_changes = self.state_changes.len(), shard_id = %self.shard_uid.shard_id()),
        skip_all,
    )]
    pub fn state_changes_into(
        &mut self,
        block_hash: &CryptoHash,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        for change_with_trie_key in self.state_changes.drain(..) {
            assert!(
                !change_with_trie_key.changes.iter().any(|RawStateChange { cause, .. }| matches!(
                    cause,
                    StateChangeCause::NotWritableToDisk
                )),
                "NotWritableToDisk changes must never be finalized."
            );

            if change_with_trie_key.changes.is_empty() {
                continue;
            }

            let storage_key = match change_with_trie_key.trie_key.get_account_id() {
                // If a TrieKey itself doesn't identify the Shard, then we need to add shard id to the row key.
                None => KeyForStateChanges::delayed_receipt_key_from_trie_key(
                    block_hash,
                    &change_with_trie_key.trie_key,
                    &self.shard_uid,
                ),
                // TrieKey has enough information to identify the shard it comes from.
                _ => KeyForStateChanges::from_trie_key(block_hash, &change_with_trie_key.trie_key),
            };

            store_update.set_state_changes(storage_key, &change_with_trie_key);
        }
    }

    #[tracing::instrument(
        level = "debug",
        target = "store::trie::shard_tries",
        "ShardTries::trie_changes_into",
        skip_all
    )]
    pub fn trie_changes_into(
        &mut self,
        block_hash: &CryptoHash,
        store_update: &mut TrieStoreUpdateAdapter,
    ) {
        store_update.set_trie_changes(self.shard_uid, block_hash, &self.trie_changes)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum KeyForStateChangesError {
    #[error(
        "Row key of StateChange of kind DelayedReceipt or DelayedReceiptIndices doesn't contain ShardUId: row_key: {0:?} ; trie_key: {1:?}"
    )]
    DelayedReceiptRowKeyError(Vec<u8>, TrieKey),
}

#[derive(derive_more::AsRef, derive_more::Into)]
pub struct KeyForStateChanges(Vec<u8>);

impl KeyForStateChanges {
    const PREFIX_LEN: usize = CryptoHash::LENGTH;

    fn new(block_hash: &CryptoHash, reserve_capacity: usize) -> Self {
        let mut key_prefix = Vec::with_capacity(block_hash.as_bytes().len() + reserve_capacity);
        key_prefix.extend(block_hash.as_bytes());
        Self(key_prefix)
    }

    pub fn for_block(block_hash: &CryptoHash) -> Self {
        Self::new(block_hash, 0)
    }

    pub fn from_raw_key(block_hash: &CryptoHash, raw_key: &[u8]) -> Self {
        let mut key = Self::new(block_hash, raw_key.len());
        key.0.extend(raw_key);
        key
    }

    pub fn from_trie_key(block_hash: &CryptoHash, trie_key: &TrieKey) -> Self {
        let mut key = Self::new(block_hash, trie_key.len());
        trie_key.append_into(&mut key.0);
        key
    }

    /// Without changing the existing TrieKey format, encodes ShardUId into the row key.
    /// See `delayed_receipt_key_from_trie_key` for decoding this row key.
    pub fn delayed_receipt_key_from_trie_key(
        block_hash: &CryptoHash,
        trie_key: &TrieKey,
        shard_uid: &ShardUId,
    ) -> Self {
        let mut key = Self::new(block_hash, trie_key.len() + std::mem::size_of::<ShardUId>());
        trie_key.append_into(&mut key.0);
        key.0.extend(shard_uid.to_bytes());
        key
    }

    /// Extracts ShardUId from row key which contains ShardUId encoded.
    /// See `delayed_receipt_key_from_trie_key` for encoding ShardUId into the row key.
    #[allow(clippy::result_large_err)]
    pub fn delayed_receipt_key_decode_shard_uid(
        row_key: &[u8],
        block_hash: &CryptoHash,
        trie_key: &TrieKey,
    ) -> Result<ShardUId, KeyForStateChangesError> {
        let prefix = KeyForStateChanges::from_trie_key(block_hash, trie_key);
        let prefix = prefix.as_ref();

        let suffix = &row_key[prefix.len()..];
        let shard_uid = ShardUId::try_from(suffix).map_err(|_err| {
            KeyForStateChangesError::DelayedReceiptRowKeyError(row_key.to_vec(), trie_key.clone())
        })?;
        Ok(shard_uid)
    }

    /// Iterates over deserialized row values where row key matches `self`.
    pub fn find_iter<'a>(
        &'a self,
        store: &'a Store,
    ) -> impl Iterator<Item = Result<RawStateChangesWithTrieKey, std::io::Error>> + 'a {
        // Split off the irrelevant part of the key, so only the original trie_key is left.
        self.find_rows_iter(store).map(|row| row.map(|kv| kv.1))
    }

    /// Iterates over deserialized row values where the row key matches `self` exactly.
    pub fn find_exact_iter<'a>(
        &'a self,
        store: &'a Store,
    ) -> impl Iterator<Item = std::io::Result<RawStateChangesWithTrieKey>> + 'a {
        let trie_key_len = self.0.len() - Self::PREFIX_LEN;
        self.find_iter(store).filter_map(move |result| match result {
            Ok(changes) if changes.trie_key.len() == trie_key_len => {
                debug_assert_eq!(changes.trie_key.to_vec(), &self.0[Self::PREFIX_LEN..]);
                Some(Ok(changes))
            }
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
    }

    /// Iterates over pairs of `(row key, deserialized row value)` where row key matches `self`.
    pub fn find_rows_iter<'a>(
        &'a self,
        store: &'a Store,
    ) -> impl Iterator<Item = Result<(Box<[u8]>, RawStateChangesWithTrieKey), std::io::Error>> + 'a
    {
        debug_assert!(
            self.0.len() >= Self::PREFIX_LEN,
            "Key length: {}, prefix length: {}, key: {:?}",
            self.0.len(),
            Self::PREFIX_LEN,
            self.0
        );
        store.iter_prefix_ser::<RawStateChangesWithTrieKey>(DBCol::StateChanges, &self.0).map(
            move |change| {
                // Split off the irrelevant part of the key, so only the original trie_key is left.
                let (key, state_changes) = change?;
                debug_assert!(key.starts_with(&self.0), "Key: {:?}, row key: {:?}", self.0, key);
                Ok((key, state_changes))
            },
        )
    }
}

#[cfg(test)]
mod test {
    use crate::adapter::StoreAdapter;
    use crate::{
        TrieConfig, config::TrieCacheConfig, test_utils::create_test_store,
        trie::DEFAULT_SHARD_CACHE_TOTAL_SIZE_LIMIT,
    };

    use super::*;
    use std::{assert_eq, str::FromStr};

    fn create_trie() -> ShardTries {
        let store = create_test_store();
        let trie_cache_config = TrieCacheConfig {
            default_max_bytes: DEFAULT_SHARD_CACHE_TOTAL_SIZE_LIMIT,
            per_shard_max_bytes: Default::default(),
            shard_cache_deletions_queue_capacity: 0,
        };
        let trie_config = TrieConfig {
            shard_cache_config: trie_cache_config.clone(),
            view_shard_cache_config: trie_cache_config,
            ..TrieConfig::default()
        };
        let shard_uids = Vec::from([ShardUId::single_shard()]);
        ShardTries::new(
            store.trie_store(),
            trie_config,
            &shard_uids,
            FlatStorageManager::new(store.flat_store()),
            StateSnapshotConfig::Disabled,
        )
    }

    #[test]
    fn test_delayed_receipt_row_key() {
        let trie_key1 = TrieKey::DelayedReceipt { index: 1 };
        let trie_key2 = TrieKey::DelayedReceiptIndices {};
        let shard_uid = ShardUId { version: 10, shard_id: 5 };

        // Random value.
        let block_hash =
            CryptoHash::from_str("32222222222233333333334444444444445555555777").unwrap();

        for trie_key in [trie_key1.clone(), trie_key2] {
            let row_key = KeyForStateChanges::delayed_receipt_key_from_trie_key(
                &block_hash,
                &trie_key,
                &shard_uid,
            );

            let got_shard_uid = KeyForStateChanges::delayed_receipt_key_decode_shard_uid(
                row_key.as_ref(),
                &block_hash,
                &trie_key,
            )
            .unwrap();
            assert_eq!(shard_uid, got_shard_uid);
        }

        // Forget to add a ShardUId to the key, fail to extra a ShardUId from the key.
        let row_key_without_shard_uid = KeyForStateChanges::from_trie_key(&block_hash, &trie_key1);
        assert!(
            KeyForStateChanges::delayed_receipt_key_decode_shard_uid(
                row_key_without_shard_uid.as_ref(),
                &block_hash,
                &trie_key1
            )
            .is_err()
        );

        // Add an extra byte to the key, fail to extra a ShardUId from the key.
        let mut row_key_extra_bytes = KeyForStateChanges::delayed_receipt_key_from_trie_key(
            &block_hash,
            &trie_key1,
            &shard_uid,
        );
        row_key_extra_bytes.0.extend([8u8]);
        assert!(
            KeyForStateChanges::delayed_receipt_key_decode_shard_uid(
                row_key_extra_bytes.as_ref(),
                &block_hash,
                &trie_key1
            )
            .is_err()
        );

        // This is the internal detail of how delayed_receipt_key_from_trie_key() works.
        let mut row_key_with_single_shard_uid =
            KeyForStateChanges::from_trie_key(&block_hash, &trie_key1);
        row_key_with_single_shard_uid.0.extend(shard_uid.to_bytes());
        assert_eq!(
            KeyForStateChanges::delayed_receipt_key_decode_shard_uid(
                row_key_with_single_shard_uid.as_ref(),
                &block_hash,
                &trie_key1
            )
            .unwrap(),
            shard_uid
        );
    }

    //TODO(jbajic) Simplify logic for creating configuration
    #[test]
    fn test_insert_delete_trie_cache() {
        let shard_uid = ShardUId::single_shard();
        let tries = create_trie();
        let trie_caches = &tries.0.caches;
        // Assert only one cache for one shard exists
        assert_eq!(trie_caches.lock().len(), 1);
        // Assert the shard uid is correct
        assert!(trie_caches.lock().get(&shard_uid).is_some());

        // Read from cache
        let key = CryptoHash::hash_borsh("alice");
        let val: Vec<u8> = Vec::from([0, 1, 2, 3, 4]);

        assert!(trie_caches.lock().get(&shard_uid).unwrap().get(&key).is_none());

        let insert_ops = Vec::from([(&key, Some(val.as_slice()))]);
        tries.update_cache(insert_ops, shard_uid);
        assert_eq!(trie_caches.lock().get(&shard_uid).unwrap().get(&key).unwrap().to_vec(), val);

        let deletions_ops = Vec::from([(&key, None)]);
        tries.update_cache(deletions_ops, shard_uid);
        assert!(trie_caches.lock().get(&shard_uid).unwrap().get(&key).is_none());
    }

    #[test]
    fn test_shard_cache_max_value() {
        let store = create_test_store();
        let trie_cache_config = TrieCacheConfig {
            default_max_bytes: DEFAULT_SHARD_CACHE_TOTAL_SIZE_LIMIT,
            per_shard_max_bytes: Default::default(),
            shard_cache_deletions_queue_capacity: 0,
        };
        let trie_config = TrieConfig {
            shard_cache_config: trie_cache_config.clone(),
            view_shard_cache_config: trie_cache_config,
            ..TrieConfig::default()
        };
        let shard_uids = Vec::from([ShardUId { shard_id: 0, version: 0 }]);
        let shard_uid = *shard_uids.first().unwrap();

        let trie = ShardTries::new(
            store.trie_store(),
            trie_config,
            &shard_uids,
            FlatStorageManager::new(store.flat_store()),
            StateSnapshotConfig::Disabled,
        );

        let trie_caches = &trie.0.caches;

        // Insert into cache value at the configured maximum size
        let key = CryptoHash::hash_borsh("alice");
        let val: Vec<u8> = vec![0; TrieConfig::max_cached_value_size() - 1];
        let insert_ops = Vec::from([(&key, Some(val.as_slice()))]);
        trie.update_cache(insert_ops, shard_uid);
        assert_eq!(trie_caches.lock().get(&shard_uid).unwrap().get(&key).unwrap().to_vec(), val);

        // Try to insert into cache value bigger then the maximum allowed size
        let key = CryptoHash::from_str("32222222222233333333334444444444445555555777").unwrap();
        let val: Vec<u8> = vec![0; TrieConfig::max_cached_value_size()];
        let insert_ops = Vec::from([(&key, Some(val.as_slice()))]);
        trie.update_cache(insert_ops, shard_uid);
        assert!(trie_caches.lock().get(&shard_uid).unwrap().get(&key).is_none());
    }
}
