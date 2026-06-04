//! P5-2: 增量同步 — Incremental sync for block-level file transfer.
//!
//! # Overview
//!
//! [`IncrementalSync`] manages the upload/download of only the blocks that have
//! changed since the last sync.  It builds on [`BlockDiffEngine`] for change
//! detection and [`VpnRouter`] for transport.
//!
//! # Upload flow
//!
//! 1. Read local file → chunk it → request remote manifest via VPN
//! 2. `BlockDiffEngine` compares local data against the remote manifest
//! 3. Only Added/Modified blocks are transmitted
//! 4. Remote manifest is updated on the target node
//!
//! # Download flow
//!
//! 1. Request remote manifest via VPN
//! 2. Compare against local file (if it exists) via `BlockDiffEngine`
//! 3. Only Missing/Modified blocks are requested from the remote
//! 4. Local file is reassembled from local + downloaded blocks
//!
//! # Sync state
//!
//! A [`SyncStateEntry`] records the last-sync timestamp per file so that
//! unchanged files can skip the diff step entirely.

use crate::storage::chunk::{Chunker, FileManifest, Hash};
use crate::storage::diff::BlockDiffEngine;
use crate::router::Router;
use crate::vpn::vpn_router::VpnRouter;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default chunk size for incremental sync (4 MiB, matching Chunker default).
pub const SYNC_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Default timeout in seconds for remote manifest requests.
pub const MANIFEST_TIMEOUT_SECS: u64 = 30;

/// Default timeout in seconds for remote block requests.
pub const BLOCK_TIMEOUT_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The result of an incremental sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Total blocks in the file.
    pub total_blocks: u32,
    /// Blocks that were actually transferred.
    pub transferred_blocks: u32,
    /// Total bytes transferred.
    pub bytes_transferred: u64,
    /// Whether the file was already in sync (no transfer needed).
    pub already_in_sync: bool,
    /// Elapsed time in seconds.
    pub elapsed_secs: u64,
}

impl SyncResult {
    fn new(
        total_blocks: u32,
        transferred_blocks: u32,
        bytes_transferred: u64,
        already_in_sync: bool,
        elapsed_secs: u64,
    ) -> Self {
        Self {
            total_blocks,
            transferred_blocks,
            bytes_transferred,
            already_in_sync,
            elapsed_secs,
        }
    }
}

impl std::fmt::Display for SyncResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.already_in_sync {
            write!(f, "Already in sync ({} blocks, 0 transferred)", self.total_blocks)
        } else {
            write!(
                f,
                "Transferred {} of {} blocks ({} bytes) in {}s",
                self.transferred_blocks,
                self.total_blocks,
                self.bytes_transferred,
                self.elapsed_secs
            )
        }
    }
}

/// Per-file sync state tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStateEntry {
    /// File name.
    pub file_name: String,
    /// SHA-256 of the last synced file version.
    pub last_synced_hash: Hash,
    /// Unix timestamp of the last successful sync.
    pub last_synced_at: u64,
    /// File size at last sync.
    pub last_size: u64,
}

/// Full sync state store (in-memory, serializable).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncStateStore {
    /// Map of file name → sync state.
    pub entries: HashMap<String, SyncStateEntry>,
}

impl SyncStateStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Get the sync state for a file, if any.
    pub fn get(&self, file_name: &str) -> Option<&SyncStateEntry> {
        self.entries.get(file_name)
    }

    /// Update or insert the sync state for a file.
    pub fn upsert(&mut self, file_name: &str, hash: Hash, size: u64) {
        let now = now_secs();
        self.entries.insert(
            file_name.to_string(),
            SyncStateEntry {
                file_name: file_name.to_string(),
                last_synced_hash: hash,
                last_synced_at: now,
                last_size: size,
            },
        );
    }

    /// Remove the sync state for a file.
    pub fn remove(&mut self, file_name: &str) {
        self.entries.remove(file_name);
    }

    /// Return the number of tracked files.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// List all tracked file names.
    pub fn list_files(&self) -> Vec<String> {
        let mut files: Vec<_> = self.entries.keys().cloned().collect();
        files.sort();
        files
    }
}

// ---------------------------------------------------------------------------
// IncrementalSync
// ---------------------------------------------------------------------------

/// Manages incremental file sync operations.
///
/// # Architecture
///
/// `IncrementalSync` co-ordinates three components:
/// - [`Chunker`] for splitting/reassembling files
/// - [`BlockDiffEngine`] for computing which blocks differ
/// - [`VpnRouter`] for sending/receiving block data over the mesh
///
/// It also maintains a [`SyncStateStore`] to track last-sync timestamps.
pub struct IncrementalSync {
    /// Chunker for splitting files into blocks.
    chunker: Chunker,
    /// Diff engine for block-level comparison.
    diff_engine: BlockDiffEngine,
    /// VPN router for network transport.
    vpn: VpnRouter,
    /// Sync state tracker.
    state: RwLock<SyncStateStore>,
}

impl IncrementalSync {
    /// Create a new `IncrementalSync` with the given VPN router.
    pub fn new(vpn: VpnRouter) -> Self {
        Self {
            chunker: Chunker::new(),
            diff_engine: BlockDiffEngine::default(),
            vpn,
            state: RwLock::new(SyncStateStore::new()),
        }
    }

    /// Create a new `IncrementalSync` with a custom chunk size.
    pub fn with_chunk_size(vpn: VpnRouter, chunk_size: usize) -> Self {
        let cs = std::cmp::max(chunk_size, 4096);
        Self {
            chunker: Chunker::with_chunk_size(cs),
            diff_engine: BlockDiffEngine::new(cs),
            vpn,
            state: RwLock::new(SyncStateStore::new()),
        }
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Incrementally upload a local file to a remote node.
    ///
    /// 1. Read and chunk the local file
    /// 2. Request the remote manifest (if it exists)
    /// 3. Compute the diff vs. remote
    /// 4. Transmit only changed blocks
    /// 5. Update the remote manifest
    /// 6. Update local sync state
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, the remote is unreachable,
    /// or block transmission fails.
    pub fn sync_file(&self, local_path: &str, remote_target: &str) -> Result<SyncResult, String> {
        let start = now_secs();
        let file_name = Path::new(local_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| local_path.to_string());

        // 1. Read and chunk local file
        let data = std::fs::read(local_path)
            .map_err(|e| format!("failed to read '{}': {}", local_path, e))?;
        let (local_manifest, local_chunks) = self.chunker.chunk_data(&data);

        // Quick check: if sync state says we already have this hash, skip
        {
            let state = self.state.read().map_err(|_| "lock poisoned".to_string())?;
            if let Some(entry) = state.get(&file_name) {
                if entry.last_synced_hash == local_manifest.file_hash {
                    return Ok(SyncResult::new(
                        local_manifest.chunks.len() as u32,
                        0,
                        0,
                        true,
                        now_secs().saturating_sub(start),
                    ));
                }
            }
        }

        // 2. Request remote manifest
        let remote_manifest = self.request_remote_manifest(&file_name, remote_target)?;

        // 3. Compute diff
        let diff = self
            .diff_engine
            .diff_files(&remote_manifest, &data)
            .map_err(|e| format!("diff computation failed: {}", e))?;

        // 4. Transmit only changed blocks
        let mut transferred = 0u32;
        let mut bytes_xfer = 0u64;

        for block in &diff.changed_blocks {
            match block.status {
                crate::storage::diff::BlockDiffStatus::Added
                | crate::storage::diff::BlockDiffStatus::Modified => {
                    let idx = block.index as usize;
                    let chunk_data = &local_chunks[idx];
                    self.send_block(remote_target, &file_name, block.index, chunk_data)?;
                    transferred += 1;
                    bytes_xfer += chunk_data.len() as u64;
                }
                _ => {} // Deleted/Unchanged — no transfer needed
            }
        }

        // 5. Update remote manifest
        self.send_manifest(remote_target, &file_name, &local_manifest)?;

        // 6. Update local sync state
        {
            let mut state = self.state.write().map_err(|_| "lock poisoned".to_string())?;
            state.upsert(
                &file_name,
                local_manifest.file_hash,
                local_manifest.file_size,
            );
        }

        let elapsed = now_secs().saturating_sub(start);
        Ok(SyncResult::new(
            local_manifest.chunks.len() as u32,
            transferred,
            bytes_xfer,
            false,
            elapsed,
        ))
    }

    /// Incrementally download a file from a remote node.
    ///
    /// 1. Request the remote manifest
    /// 2. If a local file exists, compute the diff to find missing blocks
    /// 3. Request only missing blocks from the remote
    /// 4. Reassemble and write the local file
    ///
    /// # Errors
    ///
    /// Returns an error if the remote is unreachable, block requests fail,
    /// or the file cannot be written.
    pub fn download_file(
        &self,
        remote_target: &str,
        remote_path: &str,
        local_path: &str,
    ) -> Result<SyncResult, String> {
        let start = now_secs();
        let file_name = Path::new(remote_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| remote_path.to_string());

        // 1. Request remote manifest
        let remote_manifest = self.request_remote_manifest(remote_path, remote_target)?;
        let total_blocks = remote_manifest.chunks.len() as u32;

        // 2. Check local file and compute what's missing
        let (mut local_blocks, need_download) = if Path::new(local_path).exists() {
            let local_data = std::fs::read(local_path)
                .map_err(|e| format!("failed to read local '{}': {}", local_path, e))?;
            let diff = self
                .diff_engine
                .diff_files(&remote_manifest, &local_data)
                .map_err(|e| format!("diff computation failed: {}", e))?;

            // Build a map: index → data for blocks we already have locally
            let chunker = self.chunker.clone();
            let (_, local_chunks) = chunker.chunk_data(&local_data);
            let mut have: HashMap<u32, Vec<u8>> = HashMap::new();
            for (i, chunk) in local_chunks.iter().enumerate() {
                if i < remote_manifest.chunks.len() {
                    // Only keep blocks that match the remote hash (Unchanged)
                    if remote_manifest.chunks[i].hash == compute_hash(chunk)
                    {
                        have.insert(i as u32, chunk.clone());
                    }
                }
            }
            // Determine which remote blocks we still need
            let need: Vec<u32> = (0..total_blocks)
                .filter(|i| !have.contains_key(i))
                .collect();
            (have, need)
        } else {
            (HashMap::new(), (0..total_blocks).collect())
        };

        // 3. Request missing blocks from the remote
        let mut bytes_xfer = 0u64;
        for &idx in &need_download {
            let chunk_data = self.request_block(remote_target, remote_path, idx)?;
            local_blocks.insert(idx, chunk_data.clone());
            bytes_xfer += chunk_data.len() as u64;
        }

        // 4. Reassemble in order
        let mut ordered_chunks: Vec<Vec<u8>> = Vec::with_capacity(total_blocks as usize);
        for i in 0..total_blocks {
            match local_blocks.remove(&i) {
                Some(data) => ordered_chunks.push(data),
                None => {
                    return Err(format!(
                        "missing block {} after download — this should not happen",
                        i
                    ));
                }
            }
        }

        let restored = self
            .chunker
            .reassemble(&remote_manifest, &ordered_chunks)
            .map_err(|e| format!("reassembly failed: {}", e))?;

        std::fs::write(local_path, &restored)
            .map_err(|e| format!("failed to write '{}': {}", local_path, e))?;

        // Update sync state
        {
            let mut state = self.state.write().map_err(|_| "lock poisoned".to_string())?;
            state.upsert(&file_name, remote_manifest.file_hash, remote_manifest.file_size);
        }

        let elapsed = now_secs().saturating_sub(start);
        Ok(SyncResult::new(
            total_blocks,
            need_download.len() as u32,
            bytes_xfer,
            need_download.is_empty(),
            elapsed,
        ))
    }

    /// Check whether a file needs syncing — i.e. the local hash differs from
    /// the last synced hash tracked in [`SyncStateStore`].
    ///
    /// If the file is not tracked, it is considered "needs sync".
    pub fn needs_sync(&self, local_path: &str) -> Result<bool, String> {
        let file_name = Path::new(local_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| local_path.to_string());

        let data = std::fs::read(local_path)
            .map_err(|e| format!("failed to read '{}': {}", local_path, e))?;
        let hash = sha256_from_slice(&data);

        let state = self.state.read().map_err(|_| "lock poisoned".to_string())?;
        match state.get(&file_name) {
            Some(entry) => Ok(entry.last_synced_hash != hash),
            None => Ok(true),
        }
    }

    /// Return a snapshot of the current sync state store.
    pub fn sync_state(&self) -> Result<SyncStateStore, String> {
        self.state.read().map(|g| g.clone()).map_err(|_| "lock poisoned".to_string())
    }

    /// Replace the internal sync state (e.g. after loading from disk).
    pub fn set_sync_state(&self, state: SyncStateStore) -> Result<(), String> {
        let mut w = self.state.write().map_err(|_| "lock poisoned".to_string())?;
        *w = state;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Network helpers
    // -----------------------------------------------------------------------

    /// Request a remote manifest from the target node.
    fn request_remote_manifest(
        &self,
        file_name: &str,
        target: &str,
    ) -> Result<FileManifest, String> {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let tag = format!("incr-manifest-{}", rand::random::<u64>());

        let tx_clone = tx.clone();
        let tag_clone = tag.clone();
        let file_name_owned = file_name.to_string();
        let listener = move |_from: String, data: Vec<u8>| {
            if let Ok(msg) = String::from_utf8(data) {
                if msg.starts_with(&format!("INCR_MANIFEST_RESP:{}:", tag_clone)) {
                    let resp = msg.trim_start_matches(&format!("INCR_MANIFEST_RESP:{}:", tag_clone));
                    let _ = tx_clone.send(resp.to_string());
                } else if msg.starts_with("INCR_MANIFEST_NONE:") {
                    let resp_file = msg.trim_start_matches("INCR_MANIFEST_NONE:");
                    if resp_file == file_name_owned {
                        let _ = tx_clone.send(String::new());
                    }
                }
            }
        };
        self.vpn.register_listener(listener);

        let req = format!("INCR_GET_MANIFEST:{}:{}", tag, file_name);
        self.vpn
            .send(target, req.as_bytes())
            .map_err(|e| format!("failed to request manifest: {}", e))?;

        let resp = rx
            .recv_timeout(std::time::Duration::from_secs(MANIFEST_TIMEOUT_SECS))
            .map_err(|_| format!("timeout waiting for manifest of '{}'", file_name))?;

        if resp.is_empty() {
            // Remote has no version of this file — return an empty manifest
            Ok(FileManifest {
                file_hash: [0u8; 32],
                file_size: 0,
                chunks: Vec::new(),
                chunk_size: self.chunker.chunk_size() as u64,
            })
        } else {
            serde_json::from_str(&resp)
                .map_err(|e| format!("failed to parse manifest: {}", e))
        }
    }

    /// Send a single block to the remote node.
    fn send_block(
        &self,
        target: &str,
        file_name: &str,
        block_index: u32,
        data: &[u8],
    ) -> Result<(), String> {
        let payload = serde_json::json!({
            "file_name": file_name,
            "block_index": block_index,
            "data_hex": hex::encode(data),
        });
        let msg = format!("INCR_BLOCK:{}", payload.to_string());
        self.vpn
            .send(target, msg.as_bytes())
            .map_err(|e| format!("failed to send block {}: {}", block_index, e))
    }

    /// Request a single block from the remote node.
    fn request_block(
        &self,
        target: &str,
        file_name: &str,
        block_index: u32,
    ) -> Result<Vec<u8>, String> {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let tag = format!("incr-block-{}-{}", block_index, rand::random::<u64>());

        let tx_clone = tx.clone();
        let tag_clone = tag.clone();
        let file_name_owned = file_name.to_string();
        let listener = move |_from: String, data: Vec<u8>| {
            if let Ok(msg) = String::from_utf8(data) {
                if msg.starts_with(&format!("INCR_BLOCK_RESP:{}:", tag_clone)) {
                    let resp = msg
                        .trim_start_matches(&format!("INCR_BLOCK_RESP:{}:", tag_clone));
                    let _ = tx_clone.send(resp.to_string());
                }
            }
        };
        self.vpn.register_listener(listener);

        let req = format!("INCR_GET_BLOCK:{}:{}:{}", tag, file_name, block_index);
        self.vpn
            .send(target, req.as_bytes())
            .map_err(|e| format!("failed to request block {}: {}", block_index, e))?;

        let resp = rx
            .recv_timeout(std::time::Duration::from_secs(BLOCK_TIMEOUT_SECS))
            .map_err(|_| format!("timeout waiting for block {} of '{}'", block_index, file_name))?;

        let resp_value: serde_json::Value = serde_json::from_str(&resp)
            .map_err(|e| format!("invalid block response: {}", e))?;

        let data_hex = resp_value["data_hex"]
            .as_str()
            .ok_or_else(|| "missing data_hex in block response".to_string())?;

        hex::decode(data_hex)
            .map_err(|e| format!("invalid hex data in block response: {}", e))
    }

    /// Send the updated manifest to the remote node.
    fn send_manifest(
        &self,
        target: &str,
        file_name: &str,
        manifest: &FileManifest,
    ) -> Result<(), String> {
        let manifest_json = serde_json::to_string(manifest)
            .map_err(|e| format!("failed to serialize manifest: {}", e))?;
        let msg = format!("INCR_MANIFEST:{}:{}", file_name, manifest_json);
        self.vpn
            .send(target, msg.as_bytes())
            .map_err(|e| format!("failed to send manifest: {}", e))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256 of a byte slice.
fn sha256_from_slice(data: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

/// Current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Additional Chunker helper — expose verify_chunk as a hash function
// ---------------------------------------------------------------------------

// We need a way to get the hash of a chunk without the full manifest.
// This is implemented as a thin wrapper.

/// Re-export: compute SHA-256 hash of data (used internally).
/// This mirrors chunk.rs' sha256 function.
pub fn compute_hash(data: &[u8]) -> Hash {
    sha256_from_slice(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate deterministic test data.
    fn test_data(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| (i.wrapping_add(seed as usize) % 251) as u8).collect()
    }

    // =====================================================================
    // SyncStateStore tests
    // =====================================================================

    #[test]
    fn test_sync_state_store_new_is_empty() {
        let store = SyncStateStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_sync_state_store_upsert_and_get() {
        let mut store = SyncStateStore::new();
        let hash = [0xABu8; 32];
        store.upsert("test.txt", hash, 1000);

        assert_eq!(store.len(), 1);
        let entry = store.get("test.txt").unwrap();
        assert_eq!(entry.last_synced_hash, hash);
        assert_eq!(entry.last_size, 1000);
        assert!(entry.last_synced_at > 0);
    }

    #[test]
    fn test_sync_state_store_upsert_overwrites() {
        let mut store = SyncStateStore::new();
        store.upsert("f.txt", [0x01u8; 32], 100);
        store.upsert("f.txt", [0x02u8; 32], 200);

        assert_eq!(store.len(), 1);
        let entry = store.get("f.txt").unwrap();
        assert_eq!(entry.last_synced_hash, [0x02u8; 32]);
        assert_eq!(entry.last_size, 200);
    }

    #[test]
    fn test_sync_state_store_remove() {
        let mut store = SyncStateStore::new();
        store.upsert("r.txt", [0xAAu8; 32], 500);
        assert_eq!(store.len(), 1);
        store.remove("r.txt");
        assert!(store.is_empty());
    }

    #[test]
    fn test_sync_state_store_list_files() {
        let mut store = SyncStateStore::new();
        store.upsert("b.txt", [0x01u8; 32], 10);
        store.upsert("a.txt", [0x02u8; 32], 20);
        let files = store.list_files();
        assert_eq!(files, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn test_sync_state_store_get_nonexistent() {
        let store = SyncStateStore::new();
        assert!(store.get("nope").is_none());
    }

    // =====================================================================
    // SyncResult tests
    // =====================================================================

    #[test]
    fn test_sync_result_display_in_sync() {
        let r = SyncResult::new(10, 0, 0, true, 0);
        let s = r.to_string();
        assert!(s.contains("Already in sync"));
    }

    #[test]
    fn test_sync_result_display_transferred() {
        let r = SyncResult::new(10, 3, 4096, false, 5);
        let s = r.to_string();
        assert!(s.contains("Transferred 3 of 10 blocks"));
        assert!(s.contains("4096 bytes"));
    }

    // =====================================================================
    // IncrementalSync construction
    // =====================================================================

    #[test]
    fn test_incremental_sync_new() {
        // Create a minimal VpnRouter for testing
        use crate::address::MemAddressResolver;
        use crate::vpn::identity::NodeID;
        use crate::vpn::relay::RelayManager;
        use std::sync::Arc;

        let node_id = NodeID::from_bytes(&[0xAAu8; 32]);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 29900);
        let vpn = VpnRouter::new("TestSync", node_id, resolver, None, relay);
        let sync = IncrementalSync::new(vpn);

        let state = sync.sync_state().unwrap();
        assert!(state.is_empty());
    }

    #[test]
    fn test_incremental_sync_with_chunk_size() {
        use crate::address::MemAddressResolver;
        use crate::vpn::identity::NodeID;
        use crate::vpn::relay::RelayManager;
        use std::sync::Arc;

        let node_id = NodeID::from_bytes(&[0xBBu8; 32]);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 29901);
        let vpn = VpnRouter::new("TestSync2", node_id, resolver, None, relay);
        let sync = IncrementalSync::with_chunk_size(vpn, 8192);

        assert_eq!(sync.chunker.chunk_size(), 8192);
    }

    // =====================================================================
    // needs_sync
    // =====================================================================

    #[test]
    fn test_needs_sync_new_file() {
        use crate::address::MemAddressResolver;
        use crate::vpn::identity::NodeID;
        use crate::vpn::relay::RelayManager;
        use std::sync::Arc;

        let dir = std::env::temp_dir().join("ll_vpn_incr_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("new_file.bin");
        std::fs::write(&path, b"hello").unwrap();

        let node_id = NodeID::from_bytes(&[0xCCu8; 32]);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 29902);
        let vpn = VpnRouter::new("TestNeedsSync", node_id, resolver, None, relay);
        let sync = IncrementalSync::new(vpn);

        // New file — needs sync
        assert!(sync.needs_sync(path.to_str().unwrap()).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // =====================================================================
    // compute_hash
    // =====================================================================

    #[test]
    fn test_compute_hash_consistency() {
        let data = b"Hello, incremental sync!";
        let h1 = compute_hash(data);
        let h2 = compute_hash(data);
        assert_eq!(h1, h2);
    }

    // =====================================================================
    // File sync with diff engine (unit-level, no network)
    // =====================================================================

    #[test]
    fn test_local_diff_against_manifest() {
        use crate::storage::chunk::Chunker;

        let chunker = Chunker::with_chunk_size(4096);
        let old_data = test_data(20_000, 0x10);
        let (old_manifest, _) = chunker.chunk_data(&old_data);

        let new_data = test_data(25_000, 0x11);
        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new_data).unwrap();

        // Should detect changes
        assert!(!diff.files_match);
        assert!(!diff.changed_blocks.is_empty());

        // Added blocks from the extra 5 KiB
        let added = diff
            .changed_blocks
            .iter()
            .filter(|b| b.status == crate::storage::diff::BlockDiffStatus::Added)
            .count();
        assert!(added >= 1);
    }

    #[test]
    fn test_identical_data_diff_empty() {
        use crate::storage::chunk::Chunker;

        let chunker = Chunker::with_chunk_size(4096);
        let data = test_data(15_000, 0x20);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &data).unwrap();

        assert!(diff.files_match);
        assert!(diff.changed_blocks.is_empty());
    }

    // =====================================================================
    // Sync state serde round-trip
    // =====================================================================

    #[test]
    fn test_sync_state_store_serde() {
        let mut store = SyncStateStore::new();
        store.upsert("a.txt", [0x01u8; 32], 100);
        store.upsert("b.txt", [0x02u8; 32], 200);

        let json = serde_json::to_string(&store).unwrap();
        let deser: SyncStateStore = serde_json::from_str(&json).unwrap();

        assert_eq!(deser.len(), 2);
        assert!(deser.get("a.txt").is_some());
        assert!(deser.get("b.txt").is_some());
    }
}
