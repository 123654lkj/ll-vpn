//! P5-4: 存储清理 — Garbage collection for unreferenced blocks.
//!
//! # Overview
//!
//! [`GarbageCollector`] scans version histories, identifies blocks that are no
//! longer referenced by any version, and provides statistics about storage
//! usage.  It also supports pruning old versions to free up metadata space.
//!
//! # Features
//!
//! - `collect()` — scan all versions, find unreferenced blocks, return their ids
//! - `prune_old_versions()` — keep only the N most recent versions per file
//! - `storage_stats()` — report total blocks, files, versions, and reclaimable space
//!
//! # Reference counting
//!
//! 1. Iterate over every version's block_ids (chunks)
//! 2. Blocks referenced by at least one version → retained
//! 3. Blocks found in none → candidate for deletion (returned by `collect()`)

use crate::storage::chunk::Hash;
use crate::storage::metadata::MetadataStore;
use crate::storage::version::VersionManager;
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Storage usage statistics.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total number of registered files in metadata.
    pub total_files: usize,
    /// Total number of blocks across all registered files.
    pub total_blocks: usize,
    /// Total size in bytes of all registered files.
    pub total_bytes: u64,
    /// Number of files with version history.
    pub versioned_files: usize,
    /// Total version entries across all files.
    pub total_versions: usize,
    /// Number of unique block hashes referenced by all versions.
    pub referenced_blocks: usize,
    /// Number of blocks in metadata store *not* referenced by any version.
    pub unreferenced_blocks: usize,
    /// Estimated reclaimable bytes (size of unreferenced blocks).
    pub reclaimable_bytes: u64,
}

/// Result of a garbage collection run.
#[derive(Debug, Clone, Default)]
pub struct CollectResult {
    /// Number of blocks identified as unreferenced.
    pub unreferenced_count: usize,
    /// Estimated bytes that could be reclaimed.
    pub reclaimable_bytes: u64,
    /// Hash values of unreferenced blocks.
    pub unreferenced_hashes: Vec<Hash>,
}

// ---------------------------------------------------------------------------
// GarbageCollector
// ---------------------------------------------------------------------------

/// Performs storage garbage collection and statistics.
///
/// # Thread safety
///
/// `GarbageCollector` holds no mutable state of its own — all operations are
/// performed on the supplied [`VersionManager`] and [`MetadataStore`].
pub struct GarbageCollector;

impl GarbageCollector {
    /// Create a new `GarbageCollector`.
    pub fn new() -> Self {
        Self
    }

    /// Scan all versions and return blocks that are no longer referenced.
    ///
    /// This collects the set of all unique block hashes referenced by any
    /// version in the version manager, then compares them against all blocks
    /// known to the metadata store.  Blocks in metadata but NOT in any version
    /// are returned as "unreferenced".
    ///
    /// # Note
    ///
    /// In the current implementation, unreferenced blocks are identified but
    /// NOT physically deleted — the caller is responsible for actual removal.
    /// This is a safe read-only operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata store cannot be read.
    pub fn collect(
        &self,
        version_manager: &VersionManager,
        metadata_store: &MetadataStore,
    ) -> Result<CollectResult, String> {
        // 1. Collect all block hashes referenced by all versions
        let referenced = self.collect_referenced_blocks(version_manager);

        // 2. Collect all block hashes known to the metadata store
        let all_blocks = self.collect_all_metadata_blocks(metadata_store);

        // 3. Find unreferenced blocks
        let unreferenced: Vec<Hash> = all_blocks
            .difference(&referenced)
            .copied()
            .collect();

        // 4. Estimate reclaimable space (we use average block size from metadata)
        let avg_block_size = if all_blocks.is_empty() {
            4 * 1024 * 1024 // default 4 MiB
        } else {
            self.estimate_average_block_size(metadata_store)
        };

        let count = unreferenced.len();
        let reclaimable = count as u64 * avg_block_size;

        Ok(CollectResult {
            unreferenced_count: count,
            reclaimable_bytes: reclaimable,
            unreferenced_hashes: unreferenced,
        })
    }

    /// Prune old versions, keeping only the N most recent per file.
    ///
    /// Wraps [`VersionManager::prune_all_versions`] for convenience.
    ///
    /// # Errors
    ///
    /// Returns an error if the version store lock is poisoned.
    pub fn prune_old_versions(
        &self,
        version_manager: &VersionManager,
        keep_count: usize,
    ) -> Result<usize, String> {
        version_manager.prune_all_versions(keep_count)
    }

    /// Compute storage usage statistics.
    ///
    /// Reports total file count, block count, byte usage, version counts, and
    /// the number of unreferenced (reclaimable) blocks.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata store cannot be read.
    pub fn storage_stats(
        &self,
        version_manager: &VersionManager,
        metadata_store: &MetadataStore,
    ) -> Result<StorageStats, String> {
        // Gather metadata stats
        let files = metadata_store.list_files();
        let total_files = files.len();

        let mut total_blocks = 0usize;
        let mut total_bytes = 0u64;

        for fname in &files {
            if let Some(entry) = metadata_store.query(fname) {
                total_blocks += entry.meta.blocks.len();
                total_bytes += entry.meta.file_size;
            }
        }

        // Gather version stats
        let versioned_files = version_manager.list_files().len();
        let total_versions = version_manager.total_versions();

        // Compute referenced vs unreferenced
        let referenced = self.collect_referenced_blocks(version_manager);
        let all_blocks = self.collect_all_metadata_blocks(metadata_store);

        let referenced_blocks = referenced.len();
        let unreferenced_blocks = all_blocks.len().saturating_sub(referenced_blocks);

        let avg_block_size = if all_blocks.is_empty() {
            0
        } else {
            self.estimate_average_block_size(metadata_store)
        };
        let reclaimable_bytes = unreferenced_blocks as u64 * avg_block_size;

        Ok(StorageStats {
            total_files,
            total_blocks,
            total_bytes,
            versioned_files,
            total_versions,
            referenced_blocks,
            unreferenced_blocks,
            reclaimable_bytes,
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Collect all unique block hashes referenced by all versions.
    fn collect_referenced_blocks(&self, version_manager: &VersionManager) -> HashSet<Hash> {
        let mut referenced = HashSet::new();

        for fname in version_manager.list_files() {
            for version in version_manager.list_versions(&fname) {
                for chunk in &version.manifest.chunks {
                    referenced.insert(chunk.hash);
                }
            }
        }

        referenced
    }

    /// Collect all unique block hashes known to the metadata store.
    fn collect_all_metadata_blocks(&self, metadata_store: &MetadataStore) -> HashSet<Hash> {
        let mut blocks = HashSet::new();

        for fname in metadata_store.list_files() {
            if let Some(entry) = metadata_store.query(&fname) {
                for block in &entry.meta.blocks {
                    blocks.insert(block.hash);
                }
            }
        }

        blocks
    }

    /// Estimate average block size across all files in the metadata store.
    fn estimate_average_block_size(&self, metadata_store: &MetadataStore) -> u64 {
        let mut total_size = 0u64;
        let mut total_blocks = 0u64;

        for fname in metadata_store.list_files() {
            if let Some(entry) = metadata_store.query(&fname) {
                let block_count = entry.meta.blocks.len() as u64;
                if block_count > 0 {
                    total_size += entry.meta.file_size;
                    total_blocks += block_count;
                }
            }
        }

        if total_blocks == 0 {
            4 * 1024 * 1024 // default 4 MiB
        } else {
            total_size / total_blocks
        }
    }
}

impl Default for GarbageCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Display implementations
// ---------------------------------------------------------------------------

impl std::fmt::Display for StorageStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Storage Statistics ===")?;
        writeln!(f, "Registered files:    {}", self.total_files)?;
        writeln!(f, "Total blocks:        {}", self.total_blocks)?;
        writeln!(f, "Total size:          {} bytes", self.total_bytes)?;
        writeln!(f, "Versioned files:     {}", self.versioned_files)?;
        writeln!(f, "Total versions:      {}", self.total_versions)?;
        writeln!(f, "Referenced blocks:   {}", self.referenced_blocks)?;
        writeln!(f, "Unreferenced blocks: {}", self.unreferenced_blocks)?;
        writeln!(
            f,
            "Reclaimable space:  {} bytes",
            self.reclaimable_bytes
        )?;
        Ok(())
    }
}

impl std::fmt::Display for CollectResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Garbage Collection Result ===")?;
        writeln!(f, "Unreferenced blocks: {}", self.unreferenced_count)?;
        writeln!(f, "Reclaimable bytes:   {}", self.reclaimable_bytes)?;
        if self.unreferenced_hashes.is_empty() {
            writeln!(f, "Status: Nothing to clean — all blocks are referenced.")?;
        } else {
            writeln!(
                f,
                "Status: {} blocks can be safely removed.",
                self.unreferenced_count
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::chunk::{ChunkMeta, FileManifest};
    use crate::storage::version::VersionManager;

    /// Helper: create a metadata store with some dummy blocks.
    fn make_metadata_store() -> MetadataStore {
        let store = MetadataStore::new_default();

        // Register file "a.txt" with 3 blocks
        let blocks_a = vec![
            make_block_location([0x01u8; 32], 0),
            make_block_location([0x02u8; 32], 1),
            make_block_location([0x03u8; 32], 2),
        ];
        let manifest_a = make_manifest(3000, &[0x01, 0x02, 0x03]);
        store
            .register("a.txt", [0xAAu8; 32], 3000, Some(manifest_a), blocks_a, "local")
            .unwrap();

        // Register file "b.txt" with 2 blocks (shares hash 0x02 with a.txt)
        let blocks_b = vec![
            make_block_location([0x02u8; 32], 0),
            make_block_location([0x04u8; 32], 1),
        ];
        let manifest_b = make_manifest(2000, &[0x02, 0x04]);
        store
            .register("b.txt", [0xBBu8; 32], 2000, Some(manifest_b), blocks_b, "local")
            .unwrap();

        // Register file "c.txt" with 1 block (not referenced by any version)
        let blocks_c = vec![make_block_location([0xFFu8; 32], 0)];
        let manifest_c = make_manifest(1000, &[0xFF]);
        store
            .register("c.txt", [0xCCu8; 32], 1000, Some(manifest_c), blocks_c, "local")
            .unwrap();

        store
    }

    fn make_block_location(hash: Hash, index: u32) -> crate::storage::metadata::BlockLocation {
        crate::storage::metadata::BlockLocation {
            hash,
            index,
            nodes: vec!["local".to_string()],
            last_synced: 1000,
        }
    }

    fn make_manifest(file_size: u64, hashes: &[u8]) -> FileManifest {
        let chunks: Vec<ChunkMeta> = hashes
            .iter()
            .enumerate()
            .map(|(i, &h)| ChunkMeta {
                hash: [h; 32],
                index: i as u32,
                offset: (i as u64) * 1000,
                size: 1000,
            })
            .collect();
        FileManifest {
            file_hash: [0u8; 32],
            file_size,
            chunks,
            chunk_size: 1000,
        }
    }

    fn make_version_manager() -> VersionManager {
        VersionManager::new_default()
    }

    // =====================================================================
    // GarbageCollector tests
    // =====================================================================

    #[test]
    fn test_gc_new() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = make_metadata_store();

        // No versions, all blocks are unreferenced
        let result = gc.collect(&mgr, &meta).unwrap();
        assert_eq!(result.unreferenced_count, 5); // a(3) + b(2) + c(1) = 6
    }

    #[test]
    fn test_collect_with_versions() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = make_metadata_store();

        // Create a version for "a.txt" referencing blocks 0x01, 0x02, 0x03
        let manifest_a = make_manifest(3000, &[0x01, 0x02, 0x03]);
        mgr.create_snapshot("a.txt", manifest_a, "backup").unwrap();

        // After versioning a.txt's blocks (0x01,0x02,0x03), unreferenced:
        // b.txt: 0x02(referenced by a.txt), 0x04(unreferenced)
        // c.txt: 0xFF(unreferenced)
        // So unreferenced = 0x04 + 0xFF = 2 blocks (0x02 is shared)
        let result = gc.collect(&mgr, &meta).unwrap();
        assert_eq!(result.unreferenced_count, 2);
    }

    #[test]
    fn test_collect_all_referenced() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = make_metadata_store();

        // Create versions covering all blocks
        let manifest_a = make_manifest(3000, &[0x01, 0x02, 0x03]);
        mgr.create_snapshot("a.txt", manifest_a, "backup").unwrap();

        let manifest_b = make_manifest(2000, &[0x02, 0x04]);
        mgr.create_snapshot("b.txt", manifest_b, "backup").unwrap();

        let manifest_c = make_manifest(1000, &[0xFF]);
        mgr.create_snapshot("c.txt", manifest_c, "backup").unwrap();

        let result = gc.collect(&mgr, &meta).unwrap();
        assert_eq!(result.unreferenced_count, 0);
    }

    #[test]
    fn test_prune_old_versions() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();

        for i in 0..5 {
            let m = make_manifest(100, &[i]);
            mgr.create_snapshot("f.txt", m, "").unwrap();
        }
        assert_eq!(mgr.total_versions(), 5);

        let pruned = gc.prune_old_versions(&mgr, 2).unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(mgr.total_versions(), 2);
    }

    #[test]
    fn test_prune_old_versions_under_limit() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();

        for i in 0..3 {
            let m = make_manifest(100, &[i]);
            mgr.create_snapshot("f.txt", m, "").unwrap();
        }

        let pruned = gc.prune_old_versions(&mgr, 10).unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(mgr.total_versions(), 3);
    }

    // =====================================================================
    // StorageStats tests
    // =====================================================================

    #[test]
    fn test_storage_stats_empty() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = MetadataStore::new_default();

        let stats = gc.storage_stats(&mgr, &meta).unwrap();
        assert_eq!(stats.total_files, 0);
        assert_eq!(stats.total_blocks, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.versioned_files, 0);
        assert_eq!(stats.total_versions, 0);
        assert_eq!(stats.referenced_blocks, 0);
        assert_eq!(stats.unreferenced_blocks, 0);
        assert_eq!(stats.reclaimable_bytes, 0);
    }

    #[test]
    fn test_storage_stats_with_data() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = make_metadata_store();

        let stats = gc.storage_stats(&mgr, &meta).unwrap();
        assert_eq!(stats.total_files, 3); // a.txt, b.txt, c.txt
        assert_eq!(stats.total_blocks, 6); // 3+2+1
        assert_eq!(stats.total_bytes, 6000); // 3000+2000+1000
        assert_eq!(stats.versioned_files, 0);
        assert_eq!(stats.total_versions, 0);
        assert_eq!(stats.referenced_blocks, 0);
        assert_eq!(stats.unreferenced_blocks, 5);
    }

    #[test]
    fn test_storage_stats_with_versions() {
        let gc = GarbageCollector::new();
        let mgr = make_version_manager();
        let meta = make_metadata_store();

        // Create versions for a.txt (blocks 0x01,0x02,0x03) and b.txt (0x02,0x04)
        mgr.create_snapshot("a.txt", make_manifest(3000, &[0x01, 0x02, 0x03]), "backup")
            .unwrap();
        mgr.create_snapshot("b.txt", make_manifest(2000, &[0x02, 0x04]), "backup")
            .unwrap();

        let stats = gc.storage_stats(&mgr, &meta).unwrap();
        assert_eq!(stats.total_files, 3);
        assert_eq!(stats.total_blocks, 6);
        assert_eq!(stats.total_bytes, 6000);
        assert_eq!(stats.versioned_files, 2);
        assert_eq!(stats.total_versions, 2);
        // Referenced: 0x01,0x02,0x03,0x04 (4 unique)
        assert_eq!(stats.referenced_blocks, 4);
        // Unreferenced: 0xFF (1 block from c.txt, not in any version)
        assert_eq!(stats.unreferenced_blocks, 1);
    }

    // =====================================================================
    // Display tests
    // =====================================================================

    #[test]
    fn test_storage_stats_display() {
        let stats = StorageStats {
            total_files: 3,
            total_blocks: 10,
            total_bytes: 50000,
            versioned_files: 2,
            total_versions: 5,
            referenced_blocks: 8,
            unreferenced_blocks: 2,
            reclaimable_bytes: 8192,
        };
        let s = stats.to_string();
        assert!(s.contains("Storage Statistics"));
        assert!(s.contains("3"));
        assert!(s.contains("50000"));
        assert!(s.contains("8192"));
    }

    #[test]
    fn test_collect_result_display_clean() {
        let result = CollectResult {
            unreferenced_count: 0,
            reclaimable_bytes: 0,
            unreferenced_hashes: vec![],
        };
        let s = result.to_string();
        assert!(s.contains("Nothing to clean"));
    }

    #[test]
    fn test_collect_result_display_has_work() {
        let result = CollectResult {
            unreferenced_count: 5,
            reclaimable_bytes: 20480,
            unreferenced_hashes: vec![[0x01u8; 32]; 5],
        };
        let s = result.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("20480"));
        assert!(s.contains("can be safely removed"));
    }
}
