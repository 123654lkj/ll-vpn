//! P5-1: 块差异检测 — Block-level diff detection for incremental backup.
//!
//! # Overview
//!
//! [`BlockDiffEngine`] compares local file data against a remote [`FileManifest`]
//! to determine which chunks have been added, modified, or deleted.  This is the
//! foundation for incremental sync: only changed blocks need to be transmitted.
//!
//! # Strategy
//!
//! 1. **File-level fast path** — If the overall SHA-256 hash matches, no blocks
//!    have changed; return an empty diff.
//! 2. **Chunk-level comparison** — Walk each chunk from the manifest and compare
//!    its SHA-256 against the corresponding block in the local file.  Chunks that
//!    differ are flagged as `Modified`.
//! 3. **New chunks** — If the local file is larger than the remote version,
//!    trailing blocks are flagged as `Added`.
//! 4. **Deleted chunks** — If the local file is smaller, trailing remote-manifest
//!    blocks are flagged as `Deleted`.
//!
//! # Example
//!
//! ```ignore
//! use ll_vpn::storage::chunk::{Chunker, DEFAULT_CHUNK_SIZE};
//! use ll_vpn::storage::diff::BlockDiffEngine;
//!
//! let engine = BlockDiffEngine::new(DEFAULT_CHUNK_SIZE);
//!
//! let old_data = b"Hello, World!".repeat(100);
//! let new_data = b"Hello, Rust!".repeat(100);
//!
//! let chunker = Chunker::with_chunk_size(DEFAULT_CHUNK_SIZE);
//! let (old_manifest, _) = chunker.chunk_data(&old_data);
//!
//! let diff = engine.diff_files(&old_manifest, &new_data).unwrap();
//! println!("Changed blocks: {}", diff.changed_blocks.len());
//! ```

use crate::storage::chunk::{FileManifest, Hash};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum chunk size for diff comparison (4 KiB).
pub const MIN_DIFF_CHUNK_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Status of a single block in a diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockDiffStatus {
    /// Block exists in both versions and has the same hash (no change).
    Unchanged,
    /// Block exists in both but has a different hash (modified).
    Modified,
    /// Block exists only in the new version (added).
    Added,
    /// Block exists only in the old version (deleted).
    Deleted,
}

/// Describes the difference for one block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDiff {
    /// Zero-based index of the block in the file.
    pub index: u32,
    /// Byte offset of the block in the file.
    pub offset: u64,
    /// Size of the block in bytes (may differ between versions).
    pub size: u64,
    /// Status — what happened to this block.
    pub status: BlockDiffStatus,
    /// SHA-256 hash of the new block data (empty if Deleted).
    pub new_hash: Hash,
    /// SHA-256 hash of the old block data (empty if Added).
    pub old_hash: Hash,
}

/// Full diff report between two file versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    /// Name or path of the file (for display).
    pub file_name: String,
    /// Size of the old (remote) version in bytes.
    pub old_size: u64,
    /// Size of the new (local) version in bytes.
    pub new_size: u64,
    /// Per-block differences.
    pub changed_blocks: Vec<BlockDiff>,
    /// Count of unchanged blocks (for summary display).
    pub unchanged_count: u32,
    /// Overall file-level match.
    pub files_match: bool,
}

/// A human-readable summary of the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReport {
    /// The full diff data.
    pub diff: FileDiff,
    /// Number of blocks to transfer (Added + Modified).
    pub blocks_to_transfer: u32,
    /// Total bytes to transfer.
    pub bytes_to_transfer: u64,
    /// Estimated transfer time in seconds (at 1 MB/s reference speed).
    pub estimated_secs: u64,
}

// ---------------------------------------------------------------------------
// BlockDiffEngine
// ---------------------------------------------------------------------------

/// Engine for computing block-level diffs between local data and a remote
/// [`FileManifest`].
///
/// The engine uses a fixed chunk size (matching the remote manifest) so that
/// block boundaries align.  If the local file is re-chunked with the same
/// chunk size, the comparison is one-to-one.
#[derive(Debug, Clone)]
pub struct BlockDiffEngine {
    /// Chunk size used for comparison (must match the remote manifest).
    chunk_size: usize,
}

impl BlockDiffEngine {
    /// Create a new diff engine with the given chunk size.
    ///
    /// `chunk_size` must be ≥ [`MIN_DIFF_CHUNK_SIZE`] (4 KiB); smaller values
    /// are silently clamped.
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size: std::cmp::max(chunk_size, MIN_DIFF_CHUNK_SIZE),
        }
    }

    /// Create a diff engine with the default chunk size (4 MiB).
    pub fn default() -> Self {
        Self {
            chunk_size: crate::storage::chunk::DEFAULT_CHUNK_SIZE,
        }
    }

    /// Compare local file data against a remote manifest.
    ///
    /// Returns a [`FileDiff`] describing every block that differs, plus summary
    /// stats.  Returns `None` if the local data is empty and the manifest has
    /// no chunks (trivial match).
    ///
    /// # Errors
    ///
    /// Returns an error if the chunk size in the manifest does not match the
    /// engine's configured chunk size (they must align for a valid comparison).
    pub fn diff_files(
        &self,
        remote_manifest: &FileManifest,
        local_data: &[u8],
    ) -> Result<FileDiff, String> {
        // Validate chunk size alignment
        if remote_manifest.chunk_size as usize != self.chunk_size {
            return Err(format!(
                "chunk size mismatch: manifest has {} bytes, engine has {} bytes",
                remote_manifest.chunk_size, self.chunk_size
            ));
        }

        // Fast path: file-level hash match
        let local_hash = sha256(local_data);
        if local_hash == remote_manifest.file_hash {
            return Ok(FileDiff {
                file_name: String::new(),
                old_size: remote_manifest.file_size,
                new_size: local_data.len() as u64,
                changed_blocks: Vec::new(),
                unchanged_count: remote_manifest.chunks.len() as u32,
                files_match: true,
            });
        }

        let _chunk_size = self.chunk_size as u64;
        let remote_chunks = &remote_manifest.chunks;
        let local_num_chunks = if local_data.is_empty() {
            0
        } else {
            (local_data.len() + self.chunk_size - 1) / self.chunk_size
        };

        let max_index = std::cmp::max(remote_chunks.len() as u32, local_num_chunks as u32);
        let mut changed_blocks = Vec::new();
        let mut unchanged_count = 0u32;

        for i in 0..max_index {
            let has_remote = (i as usize) < remote_chunks.len();
            let has_local = (i as usize) < local_num_chunks;

            match (has_remote, has_local) {
                (true, true) => {
                    let r_chunk = &remote_chunks[i as usize];
                    let start = i as usize * self.chunk_size;
                    let end = std::cmp::min(start + self.chunk_size, local_data.len());
                    let local_slice = &local_data[start..end];
                    let local_hash = sha256(local_slice);

                    if local_hash == r_chunk.hash {
                        unchanged_count += 1;
                    } else {
                        changed_blocks.push(BlockDiff {
                            index: i,
                            offset: r_chunk.offset,
                            size: local_slice.len() as u64,
                            status: BlockDiffStatus::Modified,
                            new_hash: local_hash,
                            old_hash: r_chunk.hash,
                        });
                    }
                }
                (true, false) => {
                    // Remote has chunk, local doesn't → Deleted
                    let r_chunk = &remote_chunks[i as usize];
                    changed_blocks.push(BlockDiff {
                        index: i,
                        offset: r_chunk.offset,
                        size: 0,
                        status: BlockDiffStatus::Deleted,
                        new_hash: [0u8; 32],
                        old_hash: r_chunk.hash,
                    });
                }
                (false, true) => {
                    // Local has chunk, remote doesn't → Added
                    let start = i as usize * self.chunk_size;
                    let end = std::cmp::min(start + self.chunk_size, local_data.len());
                    let local_slice = &local_data[start..end];
                    let local_hash = sha256(local_slice);
                    changed_blocks.push(BlockDiff {
                        index: i,
                        offset: start as u64,
                        size: local_slice.len() as u64,
                        status: BlockDiffStatus::Added,
                        new_hash: local_hash,
                        old_hash: [0u8; 32],
                    });
                }
                (false, false) => unreachable!(),
            }
        }

        Ok(FileDiff {
            file_name: String::new(),
            old_size: remote_manifest.file_size,
            new_size: local_data.len() as u64,
            changed_blocks,
            unchanged_count,
            files_match: false,
        })
    }

    /// Generate a human-readable diff report with transfer estimates.
    ///
    /// The `file_name` parameter is used for display purposes.
    /// The estimated transfer time is calculated at a reference speed of 1 MB/s.
    pub fn generate_report(&self, diff: &FileDiff, file_name: &str) -> DiffReport {
        let mut report = DiffReport {
            diff: diff.clone(),
            blocks_to_transfer: 0,
            bytes_to_transfer: 0,
            estimated_secs: 0,
        };

        // Only Added and Modified blocks need to be transferred.
        for block in &diff.changed_blocks {
            match block.status {
                BlockDiffStatus::Added | BlockDiffStatus::Modified => {
                    report.blocks_to_transfer += 1;
                    report.bytes_to_transfer += block.size;
                }
                _ => {}
            }
        }

        // Estimate: 1 MB/s reference speed
        let reference_bps = 1_000_000u64; // 1 MB/s
        if report.bytes_to_transfer > 0 && reference_bps > 0 {
            report.estimated_secs = report.bytes_to_transfer / reference_bps;
            if report.estimated_secs < 1 {
                report.estimated_secs = 1; // at least 1 second
            }
        }

        report.diff.file_name = file_name.to_string();
        report
    }

    /// Format a diff report as a printable string.
    pub fn format_report(report: &DiffReport) -> String {
        let mut output = String::new();
        let d = &report.diff;

        output.push_str(&format!("File: {}\n", d.file_name));
        output.push_str(&format!(
            "Size: {} → {} ({} {})\n",
            d.old_size,
            d.new_size,
            if d.new_size > d.old_size {
                d.new_size - d.old_size
            } else {
                d.old_size - d.new_size
            },
            if d.new_size >= d.old_size { "added" } else { "removed" }
        ));

        if d.files_match {
            output.push_str("Status: UNCHANGED (files are identical)\n");
            return output;
        }

        output.push_str(&format!(
            "Blocks: {} unchanged, {} changed\n",
            d.unchanged_count,
            d.changed_blocks.len()
        ));
        output.push_str(&format!(
            "To transfer: {} blocks, {} bytes (~{}s at 1 MB/s)\n",
            report.blocks_to_transfer,
            report.bytes_to_transfer,
            report.estimated_secs
        ));
        output.push_str("\nBlock details:\n");
        output.push_str(&format!(
            "  {:<6} {:<10} {:<8} {}\n",
            "Index", "Offset", "Size", "Status"
        ));

        for block in &d.changed_blocks {
            let status_str = match block.status {
                BlockDiffStatus::Unchanged => "=",
                BlockDiffStatus::Modified => "M",
                BlockDiffStatus::Added => "+",
                BlockDiffStatus::Deleted => "-",
            };
            output.push_str(&format!(
                "  {:<6} {:<10} {:<8} {}\n",
                block.index, block.offset, block.size, status_str
            ));
        }

        output
    }

    /// Compare a local file (on disk) against a remote manifest.
    ///
    /// This is a convenience wrapper around [`diff_files`](Self::diff_files)
    /// that reads the file from `local_path`.
    ///
    /// # Errors
    ///
    /// Returns an IO error if the file cannot be read.
    pub fn diff_file(
        &self,
        remote_manifest: &FileManifest,
        local_path: &std::path::Path,
    ) -> Result<FileDiff, String> {
        let data = std::fs::read(local_path)
            .map_err(|e| format!("failed to read '{}': {}", local_path.display(), e))?;
        self.diff_files(remote_manifest, &data)
    }
}

impl Default for BlockDiffEngine {
    fn default() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 digest of `data` as a 32-byte array.
fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::chunk::Chunker;

    /// Helper: generate deterministic test data.
    fn test_data(size: usize, seed: u8) -> Vec<u8> {
        (0..size).map(|i| (i.wrapping_add(seed as usize) % 251) as u8).collect()
    }

    // -----------------------------------------------------------------------
    // Identical files
    // -----------------------------------------------------------------------

    #[test]
    fn identical_files_no_diff() {
        let chunker = Chunker::with_chunk_size(4096);
        let data = test_data(100_000, 0xAB);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &data).unwrap();

        assert!(diff.files_match);
        assert!(diff.changed_blocks.is_empty());
        assert_eq!(diff.unchanged_count, manifest.chunks.len() as u32);
    }

    #[test]
    fn empty_files_match() {
        let chunker = Chunker::with_chunk_size(4096);
        let data: &[u8] = &[];
        let (manifest, _) = chunker.chunk_data(data);

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, data).unwrap();

        assert!(diff.files_match);
        assert!(diff.changed_blocks.is_empty());
        assert_eq!(diff.unchanged_count, 0);
    }

    // -----------------------------------------------------------------------
    // Modified blocks
    // -----------------------------------------------------------------------

    #[test]
    fn single_byte_modification_detected() {
        let chunker = Chunker::with_chunk_size(4096);
        let original = test_data(50_000, 0x01);
        let (manifest, _) = chunker.chunk_data(&original);

        let mut modified = original.clone();
        modified[100] ^= 0xFF; // flip one bit

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &modified).unwrap();

        assert!(!diff.files_match);
        // At least one block should be modified
        assert!(diff.changed_blocks.iter().any(|b| b.status == BlockDiffStatus::Modified));
    }

    #[test]
    fn multiple_modified_blocks() {
        let chunker = Chunker::with_chunk_size(4096);
        let original = test_data(100_000, 0x02);
        let (manifest, _) = chunker.chunk_data(&original);

        let mut modified = original.clone();
        // Modify first block
        modified[10] ^= 0x01;
        // Modify third block
        modified[9000] ^= 0x01;

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &modified).unwrap();

        let modified_count = diff
            .changed_blocks
            .iter()
            .filter(|b| b.status == BlockDiffStatus::Modified)
            .count();
        assert_eq!(modified_count, 2);
    }

    // -----------------------------------------------------------------------
    // Added / deleted blocks
    // -----------------------------------------------------------------------

    #[test]
    fn appended_data_detected_as_added() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(10_000, 0x03);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let new = test_data(15_000, 0x03); // 5 KiB more

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();

        let added_count = diff
            .changed_blocks
            .iter()
            .filter(|b| b.status == BlockDiffStatus::Added)
            .count();
        // Old had ceil(10000/4096)=3 chunks, new has ceil(15000/4096)=4 chunks
        // So 1 added chunk
        assert_eq!(added_count, 1);
        assert!(!diff.files_match);
    }

    #[test]
    fn truncated_data_detected_as_deleted() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(20_000, 0x04);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let new = test_data(8_000, 0x04); // truncated

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();

        let deleted_count = diff
            .changed_blocks
            .iter()
            .filter(|b| b.status == BlockDiffStatus::Deleted)
            .count();
        // Old had ceil(20000/4096)=5 chunks, new has ceil(8000/4096)=2 chunks
        // So 3 deleted chunks
        assert_eq!(deleted_count, 3);
    }

    // -----------------------------------------------------------------------
    // Mixed changes
    // -----------------------------------------------------------------------

    #[test]
    fn mixed_add_modify_delete() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(12_000, 0x05);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let mut new = test_data(15_000, 0x05);
        new[500] ^= 0xFF; // modify within first block

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();

        // First block modified, last block of old deleted, one new block added
        // Old: ceil(12000/4096)=3 chunks (0, 1, 2)
        // New: ceil(15000/4096)=4 chunks (0, 1, 2, 3)
        // Block 0: modified, Block 1: unchanged, Block 2: unchanged,
        // Block 3: added (but old has no block 3... wait old only has 3 blocks)
        // Actually old has chunk 0 (0-4095), 1 (4096-8191), 2 (8192-11999)
        // New has chunk 0 (0-4095), 1 (4096-8191), 2 (8192-12287), 3 (12288-14999)
        // So: chunk 0 modified, chunk 1 unchanged, chunk 2 different sizes → modified,
        // chunk 3 added

        let modified = diff.changed_blocks.iter().filter(|b| b.status == BlockDiffStatus::Modified).count();
        let added = diff.changed_blocks.iter().filter(|b| b.status == BlockDiffStatus::Added).count();
        assert!(modified >= 1);
        assert_eq!(added, 1);
    }

    // -----------------------------------------------------------------------
    // Chunk size mismatch
    // -----------------------------------------------------------------------

    #[test]
    fn chunk_size_mismatch_returns_error() {
        let chunker = Chunker::with_chunk_size(8192);
        let data = test_data(50_000, 0x06);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096); // different size
        let result = engine.diff_files(&manifest, &data);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("chunk size mismatch"));
    }

    // -----------------------------------------------------------------------
    // Report generation
    // -----------------------------------------------------------------------

    #[test]
    fn report_identical_files() {
        let chunker = Chunker::with_chunk_size(4096);
        let data = test_data(50_000, 0x07);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &data).unwrap();
        let report = engine.generate_report(&diff, "test.bin");

        assert_eq!(report.blocks_to_transfer, 0);
        assert_eq!(report.bytes_to_transfer, 0);
        assert!(report.diff.files_match);
    }

    #[test]
    fn report_modified_file_estimates_transfer() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(50_000, 0x08);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let mut new = old.clone();
        new[100] ^= 0xFF;

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();
        let report = engine.generate_report(&diff, "test.bin");

        assert!(report.blocks_to_transfer > 0);
        assert!(report.bytes_to_transfer > 0);
        assert!(!report.diff.files_match);
    }

    // -----------------------------------------------------------------------
    // Format report
    // -----------------------------------------------------------------------

    #[test]
    fn format_report_contains_key_info() {
        let chunker = Chunker::with_chunk_size(4096);
        let data = test_data(30_000, 0x09);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &data).unwrap();
        let report = engine.generate_report(&diff, "report_test.bin");
        let formatted = BlockDiffEngine::format_report(&report);

        assert!(formatted.contains("report_test.bin"));
        assert!(formatted.contains("UNCHANGED"));
    }

    #[test]
    fn format_modified_report() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(30_000, 0x0A);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let mut new = old.clone();
        new[42] ^= 0x01;

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();
        let report = engine.generate_report(&diff, "changed.bin");
        let formatted = BlockDiffEngine::format_report(&report);

        assert!(formatted.contains("changed.bin"));
        assert!(formatted.contains("Blocks:"));
        assert!(formatted.contains("To transfer:"));
        assert!(formatted.contains("Index"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn single_chunk_file_modified() {
        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(100, 0x0B);
        let (old_manifest, _) = chunker.chunk_data(&old);

        let mut new = old.clone();
        new[50] ^= 0xFF;

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&old_manifest, &new).unwrap();
        assert!(!diff.files_match);
        assert_eq!(diff.changed_blocks.len(), 1);
        assert_eq!(diff.changed_blocks[0].status, BlockDiffStatus::Modified);
    }

    #[test]
    fn empty_manifest_non_empty_data() {
        let chunker = Chunker::with_chunk_size(4096);
        let empty: &[u8] = &[];
        let (manifest, _) = chunker.chunk_data(empty);

        let data = test_data(5000, 0x0C);
        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_files(&manifest, &data).unwrap();

        // All blocks should be Added (manifest had 0, local has 2)
        assert!(!diff.files_match);
        let added = diff.changed_blocks.iter().filter(|b| b.status == BlockDiffStatus::Added).count();
        assert_eq!(added, 2);
    }

    #[test]
    fn min_chunk_size_clamped() {
        let engine = BlockDiffEngine::new(100); // below MIN_DIFF_CHUNK_SIZE
        assert_eq!(engine.chunk_size, MIN_DIFF_CHUNK_SIZE);
    }

    #[test]
    fn large_chunk_size_preserved() {
        let engine = BlockDiffEngine::new(1024 * 1024);
        assert_eq!(engine.chunk_size, 1024 * 1024);
    }

    // -----------------------------------------------------------------------
    // Diff file via path
    // -----------------------------------------------------------------------

    #[test]
    fn diff_file_nonexistent_path() {
        let chunker = Chunker::with_chunk_size(4096);
        let data = test_data(1000, 0x0D);
        let (manifest, _) = chunker.chunk_data(&data);

        let engine = BlockDiffEngine::new(4096);
        let result = engine.diff_file(&manifest, std::path::Path::new("/nonexistent/path/file.bin"));
        assert!(result.is_err());
    }

    #[test]
    fn diff_file_roundtrip() {
        let dir = std::env::temp_dir().join("ll_vpn_diff_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("diff_roundtrip.bin");

        let chunker = Chunker::with_chunk_size(4096);
        let old = test_data(20_000, 0x0E);
        let (old_manifest, _) = chunker.chunk_data(&old);

        // Write different data to the file
        let new = test_data(25_000, 0x0F);
        std::fs::write(&path, &new).unwrap();

        let engine = BlockDiffEngine::new(4096);
        let diff = engine.diff_file(&old_manifest, &path).unwrap();
        assert!(!diff.files_match);
        assert!(diff.new_size > diff.old_size);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
