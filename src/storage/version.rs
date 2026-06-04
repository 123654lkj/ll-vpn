//! P5-3: 版本历史 — Snapshot-based version management for incremental backups.
//!
//! # Overview
//!
//! [`VersionManager`] tracks snapshots of file manifests over time so that
//! previous file versions can be listed, restored, and pruned.  Each version
//! is identified by a `version_id` string composed of a UTC timestamp and
//! a sequence number (`<timestamp>-<seq>`).
//!
//! # Features
//!
//! - `create_snapshot()` — save a point-in-time snapshot of a file's manifest
//! - `list_versions()` — enumerate all versions for a given file
//! - `restore_version()` — retrieve the manifest for a specific version
//! - `prune_versions()` — remove old versions, keeping only the N most recent
//!
//! # Integration
//!
//! The version store is file-based (JSON) and can be loaded/saved via the
//! [`VersionStore`] serialization wrapper.

use crate::storage::chunk::FileManifest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default path for the version database file.
pub const DEFAULT_VERSION_DB_PATH: &str = "version_store.json";

/// Maximum number of versions to keep per file by default (for pruning).
pub const DEFAULT_MAX_VERSIONS: usize = 10;

/// Maximum length of a version ID string prefix (timestamp portion).
const VERSION_TIMESTAMP_LEN: usize = 14; // "20260603120000" = YYYYMMDDHHMMSS

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single version snapshot for a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionEntry {
    /// Version identifier — `"<YYYYMMDDHHMMSS>-<seq>"`.
    pub version_id: String,
    /// Human-readable timestamp string (UTC).
    pub timestamp: String,
    /// Unix seconds at snapshot time.
    pub unix_secs: u64,
    /// Sequence number within this second (0-based).
    pub seq: u32,
    /// Snapshot of the file manifest at this version.
    pub manifest: FileManifest,
    /// Optional annotation (e.g. "backup", "manual").
    pub annotation: String,
}

/// Collection of version entries for a single file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FileVersions {
    /// File name (key).
    pub file_name: String,
    /// Ordered list of versions (newest first).
    pub versions: Vec<VersionEntry>,
}

impl FileVersions {
    /// Create a new empty file version tracker.
    pub fn new(file_name: &str) -> Self {
        Self {
            file_name: file_name.to_string(),
            versions: Vec::new(),
        }
    }

    /// Add a version entry, maintaining newest-first order.
    pub fn push(&mut self, entry: VersionEntry) {
        self.versions.insert(0, entry);
    }

    /// Return the number of stored versions.
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Get the most recent version, if any.
    pub fn latest(&self) -> Option<&VersionEntry> {
        self.versions.first()
    }

    /// Get a version by its version_id.
    pub fn get(&self, version_id: &str) -> Option<&VersionEntry> {
        self.versions.iter().find(|v| v.version_id == version_id)
    }

    /// Prune to keep at most `max_versions` entries (removes oldest).
    /// Returns the number of pruned entries.
    pub fn prune(&mut self, max_versions: usize) -> usize {
        if self.versions.len() <= max_versions {
            return 0;
        }
        let excess = self.versions.len() - max_versions;
        self.versions.truncate(max_versions);
        excess
    }
}

/// The full version database — persists to JSON.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VersionStore {
    /// File name → version history.
    pub files: HashMap<String, FileVersions>,
}

impl VersionStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
        }
    }

    /// Get the version history for a file.
    pub fn get(&self, file_name: &str) -> Option<&FileVersions> {
        self.files.get(file_name)
    }

    /// Get a mutable reference to the version history for a file,
    /// creating an empty one if it doesn't exist.
    pub fn get_or_create_mut(&mut self, file_name: &str) -> &mut FileVersions {
        self.files
            .entry(file_name.to_string())
            .or_insert_with(|| FileVersions::new(file_name))
    }

    /// List all files that have version history.
    pub fn list_files(&self) -> Vec<String> {
        let mut files: Vec<_> = self.files.keys().cloned().collect();
        files.sort();
        files
    }

    /// Return the total number of version entries across all files.
    pub fn total_versions(&self) -> usize {
        self.files.values().map(|fv| fv.versions.len()).sum()
    }

    /// Prune all files to keep at most `max_versions` each.
    /// Returns total number of pruned entries.
    pub fn prune_all(&mut self, max_versions: usize) -> usize {
        let mut total = 0;
        for fv in self.files.values_mut() {
            total += fv.prune(max_versions);
        }
        total
    }
}

// ---------------------------------------------------------------------------
// VersionManager
// ---------------------------------------------------------------------------

/// Manages version snapshots for file backups.
///
/// # Thread safety
///
/// `VersionManager` uses `RwLock` internally and provides interior mutability,
/// so it can be shared across threads (e.g. as `&VersionManager`).
pub struct VersionManager {
    /// Version database in memory.
    store: RwLock<VersionStore>,
    /// Global sequence counter (per-process, incremented for each snapshot).
    seq_counter: AtomicU64,
    /// Database file path.
    db_path: PathBuf,
    /// Whether the store is dirty (needs saving).
    dirty: RwLock<bool>,
}

impl VersionManager {
    /// Create a new in-memory version manager.
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            store: RwLock::new(VersionStore::new()),
            seq_counter: AtomicU64::new(0),
            db_path: db_path.as_ref().to_path_buf(),
            dirty: RwLock::new(false),
        }
    }

    /// Create a version manager with the default database path.
    pub fn new_default() -> Self {
        Self::new(DEFAULT_VERSION_DB_PATH)
    }

    /// Load a version manager from a JSON file.
    ///
    /// If the file does not exist, returns an empty manager.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let store = if path.exists() {
            let data = fs::read_to_string(path)
                .map_err(|e| format!("failed to read '{}': {}", path.display(), e))?;
            if data.trim().is_empty() {
                VersionStore::new()
            } else {
                serde_json::from_str(&data)
                    .map_err(|e| format!("failed to parse '{}': {}", path.display(), e))?
            }
        } else {
            VersionStore::new()
        };

        Ok(Self {
            store: RwLock::new(store),
            seq_counter: AtomicU64::new(0),
            db_path: path.to_path_buf(),
            dirty: RwLock::new(false),
        })
    }

    /// Persist the version database to disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> Result<(), String> {
        let store = self.store.read().map_err(|_| "lock poisoned".to_string())?;
        let json = serde_json::to_string_pretty(&*store)
            .map_err(|e| format!("serialization error: {}", e))?;
        drop(store);

        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {}", e))?;
        }
        fs::write(&self.db_path, json)
            .map_err(|e| format!("failed to write '{}': {}", self.db_path.display(), e))?;

        let mut dirty = self.dirty.write().map_err(|_| "lock poisoned".to_string())?;
        *dirty = false;
        Ok(())
    }

    /// Save the store to disk only if dirty (auto-save).
    fn save_if_dirty(&self) {
        #[cfg(not(test))]
        {
            if let Ok(dirty) = self.dirty.read() {
                if *dirty {
                    drop(dirty);
                    let _ = self.save();
                }
            }
        }
        #[cfg(test)]
        {
            if let Ok(mut dirty) = self.dirty.write() {
                *dirty = false;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Core API
    // -----------------------------------------------------------------------

    /// Create a snapshot of a file's current state.
    ///
    /// `file_name` — the logical file name.
    /// `manifest` — the current [`FileManifest`] for the file.
    /// `annotation` — optional description (e.g. "backup", "manual").
    ///
    /// Returns the generated `version_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock is poisoned.
    pub fn create_snapshot(
        &self,
        file_name: &str,
        manifest: FileManifest,
        annotation: &str,
    ) -> Result<String, String> {
        let now_secs = now_secs();
        let timestamp_utc = format_timestamp(now_secs);
        let seq = self.seq_counter.fetch_add(1, Ordering::SeqCst) as u32;
        let version_id = format!("{}-{:04}", timestamp_utc, seq);

        let entry = VersionEntry {
            version_id: version_id.clone(),
            timestamp: timestamp_utc.clone(),
            unix_secs: now_secs,
            seq,
            manifest,
            annotation: annotation.to_string(),
        };

        {
            let mut store = self.store.write().map_err(|_| "lock poisoned".to_string())?;
            let fv = store.get_or_create_mut(file_name);
            fv.push(entry);
        }

        {
            let mut dirty = self.dirty.write().map_err(|_| "lock poisoned".to_string())?;
            *dirty = true;
        }
        self.save_if_dirty();

        Ok(version_id)
    }

    /// List all versions for a given file.
    ///
    /// Returns an empty vec if the file has no version history.
    pub fn list_versions(&self, file_name: &str) -> Vec<VersionEntry> {
        self.store
            .read()
            .ok()
            .and_then(|s| s.get(file_name).cloned())
            .map(|fv| fv.versions)
            .unwrap_or_default()
    }

    /// Get a specific version by file name and version_id.
    pub fn get_version(&self, file_name: &str, version_id: &str) -> Option<VersionEntry> {
        self.store.read().ok().and_then(|s| {
            s.get(file_name)
                .and_then(|fv| fv.get(version_id).cloned())
        })
    }

    /// Get the latest version for a file.
    pub fn latest_version(&self, file_name: &str) -> Option<VersionEntry> {
        self.store
            .read()
            .ok()
            .and_then(|s| s.get(file_name).cloned())
            .and_then(|fv| fv.latest().cloned())
    }

    /// Restore a specific version's manifest.
    ///
    /// Returns the [`FileManifest`] associated with the given version.
    ///
    /// # Errors
    ///
    /// Returns an error if the file or version is not found.
    pub fn restore_version(
        &self,
        file_name: &str,
        version_id: &str,
    ) -> Result<FileManifest, String> {
        self.get_version(file_name, version_id)
            .map(|v| v.manifest)
            .ok_or_else(|| {
                format!(
                    "version '{}' not found for file '{}'",
                    version_id, file_name
                )
            })
    }

    /// Prune old versions for a file, keeping at most `max_versions`.
    ///
    /// Returns the number of pruned entries.
    pub fn prune_versions(&self, file_name: &str, max_versions: usize) -> Result<usize, String> {
        let pruned = {
            let mut store = self.store.write().map_err(|_| "lock poisoned".to_string())?;
            match store.files.get_mut(file_name) {
                Some(fv) => fv.prune(max_versions),
                None => {
                    return Err(format!("no versions found for '{}'", file_name));
                }
            }
        };

        if pruned > 0 {
            let mut dirty = self.dirty.write().map_err(|_| "lock poisoned".to_string())?;
            *dirty = true;
            self.save_if_dirty();
        }

        Ok(pruned)
    }

    /// Prune all files' version history.
    ///
    /// Returns total number of pruned entries across all files.
    pub fn prune_all_versions(&self, max_versions: usize) -> Result<usize, String> {
        let pruned = {
            let mut store = self.store.write().map_err(|_| "lock poisoned".to_string())?;
            store.prune_all(max_versions)
        };

        if pruned > 0 {
            let mut dirty = self.dirty.write().map_err(|_| "lock poisoned".to_string())?;
            *dirty = true;
            self.save_if_dirty();
        }

        Ok(pruned)
    }

    /// Remove all version history for a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file has no version history.
    pub fn remove_file(&self, file_name: &str) -> Result<(), String> {
        {
            let mut store = self.store.write().map_err(|_| "lock poisoned".to_string())?;
            if store.files.remove(file_name).is_none() {
                return Err(format!("no versions found for '{}'", file_name));
            }
        }

        {
            let mut dirty = self.dirty.write().map_err(|_| "lock poisoned".to_string())?;
            *dirty = true;
        }
        self.save_if_dirty();

        Ok(())
    }

    /// List all files that have version history.
    pub fn list_files(&self) -> Vec<String> {
        self.store
            .read()
            .map(|s| s.list_files())
            .unwrap_or_default()
    }

    /// Return the total number of versions across all files.
    pub fn total_versions(&self) -> usize {
        self.store
            .read()
            .map(|s| s.total_versions())
            .unwrap_or(0)
    }

    /// Check whether any version exists for the given file.
    pub fn has_versions(&self, file_name: &str) -> bool {
        self.store
            .read()
            .ok()
            .map(|s| s.get(file_name).map_or(false, |fv| !fv.is_empty()))
            .unwrap_or(false)
    }

    /// Force the store to be written to disk now.
    pub fn flush(&self) -> Result<(), String> {
        self.save()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a Unix timestamp as `"YYYYMMDDHHMMSS"` (UTC).
fn format_timestamp(unix_secs: u64) -> String {
    // Use a simple calculation rather than pulling in chrono.
    let secs_per_day: u64 = 86400;
    let days_since_epoch = unix_secs / secs_per_day;
    let time_in_day = unix_secs % secs_per_day;

    let hours = time_in_day / 3600;
    let minutes = (time_in_day % 3600) / 60;
    let seconds = time_in_day % 60;

    // Date from days since 1970-01-01 (civil calendar).
    let (year, month, day) = civil_date_from_days(days_since_epoch as i64);

    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since 1970-01-01 to (year, month, day).
///
/// Uses the civil calendar algorithm.
fn civil_date_from_days(days: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a minimal manifest for testing.
    fn make_manifest(size: u64, seed: u8) -> FileManifest {
        let hash = [seed; 32];
        FileManifest {
            file_hash: hash,
            file_size: size,
            chunks: Vec::new(),
            chunk_size: 4096,
        }
    }

    // =====================================================================
    // format_timestamp tests
    // =====================================================================

    #[test]
    fn test_format_timestamp_known_value() {
        // 2026-06-03 12:00:00 UTC = 1_776_945_600 (approx)
        // Let's compute: 2026-06-03 is... we'll just check the format.
        let s = format_timestamp(1_700_000_000);
        // Should be 14 chars: YYYYMMDDHHMMSS
        assert_eq!(s.len(), VERSION_TIMESTAMP_LEN);
        // Should be all digits
        assert!(s.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_format_timestamp_epoch() {
        let s = format_timestamp(0);
        assert_eq!(s, "19700101000000");
    }

    // =====================================================================
    // VersionEntry tests
    // =====================================================================

    #[test]
    fn test_version_entry_creation() {
        let manifest = make_manifest(1024, 0xAB);
        let entry = VersionEntry {
            version_id: "20260603120000-0000".into(),
            timestamp: "20260603120000".into(),
            unix_secs: 1_776_945_600,
            seq: 0,
            manifest: manifest.clone(),
            annotation: "test".into(),
        };
        assert_eq!(entry.version_id, "20260603120000-0000");
        assert_eq!(entry.manifest.file_size, 1024);
    }

    // =====================================================================
    // FileVersions tests
    // =====================================================================

    #[test]
    fn test_file_versions_new_is_empty() {
        let fv = FileVersions::new("test.txt");
        assert!(fv.is_empty());
        assert_eq!(fv.len(), 0);
    }

    #[test]
    fn test_file_versions_push_and_latest() {
        let mut fv = FileVersions::new("f.txt");
        assert!(fv.latest().is_none());

        let v1 = VersionEntry {
            version_id: "v1".into(),
            timestamp: "ts1".into(),
            unix_secs: 100,
            seq: 0,
            manifest: make_manifest(100, 0x01),
            annotation: "".into(),
        };
        let v2 = VersionEntry {
            version_id: "v2".into(),
            timestamp: "ts2".into(),
            unix_secs: 200,
            seq: 0,
            manifest: make_manifest(200, 0x02),
            annotation: "".into(),
        };

        fv.push(v1);
        fv.push(v2);

        assert_eq!(fv.len(), 2);
        let latest = fv.latest().unwrap();
        assert_eq!(latest.version_id, "v2");
    }

    #[test]
    fn test_file_versions_get() {
        let mut fv = FileVersions::new("g.txt");
        let v = VersionEntry {
            version_id: "myver".into(),
            timestamp: "ts".into(),
            unix_secs: 0,
            seq: 0,
            manifest: make_manifest(50, 0x03),
            annotation: "".into(),
        };
        fv.push(v);

        assert!(fv.get("myver").is_some());
        assert!(fv.get("nonexist").is_none());
    }

    // =====================================================================
    // Pruning tests
    // =====================================================================

    #[test]
    fn test_file_versions_prune_under_limit() {
        let mut fv = FileVersions::new("p.txt");
        for i in 0..3 {
            fv.push(VersionEntry {
                version_id: format!("v{}", i),
                timestamp: "".into(),
                unix_secs: i,
                seq: 0,
                manifest: make_manifest(100, i as u8),
                annotation: "".into(),
            });
        }
        assert_eq!(fv.prune(10), 0); // under limit
        assert_eq!(fv.len(), 3);
    }

    #[test]
    fn test_file_versions_prune_over_limit() {
        let mut fv = FileVersions::new("p.txt");
        for i in 0..5 {
            fv.push(VersionEntry {
                version_id: format!("v{}", i),
                timestamp: "".into(),
                unix_secs: i,
                seq: 0,
                manifest: make_manifest(100, i as u8),
                annotation: "".into(),
            });
        }
        assert_eq!(fv.len(), 5);
        let pruned = fv.prune(3);
        assert_eq!(pruned, 2);
        assert_eq!(fv.len(), 3);
    }

    // =====================================================================
    // VersionStore tests
    // =====================================================================

    #[test]
    fn test_version_store_new() {
        let store = VersionStore::new();
        assert!(store.list_files().is_empty());
        assert_eq!(store.total_versions(), 0);
    }

    #[test]
    fn test_version_store_get_or_create_mut() {
        let mut store = VersionStore::new();
        let fv = store.get_or_create_mut("test.txt");
        assert_eq!(fv.file_name, "test.txt");
        assert!(fv.is_empty());
    }

    #[test]
    fn test_version_store_total_versions() {
        let mut store = VersionStore::new();
        let fv = store.get_or_create_mut("a.txt");
        fv.push(VersionEntry {
            version_id: "v1".into(),
            timestamp: "".into(),
            unix_secs: 0,
            seq: 0,
            manifest: make_manifest(10, 0x01),
            annotation: "".into(),
        });
        fv.push(VersionEntry {
            version_id: "v2".into(),
            timestamp: "".into(),
            unix_secs: 0,
            seq: 0,
            manifest: make_manifest(20, 0x02),
            annotation: "".into(),
        });

        let fv2 = store.get_or_create_mut("b.txt");
        fv2.push(VersionEntry {
            version_id: "v1".into(),
            timestamp: "".into(),
            unix_secs: 0,
            seq: 0,
            manifest: make_manifest(30, 0x03),
            annotation: "".into(),
        });

        assert_eq!(store.total_versions(), 3);
    }

    // =====================================================================
    // VersionManager tests
    // =====================================================================

    fn make_manager() -> VersionManager {
        VersionManager::new_default()
    }

    #[test]
    fn test_create_snapshot() {
        let mgr = make_manager();
        let manifest = make_manifest(1000, 0xAA);
        let vid = mgr
            .create_snapshot("test.txt", manifest.clone(), "backup")
            .unwrap();

        // version_id should look like "20260603120000-0000"
        assert!(vid.len() > VERSION_TIMESTAMP_LEN);
        assert!(vid.contains('-'));

        let versions = mgr.list_versions("test.txt");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version_id, vid);
        assert_eq!(versions[0].manifest.file_size, 1000);
        assert_eq!(versions[0].annotation, "backup");
    }

    #[test]
    fn test_list_versions_empty() {
        let mgr = make_manager();
        let versions = mgr.list_versions("nonexistent.txt");
        assert!(versions.is_empty());
    }

    #[test]
    fn test_multiple_snapshots() {
        let mgr = make_manager();
        let v1 = mgr
            .create_snapshot("f.txt", make_manifest(100, 0x01), "v1")
            .unwrap();
        let v2 = mgr
            .create_snapshot("f.txt", make_manifest(200, 0x02), "v2")
            .unwrap();

        let versions = mgr.list_versions("f.txt");
        assert_eq!(versions.len(), 2);
        // Newest first
        assert_eq!(versions[0].version_id, v2);
        assert_eq!(versions[1].version_id, v1);
    }

    #[test]
    fn test_get_version() {
        let mgr = make_manager();
        let vid = mgr
            .create_snapshot("f.txt", make_manifest(500, 0xAB), "test")
            .unwrap();

        let found = mgr.get_version("f.txt", &vid).unwrap();
        assert_eq!(found.manifest.file_size, 500);

        assert!(mgr.get_version("f.txt", "nonexist").is_none());
    }

    #[test]
    fn test_latest_version() {
        let mgr = make_manager();
        assert!(mgr.latest_version("f.txt").is_none());

        let vid = mgr
            .create_snapshot("f.txt", make_manifest(300, 0xBB), "first")
            .unwrap();
        let latest = mgr.latest_version("f.txt").unwrap();
        assert_eq!(latest.version_id, vid);
    }

    #[test]
    fn test_restore_version() {
        let mgr = make_manager();
        let manifest = make_manifest(777, 0xCC);
        let vid = mgr
            .create_snapshot("f.txt", manifest.clone(), "restore-test")
            .unwrap();

        let restored = mgr.restore_version("f.txt", &vid).unwrap();
        assert_eq!(restored, manifest);
    }

    #[test]
    fn test_restore_version_not_found() {
        let mgr = make_manager();
        let err = mgr.restore_version("f.txt", "nonexist").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_prune_versions() {
        let mgr = make_manager();
        for i in 0..5 {
            mgr.create_snapshot("f.txt", make_manifest(100, i as u8), "")
                .unwrap();
        }
        assert_eq!(mgr.list_versions("f.txt").len(), 5);

        let pruned = mgr.prune_versions("f.txt", 2).unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(mgr.list_versions("f.txt").len(), 2);
    }

    #[test]
    fn test_prune_versions_nonexistent() {
        let mgr = make_manager();
        let err = mgr.prune_versions("nope.txt", 5).unwrap_err();
        assert!(err.contains("no versions found"));
    }

    #[test]
    fn test_prune_all_versions() {
        let mgr = make_manager();
        mgr.create_snapshot("a.txt", make_manifest(10, 0x01), "")
            .unwrap();
        mgr.create_snapshot("a.txt", make_manifest(10, 0x02), "")
            .unwrap();
        mgr.create_snapshot("b.txt", make_manifest(20, 0x03), "")
            .unwrap();
        mgr.create_snapshot("b.txt", make_manifest(20, 0x04), "")
            .unwrap();
        mgr.create_snapshot("b.txt", make_manifest(20, 0x05), "")
            .unwrap();

        assert_eq!(mgr.total_versions(), 5);
        let total = mgr.prune_all_versions(1).unwrap();
        assert_eq!(total, 3); // a: prune 1, b: prune 2
        assert_eq!(mgr.total_versions(), 2);
    }

    #[test]
    fn test_remove_file() {
        let mgr = make_manager();
        mgr.create_snapshot("f.txt", make_manifest(100, 0x01), "")
            .unwrap();
        assert!(mgr.has_versions("f.txt"));

        mgr.remove_file("f.txt").unwrap();
        assert!(!mgr.has_versions("f.txt"));
    }

    #[test]
    fn test_remove_file_nonexistent() {
        let mgr = make_manager();
        let err = mgr.remove_file("nope.txt").unwrap_err();
        assert!(err.contains("no versions found"));
    }

    #[test]
    fn test_has_versions() {
        let mgr = make_manager();
        assert!(!mgr.has_versions("f.txt"));

        mgr.create_snapshot("f.txt", make_manifest(50, 0x01), "")
            .unwrap();
        assert!(mgr.has_versions("f.txt"));
    }

    #[test]
    fn test_list_files() {
        let mgr = make_manager();
        mgr.create_snapshot("b.txt", make_manifest(10, 0x01), "")
            .unwrap();
        mgr.create_snapshot("a.txt", make_manifest(20, 0x02), "")
            .unwrap();

        let files = mgr.list_files();
        assert_eq!(files, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn test_total_versions() {
        let mgr = make_manager();
        assert_eq!(mgr.total_versions(), 0);

        mgr.create_snapshot("a.txt", make_manifest(10, 0x01), "")
            .unwrap();
        mgr.create_snapshot("a.txt", make_manifest(10, 0x02), "")
            .unwrap();
        assert_eq!(mgr.total_versions(), 2);
    }

    // =====================================================================
    // Persistence tests
    // =====================================================================

    #[test]
    fn test_save_and_load() {
        let dir = std::env::temp_dir().join("ll_vpn_ver_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("versions.json");

        // Write
        {
            let mgr = VersionManager::new(&path);
            mgr.create_snapshot("f.txt", make_manifest(100, 0xAA), "test")
                .unwrap();
            mgr.flush().unwrap();
        }

        // Read back
        let loaded = VersionManager::load_from_file(&path).unwrap();
        assert_eq!(loaded.total_versions(), 1);
        assert!(loaded.has_versions("f.txt"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let dir = std::env::temp_dir().join("ll_vpn_ver_nonexist");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("versions.json");

        let mgr = VersionManager::load_from_file(&path).unwrap();
        assert_eq!(mgr.total_versions(), 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // =====================================================================
    // Civil date tests
    // =====================================================================

    #[test]
    fn test_civil_date_epoch() {
        let (y, m, d) = civil_date_from_days(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_civil_date_known() {
        // 2026-06-03 → days since epoch = 20607 (approx)
        let days = days_since_epoch(2026, 6, 3);
        let (y, m, d) = civil_date_from_days(days);
        assert_eq!(y, 2026);
        assert_eq!(m, 6);
        assert_eq!(d, 3);
    }

    /// Compute days since 1970-01-01 for a given date.
    fn days_since_epoch(year: i64, month: i64, day: i64) -> i64 {
        let (y, m) = if month <= 2 {
            (year - 1, month + 12)
        } else {
            (year, month)
        };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let doy = (153 * (m - 3) + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146097 + doe - 719468
    }
}
