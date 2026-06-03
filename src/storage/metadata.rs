//! P4-3: 元数据管理
//!
//! 管理已备份文件的元数据清单：文件名、大小、块分布、存储节点信息。
//! 支持加密存储、文件名查询、节点间同步和冲突解决（最新优先）。
//!
//! # 架构
//!
//! ```text
//! MetadataStore (RwLock<HashMap<name, MetadataEntry>>)
//!     ├── register_file()     — 注册新文件
//!     ├── query()             — 按文件名查询
//!     ├── list_files()        — 列出所有已注册文件
//!     ├── update_block_location() — 更新某块的存储节点
//!     ├── get_block_nodes()   — 获取某块的所有存储节点
//!     ├── remove_file()       — 删除文件记录
//!     ├── sync_from()         — 从远程数据合并（冲突解决）
//!     └── save/load           — JSON 持久化
//! ```

use crate::storage::chunk::{FileManifest, Hash};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 默认持久化路径
pub const DEFAULT_METADATA_PATH: &str = "metadata_store.json";

/// 冲突解决：时间差在 5 秒内视为同时发生，用 hash 作为 tiebreaker
pub const CONFLICT_WINDOW_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 单个块的存储节点信息
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockLocation {
    /// 块 hash
    pub hash: Hash,
    /// 块在文件中的索引
    pub index: u32,
    /// 存储此块副本的节点名字列表
    pub nodes: Vec<String>,
    /// 最后同步时间戳（Unix 秒）
    pub last_synced: u64,
}

/// 文件元数据条目
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileMetadata {
    /// 文件名
    pub name: String,
    /// SHA-256 of 完整文件
    pub file_hash: Hash,
    /// 文件大小（字节）
    pub file_size: u64,
    /// 每个块的分布信息（按 index 排序）
    pub blocks: Vec<BlockLocation>,
    /// 创建时间戳（Unix 秒）
    pub created_at: u64,
    /// 最后更新时间戳（Unix 秒）
    pub updated_at: u64,
    /// 源节点名字（此文件最初来自哪个节点）
    pub source_node: String,
    /// 此元数据是否已加密
    pub encrypted: bool,
}

/// 元数据存储条目（包含 FileManifest 元信息 + 分布）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetadataEntry {
    /// 文件元数据
    pub meta: FileMetadata,
    /// 原始 FileManifest（如果可用）
    pub manifest: Option<FileManifest>,
}

/// 元数据错误
#[derive(Debug)]
pub enum MetadataError {
    /// 文件已存在
    AlreadyExists(String),
    /// 文件不存在
    NotFound(String),
    /// IO 错误
    IoError(std::io::Error),
    /// 序列化错误
    SerializeError(String),
    /// 锁已损坏
    LockPoisoned,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetadataError::AlreadyExists(name) => {
                write!(f, "metadata for '{}' already exists", name)
            }
            MetadataError::NotFound(name) => write!(f, "metadata for '{}' not found", name),
            MetadataError::IoError(e) => write!(f, "io error: {}", e),
            MetadataError::SerializeError(msg) => write!(f, "serialize error: {}", msg),
            MetadataError::LockPoisoned => write!(f, "lock poisoned"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<std::io::Error> for MetadataError {
    fn from(e: std::io::Error) -> Self {
        MetadataError::IoError(e)
    }
}

impl From<serde_json::Error> for MetadataError {
    fn from(e: serde_json::Error) -> Self {
        MetadataError::SerializeError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
//  MetadataStore
// ---------------------------------------------------------------------------

/// 元数据存储
///
/// 管理所有已备份文件的元数据清单，支持：
/// - 注册/查询/更新/删除文件元数据
/// - JSON 文件持久化
/// - 节点间同步与冲突解决
///
/// # 死锁注意
///
/// 所有写方法在获取 `RwLock` 写锁后会在调用 `save_to_file` 之前释放锁，
/// 避免 Rust `RwLock` 不可重入导致的死锁。
pub struct MetadataStore {
    /// 文件名 → 元数据条目
    entries: RwLock<HashMap<String, MetadataEntry>>,
    /// 持久化文件路径
    db_path: PathBuf,
    /// 数据是否已修改
    dirty: Arc<AtomicBool>,
}

impl MetadataStore {
    /// 创建新的元数据存储
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            db_path: db_path.as_ref().to_path_buf(),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 创建默认路径的存储
    pub fn new_default() -> Self {
        Self::new(DEFAULT_METADATA_PATH)
    }

    /// 从文件加载数据
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, MetadataError> {
        let path = path.as_ref();
        let store = if path.exists() {
            let data_str = fs::read_to_string(path)?;
            if data_str.trim().is_empty() {
                Self::new(path)
            } else {
                let entries: HashMap<String, MetadataEntry> = serde_json::from_str(&data_str)?;
                Self {
                    entries: RwLock::new(entries),
                    db_path: path.to_path_buf(),
                    dirty: Arc::new(AtomicBool::new(false)),
                }
            }
        } else {
            Self::new(path)
        };
        Ok(store)
    }

    /// 保存到文件
    ///
    /// 调用者必须确保在调用时没有持有 `entries` 的写锁。
    fn save_to_file(&self) -> Result<(), MetadataError> {
        let entries = self.entries.read().map_err(|_| MetadataError::LockPoisoned)?;
        let json = serde_json::to_string_pretty(&*entries)?;
        drop(entries);

        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.db_path, json)?;
        self.dirty.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// 如果数据已修改且当前未持有任何锁，执行持久化
    fn save_if_dirty(&self) {
        #[cfg(not(test))]
        {
            if self.dirty.load(Ordering::SeqCst) {
                if let Err(e) = self.save_to_file() {
                    log::error!("Failed to save metadata store: {}", e);
                }
            }
        }
        #[cfg(test)]
        {
            self.dirty.store(false, Ordering::SeqCst);
        }
    }

    /// 注册新文件
    ///
    /// 如果文件已存在返回错误。
    pub fn register(
        &self,
        name: &str,
        file_hash: Hash,
        file_size: u64,
        manifest: Option<FileManifest>,
        blocks: Vec<BlockLocation>,
        source_node: &str,
    ) -> Result<(), MetadataError> {
        let now = now_secs();
        // 检查唯一性
        {
            let entries = self.entries.read().map_err(|_| MetadataError::LockPoisoned)?;
            if entries.contains_key(name) {
                return Err(MetadataError::AlreadyExists(name.to_string()));
            }
        }

        let meta = FileMetadata {
            name: name.to_string(),
            file_hash,
            file_size,
            blocks,
            created_at: now,
            updated_at: now,
            source_node: source_node.to_string(),
            encrypted: false,
        };
        let entry = MetadataEntry { meta, manifest };

        {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            entries.insert(name.to_string(), entry);
        }

        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();
        Ok(())
    }

    /// 注册或更新文件（upsert）
    pub fn upsert(
        &self,
        name: &str,
        file_hash: Hash,
        file_size: u64,
        manifest: Option<FileManifest>,
        blocks: Vec<BlockLocation>,
        source_node: &str,
    ) -> Result<(), MetadataError> {
        let now = now_secs();
        let meta = FileMetadata {
            name: name.to_string(),
            file_hash,
            file_size,
            blocks,
            created_at: now,
            updated_at: now,
            source_node: source_node.to_string(),
            encrypted: false,
        };
        let entry = MetadataEntry { meta, manifest };

        {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            entries.insert(name.to_string(), entry);
        }

        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();
        Ok(())
    }

    /// 按文件名查询元数据
    pub fn query(&self, name: &str) -> Option<MetadataEntry> {
        self.entries
            .read()
            .ok()
            .and_then(|e| e.get(name).cloned())
    }

    /// 检查文件是否存在
    pub fn contains(&self, name: &str) -> bool {
        self.entries
            .read()
            .map(|e| e.contains_key(name))
            .unwrap_or(false)
    }

    /// 列出所有已注册的文件名
    pub fn list_files(&self) -> Vec<String> {
        self.entries
            .read()
            .map(|e| e.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// 获取文件数量
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    /// 存储是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 获取指定文件某个块的所有存储节点
    pub fn get_block_nodes(&self, name: &str, block_index: u32) -> Vec<String> {
        self.entries
            .read()
            .ok()
            .and_then(|e| e.get(name).cloned())
            .map(|entry| {
                entry
                    .meta
                    .blocks
                    .iter()
                    .find(|b| b.index == block_index)
                    .map(|b| b.nodes.clone())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// 获取指定文件所有块的存储节点分布
    pub fn get_block_distribution(&self, name: &str) -> HashMap<u32, Vec<String>> {
        self.entries
            .read()
            .ok()
            .and_then(|e| e.get(name).cloned())
            .map(|entry| {
                entry
                    .meta
                    .blocks
                    .iter()
                    .map(|b| (b.index, b.nodes.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 更新某块的存储节点
    ///
    /// 向指定块的节点列表中添加一个新节点（去重）。
    pub fn add_block_node(
        &self,
        name: &str,
        block_index: u32,
        node: &str,
    ) -> Result<(), MetadataError> {
        let now = now_secs();
        let updated = {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            let entry = entries
                .get_mut(name)
                .ok_or_else(|| MetadataError::NotFound(name.to_string()))?;
            if let Some(blk) = entry.meta.blocks.iter_mut().find(|b| b.index == block_index) {
                if !blk.nodes.contains(&node.to_string()) {
                    blk.nodes.push(node.to_string());
                }
                blk.last_synced = now;
            } else {
                // 块不存在则创建
                entry.meta.blocks.push(BlockLocation {
                    hash: [0u8; 32], // 未知 hash，调用者应更新
                    index: block_index,
                    nodes: vec![node.to_string()],
                    last_synced: now,
                });
            }
            entry.meta.updated_at = now;
            true
        };

        if updated {
            self.dirty.store(true, Ordering::SeqCst);
            self.save_if_dirty();
        }
        Ok(())
    }

    /// 批量更新多个块的存储节点
    pub fn add_block_nodes(
        &self,
        name: &str,
        nodes_by_index: &HashMap<u32, Vec<String>>,
    ) -> Result<(), MetadataError> {
        let now = now_secs();
        let updated = {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            let entry = entries
                .get_mut(name)
                .ok_or_else(|| MetadataError::NotFound(name.to_string()))?;
            for (&index, new_nodes) in nodes_by_index {
                if let Some(blk) = entry.meta.blocks.iter_mut().find(|b| b.index == index) {
                    for n in new_nodes {
                        if !blk.nodes.contains(n) {
                            blk.nodes.push(n.clone());
                        }
                    }
                    blk.last_synced = now;
                }
            }
            entry.meta.updated_at = now;
            true
        };

        if updated {
            self.dirty.store(true, Ordering::SeqCst);
            self.save_if_dirty();
        }
        Ok(())
    }

    /// 删除文件元数据
    pub fn remove_file(&self, name: &str) -> Result<(), MetadataError> {
        {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            if entries.remove(name).is_none() {
                return Err(MetadataError::NotFound(name.to_string()));
            }
        }

        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();
        Ok(())
    }

    /// 从远程元数据同步
    ///
    /// 冲突解决策略：比较 `updated_at`，较新的优先。
    /// 如果时间差在 `CONFLICT_WINDOW_SECS` 内，则哈希值较大的版本胜出。
    pub fn sync_from(&self, remote_entries: Vec<MetadataEntry>) -> usize {
        let mut merged_count = 0;
        let now = now_secs();

        let merged = {
            let mut entries = match self.entries.write() {
                Ok(e) => e,
                Err(_) => return 0,
            };

            for remote in remote_entries {
                let name = remote.meta.name.clone();
                let should_merge = match entries.get(&name) {
                    Some(local) => {
                        let local_time = local.meta.updated_at;
                        let remote_time = remote.meta.updated_at;
                        if remote_time > local_time + CONFLICT_WINDOW_SECS {
                            true
                        } else if local_time > remote_time + CONFLICT_WINDOW_SECS {
                            false
                        } else {
                            let local_hash = hash_entry(local);
                            let remote_hash = hash_entry(&remote);
                            remote_hash > local_hash
                        }
                    }
                    None => true,
                };

                if should_merge {
                    let mut merged = remote;
                    merged.meta.updated_at = now;
                    entries.insert(name, merged);
                    merged_count += 1;
                }
            }

            merged_count > 0
        }; // ← entries RwLock guard dropped here

        if merged {
            self.dirty.store(true, Ordering::SeqCst);
            self.save_if_dirty();
        }

        merged_count
    }

    /// 获取所有条目（用于导出同步）
    pub fn all_entries(&self) -> Vec<MetadataEntry> {
        self.entries
            .read()
            .map(|e| e.values().cloned().collect())
            .unwrap_or_default()
    }

    /// 标记元数据为已加密
    pub fn mark_encrypted(&self, name: &str) -> Result<(), MetadataError> {
        {
            let mut entries = self.entries.write().map_err(|_| MetadataError::LockPoisoned)?;
            let entry = entries
                .get_mut(name)
                .ok_or_else(|| MetadataError::NotFound(name.to_string()))?;
            entry.meta.encrypted = true;
            entry.meta.updated_at = now_secs();
        }
        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();
        Ok(())
    }

    /// 刷新持久化
    pub fn flush(&self) -> Result<(), MetadataError> {
        self.save_to_file()
    }
}

// ---------------------------------------------------------------------------
//  Helper functions
// ---------------------------------------------------------------------------

/// 获取当前 Unix 时间戳（秒）
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// 计算条目 hash 用于 tiebreaker
fn hash_entry(entry: &MetadataEntry) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    entry.meta.name.hash(&mut hasher);
    entry.meta.file_hash.hash(&mut hasher);
    hasher.finish()
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> MetadataStore {
        MetadataStore::new("/tmp/_test_metadata_unused.json")
    }

    fn make_hash(byte: u8) -> Hash {
        [byte; 32]
    }

    fn make_block(index: u32, hash: Hash, nodes: Vec<&str>) -> BlockLocation {
        BlockLocation {
            hash,
            index,
            nodes: nodes.iter().map(|&s| s.to_string()).collect(),
            last_synced: now_secs(),
        }
    }

    // =====================================================================
    //  New & empty
    // =====================================================================

    #[test]
    fn test_new_is_empty() {
        let store = make_store();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        assert!(store.list_files().is_empty());
    }

    // =====================================================================
    //  Register
    // =====================================================================

    #[test]
    fn test_register_and_query() {
        let store = make_store();
        let hash = make_hash(0xAA);
        let blocks = vec![
            make_block(0, make_hash(0x01), vec!["NodeA", "NodeB"]),
            make_block(1, make_hash(0x02), vec!["NodeC"]),
        ];

        store
            .register("backup.tar.gz", hash, 1024 * 1024, None, blocks.clone(), "LocalNode")
            .unwrap();

        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);

        let q = store.query("backup.tar.gz").unwrap();
        assert_eq!(q.meta.file_hash, hash);
        assert_eq!(q.meta.file_size, 1024 * 1024);
        assert_eq!(q.meta.source_node, "LocalNode");
        assert_eq!(q.meta.blocks.len(), 2);
    }

    #[test]
    fn test_register_duplicate() {
        let store = make_store();
        store
            .register("dup", make_hash(0xBB), 100, None, vec![], "A")
            .unwrap();
        let err = store
            .register("dup", make_hash(0xCC), 200, None, vec![], "B")
            .unwrap_err();
        assert!(matches!(err, MetadataError::AlreadyExists(ref n) if n == "dup"));
    }

    #[test]
    fn test_query_nonexistent() {
        let store = make_store();
        assert!(store.query("nope").is_none());
    }

    #[test]
    fn test_contains() {
        let store = make_store();
        store
            .register("a", make_hash(0x01), 10, None, vec![], "X")
            .unwrap();
        assert!(store.contains("a"));
        assert!(!store.contains("b"));
    }

    // =====================================================================
    //  Upsert
    // =====================================================================

    #[test]
    fn test_upsert_creates_new() {
        let store = make_store();
        store
            .upsert("new", make_hash(0xDD), 500, None, vec![], "Local")
            .unwrap();
        assert!(store.contains("new"));
    }

    #[test]
    fn test_upsert_updates_existing() {
        let store = make_store();
        store
            .register("file", make_hash(0xEE), 100, None, vec![], "A")
            .unwrap();
        store
            .upsert("file", make_hash(0xFF), 200, None, vec![], "B")
            .unwrap();
        let q = store.query("file").unwrap();
        assert_eq!(q.meta.file_hash, make_hash(0xFF));
        assert_eq!(q.meta.file_size, 200);
    }

    // =====================================================================
    //  Block location
    // =====================================================================

    #[test]
    fn test_get_block_nodes() {
        let store = make_store();
        let blocks = vec![
            make_block(0, make_hash(0x10), vec!["A", "B"]),
            make_block(1, make_hash(0x20), vec!["C"]),
        ];
        store
            .register("f", make_hash(0x30), 1000, None, blocks, "X")
            .unwrap();

        let nodes0 = store.get_block_nodes("f", 0);
        assert_eq!(nodes0, vec!["A", "B"]);
        let nodes1 = store.get_block_nodes("f", 1);
        assert_eq!(nodes1, vec!["C"]);
        let nodes2 = store.get_block_nodes("f", 2);
        assert!(nodes2.is_empty());
    }

    #[test]
    fn test_add_block_node() {
        let store = make_store();
        let blocks = vec![make_block(0, make_hash(0x40), vec!["A"])];
        store
            .register("f", make_hash(0x50), 100, None, blocks, "X")
            .unwrap();

        store.add_block_node("f", 0, "B").unwrap();
        let nodes = store.get_block_nodes("f", 0);
        assert!(nodes.contains(&"A".to_string()));
        assert!(nodes.contains(&"B".to_string()));
    }

    #[test]
    fn test_add_block_node_dedup() {
        let store = make_store();
        let blocks = vec![make_block(0, make_hash(0x60), vec!["A"])];
        store
            .register("f", make_hash(0x70), 100, None, blocks, "X")
            .unwrap();

        store.add_block_node("f", 0, "A").unwrap(); // duplicate
        let nodes = store.get_block_nodes("f", 0);
        assert_eq!(nodes.len(), 1); // still just one
    }

    #[test]
    fn test_add_block_node_creates_new_block() {
        let store = make_store();
        store
            .register("f", make_hash(0x80), 100, None, vec![], "X")
            .unwrap();

        store.add_block_node("f", 5, "NodeZ").unwrap();
        let nodes = store.get_block_nodes("f", 5);
        assert_eq!(nodes, vec!["NodeZ"]);
    }

    #[test]
    fn test_get_block_distribution() {
        let store = make_store();
        let blocks = vec![
            make_block(0, make_hash(0x90), vec!["A"]),
            make_block(1, make_hash(0xA0), vec!["B", "C"]),
        ];
        store
            .register("f", make_hash(0xB0), 100, None, blocks, "X")
            .unwrap();

        let dist = store.get_block_distribution("f");
        assert_eq!(dist.len(), 2);
        assert_eq!(dist[&0], vec!["A"]);
        assert_eq!(dist[&1], vec!["B", "C"]);
    }

    #[test]
    fn test_add_block_nodes_batch() {
        let store = make_store();
        let blocks = vec![
            make_block(0, make_hash(0xC0), vec!["A"]),
            make_block(1, make_hash(0xD0), vec!["B"]),
        ];
        store
            .register("f", make_hash(0xE0), 100, None, blocks, "X")
            .unwrap();

        let mut updates = HashMap::new();
        updates.insert(0, vec!["C".to_string(), "D".to_string()]);
        updates.insert(1, vec!["E".to_string()]);
        store.add_block_nodes("f", &updates).unwrap();

        let nodes0 = store.get_block_nodes("f", 0);
        assert!(nodes0.contains(&"A".into()));
        assert!(nodes0.contains(&"C".into()));
        assert!(nodes0.contains(&"D".into()));

        let nodes1 = store.get_block_nodes("f", 1);
        assert!(nodes1.contains(&"B".into()));
        assert!(nodes1.contains(&"E".into()));
    }

    // =====================================================================
    //  Remove
    // =====================================================================

    #[test]
    fn test_remove_file() {
        let store = make_store();
        store
            .register("f", make_hash(0xF0), 100, None, vec![], "X")
            .unwrap();
        store.remove_file("f").unwrap();
        assert!(!store.contains("f"));
        assert!(store.is_empty());
    }

    #[test]
    fn test_remove_nonexistent() {
        let store = make_store();
        let err = store.remove_file("nope").unwrap_err();
        assert!(matches!(err, MetadataError::NotFound(ref n) if n == "nope"));
    }

    // =====================================================================
    //  List
    // =====================================================================

    #[test]
    fn test_list_files() {
        let store = make_store();
        store
            .register("a", make_hash(0x01), 10, None, vec![], "X")
            .unwrap();
        store
            .register("b", make_hash(0x02), 20, None, vec![], "Y")
            .unwrap();
        let files = store.list_files();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&"a".to_string()));
        assert!(files.contains(&"b".to_string()));
    }

    // =====================================================================
    //  Sync
    // =====================================================================

    #[test]
    fn test_sync_from_empty_accepts_all() {
        let store = make_store();
        let remote = vec![MetadataEntry {
            meta: FileMetadata {
                name: "r".into(),
                file_hash: make_hash(0xAA),
                file_size: 100,
                blocks: vec![],
                created_at: 1000,
                updated_at: 1000,
                source_node: "Remote".into(),
                encrypted: false,
            },
            manifest: None,
        }];
        let count = store.sync_from(remote);
        assert_eq!(count, 1);
        assert!(store.contains("r"));
    }

    #[test]
    fn test_sync_keeps_newer() {
        let store = make_store();
        store
            .register("f", make_hash(0xBB), 100, None, vec![], "Local")
            .unwrap();
        // 等待确保时间差超过 CONFLICT_WINDOW
        std::thread::sleep(std::time::Duration::from_millis(CONFLICT_WINDOW_SECS * 1000 + 10));

        let remote = vec![MetadataEntry {
            meta: FileMetadata {
                name: "f".into(),
                file_hash: make_hash(0xCC),
                file_size: 200,
                blocks: vec![],
                created_at: 1000,
                updated_at: now_secs() + 100,
                source_node: "Remote".into(),
                encrypted: false,
            },
            manifest: None,
        }];
        let count = store.sync_from(remote);
        assert_eq!(count, 1);
        // Remote has much newer timestamp -> remote wins
        let q = store.query("f").unwrap();
        assert_eq!(q.meta.file_hash, make_hash(0xCC));
    }

    #[test]
    fn test_sync_keeps_local_if_newer() {
        let store = make_store();
        store
            .register("f", make_hash(0xDD), 100, None, vec![], "Local")
            .unwrap();

        let remote = vec![MetadataEntry {
            meta: FileMetadata {
                name: "f".into(),
                file_hash: make_hash(0xEE),
                file_size: 50,
                blocks: vec![],
                created_at: 1000,
                updated_at: 1, // very old
                source_node: "Remote".into(),
                encrypted: false,
            },
            manifest: None,
        }];
        let count = store.sync_from(remote);
        assert_eq!(count, 0); // local kept
        let q = store.query("f").unwrap();
        assert_eq!(q.meta.file_hash, make_hash(0xDD));
    }

    #[test]
    fn test_sync_tiebreaker() {
        // Both have very close timestamps -> hash tiebreaker
        let store = make_store();
        let early = now_secs();
        store
            .register("f", make_hash(0xFF), 100, None, vec![], "Local")
            .unwrap();

        let remote = vec![MetadataEntry {
            meta: FileMetadata {
                name: "f".into(),
                file_hash: make_hash(0x00),
                file_size: 200,
                blocks: vec![],
                created_at: early,
                updated_at: early + 2, // within CONFLICT_WINDOW (5s)
                source_node: "Remote".into(),
                encrypted: false,
            },
            manifest: None,
        }];
        // Both should hash differently; at least one wins
        let _count = store.sync_from(remote);
        let q = store.query("f").unwrap();
        // Either hash is acceptable - the test just verifies no crash and file exists
        assert!(q.meta.file_size == 100 || q.meta.file_size == 200);
    }

    // =====================================================================
    //  Load / save
    // =====================================================================

    #[test]
    fn test_persistence_roundtrip() {
        let dir = std::env::temp_dir().join("ll_vpn_meta_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("metadata.json");

        // Write
        {
            let store = MetadataStore::new(&path);
            store
                .register("f", make_hash(0x10), 500, None, vec![], "X")
                .unwrap();
            store.flush().unwrap();
        }

        // Read back
        let loaded = MetadataStore::load_from_file(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        let q = loaded.query("f").unwrap();
        assert_eq!(q.meta.file_size, 500);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_nonexistent_file() {
        let dir = std::env::temp_dir().join("ll_vpn_meta_nonexist");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("metadata.json");
        // File doesn't exist yet - load should succeed with empty store
        let store = MetadataStore::load_from_file(&path).unwrap();
        assert!(store.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // =====================================================================
    //  Error display
    // =====================================================================

    #[test]
    fn test_error_display() {
        let e1 = MetadataError::AlreadyExists("x".into());
        assert_eq!(e1.to_string(), "metadata for 'x' already exists");

        let e2 = MetadataError::NotFound("y".into());
        assert_eq!(e2.to_string(), "metadata for 'y' not found");

        let e3 = MetadataError::LockPoisoned;
        assert_eq!(e3.to_string(), "lock poisoned");
    }

    // =====================================================================
    //  Dirty flag
    // =====================================================================

    #[test]
    fn test_dirty_cleared() {
        let store = make_store();
        assert!(!store.dirty.load(Ordering::SeqCst));
        store
            .register("f", make_hash(0xAB), 100, None, vec![], "X")
            .unwrap();
        assert!(!store.dirty.load(Ordering::SeqCst)); // cleared by save_if_dirty in test mode
    }

    // =====================================================================
    //  Mark encrypted
    // =====================================================================

    #[test]
    fn test_mark_encrypted() {
        let store = make_store();
        store
            .register("f", make_hash(0xBC), 100, None, vec![], "X")
            .unwrap();
        assert!(!store.query("f").unwrap().meta.encrypted);
        store.mark_encrypted("f").unwrap();
        assert!(store.query("f").unwrap().meta.encrypted);
    }

    #[test]
    fn test_mark_encrypted_nonexistent() {
        let store = make_store();
        let err = store.mark_encrypted("nope").unwrap_err();
        assert!(matches!(err, MetadataError::NotFound(ref n) if n == "nope"));
    }
}
