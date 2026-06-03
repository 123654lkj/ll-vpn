//! P4-4: 多源并行下载 — DownloadManager + ReorderBuffer + 进度跟踪
//!
//! 管理从多个源节点并行下载文件块的过程。支持：
//! - 重排序缓冲区（ReorderBuffer），处理块乱序到达
//! - 多任务并行管理（DownloadManager）
//! - 进度跟踪与 ETA 估算
//! - 源节点选择（负载均衡）
//! - 断点续传（记录已完成 block_index）
//!
//! # 注意
//!
//! DownloadManager 是纯状态管理，不涉及真正的网络 I/O。网络请求由外
//! 部调度层（command / main）集成。

use crate::storage::chunk::{FileManifest, Hash};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 最大失败块数 — 超过此数则整个下载标记为失败。
#[cfg_attr(not(test), allow(dead_code))]
const MAX_FAILED_BLOCKS: u32 = 3;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// 下载状态。
#[derive(Debug, Clone, PartialEq)]
pub enum DownloadStatus {
    /// 等待开始。
    Pending,
    /// 下载进行中。
    Downloading {
        /// 进度比例 0.0 ~ 1.0。
        progress: f64,
        /// 已下载字节数。
        downloaded_bytes: u64,
        /// 总字节数。
        total_bytes: u64,
    },
    /// 下载完成，包含重组后的完整文件数据。
    Completed(Vec<u8>),
    /// 下载失败，包含错误描述。
    Failed(String),
}

/// 下载任务描述。
#[derive(Debug, Clone)]
pub struct DownloadTask {
    /// 文件名。
    pub file_name: String,
    /// 文件 SHA-256 hash。
    pub file_hash: Hash,
    /// 文件总大小（字节）。
    pub total_size: u64,
    /// 文件 manifest（如果可用）。
    pub manifest: Option<FileManifest>,
    /// 块索引 → 可用源节点列表。
    pub block_sources: HashMap<u32, Vec<String>>,
}

/// 块请求消息。
#[derive(Debug, Clone)]
pub struct BlockRequest {
    /// 所属文件名。
    pub file_name: String,
    /// 块索引。
    pub block_index: u32,
    /// 块 hash。
    pub block_hash: Hash,
}

/// 块响应消息。
#[derive(Debug, Clone)]
pub struct BlockResponse {
    /// 所属文件名。
    pub file_name: String,
    /// 块索引。
    pub block_index: u32,
    /// 块数据。
    pub data: Vec<u8>,
    /// 是否成功。
    pub success: bool,
    /// 错误信息（如果失败）。
    pub error: Option<String>,
}

/// 重排序缓冲区 — 处理乱序到达的块。
///
/// 内部使用 `BTreeMap<u32, Vec<u8>>` 按键（块索引）排序存储，
/// 确保可以按连续顺序输出。
#[derive(Debug, Clone)]
pub struct ReorderBuffer {
    /// 按 index 存储的块数据。
    blocks: BTreeMap<u32, Vec<u8>>,
    /// 期望的总块数。
    expected_count: u32,
    /// 下一个期望输出的块索引。
    next_expected: u32,
}

impl ReorderBuffer {
    /// 创建新的重排序缓冲区。
    ///
    /// `expected_count` 是文件的总块数。
    pub fn new(expected_count: u32) -> Self {
        Self {
            blocks: BTreeMap::new(),
            expected_count,
            next_expected: 0,
        }
    }

    /// 接收一个块。
    ///
    /// # 错误
    ///
    /// - `index` 超出 `[0, expected_count)` 范围。
    /// - `index` 对应的块已经存在（重复推送）。
    pub fn push(&mut self, index: u32, data: Vec<u8>) -> Result<(), String> {
        if index >= self.expected_count {
            return Err(format!(
                "block index {} out of range [0, {})",
                index, self.expected_count
            ));
        }
        if self.blocks.contains_key(&index) {
            return Err(format!("block index {} already received", index));
        }
        self.blocks.insert(index, data);
        Ok(())
    }

    /// 是否所有块都已收到，可以组装成完整文件。
    pub fn can_assemble(&self) -> bool {
        self.blocks.len() == self.expected_count as usize
    }

    /// 取出所有按序可输出的连续块。
    ///
    /// 从 `next_expected` 开始，持续取出连续的块并递增
    /// `next_expected`，直到遇到缺口为止。
    pub fn drain_ordered(&mut self) -> Vec<(u32, Vec<u8>)> {
        let mut result = Vec::new();
        while let Some(data) = self.blocks.remove(&self.next_expected) {
            result.push((self.next_expected, data));
            self.next_expected += 1;
        }
        result
    }

    /// 返回尚未收到的块数量。
    pub fn remaining(&self) -> u32 {
        self.expected_count.saturating_sub(self.blocks.len() as u32)
    }

    /// 是否所有块都已收到（等价于 `can_assemble`）。
    pub fn is_complete(&self) -> bool {
        self.can_assemble()
    }
}

/// 下载进度跟踪。
#[derive(Debug, Clone)]
pub struct DownloadProgress {
    /// 文件名。
    pub file_name: String,
    /// 总块数。
    pub total_blocks: u32,
    /// 已完成块数。
    pub completed_blocks: u32,
    /// 失败块数。
    pub failed_blocks: u32,
    /// 总字节数。
    pub total_bytes: u64,
    /// 已下载字节数。
    pub downloaded_bytes: u64,
    /// 开始时间（Unix 秒）。
    pub started_at: u64,
    /// 预估剩余秒数。
    pub estimated_remaining_secs: Option<u64>,
}

impl DownloadProgress {
    /// 创建新的进度跟踪。
    pub fn new(file_name: &str, total_blocks: u32, total_bytes: u64) -> Self {
        Self {
            file_name: file_name.to_string(),
            total_blocks,
            completed_blocks: 0,
            failed_blocks: 0,
            total_bytes,
            downloaded_bytes: 0,
            started_at: now_secs(),
            estimated_remaining_secs: None,
        }
    }

    /// 更新进度数据并重新计算 ETA。
    pub fn update(&mut self, completed_blocks: u32, failed_blocks: u32, downloaded_bytes: u64) {
        self.completed_blocks = completed_blocks;
        self.failed_blocks = failed_blocks;
        self.downloaded_bytes = downloaded_bytes;
        self.update_eta();
    }

    /// 返回进度比例（0.0 ~ 1.0）。
    pub fn progress_fraction(&self) -> f64 {
        if self.total_blocks == 0 {
            return 1.0;
        }
        (self.completed_blocks as f64) / (self.total_blocks as f64)
    }

    /// 重新估算剩余时间。
    fn update_eta(&mut self) {
        if self.completed_blocks == 0 || self.total_blocks == 0 {
            self.estimated_remaining_secs = None;
            return;
        }
        let elapsed = now_secs().saturating_sub(self.started_at);
        if elapsed == 0 {
            self.estimated_remaining_secs = None;
            return;
        }
        let bytes_per_sec = self.downloaded_bytes / elapsed;
        if bytes_per_sec == 0 {
            self.estimated_remaining_secs = None;
            return;
        }
        let remaining_bytes = self.total_bytes.saturating_sub(self.downloaded_bytes);
        self.estimated_remaining_secs = Some(remaining_bytes / bytes_per_sec);
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// 内部下载任务状态。
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct InternalTask {
    /// 任务描述。
    task: DownloadTask,
    /// 当前状态。
    status: DownloadStatus,
    /// 进度跟踪。
    progress: DownloadProgress,
    /// 重排序缓冲区。
    buffer: ReorderBuffer,
    /// 已完成的块索引集合（用于断点续传）。
    completed_blocks: HashSet<u32>,
    /// 块索引 → 已失败的源节点列表。
    failed_blocks: HashMap<u32, Vec<String>>,
    /// 块索引 → 当前分配的源节点。
    node_assignments: HashMap<u32, String>,
}

impl InternalTask {
    fn new(task: DownloadTask) -> Self {
        let total_blocks = task.block_sources.len() as u32;
        let progress = DownloadProgress::new(&task.file_name, total_blocks, task.total_size);
        let buffer = ReorderBuffer::new(total_blocks);
        Self {
            status: DownloadStatus::Pending,
            progress,
            buffer,
            completed_blocks: HashSet::new(),
            failed_blocks: HashMap::new(),
            node_assignments: HashMap::new(),
            task,
        }
    }
}

// ---------------------------------------------------------------------------
// DownloadManager
// ---------------------------------------------------------------------------

/// 下载管理器 — 纯状态管理，不涉及网络 I/O。
///
/// 管理多个并行下载任务，负责任务创建、状态查询、源节点选择
/// （负载均衡）、取消下载等。
///
/// 网络请求由外部调度层（command / main）集成。
#[derive(Debug)]
pub struct DownloadManager {
    /// 所有下载任务（文件名 → 内部状态）。
    tasks: RwLock<HashMap<String, InternalTask>>,
    /// 节点负载计数（节点名 → 当前分配的块数）。
    node_load: RwLock<HashMap<String, u32>>,
}

impl DownloadManager {
    /// 创建新的下载管理器。
    pub fn new() -> Self {
        Self {
            tasks: RwLock::new(HashMap::new()),
            node_load: RwLock::new(HashMap::new()),
        }
    }

    /// 创建下载任务。
    ///
    /// `file_name` — 文件名。
    /// `manifest` — 文件 manifest。
    /// `block_sources` — 块索引 → 可用源节点列表。
    pub fn create_task(
        &self,
        file_name: &str,
        _manifest: &FileManifest,
        block_sources: HashMap<u32, Vec<String>>,
    ) -> DownloadTask {
        let total_size = _manifest.file_size;
        let file_hash = _manifest.file_hash;
        let task = DownloadTask {
            file_name: file_name.to_string(),
            file_hash,
            total_size,
            manifest: Some(_manifest.clone()),
            block_sources,
        };

        let internal = InternalTask::new(task.clone());

        if let Ok(mut tasks) = self.tasks.write() {
            tasks.insert(file_name.to_string(), internal);
        }

        task
    }

    /// 获取下载状态。
    pub fn get_status(&self, file_name: &str) -> Option<DownloadStatus> {
        let tasks = self.tasks.read().ok()?;
        tasks.get(file_name).map(|t| t.status.clone())
    }

    /// 选择最优源节点（负载均衡）。
    ///
    /// 在 `available_nodes` 中选当前负载（活跃分配数）最低的节点。
    /// 若多个节点负载相同，返回其中第一个。
    pub fn select_source(&self, available_nodes: &[String]) -> Option<String> {
        if available_nodes.is_empty() {
            return None;
        }
        let load = self.node_load.read().ok()?;
        available_nodes
            .iter()
            .min_by_key(|n| load.get(*n).copied().unwrap_or(0))
            .cloned()
    }

    /// 取消下载。
    ///
    /// # 错误
    ///
    /// - 文件不存在。
    pub fn cancel(&self, file_name: &str) -> Result<(), String> {
        let mut tasks = self.tasks.write().map_err(|_| "lock poisoned".to_string())?;
        tasks.remove(file_name).ok_or_else(|| {
            format!("download task '{}' not found", file_name)
        })?;
        Ok(())
    }

    /// 列出所有正在下载（Pending / Downloading）的文件。
    pub fn active_downloads(&self) -> Vec<String> {
        let tasks = match self.tasks.read() {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };
        tasks
            .iter()
            .filter(|(_, t)| {
                matches!(t.status, DownloadStatus::Pending | DownloadStatus::Downloading { .. })
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    // -----------------------------------------------------------------------
    // 内部方法
    // -----------------------------------------------------------------------

    /// 标记某块开始下载（增加节点负载）。
    #[cfg_attr(not(test), allow(dead_code))]
    fn assign_block(&self, file_name: &str, block_index: u32, node: String) -> Result<(), String> {
        let tasks = self.tasks.write().map_err(|_| "lock poisoned".to_string())?;
        if let Some(task) = tasks.get(file_name) {
            // Check if block is already completed
            if task.completed_blocks.contains(&block_index) {
                return Err(format!("block {} already completed", block_index));
            }
        }
        drop(tasks);

        // Increment node load
        if let Ok(mut load) = self.node_load.write() {
            *load.entry(node.clone()).or_insert(0) += 1;
        }

        // Record assignment
        let mut tasks = self.tasks.write().map_err(|_| "lock poisoned".to_string())?;
        if let Some(task) = tasks.get_mut(file_name) {
            task.node_assignments.insert(block_index, node);
        }
        Ok(())
    }

    /// 标记某块完成下载。
    #[cfg_attr(not(test), allow(dead_code))]
    fn complete_block(
        &self,
        file_name: &str,
        block_index: u32,
        data: Vec<u8>,
    ) -> Result<(), String> {
        // Find the assigned node for this block
        let node = {
            let tasks = self.tasks.read().map_err(|_| "lock poisoned".to_string())?;
            tasks
                .get(file_name)
                .and_then(|t| t.node_assignments.get(&block_index).cloned())
        };

        // Decrement node load
        if let Some(ref node) = node {
            if let Ok(mut load) = self.node_load.write() {
                if let Some(count) = load.get_mut(node) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        load.remove(node);
                    }
                }
            }
        }

        let mut tasks = self.tasks.write().map_err(|_| "lock poisoned".to_string())?;
        let task = tasks
            .get_mut(file_name)
            .ok_or_else(|| format!("download task '{}' not found", file_name))?;

        // Mark completed
        task.completed_blocks.insert(block_index);
        task.node_assignments.remove(&block_index);

        // Push to reorder buffer
        task.buffer
            .push(block_index, data)
            .map_err(|e| format!("reorder buffer push failed: {}", e))?;

        // Update progress
        let completed = task.completed_blocks.len() as u32;
        let failed = task.failed_blocks.len() as u32;
        let downloaded = task.completed_blocks.iter().map(|_idx| {
            // Estimate block size from total size / total blocks
            task.task.total_size / task.task.block_sources.len() as u64
        }).sum::<u64>();
        task.progress.update(completed, failed, downloaded);

        // Update status
        if task.buffer.is_complete() {
            task.status = DownloadStatus::Downloading {
                progress: 1.0,
                downloaded_bytes: task.task.total_size,
                total_bytes: task.task.total_size,
            };
        } else {
            task.status = DownloadStatus::Downloading {
                progress: task.progress.progress_fraction(),
                downloaded_bytes: downloaded,
                total_bytes: task.task.total_size,
            };
        }

        Ok(())
    }

    /// 标记某块下载失败。
    #[cfg_attr(not(test), allow(dead_code))]
    fn fail_block(&self, file_name: &str, block_index: u32, _error: String) -> Result<(), String> {
        // Find the assigned node for this block
        let node = {
            let tasks = self.tasks.read().map_err(|_| "lock poisoned".to_string())?;
            tasks
                .get(file_name)
                .and_then(|t| t.node_assignments.get(&block_index).cloned())
        };

        // Decrement node load
        if let Some(ref node) = node {
            if let Ok(mut load) = self.node_load.write() {
                if let Some(count) = load.get_mut(node) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        load.remove(node);
                    }
                }
            }
        }

        let mut tasks = self.tasks.write().map_err(|_| "lock poisoned".to_string())?;
        let task = tasks
            .get_mut(file_name)
            .ok_or_else(|| format!("download task '{}' not found", file_name))?;

        // Record failure
        task.node_assignments.remove(&block_index);
        let failed_nodes = task.failed_blocks.entry(block_index).or_default();
        if let Some(node) = node {
            failed_nodes.push(node);
        }

        // If total failed blocks exceeds limit, fail the entire download
        let total_failed: u32 = task.failed_blocks.len() as u32;
        if total_failed >= MAX_FAILED_BLOCKS {
            task.status = DownloadStatus::Failed(format!(
                "too many failed blocks: {} (max {})",
                total_failed, MAX_FAILED_BLOCKS
            ));
        }

        // Update progress
        let completed = task.completed_blocks.len() as u32;
        let failed = task.failed_blocks.len() as u32;
        let downloaded = task.completed_blocks.iter().map(|_idx| {
            task.task.total_size / task.task.block_sources.len() as u64
        }).sum::<u64>();
        task.progress.update(completed, failed, downloaded);

        Ok(())
    }
}

impl Default for DownloadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 获取当前 Unix 时间戳（秒）。
#[cfg_attr(not(test), allow(dead_code))]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::chunk::Chunker;

    // =====================================================================
    //  Helpers
    // =====================================================================

    /// 生成确定性测试数据。
    fn test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    /// 创建一个简单的 DownloadManager 用于测试。
    fn make_manager() -> DownloadManager {
        DownloadManager::new()
    }

    /// 创建包含 n 个块的测试 manifest。
    fn make_test_manifest(data_size: usize) -> (FileManifest, Vec<Vec<u8>>) {
        let chunker = Chunker::with_chunk_size(1024); // 1 KiB chunks for testing
        let data = test_data(data_size);
        chunker.chunk_data(&data)
    }

    /// 创建 block_sources：每个块有 2 个源节点。
    fn make_block_sources(num_blocks: u32) -> HashMap<u32, Vec<String>> {
        let mut sources = HashMap::new();
        for i in 0..num_blocks {
            sources.insert(i, vec![format!("node_{}", i), format!("backup_{}", i)]);
        }
        sources
    }

    // =====================================================================
    //  ReorderBuffer Tests
    // =====================================================================

    #[test]
    fn test_reorder_buffer_new_empty() {
        let mut buf = ReorderBuffer::new(5);
        assert_eq!(buf.expected_count, 5);
        assert_eq!(buf.next_expected, 0);
        assert_eq!(buf.remaining(), 5);
        assert!(!buf.can_assemble());
        assert!(!buf.is_complete());
        assert!(buf.drain_ordered().is_empty());
    }

    #[test]
    fn test_reorder_buffer_push_in_order() {
        let mut buf = ReorderBuffer::new(3);
        assert!(buf.push(0, vec![0; 10]).is_ok());
        assert!(buf.push(1, vec![1; 10]).is_ok());
        assert!(buf.push(2, vec![2; 10]).is_ok());
        assert!(buf.can_assemble());
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_reorder_buffer_push_out_of_order() {
        let mut buf = ReorderBuffer::new(4);
        assert!(buf.push(2, vec![2; 10]).is_ok());
        assert!(buf.push(0, vec![0; 10]).is_ok());
        assert!(buf.push(3, vec![3; 10]).is_ok());
        assert!(!buf.can_assemble()); // still missing index 1
        assert_eq!(buf.remaining(), 1);
        // drain_ordered should only return index 0
        let drained = buf.drain_ordered();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].0, 0);
        // next_expected should now be 1
        assert_eq!(buf.next_expected, 1);
    }

    #[test]
    fn test_reorder_buffer_push_duplicate_rejected() {
        let mut buf = ReorderBuffer::new(3);
        assert!(buf.push(0, vec![0; 10]).is_ok());
        let err = buf.push(0, vec![1; 10]).unwrap_err();
        assert!(err.contains("already received"));
    }

    #[test]
    fn test_reorder_buffer_push_invalid_index() {
        let mut buf = ReorderBuffer::new(3);
        let err = buf.push(3, vec![0; 10]).unwrap_err();
        assert!(err.contains("out of range"));
        let err = buf.push(999, vec![0; 10]).unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_reorder_buffer_drain_ordered_partial() {
        let mut buf = ReorderBuffer::new(5);
        // Push indices 0, 1, 3, 4 (missing 2)
        buf.push(0, vec![0; 1]).unwrap();
        buf.push(1, vec![1; 1]).unwrap();
        buf.push(3, vec![3; 1]).unwrap();
        buf.push(4, vec![4; 1]).unwrap();

        let drained = buf.drain_ordered();
        assert_eq!(drained.len(), 2); // only 0 and 1 are contiguous
        assert_eq!(drained[0].0, 0);
        assert_eq!(drained[1].0, 1);
        assert_eq!(buf.next_expected, 2);

        // Now push index 2
        buf.push(2, vec![2; 1]).unwrap();
        let drained = buf.drain_ordered();
        assert_eq!(drained.len(), 3); // 2, 3, 4
        assert_eq!(drained[0].0, 2);
        assert_eq!(drained[1].0, 3);
        assert_eq!(drained[2].0, 4);
        assert_eq!(buf.next_expected, 5);
        // All data drained — buffer is empty.
        assert!(buf.blocks.is_empty());
    }

    #[test]
    fn test_reorder_buffer_drain_ordered_all() {
        let mut buf = ReorderBuffer::new(4);
        buf.push(0, vec![0; 1]).unwrap();
        buf.push(1, vec![1; 1]).unwrap();
        buf.push(2, vec![2; 1]).unwrap();
        buf.push(3, vec![3; 1]).unwrap();

        let drained = buf.drain_ordered();
        assert_eq!(drained.len(), 4);
        for (i, (idx, _)) in drained.iter().enumerate() {
            assert_eq!(*idx, i as u32);
        }
        assert_eq!(buf.next_expected, 4);
        assert!(buf.blocks.is_empty());
        // After draining, the buffer is empty — all data consumed.
    }

    #[test]
    fn test_reorder_buffer_remaining() {
        let mut buf = ReorderBuffer::new(5);
        assert_eq!(buf.remaining(), 5);
        buf.push(0, vec![0; 1]).unwrap();
        assert_eq!(buf.remaining(), 4);
        buf.push(1, vec![1; 1]).unwrap();
        assert_eq!(buf.remaining(), 3);
        buf.push(2, vec![2; 1]).unwrap();
        assert_eq!(buf.remaining(), 2);
        buf.push(3, vec![3; 1]).unwrap();
        assert_eq!(buf.remaining(), 1);
        buf.push(4, vec![4; 1]).unwrap();
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_reorder_buffer_zero_expected() {
        let mut buf = ReorderBuffer::new(0);
        assert!(buf.can_assemble());
        assert!(buf.is_complete());
        assert_eq!(buf.remaining(), 0);
        assert!(buf.drain_ordered().is_empty());
        // Push should fail for index 0 when expected_count is 0
        let mut buf2 = ReorderBuffer::new(0);
        let err = buf2.push(0, vec![0; 1]).unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn test_reorder_buffer_can_assemble_edge() {
        let mut buf = ReorderBuffer::new(1);
        assert!(!buf.can_assemble());
        buf.push(0, vec![42; 10]).unwrap();
        assert!(buf.can_assemble());
    }

    // =====================================================================
    //  DownloadProgress Tests
    // =====================================================================

    #[test]
    fn test_download_progress_new() {
        let p = DownloadProgress::new("test.txt", 10, 1000);
        assert_eq!(p.file_name, "test.txt");
        assert_eq!(p.total_blocks, 10);
        assert_eq!(p.completed_blocks, 0);
        assert_eq!(p.total_bytes, 1000);
        assert_eq!(p.downloaded_bytes, 0);
        assert!(p.started_at > 0);
        assert!(p.estimated_remaining_secs.is_none());
    }

    #[test]
    fn test_download_progress_fraction() {
        let mut p = DownloadProgress::new("test.txt", 10, 1000);
        assert_eq!(p.progress_fraction(), 0.0);
        p.update(5, 0, 500);
        assert!((p.progress_fraction() - 0.5).abs() < 1e-10);
        p.update(10, 0, 1000);
        assert!((p.progress_fraction() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_download_progress_zero_blocks() {
        let p = DownloadProgress::new("empty.txt", 0, 0);
        assert_eq!(p.progress_fraction(), 1.0);
    }

    #[test]
    fn test_download_progress_update() {
        let mut p = DownloadProgress::new("test.txt", 20, 2000);
        p.update(5, 1, 500);
        assert_eq!(p.completed_blocks, 5);
        assert_eq!(p.failed_blocks, 1);
        assert_eq!(p.downloaded_bytes, 500);
    }

    #[test]
    fn test_download_progress_eta() {
        let mut p = DownloadProgress {
            file_name: "test.txt".to_string(),
            total_blocks: 10,
            completed_blocks: 0,
            failed_blocks: 0,
            total_bytes: 1000,
            downloaded_bytes: 0,
            started_at: now_secs() - 10, // 10 seconds ago
            estimated_remaining_secs: None,
        };
        p.update_eta();
        // No completed blocks → no ETA
        assert!(p.estimated_remaining_secs.is_none());

        p.completed_blocks = 5;
        p.downloaded_bytes = 500;
        p.update_eta();
        // 500 bytes in 10 sec = 50 bytes/sec, remaining 500 bytes → ~10 sec
        assert!(p.estimated_remaining_secs.is_some());
        assert_eq!(p.estimated_remaining_secs.unwrap(), 10);
    }

    #[test]
    fn test_download_progress_eta_zero_elapsed() {
        let mut p = DownloadProgress::new("test.txt", 10, 1000);
        p.completed_blocks = 1;
        p.downloaded_bytes = 100;
        // started_at is now, so elapsed ≈ 0
        p.update_eta();
        assert!(p.estimated_remaining_secs.is_none());
    }

    // =====================================================================
    //  DownloadManager Tests
    // =====================================================================

    #[test]
    fn test_download_manager_create_task() {
        let mgr = make_manager();
        let (manifest, _chunks) = make_test_manifest(5000);
        let sources = make_block_sources(manifest.chunks.len() as u32);

        let task = mgr.create_task("test.txt", &manifest, sources);
        assert_eq!(task.file_name, "test.txt");
        assert_eq!(task.total_size, manifest.file_size);

        let status = mgr.get_status("test.txt");
        assert!(status.is_some());
        assert_eq!(status.unwrap(), DownloadStatus::Pending);
    }

    #[test]
    fn test_download_manager_get_status_nonexistent() {
        let mgr = make_manager();
        assert!(mgr.get_status("nonexistent.txt").is_none());
    }

    #[test]
    fn test_download_manager_cancel() {
        let mgr = make_manager();
        let (manifest, _chunks) = make_test_manifest(3000);
        let sources = make_block_sources(manifest.chunks.len() as u32);
        mgr.create_task("test.txt", &manifest, sources);

        assert!(mgr.get_status("test.txt").is_some());
        mgr.cancel("test.txt").unwrap();
        assert!(mgr.get_status("test.txt").is_none());
    }

    #[test]
    fn test_download_manager_cancel_nonexistent() {
        let mgr = make_manager();
        let err = mgr.cancel("nonexistent.txt").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_download_manager_active_downloads() {
        let mgr = make_manager();
        assert!(mgr.active_downloads().is_empty());

        let (manifest1, _) = make_test_manifest(2000);
        let (manifest2, _) = make_test_manifest(3000);
        let sources1 = make_block_sources(manifest1.chunks.len() as u32);
        let sources2 = make_block_sources(manifest2.chunks.len() as u32);

        mgr.create_task("file1.txt", &manifest1, sources1);
        mgr.create_task("file2.txt", &manifest2, sources2);

        let active = mgr.active_downloads();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"file1.txt".to_string()));
        assert!(active.contains(&"file2.txt".to_string()));
    }

    #[test]
    fn test_download_manager_active_downloads_after_cancel() {
        let mgr = make_manager();
        let (manifest, _) = make_test_manifest(2000);
        let sources = make_block_sources(manifest.chunks.len() as u32);
        mgr.create_task("file.txt", &manifest, sources);
        assert_eq!(mgr.active_downloads().len(), 1);

        mgr.cancel("file.txt").unwrap();
        assert!(mgr.active_downloads().is_empty());
    }

    #[test]
    fn test_download_manager_select_source_empty() {
        let mgr = make_manager();
        let nodes: Vec<String> = vec![];
        assert!(mgr.select_source(&nodes).is_none());
    }

    #[test]
    fn test_download_manager_select_source_single() {
        let mgr = make_manager();
        let nodes = vec!["node_a".to_string()];
        let selected = mgr.select_source(&nodes);
        assert_eq!(selected, Some("node_a".to_string()));
    }

    #[test]
    fn test_download_manager_select_source_load_balancing() {
        let mgr = make_manager();
        let (manifest, _) = make_test_manifest(5000);
        let sources = make_block_sources(manifest.chunks.len() as u32);
        mgr.create_task("test.txt", &manifest, sources);

        let nodes = vec![
            "node_a".to_string(),
            "node_b".to_string(),
            "node_c".to_string(),
        ];

        // All have load 0 → pick first (node_a)
        assert_eq!(mgr.select_source(&nodes), Some("node_a".to_string()));

        // Assign a block to node_a to increase its load
        mgr.assign_block("test.txt", 0, "node_a".to_string()).unwrap();

        // Now node_b and node_c have lower load → pick node_b (first with 0)
        assert_eq!(mgr.select_source(&nodes), Some("node_b".to_string()));

        // Assign blocks to node_b as well
        mgr.assign_block("test.txt", 1, "node_b".to_string()).unwrap();
        mgr.assign_block("test.txt", 2, "node_b".to_string()).unwrap();

        // Now node_c has lowest load (0)
        assert_eq!(mgr.select_source(&nodes), Some("node_c".to_string()));
    }

    #[test]
    fn test_download_manager_select_source_all_equal_load() {
        let mgr = make_manager();
        let nodes = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        // All have same load (0) → first one
        assert_eq!(mgr.select_source(&nodes), Some("x".to_string()));
    }

    #[test]
    fn test_download_manager_complete_block() {
        let mgr = make_manager();
        let (manifest, chunks) = make_test_manifest(3000);
        let num_blocks = manifest.chunks.len() as u32;
        let sources = make_block_sources(num_blocks);
        mgr.create_task("test.txt", &manifest, sources);

        // Assign and complete each block
        for i in 0..num_blocks {
            mgr.assign_block("test.txt", i, format!("node_{}", i)).unwrap();
            mgr.complete_block("test.txt", i, chunks[i as usize].clone()).unwrap();
        }

        let status = mgr.get_status("test.txt").unwrap();
        if let DownloadStatus::Downloading { progress, .. } = status {
            assert!((progress - 1.0).abs() < 1e-10);
        } else {
            panic!("expected Downloading status, got {:?}", status);
        }
    }

    #[test]
    fn test_download_manager_fail_block() {
        let mgr = make_manager();
        let (manifest, _chunks) = make_test_manifest(5000);
        let num_blocks = manifest.chunks.len() as u32;
        let sources = make_block_sources(num_blocks);
        mgr.create_task("test.txt", &manifest, sources);

        // Fail MAX_FAILED_BLOCKS blocks
        for i in 0..MAX_FAILED_BLOCKS {
            mgr.assign_block("test.txt", i, format!("node_{}", i)).unwrap();
            mgr.fail_block("test.txt", i, format!("timeout for block {}", i)).unwrap();
        }

        let status = mgr.get_status("test.txt").unwrap();
        assert!(
            matches!(status, DownloadStatus::Failed(ref msg) if msg.contains("too many failed blocks")),
            "expected Failed status, got {:?}",
            status
        );
    }

    #[test]
    fn test_download_manager_fail_then_recover() {
        let mgr = make_manager();
        let (manifest, chunks) = make_test_manifest(3000);
        let num_blocks = manifest.chunks.len() as u32;
        let mut sources = make_block_sources(num_blocks);
        // Remove backup for block 0 to ensure no retry sources
        sources.insert(0, vec!["node_fail".to_string()]);
        mgr.create_task("test.txt", &manifest, sources);

        // Fail one block (under the max limit)
        mgr.assign_block("test.txt", 0, "node_fail".to_string()).unwrap();
        mgr.fail_block("test.txt", 0, "timeout".to_string()).unwrap();

        // Complete the rest
        for i in 1..num_blocks {
            mgr.assign_block("test.txt", i, format!("node_{}", i)).unwrap();
            mgr.complete_block("test.txt", i, chunks[i as usize].clone()).unwrap();
        }

        let status = mgr.get_status("test.txt").unwrap();
        // Should still be Downloading (not Failed — only 1 failed block < 3)
        assert!(
            matches!(status, DownloadStatus::Downloading { .. }),
            "expected Downloading status, got {:?}",
            status
        );
    }

    // =====================================================================
    //  Integration Tests
    // =====================================================================

    #[test]
    fn test_full_download_flow() {
        let mgr = make_manager();
        let chunker = Chunker::with_chunk_size(1024);
        let data = test_data(5000);
        let (manifest, chunks) = chunker.chunk_data(&data);

        let num_blocks = manifest.chunks.len() as u32;
        let sources = make_block_sources(num_blocks);

        // Create task
        mgr.create_task("flow_test.bin", &manifest, sources);
        assert_eq!(mgr.active_downloads().len(), 1);

        // Simulate downloading blocks in random order
        let mut indices: Vec<u32> = (0..num_blocks).collect();
        // Use a fixed seed for deterministic test
        indices.reverse(); // reverse order is deterministic

        for &i in &indices {
            mgr.assign_block("flow_test.bin", i, format!("node_{}", i)).unwrap();
            mgr.complete_block("flow_test.bin", i, chunks[i as usize].clone()).unwrap();
        }

        let status = mgr.get_status("flow_test.bin").unwrap();
        if let DownloadStatus::Downloading { progress, downloaded_bytes, total_bytes } = &status {
            assert!((*progress - 1.0).abs() < 1e-10);
            assert_eq!(*downloaded_bytes, data.len() as u64);
            assert_eq!(*total_bytes, data.len() as u64);
        } else {
            panic!("expected Downloading status, got {:?}", status);
        }

        // Cancel
        mgr.cancel("flow_test.bin").unwrap();
        assert!(mgr.get_status("flow_test.bin").is_none());
        assert!(mgr.active_downloads().is_empty());
    }

    #[test]
    fn test_multiple_concurrent_downloads() {
        let mgr = make_manager();
        let (manifest1, chunks1) = make_test_manifest(2000);
        let (manifest2, chunks2) = make_test_manifest(4000);

        let sources1 = make_block_sources(manifest1.chunks.len() as u32);
        let sources2 = make_block_sources(manifest2.chunks.len() as u32);

        mgr.create_task("file1.bin", &manifest1, sources1);
        mgr.create_task("file2.bin", &manifest2, sources2);

        assert_eq!(mgr.active_downloads().len(), 2);

        // Complete file1 fully
        for (i, chunk) in chunks1.iter().enumerate() {
            mgr.assign_block("file1.bin", i as u32, format!("node_{}", i)).unwrap();
            mgr.complete_block("file1.bin", i as u32, chunk.clone()).unwrap();
        }

        // Complete file2 partially (some blocks)
        for (i, chunk) in chunks2.iter().enumerate().take(2) {
            mgr.assign_block("file2.bin", i as u32, format!("node_{}", i)).unwrap();
            mgr.complete_block("file2.bin", i as u32, chunk.clone()).unwrap();
        }

        // file1 should be at 100% progress, file2 still in progress
        let status1 = mgr.get_status("file1.bin").unwrap();
        let status2 = mgr.get_status("file2.bin").unwrap();
        assert!(
            matches!(status1, DownloadStatus::Downloading { progress, .. } if (progress - 1.0).abs() < 1e-10),
            "file1 should be at 100% progress"
        );
        assert!(
            matches!(status2, DownloadStatus::Downloading { progress, .. } if progress < 1.0),
            "file2 should still be in progress"
        );
        
        let active = mgr.active_downloads();
        assert_eq!(active.len(), 2, "both should still be tracked");
    }

    #[test]
    fn test_node_load_tracking() {
        let mgr = make_manager();
        let (manifest, _chunks) = make_test_manifest(3000);
        let num_blocks = manifest.chunks.len() as u32;
        let sources = make_block_sources(num_blocks);
        mgr.create_task("test.txt", &manifest, sources);

        // All assignments go to the same node
        let node_name = "busy_node".to_string();
        for i in 0..num_blocks {
            mgr.assign_block("test.txt", i, node_name.clone()).unwrap();
        }

        // select_source should avoid busy_node if alternatives exist
        let alternatives = vec![
            "busy_node".to_string(),
            "idle_node".to_string(),
        ];
        assert_eq!(mgr.select_source(&alternatives), Some("idle_node".to_string()));

        // Complete blocks to release load
        for i in 0..num_blocks {
            mgr.complete_block("test.txt", i, vec![0u8; 10]).unwrap();
        }

        // Now busy_node has 0 load again → first alternative wins
        assert_eq!(mgr.select_source(&alternatives), Some("busy_node".to_string()));
    }

    #[test]
    fn test_download_progress_tracking_accuracy() {
        let mut p = DownloadProgress::new("test.bin", 10, 1000);
        assert_eq!(p.progress_fraction(), 0.0);

        p.update(2, 0, 200);
        assert!((p.progress_fraction() - 0.2).abs() < 1e-10);

        p.update(5, 0, 500);
        assert!((p.progress_fraction() - 0.5).abs() < 1e-10);

        p.update(10, 0, 1000);
        assert!((p.progress_fraction() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_create_task_multiple_times() {
        let mgr = make_manager();
        let (manifest, _) = make_test_manifest(1000);
        let sources = make_block_sources(manifest.chunks.len() as u32);

        // Create same file twice — second overwrites first in the map
        mgr.create_task("dup.txt", &manifest, sources.clone());
        mgr.create_task("dup.txt", &manifest, sources);

        assert!(mgr.get_status("dup.txt").is_some());
    }

    #[test]
    fn test_reorder_buffer_with_download_manager() {
        let mgr = make_manager();
        let (manifest, chunks) = make_test_manifest(4000);
        let num_blocks = manifest.chunks.len() as u32;
        let sources = make_block_sources(num_blocks);
        mgr.create_task("reorder_test.bin", &manifest, sources);

        // Deliver blocks in reverse order
        for i in (0..num_blocks).rev() {
            mgr.assign_block("reorder_test.bin", i, format!("node_{}", i)).unwrap();
            mgr.complete_block("reorder_test.bin", i, chunks[i as usize].clone()).unwrap();
        }

        let status = mgr.get_status("reorder_test.bin").unwrap();
        assert!(
            matches!(status, DownloadStatus::Downloading { progress, .. } if (progress - 1.0).abs() < 1e-10),
            "all blocks should be completed even in reverse order"
        );
    }
}
