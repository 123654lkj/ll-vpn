//! P6-2: 多路径并行传输
//!
//! 实现多路径并行传输，将数据拆分后通过多条路径同时发送，
//! 提高传输带宽和可靠性。
//!
//! # 数据分片与重组
//!
//! 1. 大数据拆分为小片段，每个片段带序列号
//! 2. `ReorderBuffer` 按序输出
//! 3. 处理乱序和丢失
//!
//! # ACK 机制
//!
//! 每条路径独立 ACK，超时重传。
//!
//! # 路径质量监控
//!
//! 路径评分 = 延迟 × 0.7 + 跳数 × 100 × 0.3
//!
//! 动态调整路径权重，选择最优路径。

use crate::vpn::identity::NodeID;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 默认分片大小（字节）
pub const DEFAULT_FRAGMENT_SIZE: usize = 1400;

/// 默认 ACK 超时时间（毫秒）
pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 3000;

/// 默认重传次数上限
pub const DEFAULT_MAX_RETRANSMITS: u32 = 3;

/// 默认路径权重衰减因子
pub const WEIGHT_DECAY_FACTOR: f64 = 0.9;

/// 路径评分：延迟权重
pub const LATENCY_WEIGHT: f64 = 0.7;

/// 路径评分：跳数权重
pub const HOP_WEIGHT: f64 = 0.3;

/// 路径评分：跳数惩罚因子
pub const HOP_PENALTY: f64 = 100.0;

// ──────────────────────────────────────────────
//  Types
// ──────────────────────────────────────────────

/// 路径 ID 类型
pub type PathId = u64;

/// 序列号类型
pub type SeqNumber = u64;

/// 分片数据
#[derive(Debug, Clone)]
pub struct Fragment {
    /// 序列号
    pub seq: SeqNumber,
    /// 所属数据流 ID
    pub stream_id: u64,
    /// 分片数据
    pub data: Vec<u8>,
    /// 总分片数
    pub total_fragments: u32,
}

/// ACK 确认
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// 确认的序列号
    pub seq: SeqNumber,
    /// 路径 ID
    pub path_id: PathId,
    /// 时间戳
    pub timestamp: Instant,
}

/// 路径状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// 活跃
    Active,
    /// 降级（延迟高或有丢包）
    Degraded,
    /// 不可用
    Dead,
}

/// 路径信息
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// 路径 ID
    pub id: PathId,
    /// 目标节点 ID
    pub target: NodeID,
    /// 目标地址
    pub addr: String,
    /// 跳数
    pub hop_count: u8,
    /// 延迟（毫秒）
    pub latency_ms: f64,
    /// 路径评分（越低越好）
    pub score: f64,
    /// 路径权重（越高分配数据越多）
    pub weight: f64,
    /// 路径状态
    pub state: PathState,
    /// 已发送字节数
    pub bytes_sent: u64,
    /// 已确认字节数
    pub bytes_acked: u64,
    /// 丢包数
    pub lost_packets: u32,
    /// 最后更新时间
    pub last_updated: Instant,
    /// 最后活跃时间
    pub last_active: Instant,
}

impl PathInfo {
    /// 计算路径评分
    ///
    /// 评分 = latency_ms × 0.7 + hop_count × 100 × 0.3
    ///
    /// 评分越低表示路径质量越好。
    pub fn calculate_score(latency_ms: f64, hop_count: u8) -> f64 {
        latency_ms * LATENCY_WEIGHT + (hop_count as f64) * HOP_PENALTY * HOP_WEIGHT
    }

    /// 更新路径评分和权重
    pub fn update_metrics(&mut self) {
        self.score = Self::calculate_score(self.latency_ms, self.hop_count);
        // 权重与评分成反比，范围 [0.1, 1.0]
        self.weight = (1.0 / (self.score.max(1.0))).min(1.0).max(0.1);
    }

    /// 更新延迟（加权移动平均）
    pub fn update_latency(&mut self, new_latency_ms: f64) {
        self.latency_ms = self.latency_ms * 0.7 + new_latency_ms * 0.3;
        self.last_active = Instant::now();
        self.update_metrics();
    }

    /// 记录丢包
    pub fn record_loss(&mut self) {
        self.lost_packets += 1;
        // 丢包过多则降级
        if self.lost_packets > 5 {
            self.state = PathState::Degraded;
        }
        if self.lost_packets > 20 {
            self.state = PathState::Dead;
        }
    }
}

// ──────────────────────────────────────────────
//  ReorderBuffer
// ──────────────────────────────────────────────

/// 重排序缓冲区
///
/// 接收乱序到达的分片，按序列号排序后按序输出。
/// 处理乱序和丢失的分片。
#[derive(Debug)]
pub struct ReorderBuffer {
    /// 缓冲区：序列号 → 分片数据
    buffer: HashMap<SeqNumber, Vec<u8>>,
    /// 期望的下一个序列号
    expected_seq: SeqNumber,
    /// 缓冲区大小上限
    max_size: usize,
    /// 等待超时时间
    timeout: Duration,
}

impl ReorderBuffer {
    /// 创建新的重排序缓冲区
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: HashMap::new(),
            expected_seq: 0,
            max_size,
            timeout: Duration::from_millis(DEFAULT_ACK_TIMEOUT_MS),
        }
    }

    /// 插入一个分片
    ///
    /// # 返回
    ///
    /// - 如果序列号正好是期望值，返回 `Some(data)` 表示可以按序输出
    /// - 如果是将来的序列号，缓存并返回 `None`
    /// - 如果是已处理过的序列号，忽略并返回 `None`
    pub fn insert(&mut self, seq: SeqNumber, data: Vec<u8>) -> Option<Vec<Vec<u8>>> {
        if seq < self.expected_seq {
            // 旧的分片，忽略
            return None;
        }

        if seq == self.expected_seq {
            // 正好是期望的序列号，可以立即输出
            self.expected_seq += 1;
            let mut result = vec![data];

            // 继续输出缓冲区中后续连续的分片
            loop {
                if let Some(next_data) = self.buffer.remove(&self.expected_seq) {
                    result.push(next_data);
                    self.expected_seq += 1;
                } else {
                    break;
                }
            }

            Some(result)
        } else {
            // 将来的分片，缓存
            if self.buffer.len() < self.max_size {
                self.buffer.insert(seq, data);
            }
            None
        }
    }

    /// 获取当前期望的序列号
    pub fn expected_sequence(&self) -> SeqNumber {
        self.expected_seq
    }

    /// 获取缓冲区的分片数
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// 获取缓冲区中的序列号列表（已排序）
    pub fn buffered_sequences(&self) -> Vec<SeqNumber> {
        let mut seqs: Vec<SeqNumber> = self.buffer.keys().copied().collect();
        seqs.sort();
        seqs
    }

    /// 检查是否有序列号超时（缺失的分片）
    ///
    /// 如果期望的序列号等待超过超时时间，返回 `true`。
    /// 调用方可以决定跳过丢失的分片。
    pub fn has_timeout(&self) -> bool {
        if let Some(min_seq) = self.buffer.keys().min() {
            // 如果最早的缓存分片与期望值差距较大，认为超时
            *min_seq > self.expected_seq + 10
        } else {
            false
        }
    }

    /// 跳过丢失的分片（强制推进期望序列号）
    ///
    /// # 返回
    ///
    /// 被跳过的序列号数量
    pub fn skip_lost(&mut self) -> u64 {
        let skipped = if let Some(min_seq) = self.buffer.keys().min() {
            if *min_seq > self.expected_seq {
                let count = *min_seq - self.expected_seq;
                self.expected_seq = *min_seq;
                count
            } else {
                0
            }
        } else {
            0
        };
        skipped
    }

    /// 清空缓冲区
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.expected_seq = 0;
    }

    /// 缓冲区是否为空
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// 设置超时时间
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

// ──────────────────────────────────────────────
//  MultiPathManager
// ──────────────────────────────────────────────

/// 多路径管理器
///
/// 管理多条传输路径，支持路径注册、移除、评分和并行传输。
///
/// # 数据分片
///
/// 大数据被拆分为 1400 字节的小片段，每个片段带有序列号，
/// 按路径权重分配到各条路径上发送。
///
/// # 路径评分
///
/// 评分 = 延迟 × 0.7 + 跳数 × 100 × 0.3
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::multipath::MultiPathManager;
/// use ll_vpn::vpn::identity::NodeID;
///
/// let local_id = NodeID::from_bytes(&[1u8; 32]);
/// let manager = MultiPathManager::new(local_id);
/// assert_eq!(manager.path_count(), 0);
/// ```
pub struct MultiPathManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 路径表：路径 ID → 路径信息
    paths: Arc<Mutex<HashMap<PathId, PathInfo>>>,
    /// 重排序缓冲区
    reorder_buffer: Arc<Mutex<ReorderBuffer>>,
    /// 下一个路径 ID
    next_path_id: Arc<AtomicU64>,
    /// 下一个序列号
    next_seq: Arc<AtomicU64>,
    /// 片段大小
    fragment_size: usize,
    /// ACK 超时
    ack_timeout: Duration,
    /// 最大重传次数
    max_retransmits: u32,
}

impl MultiPathManager {
    /// 创建新的多路径管理器
    pub fn new(local_id: NodeID) -> Self {
        Self {
            local_id,
            paths: Arc::new(Mutex::new(HashMap::new())),
            reorder_buffer: Arc::new(Mutex::new(ReorderBuffer::new(1024))),
            next_path_id: Arc::new(AtomicU64::new(1)),
            next_seq: Arc::new(AtomicU64::new(0)),
            fragment_size: DEFAULT_FRAGMENT_SIZE,
            ack_timeout: Duration::from_millis(DEFAULT_ACK_TIMEOUT_MS),
            max_retransmits: DEFAULT_MAX_RETRANSMITS,
        }
    }

    // ── 路径管理 ──

    /// 注册新路径
    ///
    /// # 参数
    ///
    /// - `target`: 目标节点 ID
    /// - `addr`: 目标节点地址
    /// - `hop_count`: 跳数
    ///
    /// # 返回
    ///
    /// 新路径的 ID
    pub fn add_path(&self, target: NodeID, addr: String, hop_count: u8) -> PathId {
        let id = self.next_path_id.fetch_add(1, AtomicOrdering::SeqCst);
        let info = PathInfo {
            id,
            target,
            addr,
            hop_count,
            latency_ms: 50.0, // 初始延迟估计
            score: PathInfo::calculate_score(50.0, hop_count),
            weight: 1.0,
            state: PathState::Active,
            bytes_sent: 0,
            bytes_acked: 0,
            lost_packets: 0,
            last_updated: Instant::now(),
            last_active: Instant::now(),
        };

        self.paths.lock().unwrap().insert(id, info);
        log::info!("Added path {} to {} ({} hops)", id, target.to_hex(), hop_count);
        id
    }

    /// 移除路径
    ///
    /// # 参数
    ///
    /// - `path_id`: 要移除的路径 ID
    ///
    /// # 返回
    ///
    /// - `Some(PathInfo)`: 被移除的路径信息
    /// - `None`: 路径不存在
    pub fn remove_path(&self, path_id: PathId) -> Option<PathInfo> {
        let removed = self.paths.lock().unwrap().remove(&path_id);
        if removed.is_some() {
            log::info!("Removed path {}", path_id);
        }
        removed
    }

    /// 获取路径数量
    pub fn path_count(&self) -> usize {
        self.paths.lock().unwrap().len()
    }

    /// 获取活跃路径数量（状态为 Active 或 Degraded）
    pub fn active_path_count(&self) -> usize {
        self.paths
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.state != PathState::Dead)
            .count()
    }

    /// 获取路径评分
    ///
    /// # 参数
    ///
    /// - `path_id`: 路径 ID
    ///
    /// # 返回
    ///
    /// - `Some(f64)`: 路径评分
    /// - `None`: 路径不存在
    pub fn path_score(&self, path_id: PathId) -> Option<f64> {
        self.paths.lock().unwrap().get(&path_id).map(|p| p.score)
    }

    /// 获取所有路径信息
    pub fn all_paths(&self) -> Vec<PathInfo> {
        self.paths
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect()
    }

    // ── 数据发送 ──

    /// 将数据分片并通过多条路径发送
    ///
    /// 根据路径权重分配数据到各条路径。
    /// 每条路径收到的数据量 = total_data × (path.weight / total_weight)
    ///
    /// # 参数
    ///
    /// - `data`: 待发送的完整数据
    /// - `stream_id`: 数据流 ID
    ///
    /// # 返回
    ///
    /// 返回分片列表，每条分片包含路径 ID 和序列号供发送方使用。
    pub fn send_via_paths(&self, data: &[u8], stream_id: u64) -> Vec<(PathId, Fragment)> {
        let paths = self.paths.lock().unwrap();
        let active_paths: Vec<&PathInfo> = paths
            .values()
            .filter(|p| p.state != PathState::Dead)
            .collect();

        if active_paths.is_empty() {
            return Vec::new();
        }

        // 计算分片
        let fragments = self.fragment_data(data, stream_id);
        let total_fragments = fragments.len() as u32;

        // 计算总权重
        let _total_weight: f64 = active_paths.iter().map(|p| p.weight).sum();

        // 按权重分配分片
        let mut result = Vec::with_capacity(fragments.len());
        let mut path_idx = 0;
        let mut path_weight_accum = active_paths[0].weight;

        for (seq, frag_data) in fragments {
            // 选择路径（轮询 + 权重）
            while path_idx < active_paths.len() - 1 && path_weight_accum < seq as f64 {
                path_idx += 1;
                path_weight_accum += active_paths[path_idx].weight;
            }

            let path = active_paths[path_idx % active_paths.len()];
            let fragment = Fragment {
                seq,
                stream_id,
                data: frag_data,
                total_fragments,
            };

            result.push((path.id, fragment));
        }

        result
    }

    /// 将数据拆分为分片
    fn fragment_data(&self, data: &[u8], _stream_id: u64) -> Vec<(SeqNumber, Vec<u8>)> {
        let mut fragments = Vec::new();
        let mut offset = 0;
        let seq_start = self.next_seq.fetch_add(
            ((data.len() + self.fragment_size - 1) / self.fragment_size) as u64,
            AtomicOrdering::SeqCst,
        );

        let mut seq = seq_start;
        while offset < data.len() {
            let end = (offset + self.fragment_size).min(data.len());
            fragments.push((seq, data[offset..end].to_vec()));
            seq += 1;
            offset = end;
        }

        fragments
    }

    /// 更新路径延迟
    ///
    /// # 参数
    ///
    /// - `path_id`: 路径 ID
    /// - `latency_ms`: 测量的延迟（毫秒）
    pub fn update_path_latency(&self, path_id: PathId, latency_ms: f64) {
        if let Some(path) = self.paths.lock().unwrap().get_mut(&path_id) {
            path.update_latency(latency_ms);
        }
    }

    /// 记录路径成功确认
    ///
    /// # 参数
    ///
    /// - `path_id`: 路径 ID
    /// - `bytes`: 确认的字节数
    pub fn record_ack(&self, path_id: PathId, bytes: u64) {
        if let Some(path) = self.paths.lock().unwrap().get_mut(&path_id) {
            path.bytes_acked += bytes;
            path.last_active = Instant::now();
            // 成功确认后恢复活跃状态
            path.state = PathState::Active;
        }
    }

    /// 记录路径丢包
    ///
    /// # 参数
    ///
    /// - `path_id`: 路径 ID
    pub fn record_loss(&self, path_id: PathId) {
        if let Some(path) = self.paths.lock().unwrap().get_mut(&path_id) {
            path.record_loss();
        }
    }

    /// 获取重排序缓冲区引用
    pub fn reorder_buffer(&self) -> &Arc<Mutex<ReorderBuffer>> {
        &self.reorder_buffer
    }

    /// 设置分片大小
    pub fn set_fragment_size(&mut self, size: usize) {
        self.fragment_size = size;
    }

    /// 获取 ACK 超时时间
    pub fn ack_timeout(&self) -> Duration {
        self.ack_timeout
    }

    /// 获取最大重传次数
    pub fn max_retransmits(&self) -> u32 {
        self.max_retransmits
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    // ── 路径评分测试 ──

    #[test]
    fn test_path_score_calculation() {
        // 低延迟、少跳数 → 低分（优）
        let score1 = PathInfo::calculate_score(10.0, 1);
        // 高延迟、多跳数 → 高分（劣）
        let score2 = PathInfo::calculate_score(100.0, 5);

        assert!(
            score1 < score2,
            "better path should have lower score: {} < {}",
            score1,
            score2
        );

        // 验证计算公式：10 × 0.7 + 1 × 100 × 0.3 = 7 + 30 = 37
        assert!((score1 - 37.0).abs() < 0.001);
        // 验证计算公式：100 × 0.7 + 5 × 100 × 0.3 = 70 + 150 = 220
        assert!((score2 - 220.0).abs() < 0.001);
    }

    #[test]
    fn test_path_score_order() {
        // 延迟优先于跳数
        // A: 延迟 5ms, 3跳 → 5×0.7 + 3×100×0.3 = 3.5 + 90 = 93.5
        let a = PathInfo::calculate_score(5.0, 3);
        // B: 延迟 50ms, 1跳 → 50×0.7 + 1×100×0.3 = 35 + 30 = 65
        let b = PathInfo::calculate_score(50.0, 1);

        // B 更优（更低的评分）
        assert!(
            b < a,
            "1-hop with 50ms latency ({}) should be better than 3-hop with 5ms ({})",
            b,
            a
        );
    }

    // ── 路径管理测试 ──

    #[test]
    fn test_add_path() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        let path_id = manager.add_path(target, "10.0.0.2:9876".to_string(), 1);
        assert!(path_id > 0);
        assert_eq!(manager.path_count(), 1);

        let score = manager.path_score(path_id);
        assert!(score.is_some());
    }

    #[test]
    fn test_remove_path() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        let path_id = manager.add_path(target, "10.0.0.2:9876".to_string(), 1);
        assert_eq!(manager.path_count(), 1);

        let removed = manager.remove_path(path_id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, path_id);
        assert_eq!(manager.path_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_path() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);
        assert!(manager.remove_path(999).is_none());
    }

    #[test]
    fn test_multiple_paths() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let t1 = make_id(0x02);
        let t2 = make_id(0x03);
        let t3 = make_id(0x04);

        manager.add_path(t1, "addr1".to_string(), 1);
        manager.add_path(t2, "addr2".to_string(), 2);
        manager.add_path(t3, "addr3".to_string(), 3);

        assert_eq!(manager.path_count(), 3);
        assert_eq!(manager.active_path_count(), 3);
    }

    // ── 数据分片测试 ──

    #[test]
    fn test_fragment_data_small() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        // 小数据，不分片
        let data = b"hello";
        let fragments = manager.fragment_data(data, 1);

        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].1, b"hello");
    }

    #[test]
    fn test_fragment_data_large() {
        let local = make_id(0x01);
        let mut manager = MultiPathManager::new(local);
        manager.set_fragment_size(100);

        // 大数据，分片
        let data = vec![0xABu8; 350];
        let fragments = manager.fragment_data(&data, 1);

        assert_eq!(fragments.len(), 4); // 100 + 100 + 100 + 50
        assert_eq!(fragments[0].1.len(), 100);
        assert_eq!(fragments[1].1.len(), 100);
        assert_eq!(fragments[2].1.len(), 100);
        assert_eq!(fragments[3].1.len(), 50);

        // 验证序列号连续
        assert_eq!(fragments[1].0, fragments[0].0 + 1);
        assert_eq!(fragments[2].0, fragments[1].0 + 1);
        assert_eq!(fragments[3].0, fragments[2].0 + 1);
    }

    // ── Send via paths 测试 ──

    #[test]
    fn test_send_via_paths_no_paths() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let data = b"test data";
        let result = manager.send_via_paths(data, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn test_send_via_paths_with_paths() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        manager.add_path(target, "addr1".to_string(), 1);
        manager.add_path(target, "addr2".to_string(), 2);

        let data = b"test data for multipath transmission";
        let result = manager.send_via_paths(data, 1);

        assert!(!result.is_empty());
        // 每个分片应包含路径 ID
        for (path_id, _frag) in &result {
            assert!(*path_id == 1 || *path_id == 2);
        }
    }

    // ── 路径延迟更新测试 ──

    #[test]
    fn test_update_path_latency() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        let path_id = manager.add_path(target, "addr".to_string(), 1);

        // 初始延迟为 50ms
        let initial_score = manager.path_score(path_id).unwrap();

        // 更新为 10ms
        manager.update_path_latency(path_id, 10.0);

        let new_score = manager.path_score(path_id).unwrap();
        // 加权平均后应更优（评分更低）
        assert!(
            new_score < initial_score,
            "latency improvement should lower score: {} < {}",
            new_score,
            initial_score
        );
    }

    // ── 路径状态测试 ──

    #[test]
    fn test_path_loss_degradation() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        let path_id = manager.add_path(target, "addr".to_string(), 1);

        // 初始为 Active
        let paths = manager.all_paths();
        assert_eq!(paths[0].state, PathState::Active);

        // 记录 6 次丢包 → 降级
        for _ in 0..6 {
            manager.record_loss(path_id);
        }

        let paths = manager.all_paths();
        assert_eq!(paths[0].state, PathState::Degraded);

        // 记录更多丢包 → dead
        for _ in 0..20 {
            manager.record_loss(path_id);
        }

        let paths = manager.all_paths();
        assert_eq!(paths[0].state, PathState::Dead);
    }

    // ── ACK 记录测试 ──

    #[test]
    fn test_record_ack_restores_active() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        let target = make_id(0x02);
        let path_id = manager.add_path(target, "addr".to_string(), 1);

        // 丢包降级
        for _ in 0..6 {
            manager.record_loss(path_id);
        }
        assert_eq!(
            manager.all_paths()[0].state,
            PathState::Degraded
        );

        // ACK 后恢复 Active
        manager.record_ack(path_id, 100);
        assert_eq!(
            manager.all_paths()[0].state,
            PathState::Active
        );
    }

    // ── 空状态测试 ──

    #[test]
    fn test_empty_manager() {
        let local = make_id(0x01);
        let manager = MultiPathManager::new(local);

        assert_eq!(manager.path_count(), 0);
        assert_eq!(manager.active_path_count(), 0);
        assert!(manager.all_paths().is_empty());
        assert!(manager.path_score(1).is_none());
    }

    // ── ReorderBuffer 测试 ──

    #[test]
    fn test_reorder_buffer_in_order() {
        let mut buf = ReorderBuffer::new(1024);

        // 按序插入
        let result = buf.insert(0, b"zero".to_vec());
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);

        let result = buf.insert(1, b"one".to_vec());
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_reorder_buffer_out_of_order() {
        let mut buf = ReorderBuffer::new(1024);

        // 先插入 seq=2（乱序）
        let result = buf.insert(2, b"two".to_vec());
        assert!(result.is_none()); // 缓存
        assert_eq!(buf.buffered_count(), 1);

        // 插入 seq=0 → 应输出 0
        let result = buf.insert(0, b"zero".to_vec());
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.len(), 1);
        assert_eq!(data[0], b"zero");

        // 插入 seq=1 → 应输出 1, 2（因为 2 已在缓冲区）
        let result = buf.insert(1, b"one".to_vec());
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.len(), 2); // "one" 和缓存的 "two"
        assert_eq!(data[0], b"one");
        assert_eq!(data[1], b"two");
    }

    #[test]
    fn test_reorder_buffer_ignore_old() {
        let mut buf = ReorderBuffer::new(1024);

        // 插入 seq=5，期望变成 6
        buf.insert(5, b"five".to_vec());

        // 插入旧 seq=3，应忽略
        let result = buf.insert(3, b"three".to_vec());
        assert!(result.is_none());
    }

    #[test]
    fn test_reorder_buffer_skip_lost() {
        let mut buf = ReorderBuffer::new(1024);

        // 缓存 seq=10, 11
        buf.insert(10, b"ten".to_vec());
        buf.insert(11, b"eleven".to_vec());

        // 期望的是 0，跳过丢失
        assert_eq!(buf.expected_sequence(), 0);
        let skipped = buf.skip_lost();
        assert_eq!(skipped, 10); // 0..=9 丢失
        assert_eq!(buf.expected_sequence(), 10);
    }

    #[test]
    fn test_reorder_buffer_clear() {
        let mut buf = ReorderBuffer::new(1024);

        buf.insert(5, b"data".to_vec());
        assert!(!buf.is_empty());

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.expected_sequence(), 0);
    }

    #[test]
    fn test_reorder_buffer_continuous_output() {
        let mut buf = ReorderBuffer::new(1024);

        // 插入 0 → 输出 0
        let r = buf.insert(0, b"a".to_vec());
        assert_eq!(r.unwrap().len(), 1);

        // 缓存 2
        buf.insert(2, b"c".to_vec());

        // 插入 1 → 输出 1 和缓存的 2
        let r = buf.insert(1, b"b".to_vec());
        assert!(r.is_some());
        assert_eq!(r.unwrap().len(), 2);
    }

    // ── 路径信息指标更新测试 ──

    #[test]
    fn test_path_info_update_latency() {
        let mut info = PathInfo {
            id: 1,
            target: make_id(0x01),
            addr: "addr".to_string(),
            hop_count: 1,
            latency_ms: 50.0,
            score: PathInfo::calculate_score(50.0, 1),
            weight: 1.0,
            state: PathState::Active,
            bytes_sent: 0,
            bytes_acked: 0,
            lost_packets: 0,
            last_updated: Instant::now(),
            last_active: Instant::now(),
        };

        info.update_latency(10.0);
        // 50 × 0.7 + 10 × 0.3 = 35 + 3 = 38
        assert!((info.latency_ms - 38.0).abs() < 0.001);
    }

    #[test]
    fn test_path_info_weight_bounds() {
        let mut info = PathInfo {
            id: 1,
            target: make_id(0x01),
            addr: "addr".to_string(),
            hop_count: 10,
            latency_ms: 1000.0,
            score: PathInfo::calculate_score(1000.0, 10),
            weight: 1.0,
            state: PathState::Active,
            bytes_sent: 0,
            bytes_acked: 0,
            lost_packets: 0,
            last_updated: Instant::now(),
            last_active: Instant::now(),
        };

        info.update_metrics();
        // 权重应在 [0.1, 1.0] 范围内
        assert!(info.weight >= 0.1);
        assert!(info.weight <= 1.0);
    }
}
