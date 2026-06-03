//! P3-2: 注册中心自动选举机制
//!
//! 基于 Raft 思想的注册中心选举，确保注册中心高可用：
//!
//! # 状态机
//!
//! ```text
//!                     ┌──────────────────┐
//!          ┌──────────│    Follower       │◄──────────────┐
//!          │          └────────┬──────────┘               │
//!          │                   │ 3次心跳无响应               │
//!          │                   ▼                           │
//!          │          ┌──────────────────┐                │
//!          │          │    Candidate     │                │
//!          │          └────────┬──────────┘               │
//!          │                   │ 获得多数投票                │
//!          │                   ▼                           │
//!          │          ┌──────────────────┐                │
//!          ├──────────│     Leader       │                │
//!          │          └──────────────────┘                │
//!          │                                               │
//!          │ 发现更高任期号                                   │
//!          └───────────────────────────────────────────────┘
//! ```
//!
//! # 选举流程
//!
//! 1. **Follower** 节点监控注册中心心跳
//! 2. 连续 3 次心跳无响应 → 转换为 **Candidate**
//! 3. **Candidate** 递增任期号，广播 `ElectionRequest`
//! 4. 每个节点基于 NodeID hash 的确定性算法投票
//! 5. 获得多数投票的 Candidate → **Leader**（新注册中心）
//! 6. 新 Leader 通知所有节点 `RegistryChange`
//! 7. 旧注册中心回归时发送更低任期号消息 → 被拒绝并降级

use crate::vpn::identity::NodeID;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/// 默认选举超时时间（毫秒）
///
/// Follower 在此时间内未收到注册中心心跳，则发起选举。
pub const DEFAULT_ELECTION_TIMEOUT_MS: u64 = 1500;

/// 默认心跳监控阈值（连续无响应次数）
///
/// 超过此阈值则判定注册中心下线。
pub const DEFAULT_HEARTBEAT_MISS_THRESHOLD: u32 = 3;

/// 默认注册中心端口
pub const DEFAULT_ELECTION_REGISTRY_PORT: u16 = 9880;

/// 选举消息子类型起始值（使用 0x11 开始，与现有 RegistryMessageType 不冲突）
pub const ELECTION_MSG_BASE: u8 = 0x11;

// ──────────────────────────────────────────────
//  RegistryStatus
// ──────────────────────────────────────────────

/// 注册中心状态机状态
///
/// 每个节点在选举机制中处于以下三种状态之一。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryStatus {
    /// 普通节点状态
    ///
    /// 接受当前注册中心的管理，没有发起选举。
    /// 监控注册中心心跳，若超时则转换为 Candidate。
    Follower,
    /// 候选者状态
    ///
    /// 检测到注册中心可能下线，正在发起选举。
    /// 广播 ElectionRequest 并收集投票。
    Candidate,
    /// 领导者状态（本节点是注册中心）
    ///
    /// 处理注册、查询等请求，定期发送心跳。
    /// 若发现更高任期号，降级为 Follower。
    Leader,
}

impl RegistryStatus {
    /// 是否为 Follower 状态
    pub fn is_follower(&self) -> bool {
        matches!(self, Self::Follower)
    }

    /// 是否为 Candidate 状态
    pub fn is_candidate(&self) -> bool {
        matches!(self, Self::Candidate)
    }

    /// 是否为 Leader 状态
    pub fn is_leader(&self) -> bool {
        matches!(self, Self::Leader)
    }
}

impl std::fmt::Display for RegistryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Follower => write!(f, "Follower"),
            Self::Candidate => write!(f, "Candidate"),
            Self::Leader => write!(f, "Leader"),
        }
    }
}

// ──────────────────────────────────────────────
//  ElectionMessageType
// ──────────────────────────────────────────────

/// 选举消息子类型
///
/// 嵌入 `MessageType::Registry` 的 payload 首字节中，
/// 与 `RegistryMessageType`（0x01-0x08）不冲突。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElectionMessageType {
    /// 选举请求（0x11）
    ///
    /// Candidate 向所有已知节点广播，发起选举。
    ElectionRequest = 0x11,
    /// 投票（0x12）
    ///
    /// 节点对 ElectionRequest 的响应，表达对某候选人的支持。
    ElectionVote = 0x12,
    /// 选举结果（0x13）
    ///
    /// 新当选的 Leader 广播选举结果。
    ElectionResult = 0x13,
    /// 注册中心变更通知（0x14）
    ///
    /// Leader 通知所有节点注册中心已变更。
    RegistryChange = 0x14,
    /// 数据同步请求（0x15）
    ///
    /// 新 Follower 向 Leader 请求当前注册数据。
    RegistrySync = 0x15,
}

impl ElectionMessageType {
    /// 从 u8 解析选举消息子类型
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x11 => Some(Self::ElectionRequest),
            0x12 => Some(Self::ElectionVote),
            0x13 => Some(Self::ElectionResult),
            0x14 => Some(Self::RegistryChange),
            0x15 => Some(Self::RegistrySync),
            _ => None,
        }
    }

    /// 转换为 u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ──────────────────────────────────────────────
//  Payload structs
// ──────────────────────────────────────────────

/// 选举请求载荷
///
/// Candidate 广播此消息发起选举。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionRequestPayload {
    /// 发起选举的节点 ID
    pub candidate_id: NodeID,
    /// 发起选举节点的名字
    pub candidate_name: String,
    /// 当前任期号
    pub term: u64,
}

/// 投票载荷
///
/// Follower 响应 ElectionRequest 时发送。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionVotePayload {
    /// 投票者节点 ID
    pub voter_id: NodeID,
    /// 投票支持的候选人节点 ID
    pub candidate_id: NodeID,
    /// 当前任期号
    pub term: u64,
    /// 是否同意
    pub granted: bool,
}

/// 选举结果载荷
///
/// 新 Leader 当选后广播通知所有节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElectionResultPayload {
    /// 新 Leader 的节点 ID
    pub leader_id: NodeID,
    /// 新 Leader 的名字
    pub leader_name: String,
    /// 当选时的任期号
    pub term: u64,
}

/// 注册中心变更通知载荷
///
/// 新 Leader 通知所有节点注册中心地址已变更。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryChangePayload {
    /// 新注册中心节点 ID
    pub registry_id: NodeID,
    /// 新注册中心名字
    pub registry_name: String,
    /// 新注册中心地址（IP:Port）
    pub registry_addr: String,
    /// 当前任期号
    pub term: u64,
}

/// 数据同步请求载荷
///
/// 旧注册中心回归后，向当前 Leader 请求同步数据。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySyncPayload {
    /// 请求同步的节点 ID
    pub requester_id: NodeID,
    /// 请求同步的节点名字
    pub requester_name: String,
    /// 请求者的任期号
    pub term: u64,
}

/// 数据同步响应载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySyncResponsePayload {
    /// 当前 Leader 的节点 ID
    pub leader_id: NodeID,
    /// 当前 Leader 的名字
    pub leader_name: String,
    /// 当前任期号
    pub term: u64,
    /// 注册数据（JSON 序列化的注册表）
    pub registry_data: String,
}

// ──────────────────────────────────────────────
//  ElectionConfig
// ──────────────────────────────────────────────

/// 选举配置
#[derive(Debug, Clone)]
pub struct ElectionConfig {
    /// 心跳缺失阈值（连续 N 次无响应判定下线）
    pub heartbeat_miss_threshold: u32,
    /// 选举超时时间
    pub election_timeout: Duration,
}

impl Default for ElectionConfig {
    fn default() -> Self {
        Self {
            heartbeat_miss_threshold: DEFAULT_HEARTBEAT_MISS_THRESHOLD,
            election_timeout: Duration::from_millis(DEFAULT_ELECTION_TIMEOUT_MS),
        }
    }
}

// ──────────────────────────────────────────────
//  ElectionError
// ──────────────────────────────────────────────

/// 选举错误类型
#[derive(Debug)]
pub enum ElectionError {
    /// 无中继管理器
    NoRelayManager,
    /// 序列化错误
    SerializeError(String),
    /// 发送失败
    SendFailed(String),
    /// 锁已损坏
    LockPoisoned,
    /// 选举超时
    ElectionTimeout,
    /// 无足够节点参与选举
    NotEnoughNodes,
}

impl std::fmt::Display for ElectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRelayManager => write!(f, "no relay manager configured"),
            Self::SerializeError(msg) => write!(f, "serialize error: {}", msg),
            Self::SendFailed(msg) => write!(f, "send failed: {}", msg),
            Self::LockPoisoned => write!(f, "lock poisoned"),
            Self::ElectionTimeout => write!(f, "election timeout"),
            Self::NotEnoughNodes => write!(f, "not enough nodes for election"),
        }
    }
}

impl std::error::Error for ElectionError {}

impl From<serde_json::Error> for ElectionError {
    fn from(e: serde_json::Error) -> Self {
        ElectionError::SerializeError(e.to_string())
    }
}

// ──────────────────────────────────────────────
//  ElectionManager
// ──────────────────────────────────────────────

/// 选举管理器
///
/// 管理注册中心状态机，处理选举全流程。
///
/// # 线程安全
///
/// 所有内部状态通过 `Arc<RwLock<...>>` 或 `Atomic*` 保护，
/// 支持跨线程共享。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::registry::election::{ElectionManager, ElectionConfig};
/// use ll_vpn::vpn::identity::NodeID;
/// use std::sync::Arc;
///
/// let (node_id, _) = NodeID::generate();
/// let manager = ElectionManager::new(node_id, "TestNode".to_string(), None);
/// assert!(manager.status().is_follower());
/// ```
pub struct ElectionManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 本地节点名字
    local_name: String,
    /// 当前状态
    status: RwLock<RegistryStatus>,
    /// 当前任期号（全局唯一递增）
    term: AtomicU64,
    /// 本任期已投票给谁
    voted_for: RwLock<Option<NodeID>>,
    /// 当前注册中心的节点 ID
    registry_id: RwLock<Option<NodeID>>,
    /// 当前注册中心的名字
    registry_name: RwLock<Option<String>>,
    /// 当前注册中心地址
    registry_addr: RwLock<Option<String>>,
    /// 最后收到注册中心心跳的时间
    last_registry_heartbeat: RwLock<Instant>,
    /// 连续未收到注册中心心跳次数
    missed_heartbeats: AtomicU32,
    /// 心跳缺失阈值
    heartbeat_miss_threshold: u32,
    /// 选举超时时间
    election_timeout: Duration,
    /// 已知节点列表（NodeID → 地址:端口）
    known_nodes: RwLock<Vec<KnownNode>>,
    /// 选举收到的投票
    votes_received: RwLock<Vec<NodeID>>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 监控线程句柄
    monitor_handle: RwLock<Option<thread::JoinHandle<()>>>,
    /// 发送消息回调（由外部注入，避免依赖 RelayManager 类型）
    send_fn: RwLock<Option<Arc<dyn Fn(&str, &[u8]) -> Result<(), String> + Send + Sync>>>,
    /// 注册中心服务端控制回调（由外部注入，用于启停注册中心）
    registry_control: RwLock<Option<Arc<dyn Fn(bool) + Send + Sync>>>,
    /// 数据同步回调（由外部注入，用于同步注册数据）
    sync_callback: RwLock<Option<Arc<dyn Fn() -> String + Send + Sync>>>,
    /// 数据加载回调（由外部注入，用于加载同步来的数据）
    load_callback: RwLock<Option<Arc<dyn Fn(&str) + Send + Sync>>>,
}

/// 已知节点信息
#[derive(Debug, Clone)]
struct KnownNode {
    /// 节点 ID
    id: NodeID,
    /// 节点名字
    name: String,
    /// 节点地址（IP:Port）
    addr: String,
}

impl ElectionManager {
    /// 创建新的选举管理器
    ///
    /// # 参数
    ///
    /// * `local_id` - 本地节点 ID
    /// * `local_name` - 本地节点名字
    /// * `config` - 选举配置（传 `None` 使用默认配置）
    pub fn new(
        local_id: NodeID,
        local_name: String,
        config: Option<ElectionConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        Self {
            local_id,
            local_name,
            status: RwLock::new(RegistryStatus::Follower),
            term: AtomicU64::new(0),
            voted_for: RwLock::new(None),
            registry_id: RwLock::new(None),
            registry_name: RwLock::new(None),
            registry_addr: RwLock::new(None),
            last_registry_heartbeat: RwLock::new(Instant::now()),
            missed_heartbeats: AtomicU32::new(0),
            heartbeat_miss_threshold: config.heartbeat_miss_threshold,
            election_timeout: config.election_timeout,
            known_nodes: RwLock::new(Vec::new()),
            votes_received: RwLock::new(Vec::new()),
            running: Arc::new(AtomicBool::new(false)),
            monitor_handle: RwLock::new(None),
            send_fn: RwLock::new(None),
            registry_control: RwLock::new(None),
            sync_callback: RwLock::new(None),
            load_callback: RwLock::new(None),
        }
    }

    /// 设置消息发送函数
    ///
    /// 由外部注入，用于发送选举消息到其他节点。
    /// 参数为（目标地址, 序列化后的消息字节）。
    pub fn set_send_fn<F>(&self, send_fn: F)
    where
        F: Fn(&str, &[u8]) -> Result<(), String> + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.send_fn.write() {
            *guard = Some(Arc::new(send_fn));
        }
    }

    /// 设置注册中心控制回调
    ///
    /// 当本节点成为 Leader 时调用 `callback(true)` 启动注册中心，
    /// 降级为 Follower 时调用 `callback(false)` 停止注册中心。
    pub fn set_registry_control<F>(&self, control: F)
    where
        F: Fn(bool) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.registry_control.write() {
            *guard = Some(Arc::new(control));
        }
    }

    /// 设置数据同步回调
    ///
    /// 当其他节点请求数据同步时调用此回调获取当前注册数据（JSON 字符串）。
    pub fn set_sync_callback<F>(&self, callback: F)
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.sync_callback.write() {
            *guard = Some(Arc::new(callback));
        }
    }

    /// 设置数据加载回调
    ///
    /// 当本节点从 Leader 同步数据时调用此回调加载数据。
    pub fn set_load_callback<F>(&self, callback: F)
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        if let Ok(mut guard) = self.load_callback.write() {
            *guard = Some(Arc::new(callback));
        }
    }

    /// 添加已知节点
    ///
    /// 向选举管理器注册一个已知节点，用于发送选举消息。
    pub fn add_known_node(&self, id: NodeID, name: String, addr: String) {
        if let Ok(mut guard) = self.known_nodes.write() {
            // 不重复添加
            if !guard.iter().any(|n| n.id == id) {
                guard.push(KnownNode { id, name, addr });
            }
        }
    }

    /// 移除已知节点
    pub fn remove_known_node(&self, id: &NodeID) {
        if let Ok(mut guard) = self.known_nodes.write() {
            guard.retain(|n| n.id != *id);
        }
    }

    /// 设置当前注册中心
    ///
    /// 在 Follower 模式下，记录当前注册中心的身份信息。
    pub fn set_registry(&self, id: NodeID, name: String, addr: String) {
        if let Ok(mut rid) = self.registry_id.write() {
            *rid = Some(id);
        }
        if let Ok(mut rn) = self.registry_name.write() {
            *rn = Some(name);
        }
        if let Ok(mut ra) = self.registry_addr.write() {
            *ra = Some(addr);
        }
        // 重置心跳监控
        self.reset_heartbeat_monitor();
    }

    /// 重置心跳监控计数器
    ///
    /// 收到注册中心心跳后调用。
    pub fn reset_heartbeat_monitor(&self) {
        if let Ok(mut guard) = self.last_registry_heartbeat.write() {
            *guard = Instant::now();
        }
        self.missed_heartbeats.store(0, Ordering::SeqCst);
    }

    /// 记录一次心跳缺失
    ///
    /// 由监控线程定期调用，累计缺失次数。
    pub fn record_missed_heartbeat(&self) {
        self.missed_heartbeats.fetch_add(1, Ordering::SeqCst);
    }

    /// 获取心跳缺失次数
    pub fn missed_heartbeats(&self) -> u32 {
        self.missed_heartbeats.load(Ordering::SeqCst)
    }

    /// 获取当前状态
    pub fn status(&self) -> RegistryStatus {
        self.status.read().map(|s| *s).unwrap_or(RegistryStatus::Follower)
    }

    /// 设置当前状态（仅测试用）
    #[cfg(test)]
    pub fn set_status(&self, s: RegistryStatus) {
        if let Ok(mut guard) = self.status.write() {
            *guard = s;
        }
    }

    /// 获取当前任期号
    pub fn term(&self) -> u64 {
        self.term.load(Ordering::SeqCst)
    }

    /// 获取注册中心 ID
    pub fn registry_id(&self) -> Option<NodeID> {
        *self.registry_id.read().ok()?
    }

    /// 获取注册中心名字
    pub fn registry_name(&self) -> Option<String> {
        self.registry_name.read().ok()?.clone()
    }

    /// 获取注册中心地址
    pub fn registry_addr(&self) -> Option<String> {
        self.registry_addr.read().ok()?.clone()
    }

    /// 获取本节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取所有已知节点
    pub fn known_nodes(&self) -> Vec<(NodeID, String, String)> {
        self.known_nodes
            .read()
            .map(|nodes| nodes.iter().map(|n| (n.id, n.name.clone(), n.addr.clone())).collect())
            .unwrap_or_default()
    }

    /// 获取已知节点数量
    pub fn known_nodes_count(&self) -> usize {
        self.known_nodes.read().map(|n| n.len()).unwrap_or(0)
    }

    /// 启动选举监控
    ///
    /// 在后台启动监控线程，定期检查注册中心心跳状态。
    /// 若检测到注册中心下线，自动发起选举。
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();

        // 监控线程的存在是为了提供一个可选的定时检查机制。
        // 实际的心跳监控由外部的心跳管理器驱动，
        // 通过 reset_heartbeat_monitor / record_missed_heartbeat 接口工作。
        // 这个线程仅确保 running 标志被检查退出。
        let handle = thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(100));
            }
        });

        if let Ok(mut guard) = self.monitor_handle.write() {
            *guard = Some(handle);
        }
    }

    /// 停止选举监控
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.monitor_handle.write() {
            if let Some(handle) = guard.take() {
                handle.join().ok();
            }
        }
    }

    // ──────────────────────────────────────────
    //  状态转换
    // ──────────────────────────────────────────

    /// 转换为 Candidate 并发起选举
    ///
    /// 检测到注册中心下线时调用。
    /// 递增任期号，广播 ElectionRequest。
    ///
    /// # 返回
    ///
    /// 返回发起选举的结果。
    pub fn start_election(&self) -> Result<(), ElectionError> {
        // 检查是否已在选举中
        if self.status.read().map_err(|_| ElectionError::LockPoisoned)?.is_candidate() {
            return Ok(()); // 已在选举中
        }

        // 检查是否有足够的节点
        let node_count = self.known_nodes.read()
            .map_err(|_| ElectionError::LockPoisoned)?
            .len();
        if node_count == 0 {
            return Err(ElectionError::NotEnoughNodes);
        }

        // 转换为 Candidate
        {
            let mut status = self.status.write().map_err(|_| ElectionError::LockPoisoned)?;
            *status = RegistryStatus::Candidate;
        }

        // 递增任期号
        let new_term = self.term.fetch_add(1, Ordering::SeqCst) + 1;

        // 投票给自己
        {
            let mut vf = self.voted_for.write().map_err(|_| ElectionError::LockPoisoned)?;
            *vf = Some(self.local_id);
        }

        // 清空之前的投票计数
        {
            let mut vr = self.votes_received.write().map_err(|_| ElectionError::LockPoisoned)?;
            vr.clear();
            vr.push(self.local_id); // 自己投给自己
        }

        // 构建 ElectionRequest 消息
        let req_payload = ElectionRequestPayload {
            candidate_id: self.local_id,
            candidate_name: self.local_name.clone(),
            term: new_term,
        };
        let json = serde_json::to_vec(&req_payload)?;
        let mut msg = vec![ElectionMessageType::ElectionRequest.to_u8()];
        msg.extend(json);

        // 广播给所有已知节点
        self.broadcast(&msg)?;

        log::info!(
            "[Election] {} started election at term {}",
            self.local_name, new_term
        );

        Ok(())
    }

    /// 转换为 Leader
    ///
    /// 在获得多数投票后调用。
    /// 启动注册中心服务端，通知所有节点。
    fn become_leader(&self) -> Result<(), ElectionError> {
        // 设置状态为 Leader
        {
            let mut status = self.status.write().map_err(|_| ElectionError::LockPoisoned)?;
            *status = RegistryStatus::Leader;
        }

        // 更新注册中心信息
        let local_addr = self.get_local_addr();

        let term = self.term.load(Ordering::SeqCst);

        {
            let mut rid = self.registry_id.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rid = Some(self.local_id);
        }
        {
            let mut rn = self.registry_name.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rn = Some(self.local_name.clone());
        }
        {
            let mut ra = self.registry_addr.write().map_err(|_| ElectionError::LockPoisoned)?;
            *ra = local_addr.clone();
        }

        // 启动注册中心服务端
        if let Ok(guard) = self.registry_control.read() {
            if let Some(ctrl) = guard.as_ref() {
                ctrl(true);
            }
        }

        // 广播 ElectionResult
        let result_payload = ElectionResultPayload {
            leader_id: self.local_id,
            leader_name: self.local_name.clone(),
            term,
        };
        if let Ok(json) = serde_json::to_vec(&result_payload) {
            let mut msg = vec![ElectionMessageType::ElectionResult.to_u8()];
            msg.extend(json);
            let _ = self.broadcast(&msg);
        }

        // 广播 RegistryChange
        if let Some(addr) = local_addr {
            let change_payload = RegistryChangePayload {
                registry_id: self.local_id,
                registry_name: self.local_name.clone(),
                registry_addr: addr,
                term,
            };
            if let Ok(json) = serde_json::to_vec(&change_payload) {
                let mut msg = vec![ElectionMessageType::RegistryChange.to_u8()];
                msg.extend(json);
                let _ = self.broadcast(&msg);
            }
        }

        log::info!(
            "[Election] {} became Leader at term {}",
            self.local_name, term
        );

        Ok(())
    }

    /// 降级为 Follower
    ///
    /// 发现更高任期号或收到合法 Leader 通知时调用。
    /// 停止注册中心服务端。
    fn become_follower(&self, new_term: u64, new_registry_id: Option<NodeID>) -> Result<(), ElectionError> {
        // 比对新任期号
        let current_term = self.term.load(Ordering::SeqCst);
        if new_term > current_term {
            self.term.store(new_term, Ordering::SeqCst);
        }

        // 设置状态为 Follower
        {
            let mut status = self.status.write().map_err(|_| ElectionError::LockPoisoned)?;
            *status = RegistryStatus::Follower;
        }

        // 清空投票记录
        {
            let mut vf = self.voted_for.write().map_err(|_| ElectionError::LockPoisoned)?;
            *vf = None;
        }
        {
            let mut vr = self.votes_received.write().map_err(|_| ElectionError::LockPoisoned)?;
            vr.clear();
        }

        // 更新注册中心信息
        if let Some(registry_id) = new_registry_id {
            // 设置新注册中心 ID
            if let Ok(mut rid) = self.registry_id.write() {
                *rid = Some(registry_id);
            }

            if registry_id != self.local_id {
                // 不是自己，停止注册中心服务端
                if let Ok(guard) = self.registry_control.read() {
                    if let Some(ctrl) = guard.as_ref() {
                        ctrl(false);
                    }
                }
            }
        }

        // 重置心跳监控
        self.reset_heartbeat_monitor();

        log::info!(
            "[Election] {} became Follower at term {}",
            self.local_name, new_term
        );

        Ok(())
    }

    // ──────────────────────────────────────────
    //  消息处理
    // ──────────────────────────────────────────

    /// 处理接收到的选举消息
    ///
    /// 由外部消息分发器调用，解析并处理选举相关消息。
    ///
    /// # 参数
    ///
    /// * `data` - 完整消息载荷（首字节为 ElectionMessageType）
    ///
    /// # 返回
    ///
    /// 如果消息需要回复，返回响应消息字节；否则返回 None。
    pub fn handle_message(&self, data: &[u8], _sender_addr: Option<&str>) -> Result<Option<Vec<u8>>, ElectionError> {
        if data.is_empty() {
            return Ok(None);
        }

        let sub_type = ElectionMessageType::from_u8(data[0]);
        let payload = if data.len() > 1 { &data[1..] } else { &[] };

        match sub_type {
            Some(ElectionMessageType::ElectionRequest) => {
                self.handle_election_request(payload)
            }
            Some(ElectionMessageType::ElectionVote) => {
                self.handle_election_vote(payload)
            }
            Some(ElectionMessageType::ElectionResult) => {
                self.handle_election_result(payload)
            }
            Some(ElectionMessageType::RegistryChange) => {
                self.handle_registry_change(payload)
            }
            Some(ElectionMessageType::RegistrySync) => {
                self.handle_registry_sync(payload)
            }
            None => Ok(None),
        }
    }

    /// 处理选举请求
    fn handle_election_request(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, ElectionError> {
        let req: ElectionRequestPayload = serde_json::from_slice(payload)?;
        let current_term = self.term.load(Ordering::SeqCst);

        // 如果请求的任期号小于当前任期号，拒绝
        if req.term < current_term {
            return Ok(Some(self.build_vote_message(req.candidate_id, req.term, false)));
        }

        // 如果请求的任期号大于当前任期号，更新并降级为 Follower
        if req.term > current_term {
            self.become_follower(req.term, None)?;
        }

        // 决定是否投票
        let granted = self.should_vote_for(&req.candidate_id, req.term);

        if granted {
            // 记录已投票
            if let Ok(mut vf) = self.voted_for.write() {
                *vf = Some(req.candidate_id);
            }
        }

        log::info!(
            "[Election] {} {} vote for {} at term {}",
            self.local_name,
            if granted { "grants" } else { "denies" },
            req.candidate_name,
            req.term
        );

        Ok(Some(self.build_vote_message(req.candidate_id, req.term, granted)))
    }

    /// 处理投票消息
    fn handle_election_vote(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, ElectionError> {
        let vote: ElectionVotePayload = serde_json::from_slice(payload)?;

        // 只有 Candidate 才处理投票
        if !self.status.read().map_err(|_| ElectionError::LockPoisoned)?.is_candidate() {
            return Ok(None);
        }

        // 只处理当前任期的投票
        if vote.term != self.term.load(Ordering::SeqCst) {
            return Ok(None);
        }

        // 只处理投给自己的票
        if vote.candidate_id != self.local_id {
            return Ok(None);
        }

        if vote.granted {
            let mut vr = self.votes_received.write().map_err(|_| ElectionError::LockPoisoned)?;
            if !vr.contains(&vote.voter_id) {
                vr.push(vote.voter_id);

                // 检查是否获得多数投票
                let total_nodes = self.known_nodes.read()
                    .map_err(|_| ElectionError::LockPoisoned)?
                    .len()
                    + 1; // +1 包含自己

                let votes = vr.len();
                // 多数 = 超过半数（> 50%）
                if votes > total_nodes / 2 {
                    // 释放锁后再调用 become_leader
                    drop(vr);
                    // 当选！
                    self.become_leader()?;
                }
            }
        }

        Ok(None)
    }

    /// 处理选举结果
    fn handle_election_result(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, ElectionError> {
        let result: ElectionResultPayload = serde_json::from_slice(payload)?;
        let current_term = self.term.load(Ordering::SeqCst);

        // 如果结果的任期号小于当前任期号，忽略（可能是旧消息）
        if result.term < current_term {
            return Ok(None);
        }

        // 如果自己是新的 Leader，忽略此消息
        if result.leader_id == self.local_id {
            return Ok(None);
        }

        // 降级为 Follower
        self.become_follower(result.term, Some(result.leader_id))?;

        log::info!(
            "[Election] {} acknowledged {} as Leader at term {}",
            self.local_name, result.leader_name, result.term
        );

        Ok(None)
    }

    /// 处理注册中心变更通知
    fn handle_registry_change(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, ElectionError> {
        let change: RegistryChangePayload = serde_json::from_slice(payload)?;
        let current_term = self.term.load(Ordering::SeqCst);

        // 如果变更通知的任期号小于当前任期号，忽略
        if change.term < current_term {
            return Ok(None);
        }

        // 如果自己就是新的注册中心，忽略
        if change.registry_id == self.local_id {
            return Ok(None);
        }

        // 更新注册中心信息
        {
            let mut rid = self.registry_id.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rid = Some(change.registry_id);
        }
        {
            let mut rn = self.registry_name.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rn = Some(change.registry_name.clone());
        }
        {
            let mut ra = self.registry_addr.write().map_err(|_| ElectionError::LockPoisoned)?;
            *ra = Some(change.registry_addr.clone());
        }

        // 确保是 Follower
        if self.status.read().map_err(|_| ElectionError::LockPoisoned)?.is_leader() {
            if let Ok(guard) = self.registry_control.read() {
                if let Some(ctrl) = guard.as_ref() {
                    ctrl(false);
                }
            }
        }

        self.become_follower(change.term, Some(change.registry_id))?;

        log::info!(
            "[Election] Registry changed to {} ({}) at term {}",
            change.registry_name, change.registry_addr, change.term
        );

        Ok(None)
    }

    /// 处理数据同步请求
    fn handle_registry_sync(&self, payload: &[u8]) -> Result<Option<Vec<u8>>, ElectionError> {
        let sync: RegistrySyncPayload = serde_json::from_slice(payload)?;
        let current_term = self.term.load(Ordering::SeqCst);

        // 只有 Leader 才处理同步请求
        if !self.status.read().map_err(|_| ElectionError::LockPoisoned)?.is_leader() {
            return Ok(None);
        }

        // 如果请求者的任期号大于当前任期号，说明有更新的 Leader
        if sync.term > current_term {
            self.become_follower(sync.term, Some(sync.requester_id))?;
            return Ok(None);
        }

        // 获取注册数据
        let data = if let Ok(guard) = self.sync_callback.read() {
            if let Some(cb) = guard.as_ref() {
                cb()
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let response = RegistrySyncResponsePayload {
            leader_id: self.local_id,
            leader_name: self.local_name.clone(),
            term: current_term,
            registry_data: data,
        };

        let json = serde_json::to_vec(&response)?;
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        log::info!(
            "[Election] Sent sync data to {} at term {}",
            sync.requester_name, sync.term
        );

        Ok(Some(msg))
    }

    /// 请求数据同步
    ///
    /// 旧注册中心回归后，向当前 Leader 请求完整注册数据。
    pub fn request_sync(&self, leader_addr: &str) -> Result<(), ElectionError> {
        let term = self.term.load(Ordering::SeqCst);

        let sync_payload = RegistrySyncPayload {
            requester_id: self.local_id,
            requester_name: self.local_name.clone(),
            term,
        };

        let json = serde_json::to_vec(&sync_payload)?;
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        if let Ok(guard) = self.send_fn.read() {
            if let Some(send) = guard.as_ref() {
                send(leader_addr, &msg).map_err(ElectionError::SendFailed)?;
            } else {
                return Err(ElectionError::NoRelayManager);
            }
        } else {
            return Err(ElectionError::NoRelayManager);
        }

        Ok(())
    }

    /// 处理数据同步响应
    ///
    /// 接收 Leader 返回的同步数据并加载到本地注册中心。
    pub fn handle_sync_response(&self, payload: &[u8]) -> Result<(), ElectionError> {
        let response: RegistrySyncResponsePayload = serde_json::from_slice(payload)?;
        let current_term = self.term.load(Ordering::SeqCst);

        // 如果 Leader 的任期号大于当前任期号，更新
        if response.term > current_term {
            self.term.store(response.term, Ordering::SeqCst);
        }

        // 更新注册中心信息
        {
            let mut rid = self.registry_id.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rid = Some(response.leader_id);
        }
        {
            let mut rn = self.registry_name.write().map_err(|_| ElectionError::LockPoisoned)?;
            *rn = Some(response.leader_name);
        }

        // 加载同步的数据
        if !response.registry_data.is_empty() {
            if let Ok(guard) = self.load_callback.read() {
                if let Some(cb) = guard.as_ref() {
                    cb(&response.registry_data);
                }
            }
        }

        log::info!(
            "[Election] Synced data from Leader at term {}",
            response.term
        );

        Ok(())
    }

    // ──────────────────────────────────────────
    //  内部辅助方法
    // ──────────────────────────────────────────

    /// 广播消息到所有已知节点
    fn broadcast(&self, msg: &[u8]) -> Result<(), ElectionError> {
        let nodes = self.known_nodes.read()
            .map_err(|_| ElectionError::LockPoisoned)?
            .clone();

        let send_fn = self.send_fn.read()
            .map_err(|_| ElectionError::LockPoisoned)?
            .clone();

        drop(send_fn);

        // 逐个发送（不持有任何锁）
        for node in &nodes {
            if let Ok(guard) = self.send_fn.read() {
                if let Some(send) = guard.as_ref() {
                    if let Err(e) = send(&node.addr, msg) {
                        log::warn!(
                            "[Election] Failed to send to {} ({}): {}",
                            node.name, node.addr, e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// 构建投票消息
    fn build_vote_message(&self, candidate_id: NodeID, term: u64, granted: bool) -> Vec<u8> {
        let vote_payload = ElectionVotePayload {
            voter_id: self.local_id,
            candidate_id,
            term,
            granted,
        };
        let json = serde_json::to_vec(&vote_payload).unwrap_or_default();
        let mut msg = vec![ElectionMessageType::ElectionVote.to_u8()];
        msg.extend(json);
        msg
    }

    /// 决定是否投票给某 Candidate
    ///
    /// 投票算法：基于 NodeID hash 的确定性投票。
    /// 计算 `hash(candidate_id || term)`，若哈希值的高位字节
    /// 满足条件（前 4 字节 XOR 后 > 本节点 ID 对应字节）则投票。
    /// 每个节点在同一任期最多投一票。
    fn should_vote_for(&self, candidate_id: &NodeID, term: u64) -> bool {
        // 已经投票过了
        if let Ok(vf) = self.voted_for.read() {
            if vf.is_some() {
                return false;
            }
        }

        // 不投给自己（自己发起的选举不需要处理自己的请求）
        if *candidate_id == self.local_id {
            return true; // 自己当然支持自己
        }

        // 基于 NodeID hash 的确定性投票算法
        //
        // 计算：hash_result = SHA256(candidate_id_bytes || term_bytes)
        // 取前 8 字节作为 u64 值，与本地节点 ID 的前 8 字节 XOR 结果比较。
        // 如果 candidate 的哈希 > 本地节点 ID 的相应值，则投票。
        //
        // 这样每个节点对同一 candidate 的投票是确定性的，
        // 且由于哈希均匀分布，每个 candidate 获得的预期票数相近。
        let candidate_hash = compute_candidate_hash(candidate_id, term);
        let local_value = u64::from_be_bytes(
            self.local_id.as_bytes()[..8].try_into().unwrap_or([0u8; 8]),
        );

        // 如果候选人的哈希值大于本地节点ID的对应值，则投票
        // 这确保每个节点对不同的候选人可能有不同的投票偏好
        candidate_hash > local_value
    }

    /// 获取本地地址（从已知节点中查找）
    fn get_local_addr(&self) -> Option<String> {
        if let Ok(guard) = self.known_nodes.read() {
            for node in guard.iter() {
                if node.id == self.local_id {
                    return Some(node.addr.clone());
                }
            }
        }
        None
    }

    /// 检查注册中心是否健康
    ///
    /// 如果注册中心连续 `heartbeat_miss_threshold` 次无响应，返回 false。
    pub fn is_registry_healthy(&self) -> bool {
        self.missed_heartbeats.load(Ordering::SeqCst) < self.heartbeat_miss_threshold
    }

    /// 判断是否需要发起选举
    ///
    /// 当状态为 Follower、有注册中心且注册中心心跳超时时返回 true。
    pub fn should_start_election(&self) -> bool {
        if !self.status.read().map(|s| s.is_follower()).unwrap_or(false) {
            return false;
        }

        if self.registry_id.read().map(|r| r.is_none()).unwrap_or(true) {
            return false;
        }

        !self.is_registry_healthy()
    }
}

// ──────────────────────────────────────────────
//  辅助函数
// ──────────────────────────────────────────────

/// 计算候选人在指定任期下的哈希值
///
/// 用于确定性投票算法。
/// 输入：candidate 的 NodeID（32 字节）+ 任期号（8 字节大端）
/// 输出：u64 哈希值
fn compute_candidate_hash(candidate_id: &NodeID, term: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(candidate_id.as_bytes());
    hasher.update(&term.to_be_bytes());
    let hash = hasher.finalize();
    let bytes = hash.as_slice();
    u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0u8; 8]))
}

/// 获取当前 Unix 时间戳（秒）
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ──────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ElectionMessageType 测试 ──

    #[test]
    fn test_election_message_type_conversion() {
        assert_eq!(
            ElectionMessageType::from_u8(0x11),
            Some(ElectionMessageType::ElectionRequest)
        );
        assert_eq!(
            ElectionMessageType::from_u8(0x12),
            Some(ElectionMessageType::ElectionVote)
        );
        assert_eq!(
            ElectionMessageType::from_u8(0x13),
            Some(ElectionMessageType::ElectionResult)
        );
        assert_eq!(
            ElectionMessageType::from_u8(0x14),
            Some(ElectionMessageType::RegistryChange)
        );
        assert_eq!(
            ElectionMessageType::from_u8(0x15),
            Some(ElectionMessageType::RegistrySync)
        );
        assert_eq!(ElectionMessageType::from_u8(0x01), None);
        assert_eq!(ElectionMessageType::from_u8(0xFF), None);

        assert_eq!(ElectionMessageType::ElectionRequest.to_u8(), 0x11);
        assert_eq!(ElectionMessageType::ElectionVote.to_u8(), 0x12);
        assert_eq!(ElectionMessageType::ElectionResult.to_u8(), 0x13);
        assert_eq!(ElectionMessageType::RegistryChange.to_u8(), 0x14);
        assert_eq!(ElectionMessageType::RegistrySync.to_u8(), 0x15);
    }

    // ── RegistryStatus 测试 ──

    #[test]
    fn test_registry_status_helpers() {
        assert!(RegistryStatus::Follower.is_follower());
        assert!(!RegistryStatus::Follower.is_candidate());
        assert!(!RegistryStatus::Follower.is_leader());

        assert!(!RegistryStatus::Candidate.is_follower());
        assert!(RegistryStatus::Candidate.is_candidate());
        assert!(!RegistryStatus::Candidate.is_leader());

        assert!(!RegistryStatus::Leader.is_follower());
        assert!(!RegistryStatus::Leader.is_candidate());
        assert!(RegistryStatus::Leader.is_leader());
    }

    #[test]
    fn test_registry_status_display() {
        assert_eq!(format!("{}", RegistryStatus::Follower), "Follower");
        assert_eq!(format!("{}", RegistryStatus::Candidate), "Candidate");
        assert_eq!(format!("{}", RegistryStatus::Leader), "Leader");
    }

    // ── ElectionManager 测试 ──

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    #[test]
    fn test_election_manager_new() {
        let (node_id, _) = NodeID::generate();
        let manager = ElectionManager::new(node_id, "TestNode".to_string(), None);

        assert_eq!(manager.status(), RegistryStatus::Follower);
        assert_eq!(manager.term(), 0);
        assert_eq!(*manager.local_id(), node_id);
        assert!(manager.registry_id().is_none());
        assert_eq!(manager.known_nodes_count(), 0);
    }

    #[test]
    fn test_election_manager_add_known_nodes() {
        let (local_id, _) = NodeID::generate();
        let (node_a, _) = NodeID::generate();
        let (node_b, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);
        manager.add_known_node(node_a, "NodeA".to_string(), "127.0.0.1:9881".to_string());
        manager.add_known_node(node_b, "NodeB".to_string(), "127.0.0.1:9882".to_string());

        assert_eq!(manager.known_nodes_count(), 2);

        let nodes = manager.known_nodes();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().any(|(id, _, _)| *id == node_a));
        assert!(nodes.iter().any(|(id, _, _)| *id == node_b));
    }

    #[test]
    fn test_election_manager_remove_known_node() {
        let (local_id, _) = NodeID::generate();
        let (node_a, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);
        manager.add_known_node(node_a, "NodeA".to_string(), "127.0.0.1:9881".to_string());
        assert_eq!(manager.known_nodes_count(), 1);

        manager.remove_known_node(&node_a);
        assert_eq!(manager.known_nodes_count(), 0);
    }

    #[test]
    fn test_election_manager_set_registry() {
        let (local_id, _) = NodeID::generate();
        let (reg_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);
        manager.set_registry(reg_id, "Registry1".to_string(), "127.0.0.1:9880".to_string());

        assert_eq!(manager.registry_id(), Some(reg_id));
        assert_eq!(manager.registry_name(), Some("Registry1".to_string()));
        assert_eq!(
            manager.registry_addr(),
            Some("127.0.0.1:9880".to_string())
        );
    }

    #[test]
    fn test_election_manager_heartbeat_monitoring() {
        let (local_id, _) = NodeID::generate();
        let (reg_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);
        manager.set_registry(reg_id, "Registry1".to_string(), "127.0.0.1:9880".to_string());

        assert_eq!(manager.missed_heartbeats(), 0);
        assert!(manager.is_registry_healthy());

        manager.record_missed_heartbeat();
        manager.record_missed_heartbeat();
        assert_eq!(manager.missed_heartbeats(), 2);
        assert!(manager.is_registry_healthy());

        manager.record_missed_heartbeat();
        assert_eq!(manager.missed_heartbeats(), 3);
        assert!(!manager.is_registry_healthy());

        // 重置后恢复
        manager.reset_heartbeat_monitor();
        assert_eq!(manager.missed_heartbeats(), 0);
        assert!(manager.is_registry_healthy());
    }

    #[test]
    fn test_election_manager_should_start_election() {
        let (local_id, _) = NodeID::generate();
        let (reg_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 没有注册中心时不应发起选举
        assert!(!manager.should_start_election());

        // 设置注册中心
        manager.set_registry(reg_id, "Registry".to_string(), "127.0.0.1:9880".to_string());
        assert!(!manager.should_start_election()); // 健康

        // 心跳缺失达到阈值
        manager.record_missed_heartbeat();
        manager.record_missed_heartbeat();
        manager.record_missed_heartbeat();
        assert!(manager.should_start_election());
    }

    #[test]
    fn test_compute_candidate_hash() {
        let (id_a, _) = NodeID::generate();
        let (id_b, _) = NodeID::generate();

        // 同一候选人 + 同一任期 → 相同哈希
        let hash1 = compute_candidate_hash(&id_a, 1);
        let hash2 = compute_candidate_hash(&id_a, 1);
        assert_eq!(hash1, hash2);

        // 不同候选人 → 不同哈希（大概率）
        let hash_b = compute_candidate_hash(&id_b, 1);
        assert_ne!(hash1, hash_b);

        // 不同任期 → 不同哈希（大概率）
        let hash3 = compute_candidate_hash(&id_a, 2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_should_vote_for_deterministic() {
        let (local_id, _) = NodeID::generate();
        let (candidate_a, _) = NodeID::generate();
        let (_candidate_b, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 同一候选人 + 同一任期 → 稳定
        let vote1 = manager.should_vote_for(&candidate_a, 1);
        let vote2 = manager.should_vote_for(&candidate_a, 1);
        assert_eq!(vote1, vote2);
    }

    #[test]
    fn test_election_manager_start_election_no_nodes() {
        let (local_id, _) = NodeID::generate();
        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 没有已知节点时发起选举应失败
        let result = manager.start_election();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ElectionError::NotEnoughNodes));
    }

    #[test]
    fn test_election_manager_become_follower_higher_term() {
        let (local_id, _) = NodeID::generate();
        let (new_registry_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 初始任期 0
        assert_eq!(manager.term(), 0);

        // 降级为 Follower，任期 5
        manager.become_follower(5, Some(new_registry_id)).unwrap();
        assert_eq!(manager.term(), 5);
        assert!(manager.status().is_follower());
        assert_eq!(manager.registry_id(), Some(new_registry_id));
    }

    #[test]
    fn test_election_manager_vote_counting() {
        let (local_id, _) = NodeID::generate();
        let (node_a, _) = NodeID::generate();
        let (node_b, _) = NodeID::generate();
        let (node_c, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 添加 3 个节点 + 自己 = 4 个节点
        manager.add_known_node(node_a, "NodeA".to_string(), "127.0.0.1:9001".to_string());
        manager.add_known_node(node_b, "NodeB".to_string(), "127.0.0.1:9002".to_string());
        manager.add_known_node(node_c, "NodeC".to_string(), "127.0.0.1:9003".to_string());

        // 设置发送函数（no-op）
        manager.set_send_fn(|_, _| Ok(()));

        // 发起选举
        manager.start_election().unwrap();
        assert!(manager.status().is_candidate());
        let term = manager.term();

        // 模拟收到投票
        let vote_payload = ElectionVotePayload {
            voter_id: node_a,
            candidate_id: local_id,
            term,
            granted: true,
        };
        let json = serde_json::to_vec(&vote_payload).unwrap();
        let mut msg = vec![ElectionMessageType::ElectionVote.to_u8()];
        msg.extend(json);
        manager.handle_message(&msg, None).unwrap();

        // 还需要一票才能到多数（4个节点需要3票）
        // 自己投了自己，加上 node_a 的一票 = 2票，还需要一票
        assert!(manager.status().is_candidate());

        let vote_payload2 = ElectionVotePayload {
            voter_id: node_b,
            candidate_id: local_id,
            term,
            granted: true,
        };
        let json2 = serde_json::to_vec(&vote_payload2).unwrap();
        let mut msg2 = vec![ElectionMessageType::ElectionVote.to_u8()];
        msg2.extend(json2);
        manager.handle_message(&msg2, None).unwrap();

        // 现在 3/4 票，应该成为 Leader
        assert!(manager.status().is_leader());
    }

    #[test]
    fn test_election_manager_handle_election_request() {
        let (local_id, _) = NodeID::generate();
        let (candidate_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 构建 ElectionRequest
        let req_payload = ElectionRequestPayload {
            candidate_id,
            candidate_name: "Candidate".to_string(),
            term: 1,
        };
        let json = serde_json::to_vec(&req_payload).unwrap();
        let mut msg = vec![ElectionMessageType::ElectionRequest.to_u8()];
        msg.extend(json);

        let response = manager.handle_message(&msg, None).unwrap();
        assert!(response.is_some());

        // 验证响应是 ElectionVote
        let resp = response.unwrap();
        assert_eq!(resp[0], ElectionMessageType::ElectionVote.to_u8());

        let vote: ElectionVotePayload = serde_json::from_slice(&resp[1..]).unwrap();
        assert_eq!(vote.candidate_id, candidate_id);
        assert_eq!(vote.term, 1);
        assert_eq!(vote.voter_id, local_id);
        // granted 取决于 should_vote_for 的结果
    }

    #[test]
    fn test_election_manager_handle_election_result() {
        let (local_id, _) = NodeID::generate();
        let (leader_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 先模拟自己是 Candidate
        manager.set_status(RegistryStatus::Candidate);

        // 收到选举结果（另一个节点当选）
        let result_payload = ElectionResultPayload {
            leader_id,
            leader_name: "NewLeader".to_string(),
            term: 3,
        };
        let json = serde_json::to_vec(&result_payload).unwrap();
        let mut msg = vec![ElectionMessageType::ElectionResult.to_u8()];
        msg.extend(json);

        manager.handle_message(&msg, None).unwrap();

        // 应该降级为 Follower
        assert!(manager.status().is_follower());
        assert_eq!(manager.term(), 3);
        assert_eq!(manager.registry_id(), Some(leader_id));
    }

    #[test]
    fn test_election_manager_handle_registry_change() {
        let (local_id, _) = NodeID::generate();
        let (new_reg_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        let change_payload = RegistryChangePayload {
            registry_id: new_reg_id,
            registry_name: "NewRegistry".to_string(),
            registry_addr: "127.0.0.1:9880".to_string(),
            term: 2,
        };
        let json = serde_json::to_vec(&change_payload).unwrap();
        let mut msg = vec![ElectionMessageType::RegistryChange.to_u8()];
        msg.extend(json);

        manager.handle_message(&msg, None).unwrap();

        assert_eq!(manager.registry_id(), Some(new_reg_id));
        assert_eq!(manager.registry_name(), Some("NewRegistry".to_string()));
        assert_eq!(manager.registry_addr(), Some("127.0.0.1:9880".to_string()));
        assert_eq!(manager.term(), 2);
    }

    #[test]
    fn test_election_manager_old_term_rejected() {
        let (local_id, _) = NodeID::generate();
        let (candidate_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // 先设置高任期号
        manager.term.store(10, Ordering::SeqCst);

        // 收到低任期号的选举请求
        let req_payload = ElectionRequestPayload {
            candidate_id,
            candidate_name: "OldCandidate".to_string(),
            term: 5,
        };
        let json = serde_json::to_vec(&req_payload).unwrap();
        let mut msg = vec![ElectionMessageType::ElectionRequest.to_u8()];
        msg.extend(json);

        let response = manager.handle_message(&msg, None).unwrap();
        assert!(response.is_some());

        // 应该拒绝投票
        let resp = response.unwrap();
        let vote: ElectionVotePayload = serde_json::from_slice(&resp[1..]).unwrap();
        assert!(!vote.granted);
    }

    #[test]
    fn test_election_manager_handle_sync_request_as_follower() {
        let (local_id, _) = NodeID::generate();
        let (requester_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Local".to_string(), None);

        // Follower 不应处理同步请求
        let sync_payload = RegistrySyncPayload {
            requester_id,
            requester_name: "Requester".to_string(),
            term: 1,
        };
        let json = serde_json::to_vec(&sync_payload).unwrap();
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        let response = manager.handle_message(&msg, None).unwrap();
        assert!(response.is_none()); // Follower 不处理
    }

    #[test]
    fn test_election_manager_handle_sync_request_as_leader() {
        let (local_id, _) = NodeID::generate();
        let (requester_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "LeaderNode".to_string(), None);

        // 设置为 Leader，确保 term 大于 sync 请求的 term
        manager.term.store(5, Ordering::SeqCst);
        manager.set_status(RegistryStatus::Leader);

        // 设置同步回调
        manager.set_sync_callback(|| r#"{"names":{},"reverse":{}}"#.to_string());

        // Leader 处理同步请求
        let sync_payload = RegistrySyncPayload {
            requester_id,
            requester_name: "Requester".to_string(),
            term: 1,
        };
        let json = serde_json::to_vec(&sync_payload).unwrap();
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        let response = manager.handle_message(&msg, None).unwrap();
        assert!(response.is_some());

        let resp = response.unwrap();
        assert_eq!(resp[0], ElectionMessageType::RegistrySync.to_u8());

        let sync_resp: RegistrySyncResponsePayload =
            serde_json::from_slice(&resp[1..]).unwrap();
        assert_eq!(sync_resp.leader_id, local_id);
        assert_eq!(sync_resp.registry_data, r#"{"names":{},"reverse":{}}"#);
    }

    #[test]
    fn test_election_manager_handle_sync_request_leader_demotion() {
        let (local_id, _) = NodeID::generate();
        let (requester_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "LeaderNode".to_string(), None);
        manager.set_status(RegistryStatus::Leader);
        manager.term.store(5, Ordering::SeqCst);

        // 同步请求的 term 大于当前 term → Leader 应降级
        let sync_payload = RegistrySyncPayload {
            requester_id,
            requester_name: "NewLeader".to_string(),
            term: 10,
        };
        let json = serde_json::to_vec(&sync_payload).unwrap();
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        let response = manager.handle_message(&msg, None).unwrap();
        assert!(response.is_none()); // Leader 降级，无响应
        assert!(manager.status().is_follower());
        assert_eq!(manager.term(), 10);
    }

    #[test]
    fn test_election_manager_payload_roundtrip() {
        let (id_a, _) = NodeID::generate();
        let (id_b, _) = NodeID::generate();

        // ElectionRequest
        let req = ElectionRequestPayload {
            candidate_id: id_a,
            candidate_name: "Alice".to_string(),
            term: 42,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let deserialized: ElectionRequestPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.candidate_id, id_a);
        assert_eq!(deserialized.candidate_name, "Alice");
        assert_eq!(deserialized.term, 42);

        // ElectionVote
        let vote = ElectionVotePayload {
            voter_id: id_b,
            candidate_id: id_a,
            term: 42,
            granted: true,
        };
        let json = serde_json::to_vec(&vote).unwrap();
        let deserialized: ElectionVotePayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.voter_id, id_b);
        assert_eq!(deserialized.candidate_id, id_a);
        assert!(deserialized.granted);

        // ElectionResult
        let result = ElectionResultPayload {
            leader_id: id_a,
            leader_name: "Alice".to_string(),
            term: 42,
        };
        let json = serde_json::to_vec(&result).unwrap();
        let deserialized: ElectionResultPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.leader_id, id_a);
        assert_eq!(deserialized.term, 42);

        // RegistryChange
        let change = RegistryChangePayload {
            registry_id: id_a,
            registry_name: "AliceRegistry".to_string(),
            registry_addr: "192.168.1.1:9880".to_string(),
            term: 42,
        };
        let json = serde_json::to_vec(&change).unwrap();
        let deserialized: RegistryChangePayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(deserialized.registry_addr, "192.168.1.1:9880");
    }

    #[test]
    fn test_election_error_display() {
        let err = ElectionError::NoRelayManager;
        assert!(format!("{}", err).contains("no relay manager"));

        let err = ElectionError::SerializeError("bad json".to_string());
        assert!(format!("{}", err).contains("bad json"));

        let err = ElectionError::SendFailed("timeout".to_string());
        assert!(format!("{}", err).contains("timeout"));

        let err = ElectionError::NotEnoughNodes;
        assert!(format!("{}", err).contains("not enough nodes"));
    }

    #[test]
    fn test_election_config_default() {
        let config = ElectionConfig::default();
        assert_eq!(config.heartbeat_miss_threshold, DEFAULT_HEARTBEAT_MISS_THRESHOLD);
        assert_eq!(config.election_timeout, Duration::from_millis(DEFAULT_ELECTION_TIMEOUT_MS));
    }

    #[test]
    fn test_election_manager_with_custom_config() {
        let (local_id, _) = NodeID::generate();
        let config = ElectionConfig {
            heartbeat_miss_threshold: 5,
            election_timeout: Duration::from_secs(3),
        };
        let manager = ElectionManager::new(local_id, "Custom".to_string(), Some(config));

        assert_eq!(manager.heartbeat_miss_threshold, 5);
        assert_eq!(manager.election_timeout, Duration::from_secs(3));
    }

    #[test]
    fn test_election_manager_start_stop() {
        let (local_id, _) = NodeID::generate();
        let manager = ElectionManager::new(local_id, "Test".to_string(), None);

        manager.start();
        // 运行一小段时间
        thread::sleep(Duration::from_millis(50));
        manager.stop();
        // 正常停止没有 panic
    }

    #[test]
    fn test_election_manager_registry_control_callback() {
        let (local_id, _) = NodeID::generate();
        let manager = ElectionManager::new(local_id, "Test".to_string(), None);

        let started = Arc::new(AtomicBool::new(false));
        let started_clone = started.clone();
        manager.set_registry_control(move |on| {
            started_clone.store(on, Ordering::SeqCst);
        });

        // 模拟成为 Leader
        manager.set_send_fn(|_, _| Ok(()));
        let (node_a, _) = NodeID::generate();
        manager.add_known_node(node_a, "NodeA".to_string(), "127.0.0.1:9001".to_string());

        // 模拟选举流程：先设置为 Candidate，通过 start_election 加入自投票
        manager.term.store(1, Ordering::SeqCst);
        {
            let mut vr = manager.votes_received.write().unwrap();
            vr.push(local_id); // 自己投给自己
        }
        manager.set_status(RegistryStatus::Candidate);

        // 模拟收到多数投票
        // 2 个节点（自己 + node_a），需要 2 票
        let vote_payload = ElectionVotePayload {
            voter_id: node_a,
            candidate_id: local_id,
            term: 1,
            granted: true,
        };
        let json = serde_json::to_vec(&vote_payload).unwrap();
        let mut msg = vec![ElectionMessageType::ElectionVote.to_u8()];
        msg.extend(json);
        manager.handle_message(&msg, None).unwrap();

        // should be leader now
        assert!(manager.status().is_leader());
        // registry_control(true) 应该被调用过
        assert!(started.load(Ordering::SeqCst));
    }

    #[test]
    fn test_election_manager_handle_sync_response() {
        let (local_id, _) = NodeID::generate();
        let (leader_id, _) = NodeID::generate();

        let manager = ElectionManager::new(local_id, "Test".to_string(), None);

        let loaded = Arc::new(RwLock::new(String::new()));
        let loaded_clone = loaded.clone();
        manager.set_load_callback(move |data| {
            *loaded_clone.write().unwrap() = data.to_string();
        });

        let response = RegistrySyncResponsePayload {
            leader_id,
            leader_name: "LeaderNode".to_string(),
            term: 5,
            registry_data: r#"{"names":{"alice":{}}}"#.to_string(),
        };
        let json = serde_json::to_vec(&response).unwrap();
        let mut msg = vec![ElectionMessageType::RegistrySync.to_u8()];
        msg.extend(json);

        // 直接调用 handle_sync_response
        let result = manager.handle_sync_response(&msg[1..]); // 跳过子类型
        assert!(result.is_ok());

        assert_eq!(manager.term(), 5);
        assert_eq!(manager.registry_id(), Some(leader_id));
        assert!(loaded.read().unwrap().contains("alice"));
    }
}
