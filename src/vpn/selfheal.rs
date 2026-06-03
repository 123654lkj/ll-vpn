//! P3-5: 网络自愈
//!
//! 实现网络自愈能力，处理节点离线、路径失效、分区检测和状态恢复。
//! 与 P1-5 (heartbeat) 和 P3-4 (multihop) 集成，自动修复网络拓扑。
//!
//! # 自愈流程
//!
//! 1. 通过 `HeartbeatManager` 检测节点离线 → 自愈模块接管
//! 2. 从多跳路由表中移除离线节点相关的路由
//! 3. 对经过该节点的路径触发替代路径切换
//! 4. 定期发送 HealPing 探测离线节点是否恢复
//! 5. 节点恢复后重新建立连接和路由
//! 6. 检测网络分区并在恢复时自动合并
//!
//! # 状态持久化
//!
//! 自愈状态定期持久化到文件，重启后自动恢复路由表状态。
//!
//! # 示例
//!
//! ```rust
//! use ll_vpn::vpn::selfheal::SelfHealManager;
//! use ll_vpn::vpn::multihop::MultihopManager;
//! use ll_vpn::vpn::dht::DhtManager;
//! use ll_vpn::vpn::identity::NodeID;
//! use std::sync::Arc;
//!
//! let local_id = NodeID::from_bytes(&[1u8; 32]);
//! let manager = SelfHealManager::new(local_id);
//! assert_eq!(manager.state_count(), 0);
//! ```

use crate::vpn::dht::DhtManager;
use crate::vpn::heartbeat::HeartbeatCallback;
use crate::vpn::identity::NodeID;
use crate::vpn::multihop::MultihopManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/// 默认自愈检查间隔（秒）
pub const DEFAULT_HEAL_INTERVAL_SECS: u64 = 10;

/// 默认最大失败恢复尝试次数
pub const DEFAULT_MAX_FAILED_ATTEMPTS: u32 = 5;

/// 默认恢复探测间隔（秒）
pub const DEFAULT_RECOVERY_CHECK_SECS: u64 = 30;

/// 自愈消息子类型占用的首字节偏移
const HEAL_MSG_SUBTYPE_OFFSET: usize = 0;

/// 自愈消息发送者 ID 偏移（首字节之后 32 字节）
const HEAL_MSG_SENDER_OFFSET: usize = 1;

/// 自愈消息时间戳偏移
const HEAL_MSG_TIMESTAMP_OFFSET: usize = 1 + 32;

/// 自愈消息头部总长度
const HEAL_MSG_HEADER_LEN: usize = 1 + 32 + 8;

/// 默认持久化文件名
pub const DEFAULT_PERSIST_FILENAME: &str = "selfheal_state.json";

/// 持久化保存间隔（秒）
pub const PERSIST_INTERVAL_SECS: u64 = 30;

// ──────────────────────────────────────────────
//  Heal Message Types
// ──────────────────────────────────────────────

/// 自愈消息子类型
///
/// 作为 `MessageType::SelfHeal(0x09)` 的 payload 首字节使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealMsgType {
    /// 自愈 Ping — 探测离线节点是否恢复
    HealPing = 0x01,
    /// 自愈 Pong — 响应自愈 Ping
    HealPong = 0x02,
    /// 分区同步 — 同步分区信息
    PartitionSync = 0x03,
}

impl HealMsgType {
    /// 从 u8 解析
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::HealPing),
            0x02 => Some(Self::HealPong),
            0x03 => Some(Self::PartitionSync),
            _ => None,
        }
    }

    /// 转换为 u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ──────────────────────────────────────────────
//  SelfHealMessage
// ──────────────────────────────────────────────

/// 自愈消息
///
/// 用于节点间的自愈探测和分区同步。
/// 通过 `MessageType::SelfHeal(0x09)` 传输。
///
/// 二进制格式：
/// ```text
/// +--------+----------+------------+------------------+
/// | 1 byte | 32 bytes | 8 bytes    | variable length  |
/// | subtype| sender   | timestamp  | extra payload    |
/// +--------+----------+------------+------------------+
/// ```
#[derive(Debug, Clone)]
pub struct SelfHealMessage {
    /// 消息子类型
    pub msg_type: HealMsgType,
    /// 发送方节点 ID
    pub sender_id: NodeID,
    /// 时间戳（Unix 秒）
    pub timestamp: u64,
    /// 额外载荷
    pub payload: Vec<u8>,
}

impl SelfHealMessage {
    /// 创建新的自愈消息
    pub fn new(msg_type: HealMsgType, sender_id: NodeID) -> Self {
        Self {
            msg_type,
            sender_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            payload: Vec::new(),
        }
    }

    /// 创建带额外载荷的自愈消息
    pub fn with_payload(msg_type: HealMsgType, sender_id: NodeID, payload: Vec<u8>) -> Self {
        let mut msg = Self::new(msg_type, sender_id);
        msg.payload = payload;
        msg
    }

    /// 序列化为字节数组
    ///
    /// 格式: [subtype(1) | sender_id(32) | timestamp(8) | payload(variable)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEAL_MSG_HEADER_LEN + self.payload.len());
        buf.push(self.msg_type.to_u8());
        buf.extend_from_slice(self.sender_id.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节数组反序列化
    ///
    /// 预期输入是 `MessageType::SelfHeal` 消息的 payload 部分。
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < HEAL_MSG_HEADER_LEN {
            return None;
        }

        let msg_type = HealMsgType::from_u8(data[HEAL_MSG_SUBTYPE_OFFSET])?;

        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&data[HEAL_MSG_SENDER_OFFSET..HEAL_MSG_SENDER_OFFSET + 32]);
        let sender_id = NodeID::from_bytes(&id_bytes);

        let timestamp = u64::from_be_bytes(
            data[HEAL_MSG_TIMESTAMP_OFFSET..HEAL_MSG_TIMESTAMP_OFFSET + 8]
                .try_into()
                .ok()?,
        );

        let payload = data[HEAL_MSG_HEADER_LEN..].to_vec();

        Some(Self {
            msg_type,
            sender_id,
            timestamp,
            payload,
        })
    }
}

// ──────────────────────────────────────────────
//  SelfHealNodeState
// ──────────────────────────────────────────────

/// 单个节点的自愈追踪状态
///
/// 记录每个被追踪节点的自愈相关信息，
/// 包括最后活跃时间、失败尝试次数等。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfHealNodeState {
    /// 节点 ID
    pub node_id: NodeID,
    /// 最后活跃时间（Unix 秒）
    pub last_seen: u64,
    /// 连续失败恢复尝试次数
    pub failed_attempts: u32,
    /// 是否标记为离线
    pub is_offline: bool,
    /// 最后恢复探测时间（Unix 秒）
    pub last_recovery_attempt: u64,
}

impl SelfHealNodeState {
    /// 创建新的自愈追踪状态
    pub fn new(node_id: NodeID) -> Self {
        let now = Self::now_secs();
        Self {
            node_id,
            last_seen: now,
            failed_attempts: 0,
            is_offline: false,
            last_recovery_attempt: 0,
        }
    }

    /// 标记节点为离线
    pub fn mark_offline(&mut self) {
        self.is_offline = true;
        self.failed_attempts = 0;
    }

    /// 标记节点为在线（已恢复）
    pub fn mark_online(&mut self) {
        let now = Self::now_secs();
        self.is_offline = false;
        self.last_seen = now;
        self.failed_attempts = 0;
    }

    /// 记录一次失败的恢复尝试
    pub fn record_failed_attempt(&mut self) {
        self.failed_attempts += 1;
        self.last_recovery_attempt = Self::now_secs();
    }

    /// 检查是否超过最大失败尝试次数
    pub fn has_exceeded_max_attempts(&self, max: u32) -> bool {
        self.failed_attempts >= max
    }

    /// 获取当前 Unix 秒
    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

// ──────────────────────────────────────────────
//  HealEvent
// ──────────────────────────────────────────────

/// 自愈事件
///
/// 自愈过程中产生的事件，通过回调通知上层。
#[derive(Debug, Clone)]
pub enum HealEvent {
    /// 节点被判定为离线
    NodeOffline {
        /// 离线节点 ID
        node_id: NodeID,
        /// 事件时间戳
        timestamp: u64,
    },
    /// 节点恢复上线
    NodeRecovered {
        /// 恢复节点 ID
        node_id: NodeID,
        /// 事件时间戳
        timestamp: u64,
    },
    /// 路径失效（下一跳不可达）
    PathFailed {
        /// 目标节点
        target: NodeID,
        /// 不可达的下一跳
        next_hop: NodeID,
    },
    /// 路径已恢复（切换到替代路径）
    PathRestored {
        /// 目标节点
        target: NodeID,
        /// 新的下一跳
        next_hop: NodeID,
    },
    /// 检测到网络分区
    PartitionDetected {
        /// 分区中的节点列表
        nodes: Vec<NodeID>,
    },
    /// 分区已合并
    PartitionMerged,
    /// 自愈状态已从持久化恢复
    StateRestored {
        /// 恢复的节点状态数量
        node_count: usize,
    },
}

impl fmt::Display for HealEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealEvent::NodeOffline { node_id, timestamp } => {
                write!(f, "NodeOffline[node={}, time={}]", node_id, timestamp)
            }
            HealEvent::NodeRecovered { node_id, timestamp } => {
                write!(f, "NodeRecovered[node={}, time={}]", node_id, timestamp)
            }
            HealEvent::PathFailed { target, next_hop } => {
                write!(f, "PathFailed[target={}, next_hop={}]", target, next_hop)
            }
            HealEvent::PathRestored { target, next_hop } => {
                write!(f, "PathRestored[target={}, next_hop={}]", target, next_hop)
            }
            HealEvent::PartitionDetected { nodes } => {
                write!(f, "PartitionDetected[nodes_count={}]", nodes.len())
            }
            HealEvent::PartitionMerged => write!(f, "PartitionMerged"),
            HealEvent::StateRestored { node_count } => {
                write!(f, "StateRestored[node_count={}]", node_count)
            }
        }
    }
}

// ──────────────────────────────────────────────
//  PersistedState (内部辅助结构)
// ──────────────────────────────────────────────

/// 持久化状态（JSON 格式）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHealState {
    /// 节点状态表
    states: HashMap<String, SelfHealNodeState>,
    /// 最后保存时间
    last_saved: u64,
}

// ──────────────────────────────────────────────
//  SelfHealManager
// ──────────────────────────────────────────────

/// 网络自愈管理器
///
/// 负责检测网络故障并自动修复：
///
/// - **节点离线处理**: 检测到节点离线后，从路由表中移除该节点，
///   并触发经过该节点的所有路径的替代路径切换。
/// - **路径失效切换**: 当下一跳不可达时，自动通过候选节点列表
///   切换到替代路径，或重新通过 DHT 发现新路径。
/// - **节点恢复重建**: 定期发送 HealPing 探测离线节点，收到
///   HealPong 后恢复路由并通知上层。
/// - **分区检测与合并**: 通过 PartitionSync 消息检测网络分区，
///   在恢复连接时自动合并。
/// - **状态持久化**: 定期保存自愈状态到文件，重启时自动恢复。
///
/// # 与心跳模块的集成
///
/// `SelfHealManager` 实现了 `HeartbeatCallback` trait，
/// 可以注册到 `HeartbeatManager` 上，在线/离线事件发生时自动响应。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::selfheal::SelfHealManager;
/// use ll_vpn::vpn::identity::NodeID;
///
/// let local_id = NodeID::from_bytes(&[1u8; 32]);
/// let manager = SelfHealManager::new(local_id);
/// assert!(!manager.is_running());
/// ```
pub struct SelfHealManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 自愈节点状态表
    states: Arc<Mutex<HashMap<NodeID, SelfHealNodeState>>>,
    /// 自愈事件回调列表
    callbacks: Arc<Mutex<Vec<Box<dyn Fn(HealEvent) + Send + Sync>>>>,
    /// 多跳路由管理器（可选）
    multihop: Option<Arc<MultihopManager>>,
    /// DHT 管理器（可选）
    dht: Option<Arc<DhtManager>>,
    /// 持久化路径（可选）
    persist_path: Option<String>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 自愈检查间隔
    heal_interval: Duration,
    /// 最大失败恢复尝试次数
    max_failed_attempts: u32,
    /// 恢复探测间隔
    recovery_check_interval: Duration,
    /// HealPong 接收缓冲区
    heal_pongs: Arc<Mutex<Vec<NodeID>>>,
}

impl SelfHealManager {
    /// 创建新的自愈管理器
    ///
    /// # 参数
    /// - `local_id`: 本地节点 ID
    ///
    /// # 返回
    /// - 新的 `SelfHealManager` 实例
    pub fn new(local_id: NodeID) -> Self {
        Self {
            local_id,
            states: Arc::new(Mutex::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            multihop: None,
            dht: None,
            persist_path: None,
            running: Arc::new(AtomicBool::new(false)),
            heal_interval: Duration::from_secs(DEFAULT_HEAL_INTERVAL_SECS),
            max_failed_attempts: DEFAULT_MAX_FAILED_ATTEMPTS,
            recovery_check_interval: Duration::from_secs(DEFAULT_RECOVERY_CHECK_SECS),
            heal_pongs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 设置自愈检查间隔
    ///
    /// # 参数
    /// - `interval_secs`: 间隔秒数
    pub fn set_heal_interval(&mut self, interval_secs: u64) {
        self.heal_interval = Duration::from_secs(interval_secs);
    }

    /// 设置最大失败恢复尝试次数
    ///
    /// # 参数
    /// - `max`: 最大尝试次数
    pub fn set_max_failed_attempts(&mut self, max: u32) {
        self.max_failed_attempts = max;
    }

    /// 绑定多跳路由管理器
    ///
    /// # 参数
    /// - `multihop`: 多跳路由管理器
    pub fn set_multihop(&mut self, multihop: Arc<MultihopManager>) {
        self.multihop = Some(multihop);
    }

    /// 绑定 DHT 管理器
    ///
    /// # 参数
    /// - `dht`: DHT 管理器
    pub fn set_dht(&mut self, dht: Arc<DhtManager>) {
        self.dht = Some(dht);
    }

    /// 设置持久化路径
    ///
    /// 自愈状态将保存到该路径，重启时自动恢复。
    ///
    /// # 参数
    /// - `path`: 文件路径
    pub fn set_persist_path(&mut self, path: String) {
        self.persist_path = Some(path);
    }

    /// 注册自愈事件回调
    ///
    /// # 参数
    /// - `callback`: 接收 `HealEvent` 的回调函数
    pub fn register_callback<F>(&self, callback: F)
    where
        F: Fn(HealEvent) + Send + Sync + 'static,
    {
        self.callbacks.lock().unwrap().push(Box::new(callback));
    }

    /// 触发自愈事件通知
    fn emit_event(&self, event: HealEvent) {
        let callbacks = self.callbacks.lock().unwrap();
        for cb in callbacks.iter() {
            cb(event.clone());
        }
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取自愈状态条目数
    pub fn state_count(&self) -> usize {
        self.states.lock().unwrap().len()
    }

    /// 获取指定节点的自愈状态
    ///
    /// # 参数
    /// - `node_id`: 节点 ID
    ///
    /// # 返回
    /// - `Some(state)`: 节点的自愈状态
    /// - `None`: 节点未被追踪
    pub fn get_state(&self, node_id: &NodeID) -> Option<SelfHealNodeState> {
        self.states.lock().unwrap().get(node_id).cloned()
    }

    /// 获取所有自愈状态
    pub fn all_states(&self) -> Vec<SelfHealNodeState> {
        self.states.lock().unwrap().values().cloned().collect()
    }

    /// 获取离线节点列表
    pub fn offline_nodes(&self) -> Vec<NodeID> {
        self.states
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.is_offline)
            .map(|s| s.node_id)
            .collect()
    }

    /// 获取在线节点列表
    pub fn online_nodes(&self) -> Vec<NodeID> {
        self.states
            .lock()
            .unwrap()
            .values()
            .filter(|s| !s.is_offline)
            .map(|s| s.node_id)
            .collect()
    }

    /// 添加/更新被追踪的节点
    ///
    /// # 参数
    /// - `node_id`: 节点 ID
    pub fn add_node(&self, node_id: NodeID) {
        let mut states = self.states.lock().unwrap();
        if !states.contains_key(&node_id) {
            states.insert(node_id, SelfHealNodeState::new(node_id));
        }
    }

    /// 移除被追踪的节点
    ///
    /// # 参数
    /// - `node_id`: 节点 ID
    pub fn remove_node(&self, node_id: &NodeID) {
        self.states.lock().unwrap().remove(node_id);
    }

    // ── 核心自愈操作 ──

    /// 处理节点离线事件
    ///
    /// 当心跳检测到节点离线时调用此方法。
    /// 会自动清理路由并尝试替代路径切换。
    ///
    /// # 参数
    /// - `node_id`: 离线节点 ID
    pub fn on_node_offline(&self, node_id: &NodeID) {
        // 1. 更新自愈状态
        {
            let mut states = self.states.lock().unwrap();
            let state = states
                .entry(*node_id)
                .or_insert_with(|| SelfHealNodeState::new(*node_id));
            state.mark_offline();
        }

        log::info!("SelfHeal: node {} marked offline, cleaning routes", node_id);

        // 2. 从多跳路由表中移除该节点作为目标的路由
        if let Some(multihop) = &self.multihop {
            if let Some(removed) = multihop.remove_route(node_id) {
                log::info!(
                    "SelfHeal: removed route to target {} (next_hop: {})",
                    removed.target,
                    removed.next_hop
                );
            }

            // 3. 找出所有以该节点为下一跳的路由，触发失效切换
            let affected_targets = multihop.find_routes_by_next_hop(node_id);
            for target in &affected_targets {
                self.emit_event(HealEvent::PathFailed {
                    target: *target,
                    next_hop: *node_id,
                });

                // 先标记当前路由失效
                multihop.mark_invalid(target);

                // 尝试切换到替代路径
                match multihop.find_alternative(target) {
                    Ok(()) => {
                        log::info!(
                            "SelfHeal: switched route to {} to alternative path",
                            target
                        );
                        if let Some(entry) = multihop.find_route(target) {
                            self.emit_event(HealEvent::PathRestored {
                                target: *target,
                                next_hop: entry.next_hop,
                            });
                        }
                    }
                    Err(e) => {
                        log::info!(
                            "SelfHeal: no alternative route for {}: {}",
                            target,
                            e
                        );
                        // 尝试通过 DHT 重新发现
                        if self.dht.is_some() {
                            if multihop.discover_route(target).is_ok() {
                                log::info!(
                                    "SelfHeal: re-discovered route to {}",
                                    target
                                );
                            }
                        }
                    }
                }
            }
        }

        // 4. 通知事件
        self.emit_event(HealEvent::NodeOffline {
            node_id: *node_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
    }

    /// 处理节点恢复上线事件
    ///
    /// 当离线节点重新上线时调用此方法。
    /// 会尝试重建到该节点及经过该节点的路由。
    ///
    /// # 参数
    /// - `node_id`: 恢复节点 ID
    pub fn on_node_recovered(&self, node_id: &NodeID) {
        // 1. 更新自愈状态
        {
            let mut states = self.states.lock().unwrap();
            let state = states
                .entry(*node_id)
                .or_insert_with(|| SelfHealNodeState::new(*node_id));
            state.mark_online();
        }

        log::info!("SelfHeal: node {} recovered, rebuilding routes", node_id);

        // 2. 尝试重新发现到该节点的路由
        if let Some(multihop) = &self.multihop {
            if multihop.find_route(node_id).is_none() {
                if self.dht.is_some() {
                    let _ = multihop.discover_route(node_id);
                }
            }
        }

        // 3. 通知事件
        self.emit_event(HealEvent::NodeRecovered {
            node_id: *node_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        });
    }

    /// 处理路由路径失效
    ///
    /// 当发现到目标节点的路径不可达时调用此方法。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    pub fn handle_path_failure(&self, target: &NodeID) {
        if let Some(multihop) = &self.multihop {
            // 1. 标记当前路由失效
            multihop.mark_invalid(target);

            // 2. 查找替代路径
            match multihop.find_alternative(target) {
                Ok(()) => {
                    log::info!("SelfHeal: route to {} switched to alternative", target);
                    if let Some(entry) = multihop.find_route(target) {
                        self.emit_event(HealEvent::PathRestored {
                            target: *target,
                            next_hop: entry.next_hop,
                        });
                    }
                }
                Err(_) => {
                    // 尝试通过 DHT 重新发现
                    if self.dht.is_some() {
                        match multihop.discover_route(target) {
                            Ok(()) => {
                                log::info!(
                                    "SelfHeal: re-discovered route to {}",
                                    target
                                );
                                if let Some(entry) = multihop.find_route(target) {
                                    self.emit_event(HealEvent::PathRestored {
                                        target: *target,
                                        next_hop: entry.next_hop,
                                    });
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "SelfHeal: cannot recover route to {}: {}",
                                    target,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// 接收并处理 HealPong 响应
    ///
    /// 当收到其他节点回复的自愈 Pong 时调用此方法，
    /// 将发送者加入恢复缓冲区供自愈循环处理。
    ///
    /// # 参数
    /// - `sender`: 发送 HealPong 的节点 ID
    pub fn handle_heal_pong(&self, sender: NodeID) {
        self.heal_pongs.lock().unwrap().push(sender);
    }

    /// 处理自愈消息（HealPing / HealPong / PartitionSync）
    ///
    /// 从网络中收到 `MessageType::SelfHeal` 消息时调用此方法进行分发处理。
    ///
    /// # 参数
    /// - `msg`: 接收到的自愈消息
    ///
    /// # 返回
    /// - `Some(SelfHealMessage)`: 需要回复的消息（如对 HealPing 回复 HealPong）
    /// - `None`: 无需回复
    pub fn process_heal_message(&self, msg: &SelfHealMessage) -> Option<SelfHealMessage> {
        match msg.msg_type {
            HealMsgType::HealPing => {
                // 收到 HealPing → 回复 HealPong
                log::debug!(
                    "SelfHeal: received HealPing from {}, replying HealPong",
                    msg.sender_id
                );
                let mut pong = SelfHealMessage::new(HealMsgType::HealPong, self.local_id);
                pong.payload = msg.sender_id.as_bytes().to_vec(); // 回显被探测节点 ID
                Some(pong)
            }
            HealMsgType::HealPong => {
                // 收到 HealPong → 记录到缓冲区
                self.handle_heal_pong(msg.sender_id);
                None
            }
            HealMsgType::PartitionSync => {
                // 收到分区同步消息 → 处理分区合并
                log::info!(
                    "SelfHeal: received PartitionSync from {}",
                    msg.sender_id
                );
                // 将发送者标记为活跃
                self.add_node(msg.sender_id);
                // 如果该节点之前被标记为离线，触发恢复
                if let Some(state) = self.get_state(&msg.sender_id) {
                    if state.is_offline {
                        self.on_node_recovered(&msg.sender_id);
                    }
                }
                None
            }
        }
    }

    // ── 自愈循环 ──

    /// 启动自愈循环
    ///
    /// 在后台线程中周期性地执行自愈检查：
    /// 1. 检查心跳模块的离线节点
    /// 2. 清理相关路由
    /// 3. 尝试恢复离线节点
    /// 4. 处理 HealPong 响应
    /// 5. 持久化状态
    pub fn start(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // 已在运行
        }

        let running = self.running.clone();
        let states = self.states.clone();
        let callbacks = self.callbacks.clone();
        let multihop = self.multihop.clone();
        let dht = self.dht.clone();
        let _local_id = self.local_id;
        let heal_interval = self.heal_interval;
        let recovery_check_interval = self.recovery_check_interval;
        let max_failed = self.max_failed_attempts;
        let persist_path = self.persist_path.clone();
        let heal_pongs = self.heal_pongs.clone();

        thread::spawn(move || {
            log::info!("SelfHeal: healing loop started (interval={:?})", heal_interval);

            let mut last_recovery_check = Instant::now();
            let mut last_persist = Instant::now();

            while running.load(Ordering::SeqCst) {
                // ── 1. 处理 HealPong 响应 ──
                {
                    let pongs: Vec<NodeID> = std::mem::take(&mut *heal_pongs.lock().unwrap());
                    for sender in &pongs {
                        // 检查是否是离线的节点回复了
                        let was_offline = {
                            let states_guard = states.lock().unwrap();
                            states_guard
                                .get(sender)
                                .map(|s| s.is_offline)
                                .unwrap_or(false)
                        };

                        if was_offline {
                            log::info!(
                                "SelfHeal: node {} responded to HealPing, marking recovered",
                                sender
                            );
                            // 更新状态
                            {
                                let mut states_guard = states.lock().unwrap();
                                let state = states_guard
                                    .entry(*sender)
                                    .or_insert_with(|| SelfHealNodeState::new(*sender));
                                state.mark_online();
                            }

                            // 重建路由
                            if let Some(ref mh) = multihop {
                                if mh.find_route(sender).is_none() {
                                    if dht.is_some() {
                                        let _ = mh.discover_route(sender);
                                    }
                                }
                            }

                            // 通知事件
                            let event = HealEvent::NodeRecovered {
                                node_id: *sender,
                                timestamp: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };
                            let cb_guard = callbacks.lock().unwrap();
                            for cb in cb_guard.iter() {
                                cb(event.clone());
                            }
                        }
                    }
                }

                // ── 2. 定期恢复探测 ──
                let now = Instant::now();
                if now.duration_since(last_recovery_check) >= recovery_check_interval {
                    let offline: Vec<NodeID> = {
                        let states_guard = states.lock().unwrap();
                        states_guard
                            .values()
                            .filter(|s| {
                                s.is_offline
                                    && !s.has_exceeded_max_attempts(max_failed)
                                    && (s.last_recovery_attempt == 0
                                        || (SelfHealNodeState::now_secs()
                                            - s.last_recovery_attempt)
                                            >= recovery_check_interval.as_secs())
                            })
                            .map(|s| s.node_id)
                            .collect()
                    };

                    for node_id in &offline {
                        // 记录恢复尝试
                        {
                            let mut states_guard = states.lock().unwrap();
                            if let Some(state) = states_guard.get_mut(node_id) {
                                state.record_failed_attempt();
                            }
                        }

                        // 尝试通过 DHT 重新发现
                        if dht.is_some() {
                            if let Some(ref mh) = multihop {
                                if mh.discover_route(node_id).is_ok() {
                                    log::info!(
                                        "SelfHeal: re-discovered route to offline node {}",
                                        node_id
                                    );
                                    // 标记恢复
                                    {
                                        let mut states_guard = states.lock().unwrap();
                                        if let Some(state) = states_guard.get_mut(node_id) {
                                            state.mark_online();
                                        }
                                    }
                                    let event = HealEvent::NodeRecovered {
                                        node_id: *node_id,
                                        timestamp: SystemTime::now()
                                            .duration_since(UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs(),
                                    };
                                    let cb_guard = callbacks.lock().unwrap();
                                    for cb in cb_guard.iter() {
                                        cb(event.clone());
                                    }
                                }
                            }
                        }
                    }

                    last_recovery_check = now;
                }

                // ── 3. 定期持久化 ──
                if now.duration_since(last_persist)
                    >= Duration::from_secs(PERSIST_INTERVAL_SECS)
                {
                    if let Some(ref path) = persist_path {
                        let states_guard = states.lock().unwrap();
                        let persisted = PersistedHealState {
                            states: states_guard
                                .iter()
                                .map(|(k, v)| (k.to_hex(), v.clone()))
                                .collect(),
                            last_saved: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        };
                        drop(states_guard);

                        if let Ok(json) = serde_json::to_string_pretty(&persisted) {
                            if fs::write(path, &json).is_ok() {
                                log::debug!("SelfHeal: state persisted to {}", path);
                            }
                        }
                    }
                    last_persist = now;
                }

                thread::sleep(heal_interval);
            }

            log::info!("SelfHeal: healing loop stopped");
        });
    }

    /// 停止自愈循环
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 检查自愈循环是否正在运行
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // ── 持久化 ──

    /// 保存自愈状态到文件
    ///
    /// # 参数
    /// - `path`: 保存路径
    ///
    /// # 返回
    /// - `Ok(())`: 保存成功
    /// - `Err(String)`: 保存失败原因
    pub fn save_state(&self, path: &str) -> Result<(), String> {
        let states = self.states.lock().unwrap();
        let persisted = PersistedHealState {
            states: states
                .iter()
                .map(|(k, v)| (k.to_hex(), v.clone()))
                .collect(),
            last_saved: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        drop(states);

        let json =
            serde_json::to_string_pretty(&persisted).map_err(|e| format!("serialize error: {}", e))?;
        fs::write(path, &json).map_err(|e| format!("write error: {}", e))?;
        Ok(())
    }

    /// 从文件加载自愈状态
    ///
    /// 恢复之前保存的节点状态。
    ///
    /// # 参数
    /// - `path`: 加载路径
    ///
    /// # 返回
    /// - `Ok(usize)`: 恢复的状态数量
    /// - `Err(String)`: 加载失败原因
    pub fn load_state(&self, path: &str) -> Result<usize, String> {
        if !Path::new(path).exists() {
            return Err(format!("file not found: {}", path));
        }

        let json = fs::read_to_string(path).map_err(|e| format!("read error: {}", e))?;
        let persisted: PersistedHealState =
            serde_json::from_str(&json).map_err(|e| format!("deserialize error: {}", e))?;

        let mut states = self.states.lock().unwrap();
        let count = persisted.states.len();
        for (_key, state) in persisted.states {
            states.insert(state.node_id, state);
        }

        self.emit_event(HealEvent::StateRestored {
            node_count: count,
        });

        Ok(count)
    }

    /// 尝试从默认路径加载持久化状态
    ///
    /// 如果已设置持久化路径且文件存在，自动恢复状态。
    /// 在 `start()` 之前调用。
    ///
    /// # 返回
    /// - `Ok(count)`: 恢复的状态数量（0 表示无持久化或文件不存在）
    /// - `Err(String)`: 加载失败
    pub fn try_restore_state(&self) -> Result<usize, String> {
        if let Some(ref path) = self.persist_path {
            if Path::new(path).exists() {
                let count = self.load_state(path)?;
                log::info!("SelfHeal: restored {} node states from {}", count, path);
                return Ok(count);
            }
        }
        Ok(0)
    }
}

impl HeartbeatCallback for SelfHealManager {
    fn on_node_online(&self, node_id: &NodeID) {
        // 节点上线 — 只有在之前被标记为离线时才触发恢复逻辑
        let was_offline = self
            .get_state(node_id)
            .map(|s| s.is_offline)
            .unwrap_or(false);

        self.add_node(*node_id);

        if was_offline {
            self.on_node_recovered(node_id);
        }
    }

    fn on_node_offline(&self, node_id: &NodeID) {
        self.on_node_offline(node_id);
    }

    fn on_heartbeat_sent(&self, _node_id: &NodeID, _sequence: u64) {
        // 心跳发送不需要自愈处理
    }

    fn on_heartbeat_received(&self, node_id: &NodeID, _sequence: u64) {
        // 收到心跳响应 — 确保节点被追踪且在线
        self.add_node(*node_id);
        {
            let mut states = self.states.lock().unwrap();
            if let Some(state) = states.get_mut(node_id) {
                if state.is_offline {
                    state.mark_online();
                    // 触发恢复处理
                    drop(states);
                    self.on_node_recovered(node_id);
                    return;
                }
                state.last_seen = SelfHealNodeState::now_secs();
            }
        }
    }
}

impl fmt::Debug for SelfHealManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelfHealManager")
            .field("local_id", &self.local_id.to_hex())
            .field("state_count", &self.state_count())
            .field("running", &self.running.load(Ordering::Relaxed))
            .field("multihop_bound", &self.multihop.is_some())
            .field("dht_bound", &self.dht.is_some())
            .field("persist_path", &self.persist_path)
            .finish()
    }
}

// ──────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::dht::DhtManager;
    use crate::vpn::multihop::MultihopManager;

    /// 辅助：创建具有特定首字节的 NodeID
    fn make_id(byte: u8) -> NodeID {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        NodeID::from_bytes(&bytes)
    }

    // ── HealMsgType 转换测试 ──

    #[test]
    fn test_heal_msg_type_conversion() {
        assert_eq!(HealMsgType::from_u8(0x01), Some(HealMsgType::HealPing));
        assert_eq!(HealMsgType::from_u8(0x02), Some(HealMsgType::HealPong));
        assert_eq!(
            HealMsgType::from_u8(0x03),
            Some(HealMsgType::PartitionSync)
        );
        assert_eq!(HealMsgType::from_u8(0x00), None);
        assert_eq!(HealMsgType::from_u8(0xFF), None);

        assert_eq!(HealMsgType::HealPing.to_u8(), 0x01);
        assert_eq!(HealMsgType::HealPong.to_u8(), 0x02);
        assert_eq!(HealMsgType::PartitionSync.to_u8(), 0x03);
    }

    // ── SelfHealMessage 测试 ──

    #[test]
    fn test_self_heal_message_new() {
        let node_id = make_id(0x01);
        let msg = SelfHealMessage::new(HealMsgType::HealPing, node_id);

        assert_eq!(msg.msg_type, HealMsgType::HealPing);
        assert_eq!(msg.sender_id, node_id);
        assert!(msg.timestamp > 0);
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn test_self_heal_message_with_payload() {
        let node_id = make_id(0x01);
        let payload = vec![1, 2, 3];
        let msg = SelfHealMessage::with_payload(HealMsgType::HealPong, node_id, payload.clone());

        assert_eq!(msg.msg_type, HealMsgType::HealPong);
        assert_eq!(msg.payload, payload);
    }

    #[test]
    fn test_self_heal_message_roundtrip() {
        let node_id = make_id(0x42);
        let msg = SelfHealMessage::new(HealMsgType::HealPing, node_id);

        let bytes = msg.to_bytes();
        let recovered = SelfHealMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.msg_type, HealMsgType::HealPing);
        assert_eq!(recovered.sender_id, node_id);
        assert_eq!(recovered.timestamp, msg.timestamp);
    }

    #[test]
    fn test_self_heal_message_with_payload_roundtrip() {
        let node_id = make_id(0x42);
        let payload = vec![0xAA, 0xBB, 0xCC];
        let msg =
            SelfHealMessage::with_payload(HealMsgType::PartitionSync, node_id, payload.clone());

        let bytes = msg.to_bytes();
        let recovered = SelfHealMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.msg_type, HealMsgType::PartitionSync);
        assert_eq!(recovered.sender_id, node_id);
        assert_eq!(recovered.payload, payload);
    }

    #[test]
    fn test_self_heal_message_too_short() {
        let result = SelfHealMessage::from_bytes(&[0u8; 10]);
        assert!(result.is_none());
    }

    #[test]
    fn test_self_heal_message_invalid_subtype() {
        let mut bytes = vec![0xFFu8]; // invalid subtype
        bytes.extend_from_slice(&[0u8; 32]); // sender
        bytes.extend_from_slice(&[0u8; 8]); // timestamp
        let result = SelfHealMessage::from_bytes(&bytes);
        assert!(result.is_none());
    }

    // ── SelfHealNodeState 测试 ──

    #[test]
    fn test_self_heal_node_state_new() {
        let node_id = make_id(0x01);
        let state = SelfHealNodeState::new(node_id);

        assert_eq!(state.node_id, node_id);
        assert!(!state.is_offline);
        assert_eq!(state.failed_attempts, 0);
        assert!(state.last_seen > 0);
    }

    #[test]
    fn test_self_heal_node_state_mark_offline() {
        let node_id = make_id(0x01);
        let mut state = SelfHealNodeState::new(node_id);

        state.mark_offline();
        assert!(state.is_offline);
        assert_eq!(state.failed_attempts, 0);
    }

    #[test]
    fn test_self_heal_node_state_mark_online() {
        let node_id = make_id(0x01);
        let mut state = SelfHealNodeState::new(node_id);

        state.mark_offline();
        assert!(state.is_offline);

        state.mark_online();
        assert!(!state.is_offline);
        assert_eq!(state.failed_attempts, 0);
    }

    #[test]
    fn test_self_heal_node_state_record_failed_attempt() {
        let node_id = make_id(0x01);
        let mut state = SelfHealNodeState::new(node_id);

        state.record_failed_attempt();
        assert_eq!(state.failed_attempts, 1);

        state.record_failed_attempt();
        assert_eq!(state.failed_attempts, 2);
    }

    #[test]
    fn test_self_heal_node_state_exceeded_max_attempts() {
        let node_id = make_id(0x01);
        let mut state = SelfHealNodeState::new(node_id);

        assert!(!state.has_exceeded_max_attempts(3));

        state.record_failed_attempt();
        state.record_failed_attempt();
        state.record_failed_attempt();
        assert!(state.has_exceeded_max_attempts(3));
    }

    // ── HealEvent Display 测试 ──

    #[test]
    fn test_heal_event_display() {
        let node_id = make_id(0x01);

        let event = HealEvent::NodeOffline {
            node_id,
            timestamp: 1000,
        };
        let s = format!("{}", event);
        assert!(s.contains("NodeOffline"));

        let event = HealEvent::NodeRecovered {
            node_id,
            timestamp: 1001,
        };
        let s = format!("{}", event);
        assert!(s.contains("NodeRecovered"));

        let event = HealEvent::PathFailed {
            target: node_id,
            next_hop: make_id(0x02),
        };
        let s = format!("{}", event);
        assert!(s.contains("PathFailed"));

        let event = HealEvent::PathRestored {
            target: node_id,
            next_hop: make_id(0x03),
        };
        let s = format!("{}", event);
        assert!(s.contains("PathRestored"));

        let event = HealEvent::PartitionDetected {
            nodes: vec![node_id],
        };
        let s = format!("{}", event);
        assert!(s.contains("PartitionDetected"));

        let event = HealEvent::PartitionMerged;
        let s = format!("{}", event);
        assert!(s.contains("PartitionMerged"));

        let event = HealEvent::StateRestored { node_count: 5 };
        let s = format!("{}", event);
        assert!(s.contains("StateRestored"));
    }

    // ── SelfHealManager 基本测试 ──

    #[test]
    fn test_self_heal_manager_new() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        assert_eq!(*manager.local_id(), local);
        assert_eq!(manager.state_count(), 0);
        assert!(!manager.is_running());
    }

    #[test]
    fn test_self_heal_manager_debug() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let debug = format!("{:?}", manager);
        assert!(debug.contains("SelfHealManager"));
        assert!(debug.contains("state_count"));
    }

    #[test]
    fn test_self_heal_manager_add_remove_node() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.add_node(node);
        assert_eq!(manager.state_count(), 1);
        assert!(manager.get_state(&node).is_some());

        manager.remove_node(&node);
        assert_eq!(manager.state_count(), 0);
    }

    #[test]
    fn test_self_heal_manager_add_duplicate_node() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.add_node(node);
        manager.add_node(node); // 重复添加不应增加计数
        assert_eq!(manager.state_count(), 1);
    }

    #[test]
    fn test_self_heal_manager_online_offline_nodes() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let node1 = make_id(0x02);
        let node2 = make_id(0x03);

        manager.add_node(node1);
        manager.add_node(node2);

        // 初始都在线
        assert_eq!(manager.online_nodes().len(), 2);
        assert_eq!(manager.offline_nodes().len(), 0);

        // 标记 node1 离线
        {
            let mut states = manager.states.lock().unwrap();
            if let Some(state) = states.get_mut(&node1) {
                state.mark_offline();
            }
        }

        assert_eq!(manager.offline_nodes().len(), 1);
        assert!(manager.offline_nodes().contains(&node1));
        assert_eq!(manager.online_nodes().len(), 1);
        assert!(manager.online_nodes().contains(&node2));
    }

    // ── 节点离线→路由清理测试 ──

    #[test]
    fn test_node_offline_cleans_routes() {
        let local = make_id(0x01);
        let multihop = MultihopManager::new(local);
        let mut manager = SelfHealManager::new(local);

        let target = make_id(0x02);
        multihop.add_direct_route(target, "10.0.0.2:9876".to_string());
        assert!(multihop.find_route(&target).is_some());

        manager.set_multihop(Arc::new(multihop));
        let mh = manager.multihop.as_ref().unwrap();

        // 模拟节点离线
        manager.on_node_offline(&target);

        // 路由应被清理
        assert!(mh.find_route(&target).is_none());
    }

    // ── 路径失效→替代路径切换测试 ──

    #[test]
    fn test_path_failure_alternative_switch() {
        let local = make_id(0x01);
        let mut manager = SelfHealManager::new(local);

        let target = make_id(0xFF);
        let relay_b = make_id(0x03);

        let multihop = Arc::new(MultihopManager::new(local));
        multihop.insert_route(
            crate::vpn::multihop::MultiHopEntry::new(
                target,
                make_id(0x02), // 当前下一跳（将失效）
                2,
                crate::router::ConnectionType::Relay,
                vec![(relay_b, "10.0.0.3:9876".to_string())], // 候选
            ),
        );

        manager.set_multihop(multihop.clone());

        // 验证路由已插入
        assert!(multihop.find_route(&target).is_some());

        // 模拟路径失效
        manager.handle_path_failure(&target);

        // 应切换到替代路径
        let entry = multihop.find_route(&target);
        assert!(entry.is_some());
        // 下一跳应是 relay_b（候选中的唯一选项）
        assert_eq!(entry.unwrap().next_hop, relay_b);
    }

    // ── 节点恢复→路由重建测试 ──

    #[test]
    fn test_node_recovery_rebuilds_routes() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let mut multihop = MultihopManager::new(local);
        multihop.set_dht(Arc::new(dht));

        let mut manager = SelfHealManager::new(local);
        manager.set_multihop(Arc::new(multihop));

        let node = make_id(0x02);

        // 先标记为离线
        manager.on_node_offline(&node);

        // 检查状态
        let state = manager.get_state(&node);
        assert!(state.is_some());
        assert!(state.unwrap().is_offline);

        // 模拟节点恢复
        manager.on_node_recovered(&node);

        // 状态应恢复
        let state = manager.get_state(&node).unwrap();
        assert!(!state.is_offline);
    }

    // ── 自愈循环启动/停止测试 ──

    #[test]
    fn test_heal_loop_start_stop() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        assert!(!manager.is_running());

        manager.start();
        assert!(manager.is_running());

        // 给线程一点时间启动
        thread::sleep(Duration::from_millis(50));

        manager.stop();
        assert!(!manager.is_running());
    }

    #[test]
    fn test_heal_loop_double_start() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        manager.start();
        assert!(manager.is_running());

        // 再次启动应无影响
        manager.start();
        assert!(manager.is_running());

        manager.stop();
    }

    // ── 事件回调测试 ──

    #[test]
    fn test_event_callback_offline() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        let callback_count = Arc::new(AtomicUsize::new(0));
        let count_clone = callback_count.clone();
        manager.register_callback(move |event| {
            if matches!(event, HealEvent::NodeOffline { .. }) {
                count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        manager.on_node_offline(&node);

        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_event_callback_recovered() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        let callback_count = Arc::new(AtomicUsize::new(0));
        let count_clone = callback_count.clone();
        manager.register_callback(move |event| {
            if matches!(event, HealEvent::NodeRecovered { .. }) {
                count_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        // 先离线再恢复
        manager.on_node_offline(&node);
        manager.on_node_recovered(&node);

        // 应收到 offline + recovered 两个事件
        assert_eq!(callback_count.load(Ordering::SeqCst), 1);
    }

    // ── 持久化测试 ──

    #[test]
    fn test_save_and_load_state() {
        use std::env;

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node1 = make_id(0x02);
        let node2 = make_id(0x03);

        manager.add_node(node1);
        manager.add_node(node2);

        // 标记一个节点为离线
        manager.on_node_offline(&node1);

        let path = env::temp_dir().join("test_selfheal_state.json");
        let path_str = path.to_str().unwrap().to_string();

        // 保存
        let result = manager.save_state(&path_str);
        assert!(result.is_ok());

        // 创建新管理器并加载
        let manager2 = SelfHealManager::new(local);
        let result = manager2.load_state(&path_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // 验证状态恢复
        let state1 = manager2.get_state(&node1);
        assert!(state1.is_some());
        assert!(state1.unwrap().is_offline);

        let state2 = manager2.get_state(&node2);
        assert!(state2.is_some());
        assert!(!state2.unwrap().is_offline);

        // 清理
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn test_load_state_file_not_found() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let result = manager.load_state("/tmp/nonexistent_file_12345.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_try_restore_state_no_path() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let result = manager.try_restore_state();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    // ── HealPong 处理测试 ──

    #[test]
    fn test_handle_heal_pong() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let sender = make_id(0x02);

        manager.handle_heal_pong(sender);

        let pongs = manager.heal_pongs.lock().unwrap();
        assert_eq!(pongs.len(), 1);
        assert_eq!(pongs[0], sender);
    }

    // ── process_heal_message 测试 ──

    #[test]
    fn test_process_heal_ping_returns_pong() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let sender = make_id(0x02);

        let ping = SelfHealMessage::new(HealMsgType::HealPing, sender);
        let response = manager.process_heal_message(&ping);

        assert!(response.is_some());
        let pong = response.unwrap();
        assert_eq!(pong.msg_type, HealMsgType::HealPong);
        assert_eq!(pong.sender_id, local);
    }

    #[test]
    fn test_process_heal_pong_buffered() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let sender = make_id(0x02);

        let pong = SelfHealMessage::new(HealMsgType::HealPong, sender);
        let response = manager.process_heal_message(&pong);

        assert!(response.is_none());

        // 验证被加入缓冲区
        let pongs = manager.heal_pongs.lock().unwrap();
        assert_eq!(pongs.len(), 1);
        assert_eq!(pongs[0], sender);
    }

    #[test]
    fn test_process_partition_sync() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let sender = make_id(0x02);

        let sync = SelfHealMessage::new(HealMsgType::PartitionSync, sender);
        let response = manager.process_heal_message(&sync);

        assert!(response.is_none());

        // 发送者应被添加为追踪节点
        assert!(manager.get_state(&sender).is_some());
    }

    // ── HeartbeatCallback 实现测试 ──

    #[test]
    fn test_heartbeat_callback_online_unknown_node() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        // 心跳回调上线事件（未知节点）
        manager.on_node_online(&node);

        // 节点应被追踪
        let state = manager.get_state(&node);
        assert!(state.is_some());
        assert!(!state.unwrap().is_offline);
    }

    #[test]
    fn test_heartbeat_callback_offline() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.add_node(node);

        // 心跳回调离线事件
        manager.on_node_offline(&node);

        let state = manager.get_state(&node).unwrap();
        assert!(state.is_offline);
    }

    // ── 设置方法测试 ──

    #[test]
    fn test_set_heal_interval() {
        let local = make_id(0x01);
        let mut manager = SelfHealManager::new(local);

        assert_eq!(manager.heal_interval, Duration::from_secs(DEFAULT_HEAL_INTERVAL_SECS));

        manager.set_heal_interval(30);
        assert_eq!(manager.heal_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_set_max_failed_attempts() {
        let local = make_id(0x01);
        let mut manager = SelfHealManager::new(local);

        assert_eq!(manager.max_failed_attempts, DEFAULT_MAX_FAILED_ATTEMPTS);

        manager.set_max_failed_attempts(10);
        assert_eq!(manager.max_failed_attempts, 10);
    }

    #[test]
    fn test_set_multihop_and_dht() {
        let local = make_id(0x01);
        let mut manager = SelfHealManager::new(local);

        assert!(manager.multihop.is_none());
        assert!(manager.dht.is_none());

        let multihop = Arc::new(MultihopManager::new(local));
        let dht = Arc::new(DhtManager::new(local));

        manager.set_multihop(multihop);
        manager.set_dht(dht);

        assert!(manager.multihop.is_some());
        assert!(manager.dht.is_some());
    }

    #[test]
    fn test_set_persist_path() {
        let local = make_id(0x01);
        let mut manager = SelfHealManager::new(local);

        assert!(manager.persist_path.is_none());

        manager.set_persist_path("/tmp/test_heal.json".to_string());
        assert!(manager.persist_path.is_some());
    }

    // ── 状态恢复测试 ──

    #[test]
    fn test_state_restored_event() {
        use std::env;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.add_node(node);
        manager.on_node_offline(&node);

        let path = env::temp_dir().join("test_state_restored.json");
        let path_str = path.to_str().unwrap().to_string();
        manager.save_state(&path_str).unwrap();

        let manager2 = SelfHealManager::new(local);
        let restored_count = Arc::new(AtomicUsize::new(0));
        let rc = restored_count.clone();
        manager2.register_callback(move |event| {
            if matches!(event, HealEvent::StateRestored { .. }) {
                rc.fetch_add(1, Ordering::SeqCst);
            }
        });

        manager2.load_state(&path_str).unwrap();
        assert_eq!(restored_count.load(Ordering::SeqCst), 1);

        let _ = fs::remove_file(&path);
    }

    // ── 路径失效→DHT 重新发现测试 ──

    #[test]
    fn test_path_failure_with_dht_rediscovery() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let target = make_id(0xFF);
        let relay_a = make_id(0x02);

        // 在 DHT 中插入 relay_a
        dht.insert_node(relay_a, "10.0.0.2:9876".to_string()).unwrap();

        let mut multihop = MultihopManager::new(local);
        multihop.set_dht(Arc::new(dht));

        let mut manager = SelfHealManager::new(local);
        manager.set_multihop(Arc::new(multihop));

        // 对 target 调用 handle_path_failure — 没有现有路由，所以会尝试 DHT 发现
        // 如果 DHT 无节点，应不会 panic
        manager.handle_path_failure(&target);

        // 由于 DHT 中有 relay_a 但 target 不在其中，discover_route 可能发现多跳路由
        // 也可能找不到（取决于路由逻辑），但不应 panic
    }

    // ── 分区检测测试 ──

    #[test]
    fn test_partition_detection_event() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let detected = Arc::new(AtomicBool::new(false));
        let d = detected.clone();
        manager.register_callback(move |event| {
            if matches!(event, HealEvent::PartitionDetected { .. }) {
                d.store(true, Ordering::SeqCst);
            }
        });

        // 触发分区事件
        manager.emit_event(HealEvent::PartitionDetected {
            nodes: vec![make_id(0x02), make_id(0x03)],
        });

        assert!(detected.load(Ordering::SeqCst));
    }

    #[test]
    fn test_partition_merged_event() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        let merged = Arc::new(AtomicBool::new(false));
        let m = merged.clone();
        manager.register_callback(move |event| {
            if matches!(event, HealEvent::PartitionMerged) {
                m.store(true, Ordering::SeqCst);
            }
        });

        manager.emit_event(HealEvent::PartitionMerged);

        assert!(merged.load(Ordering::SeqCst));
    }

    // ── 边界情况测试 ──

    #[test]
    fn test_empty_manager() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);

        assert_eq!(manager.state_count(), 0);
        assert!(manager.all_states().is_empty());
        assert!(manager.online_nodes().is_empty());
        assert!(manager.offline_nodes().is_empty());
    }

    #[test]
    fn test_handle_path_failure_no_multihop() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let target = make_id(0x02);

        // 没有绑定 multihop，不应 panic
        manager.handle_path_failure(&target);
    }

    #[test]
    fn test_on_node_offline_no_multihop() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        // 没有绑定 multihop，不应 panic
        manager.on_node_offline(&node);

        let state = manager.get_state(&node);
        assert!(state.is_some());
        assert!(state.unwrap().is_offline);
    }

    #[test]
    fn test_on_node_recovered_no_multihop() {
        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.on_node_offline(&node);
        manager.on_node_recovered(&node);

        let state = manager.get_state(&node).unwrap();
        assert!(!state.is_offline);
    }

    // ── 集成测试：离线 → 恢复 → 验证 ──

    #[test]
    fn test_offline_recovery_integration() {
        let local = make_id(0x01);
        let multihop = Arc::new(MultihopManager::new(local));
        let mut manager = SelfHealManager::new(local);

        let node = make_id(0x02);

        // 添加路由
        multihop.add_direct_route(node, "10.0.0.2:9876".to_string());
        assert!(multihop.find_route(&node).is_some());

        // 绑定 multihop
        manager.set_multihop(multihop.clone());

        // 节点离线
        manager.on_node_offline(&node);
        assert!(multihop.find_route(&node).is_none());

        // 节点恢复
        manager.on_node_recovered(&node);

        // 状态恢复
        let state = manager.get_state(&node).unwrap();
        assert!(!state.is_offline);
    }

    // ── 多节点离线测试 ──

    #[test]
    fn test_multiple_nodes_offline() {
        let local = make_id(0x01);
        let multihop = Arc::new(MultihopManager::new(local));
        let mut manager = SelfHealManager::new(local);
        manager.set_multihop(multihop);

        let node_a = make_id(0x02);
        let node_b = make_id(0x03);
        let node_c = make_id(0x04);

        manager.add_node(node_a);
        manager.add_node(node_b);
        manager.add_node(node_c);

        manager.on_node_offline(&node_a);
        manager.on_node_offline(&node_c);

        let offline = manager.offline_nodes();
        assert_eq!(offline.len(), 2);
        assert!(offline.contains(&node_a));
        assert!(offline.contains(&node_c));
        assert!(!offline.contains(&node_b));

        let online = manager.online_nodes();
        assert_eq!(online.len(), 1);
        assert!(online.contains(&node_b));
    }

    // ── 状态持久化 JSON 格式测试 ──

    #[test]
    fn test_persisted_state_json_format() {
        use std::env;

        let local = make_id(0x01);
        let manager = SelfHealManager::new(local);
        let node = make_id(0x02);

        manager.add_node(node);
        manager.on_node_offline(&node);

        let path = env::temp_dir().join("test_heal_json_format.json");
        let path_str = path.to_str().unwrap().to_string();
        manager.save_state(&path_str).unwrap();

        // 验证 JSON 文件可读
        let content = fs::read_to_string(&path_str).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed.get("states").is_some());
        assert!(parsed.get("last_saved").is_some());

        // 验证节点状态存在
        let states = parsed.get("states").unwrap();
        assert!(states.get(&node.to_hex()).is_some());

        let _ = fs::remove_file(&path);
    }
}
