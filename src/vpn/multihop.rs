//! P3-4: 多跳路由
//!
//! 实现基于 DHT 的多跳路由发现和路径管理。
//! 支持自动发现 3 跳以内的路由、路径失效切换和路由表维护。
//!
//! # 路由发现流程
//!
//! 1. 收到发送请求 → 检查路由表
//! 2. 有缓存路由且未过期 → 直接使用
//! 3. 无缓存 → 通过 DHT `find_node()` 获取目标附近的节点列表
//! 4. 选择距离 target 最近的节点作为下一跳
//! 5. 如果该节点不是 target 本身，跳数 +1
//! 6. 缓存结果
//!
//! # 路由失效处理
//!
//! - 下一跳不可达 → 从路由表移除
//! - 调用 `find_alternative()` 使用上次候选列表寻找替代路径
//! - 如果无替代路径，重新调用 `discover_route()`

use crate::router::{ConnectionType, RouterError};
use crate::vpn::dht::DhtManager;
use crate::vpn::identity::NodeID;
use crate::vpn::relay::RelayManager;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/// 路由表最大条目数（验收标准要求 1000）
pub const MAX_ROUTE_ENTRIES: usize = 1000;

/// 默认路由超时时间（秒）
pub const DEFAULT_ROUTE_TIMEOUT_SECS: u64 = 300;

/// 路由发现超时（秒）
pub const ROUTE_DISCOVERY_TIMEOUT_SECS: u64 = 10;

/// 最大跳数
pub const MAX_HOP_COUNT: u8 = 10;

/// 路由度量：每跳基础值
pub const METRIC_PER_HOP: u32 = 100;

/// 路由度量：中继附加惩罚
pub const METRIC_RELAY_PENALTY: u32 = 50;

/// 路由度量：直连附加惩罚
pub const METRIC_DIRECT_PENALTY: u32 = 10;

/// 过期清理周期（秒）
pub const CLEANUP_INTERVAL_SECS: u64 = 60;

// ──────────────────────────────────────────────
//  Route Message Types
// ──────────────────────────────────────────────

/// 路由消息子类型
///
/// 作为 `MessageType::Route(0x08)` 的 payload 首字节使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteMessageType {
    /// 路由发现请求
    RouteDiscovery = 0x01,
    /// 路由发现响应
    RouteReply = 0x02,
    /// 路由错误
    RouteError = 0x03,
}

impl RouteMessageType {
    /// 从 u8 解析
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::RouteDiscovery),
            0x02 => Some(Self::RouteReply),
            0x03 => Some(Self::RouteError),
            _ => None,
        }
    }

    /// 转换为 u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ──────────────────────────────────────────────
//  Multi-Hop Route Entry
// ──────────────────────────────────────────────

/// 多跳路由条目
///
/// 记录到目标节点的路由信息，包括下一跳、跳数、度量值、
/// 过期时间和失效切换用的候选节点列表。
#[derive(Debug, Clone)]
pub struct MultiHopEntry {
    /// 目标节点
    pub target: NodeID,
    /// 下一跳节点
    pub next_hop: NodeID,
    /// 跳数（1 = 直连）
    pub hop_count: u8,
    /// 路由度量（越小越好）
    pub metric: u32,
    /// 连接类型
    pub connection_type: ConnectionType,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 过期时间
    pub expires_at: Instant,
    /// 候选节点列表（用于失效后切换）
    ///
    /// 保存上一次 DHT 查询返回的其他候选节点，
    /// 在当前下一跳不可达时尝试切换。
    pub candidates: Vec<(NodeID, String)>,
}

impl MultiHopEntry {
    /// 创建新的多跳路由条目
    pub fn new(
        target: NodeID,
        next_hop: NodeID,
        hop_count: u8,
        connection_type: ConnectionType,
        candidates: Vec<(NodeID, String)>,
    ) -> Self {
        let metric = Self::calculate_metric(hop_count, connection_type);
        let now = Instant::now();
        Self {
            target,
            next_hop,
            hop_count,
            metric,
            connection_type,
            last_active: now,
            expires_at: now + Duration::from_secs(DEFAULT_ROUTE_TIMEOUT_SECS),
            candidates,
        }
    }

    /// 计算路由度量值
    ///
    /// 度量 = hop_count * METRIC_PER_HOP + 连接类型惩罚
    /// - Relay: +50
    /// - Direct(LAN): +10
    fn calculate_metric(hop_count: u8, conn_type: ConnectionType) -> u32 {
        let base = (hop_count as u32) * METRIC_PER_HOP;
        match conn_type {
            ConnectionType::Relay => base + METRIC_RELAY_PENALTY,
            ConnectionType::Lan | ConnectionType::Vpn => base + METRIC_DIRECT_PENALTY,
            ConnectionType::Unknown => base + 999,
        }
    }

    /// 检查路由是否已过期
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// 更新最后活跃时间并延长过期时间
    pub fn refresh(&mut self) {
        self.last_active = Instant::now();
        self.expires_at = self.last_active + Duration::from_secs(DEFAULT_ROUTE_TIMEOUT_SECS);
    }

    /// 是否直连路由（跳数 = 1）
    pub fn is_direct(&self) -> bool {
        self.hop_count == 1
    }
}

// ──────────────────────────────────────────────
//  MultihopManager
// ──────────────────────────────────────────────

/// 多跳路由管理器
///
/// 管理多跳路由表的生命周期：路由发现、缓存、失效切换和过期清理。
///
/// 与 `DhtManager` 配合进行节点发现，与 `RelayManager` 配合进行消息转发。
///
/// # 路由表容量
///
/// 上限 1000 条目，达到上限后新路由会驱逐最旧条目。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::multihop::MultihopManager;
/// use ll_vpn::vpn::identity::NodeID;
///
/// let local_id = NodeID::from_bytes(&[1u8; 32]);
/// let manager = MultihopManager::new(local_id);
/// assert_eq!(manager.route_count(), 0);
/// ```
pub struct MultihopManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 路由表（目标 → 路由条目）
    routes: Arc<Mutex<HashMap<NodeID, MultiHopEntry>>>,
    /// DHT 管理器引用
    dht: Option<Arc<DhtManager>>,
    /// 中继管理器引用
    relay: Option<Arc<RelayManager>>,
    /// 路由表最大条目数
    max_entries: usize,
    /// 上次清理时间
    last_cleanup: Mutex<Instant>,
}


impl MultihopManager {
    /// 创建新的多跳路由管理器
    ///
    /// # 参数
    /// - `local_id`: 本地节点 ID
    pub fn new(local_id: NodeID) -> Self {
        Self {
            local_id,
            routes: Arc::new(Mutex::new(HashMap::new())),
            dht: None,
            relay: None,
            max_entries: MAX_ROUTE_ENTRIES,
            last_cleanup: Mutex::new(Instant::now()),
        }
    }

    /// 绑定 DHT 管理器
    ///
    /// 用于路由发现时查询目标节点附近的节点列表。
    pub fn set_dht(&mut self, dht: Arc<DhtManager>) {
        self.dht = Some(dht);
    }

    /// 绑定中继管理器
    ///
    /// 用于发送路由发现消息和转发数据。
    pub fn set_relay(&mut self, relay: Arc<RelayManager>) {
        self.relay = Some(relay);
    }

    // ── 核心路由操作 ──

    /// 通过 DHT 发现到目标节点的路由
    ///
    /// 使用 DHT `find_node()` 获取目标附近的节点列表，选择距离目标最近的节点作为下一跳。
    /// 如果最近节点就是 target 本身，则为直连路由（跳数=1），否则为多跳路由。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    ///
    /// # 返回
    /// - `Ok(())`: 路由发现成功
    /// - `Err(RouterError)`: 发现失败（DHT 未绑定、无可用节点等）
    pub fn discover_route(&self, target: &NodeID) -> Result<(), RouterError> {
        if target == &self.local_id {
            return Err(RouterError::InvalidData("cannot route to self".to_string()));
        }

        let dht = self
            .dht
            .as_ref()
            .ok_or_else(|| RouterError::SendFailed("DHT not bound".to_string()))?;

        // 1. 通过 DHT 查找目标附近的节点
        let candidates = dht.find_node(target);
        if candidates.is_empty() {
            return Err(RouterError::NoRoute(*target));
        }

        // 2. 按 XOR 距离对 target 排序
        let mut sorted: Vec<(NodeID, String)> = candidates;
        sorted.sort_by(|a, b| {
            let dist_a = xor_distance_u128(&a.0, target);
            let dist_b = xor_distance_u128(&b.0, target);
            dist_a.cmp(&dist_b)
        });

        // 3. 选择距离 target 最近的节点作为下一跳
        let (next_hop, _addr) = &sorted[0];

        // 4. 如果最近节点就是 target 本身 → 直连
        //    否则 → 多跳
        let hop_count: u8;
        let conn_type: ConnectionType;

        if *next_hop == *target {
            hop_count = 1;
            conn_type = ConnectionType::Lan;
        } else {
            hop_count = 2; // 至少两跳（本地 → next_hop → target）
            conn_type = ConnectionType::Relay;
        }

        // 5. 缓存结果（排除 next_hop 本身作为候选）
        let candidates_for_fallback: Vec<(NodeID, String)> = sorted[1..]
            .iter()
            .filter(|(id, _)| *id != *next_hop)
            .take(K_CANDIDATES_MAX)
            .cloned()
            .collect();

        let entry = MultiHopEntry::new(
            *target,
            *next_hop,
            hop_count,
            conn_type,
            candidates_for_fallback,
        );

        // 6. 插入路由表（如果已满则驱逐最旧条目）
        self.insert_or_evict(entry);

        Ok(())
    }

    /// 添加直连路由（跳数=1）
    ///
    /// 用于已知的直连节点，无需通过 DHT 发现。
    /// 路由度量最优（1*100 + 10 = 110）。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    /// - `addr`: 目标节点地址（保留用于候选列表）
    pub fn add_direct_route(&self, target: NodeID, addr: String) {
        if target == self.local_id {
            return;
        }

        let entry = MultiHopEntry::new(
            target,
            target, // 直连，下一跳即目标
            1,
            ConnectionType::Lan,
            vec![(target, addr)], // 候选列表包含自身
        );

        self.insert_or_evict(entry);
    }

    /// 查找路由
    ///
    /// 返回目标节点的路由信息（如果存在且未过期）。
    /// 不会自动触发路由发现。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    ///
    /// # 返回
    /// - `Some(&MultiHopEntry)`: 存在的有效路由
    /// - `None`: 路由不存在或已过期
    pub fn find_route(&self, target: &NodeID) -> Option<MultiHopEntry> {
        let routes = self.routes.lock().unwrap();
        routes.get(target).and_then(|entry| {
            if entry.is_expired() {
                None // 已过期视为不存在
            } else {
                Some(entry.clone())
            }
        })
    }

    /// 获取下一跳节点
    ///
    /// 如果路由不存在或已过期，返回 `RouterError::NoRoute`。
    /// 这是发送数据前的快捷查询方法。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    ///
    /// # 返回
    /// - `Ok(NodeID)`: 下一跳节点 ID
    /// - `Err(RouterError)`: 路由不可用
    pub fn next_hop(&self, target: &NodeID) -> Result<NodeID, RouterError> {
        self.find_route(target)
            .map(|entry| entry.next_hop)
            .ok_or_else(|| RouterError::NoRoute(*target))
    }

    /// 移除路由
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    ///
    /// # 返回
    /// - `Some(MultiHopEntry)`: 被移除的路由条目
    /// - `None`: 路由不存在
    pub fn remove_route(&self, target: &NodeID) -> Option<MultiHopEntry> {
        self.routes.lock().unwrap().remove(target)
    }

    /// 标记路由失效
    ///
    /// 将路由的过期时间设为过去，使其立即失效。
    /// 后续 `find_route()` 调用将不会返回该路由。
    /// 用于下一跳不可达时主动失效路由。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    pub fn mark_invalid(&self, target: &NodeID) {
        let mut routes = self.routes.lock().unwrap();
        if let Some(entry) = routes.get_mut(target) {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    /// 查找替代路径
    ///
    /// 当下一跳不可达时，从候选节点列表中寻找替代路径。
    /// 候选列表来自上次 DHT 查询时返回的其他节点。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    ///
    /// # 返回
    /// - `Ok(())`: 成功切换到替代路径
    /// - `Err(RouterError)`: 无可用替代路径
    pub fn find_alternative(&self, target: &NodeID) -> Result<(), RouterError> {
        let mut routes = self.routes.lock().unwrap();

        let (next_best, _addr) = {
            let entry = routes
                .get(target)
                .ok_or_else(|| RouterError::NoRoute(*target))?;

            // 从候选列表中找第一个 != current_next_hop 的节点
            let current_next = entry.next_hop;
            let candidates = &entry.candidates;

            candidates
                .iter()
                .find(|(id, _)| *id != current_next && *id != self.local_id)
                .cloned()
                .ok_or_else(|| RouterError::NoRoute(*target))?
        };

        // 构建新的路由条目（跳数不变，使用新下一跳）
        let old_entry = routes.get(target).unwrap();
        let new_entry = MultiHopEntry {
            target: *target,
            next_hop: next_best,
            hop_count: old_entry.hop_count,
            metric: MultiHopEntry::calculate_metric(old_entry.hop_count, ConnectionType::Relay),
            connection_type: ConnectionType::Relay,
            last_active: Instant::now(),
            expires_at: Instant::now() + Duration::from_secs(DEFAULT_ROUTE_TIMEOUT_SECS),
            candidates: old_entry.candidates.clone(),
        };

        routes.insert(*target, new_entry);
        Ok(())
    }

    /// 刷新过时路由
    ///
    /// 遍历路由表，对过期的路由重新发起 DHT 发现。
    /// 如果 DHT 不可用或无替代节点，保留原条目但标记为已刷新（延长过期时间）。
    ///
    /// # 返回
    /// - 成功刷新的路由数量
    pub fn refresh_stale_routes(&self) -> usize {
        let stale_targets: Vec<NodeID> = {
            let routes = self.routes.lock().unwrap();
            routes
                .iter()
                .filter(|(_, entry)| entry.is_expired())
                .map(|(target, _)| *target)
                .collect()
        };

        let mut refreshed = 0;
        for target in &stale_targets {
            // 尝试重新发现
            if self.discover_route(target).is_ok() {
                refreshed += 1;
            } else {
                // 无法刷新：延长过期时间避免反复刷新
                let mut routes = self.routes.lock().unwrap();
                if let Some(entry) = routes.get_mut(target) {
                    entry.expires_at =
                        Instant::now() + Duration::from_secs(DEFAULT_ROUTE_TIMEOUT_SECS);
                }
            }
        }

        refreshed
    }

    /// 获取路由条目数
    pub fn route_count(&self) -> usize {
        self.routes.lock().unwrap().len()
    }

    /// 插入自定义路由条目
    ///
    /// 直接将一个完整的路由条目插入路由表。
    /// 如果表已满，会驱逐最旧的条目。
    /// 如果目标已存在，会覆盖原有条目。
    ///
    /// # 参数
    /// - `entry`: 要插入的路由条目
    pub fn insert_route(&self, entry: MultiHopEntry) {
        self.insert_or_evict(entry);
    }

    /// 查找使用指定节点作为下一跳的所有路由目标
    ///
    /// 用于自愈模块：当节点离线时，找出所有经过该节点的路由，
    /// 以便触发替代路径切换。
    ///
    /// # 参数
    /// - `next_hop`: 下一跳节点 ID
    ///
    /// # 返回
    /// - 使用该节点作为下一跳的所有目标节点列表
    pub fn find_routes_by_next_hop(&self, next_hop: &NodeID) -> Vec<NodeID> {
        let routes = self.routes.lock().unwrap();
        routes
            .iter()
            .filter(|(_, entry)| entry.next_hop == *next_hop)
            .map(|(target, _)| *target)
            .collect()
    }

    /// 清理过期路由
    ///
    /// 移除所有已过期的路由条目。
    /// 每 `CLEANUP_INTERVAL_SECS` 秒执行一次，避免高频调用。
    ///
    /// # 返回
    /// - 被清理的路由数量
    pub fn cleanup_expired(&self) -> usize {
        let mut last_cleanup = self.last_cleanup.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last_cleanup) < Duration::from_secs(CLEANUP_INTERVAL_SECS) {
            return 0; // 距上次清理不足 60 秒，跳过
        }
        *last_cleanup = now;
        drop(last_cleanup);

        let mut routes = self.routes.lock().unwrap();
        let before = routes.len();
        routes.retain(|_, entry| !entry.is_expired());
        before - routes.len()
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    // ── 内部辅助方法 ──

    /// 插入路由条目，如果表满则驱逐最旧条目
    fn insert_or_evict(&self, entry: MultiHopEntry) {
        let mut routes = self.routes.lock().unwrap();

        // 如果已存在，直接更新
        if routes.contains_key(&entry.target) {
            routes.insert(entry.target, entry);
            return;
        }

        // 如果未满，直接插入
        if routes.len() < self.max_entries {
            routes.insert(entry.target, entry);
            return;
        }

        // 已满：找到最旧的条目驱逐
        let oldest_target = routes
            .iter()
            .min_by_key(|(_, e)| e.last_active)
            .map(|(k, _)| *k);

        if let Some(oldest) = oldest_target {
            routes.remove(&oldest);
        }

        routes.insert(entry.target, entry);
    }
}

impl fmt::Debug for MultihopManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultihopManager")
            .field("local_id", &self.local_id.to_hex())
            .field("route_count", &self.route_count())
            .field("max_entries", &self.max_entries)
            .field("dht_bound", &self.dht.is_some())
            .field("relay_bound", &self.relay.is_some())
            .finish()
    }
}

// ──────────────────────────────────────────────
//  Internal Helpers
// ──────────────────────────────────────────────

/// 候选节点最大保留数
const K_CANDIDATES_MAX: usize = 10;

/// 计算两个 NodeID 之间的 XOR 距离并返回 u128 值
///
/// 用于候选节点排序，值越小表示距离目标越近。
fn xor_distance_u128(a: &NodeID, b: &NodeID) -> u128 {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let mut dist: u128 = 0;
    for i in 0..16 {
        // 前 16 字节 → u128 的高位
        dist = (dist << 8) | (a_bytes[i] ^ b_bytes[i]) as u128;
    }
    dist
}

// ──────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::dht::DhtManager;
    use crate::vpn::identity::NodeID;

    /// 辅助：创建具有特定首字节的 NodeID
    fn make_id(byte: u8) -> NodeID {
        let mut bytes = [0u8; 32];
        bytes[0] = byte;
        NodeID::from_bytes(&bytes)
    }

    /// 辅助：创建具有特定前 16 字节的 NodeID
    fn make_id_from(prefix: &[u8]) -> NodeID {
        let mut bytes = [0u8; 32];
        let n = prefix.len().min(32);
        bytes[..n].copy_from_slice(&prefix[..n]);
        NodeID::from_bytes(&bytes)
    }

    // ── RouteMessageType 转换测试 ──

    #[test]
    fn test_route_message_type_conversion() {
        assert_eq!(
            RouteMessageType::from_u8(0x01),
            Some(RouteMessageType::RouteDiscovery)
        );
        assert_eq!(
            RouteMessageType::from_u8(0x02),
            Some(RouteMessageType::RouteReply)
        );
        assert_eq!(
            RouteMessageType::from_u8(0x03),
            Some(RouteMessageType::RouteError)
        );
        assert_eq!(RouteMessageType::from_u8(0x00), None);
        assert_eq!(RouteMessageType::from_u8(0xFF), None);

        assert_eq!(RouteMessageType::RouteDiscovery.to_u8(), 0x01);
        assert_eq!(RouteMessageType::RouteReply.to_u8(), 0x02);
        assert_eq!(RouteMessageType::RouteError.to_u8(), 0x03);
    }

    // ── MultiHopEntry 测试 ──

    #[test]
    fn test_multi_hop_entry_new_direct() {
        let target = make_id(0x02);

        let entry = MultiHopEntry::new(target, target, 1, ConnectionType::Lan, vec![]);

        assert_eq!(entry.target, target);
        assert_eq!(entry.next_hop, target);
        assert_eq!(entry.hop_count, 1);
        assert_eq!(entry.connection_type, ConnectionType::Lan);
        assert!(entry.is_direct());
        assert!(!entry.is_expired());
        // metric = 1*100 + 10 = 110
        assert_eq!(entry.metric, 110);
    }

    #[test]
    fn test_multi_hop_entry_new_relay() {
        let target = make_id(0x02);
        let next_hop = make_id(0x03);

        let entry = MultiHopEntry::new(target, next_hop, 2, ConnectionType::Relay, vec![]);

        assert_eq!(entry.target, target);
        assert_eq!(entry.next_hop, next_hop);
        assert_eq!(entry.hop_count, 2);
        assert!(!entry.is_direct());
        // metric = 2*100 + 50 = 250
        assert_eq!(entry.metric, 250);
    }

    #[test]
    fn test_multi_hop_entry_expiry() {
        let target = make_id(0x02);

        // 创建一个已过期的条目
        let mut entry = MultiHopEntry::new(target, target, 1, ConnectionType::Lan, vec![]);
        entry.expires_at = Instant::now() - Duration::from_secs(1);
        assert!(entry.is_expired());

        // 刷新后不再过期
        entry.refresh();
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_multi_hop_entry_calculate_metric() {
        assert_eq!(
            MultiHopEntry::calculate_metric(1, ConnectionType::Lan),
            110
        );
        assert_eq!(
            MultiHopEntry::calculate_metric(1, ConnectionType::Vpn),
            110
        );
        assert_eq!(
            MultiHopEntry::calculate_metric(2, ConnectionType::Relay),
            250
        );
        assert_eq!(
            MultiHopEntry::calculate_metric(3, ConnectionType::Relay),
            350
        );
        assert_eq!(
            MultiHopEntry::calculate_metric(1, ConnectionType::Unknown),
            1099
        );
    }

    // ── MultihopManager 基本测试 ──

    #[test]
    fn test_multihop_manager_new() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        assert_eq!(*manager.local_id(), local);
        assert_eq!(manager.route_count(), 0);
    }

    #[test]
    fn test_multihop_manager_debug() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let debug = format!("{:?}", manager);
        assert!(debug.contains("MultihopManager"));
        assert!(debug.contains("route_count"));
    }

    // ── 直连路由测试 ──

    #[test]
    fn test_add_direct_route() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());

        assert_eq!(manager.route_count(), 1);

        let found = manager.find_route(&target);
        assert!(found.is_some());
        let entry = found.unwrap();
        assert_eq!(entry.next_hop, target);
        assert_eq!(entry.hop_count, 1);
        assert_eq!(entry.connection_type, ConnectionType::Lan);
    }

    #[test]
    fn test_add_direct_route_self() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        // 添加自身不应有影响
        manager.add_direct_route(local, "127.0.0.1:9876".to_string());
        assert_eq!(manager.route_count(), 0);
    }

    #[test]
    fn test_add_multiple_direct_routes() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        for i in 0..5 {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x10 + i;
            let target = NodeID::from_bytes(&bytes);
            manager.add_direct_route(target, format!("10.0.0.{}:9876", i + 2));
        }

        assert_eq!(manager.route_count(), 5);
    }

    // ── 查找路由测试 ──

    #[test]
    fn test_find_route_nonexistent() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let unknown = make_id(0xFF);
        assert!(manager.find_route(&unknown).is_none());
    }

    #[test]
    fn test_find_route_expired() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());
        assert!(manager.find_route(&target).is_some());

        // 标记失效后应查不到
        manager.mark_invalid(&target);
        assert!(manager.find_route(&target).is_none());
    }

    #[test]
    fn test_next_hop() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());

        let hop = manager.next_hop(&target);
        assert!(hop.is_ok());
        assert_eq!(hop.unwrap(), target);
    }

    #[test]
    fn test_next_hop_nonexistent() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let unknown = make_id(0xFF);
        let result = manager.next_hop(&unknown);
        assert!(result.is_err());
    }

    // ── 移除路由测试 ──

    #[test]
    fn test_remove_route() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());
        assert_eq!(manager.route_count(), 1);

        let removed = manager.remove_route(&target);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().target, target);
        assert_eq!(manager.route_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_route() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let unknown = make_id(0xFF);
        assert!(manager.remove_route(&unknown).is_none());
    }

    // ── 路由失效测试 ──

    #[test]
    fn test_mark_invalid() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());
        assert!(manager.find_route(&target).is_some());

        manager.mark_invalid(&target);
        assert!(manager.find_route(&target).is_none());
        // 路由仍存在于表中但标记为过期
        assert_eq!(manager.route_count(), 1);
    }

    // ── DHT 发现路由测试 ──

    #[test]
    fn test_discover_route_no_dht() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        // DHT 未绑定，应返回错误
        let result = manager.discover_route(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_discover_route_with_dht_direct() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let target = make_id(0x02);
        // 将 target 插入 DHT（模拟它就在网络中）
        dht.insert_node(target, "10.0.0.2:9876".to_string()).unwrap();

        let mut manager = MultihopManager::new(local);
        manager.set_dht(Arc::new(dht));

        let result = manager.discover_route(&target);
        assert!(result.is_ok(), "discover_route failed: {:?}", result);

        let found = manager.find_route(&target);
        assert!(found.is_some());
        let entry = found.unwrap();
        // 因为最近节点就是 target 本身
        assert_eq!(entry.next_hop, target);
        assert_eq!(entry.hop_count, 1);
    }

    #[test]
    fn test_discover_route_with_dht_multihop() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // 插入多个节点，target 不在其中（需要多跳）
        let target = make_id(0xFF);
        let relay_a = make_id(0x02);
        let relay_b = make_id(0x03);

        dht.insert_node(relay_a, "10.0.0.2:9876".to_string()).unwrap();
        dht.insert_node(relay_b, "10.0.0.3:9876".to_string()).unwrap();

        let mut manager = MultihopManager::new(local);
        manager.set_dht(Arc::new(dht));

        let result = manager.discover_route(&target);
        assert!(result.is_ok(), "discover_route failed: {:?}", result);

        let found = manager.find_route(&target);
        assert!(found.is_some());
        let entry = found.unwrap();
        // target 不在 DHT 中，下一跳应是 relay_a 或 relay_b
        assert!(entry.next_hop == relay_a || entry.next_hop == relay_b);
        assert_eq!(entry.hop_count, 2);
        assert_eq!(entry.connection_type, ConnectionType::Relay);
    }

    #[test]
    fn test_discover_route_self() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let mut manager = MultihopManager::new(local);
        manager.set_dht(Arc::new(dht));

        let result = manager.discover_route(&local);
        assert!(result.is_err()); // 不能路由到自身
    }

    // ── 路由发现 → 查找 → 替代路径测试 ──

    #[test]
    fn test_find_alternative_no_candidates() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0x02);
        // 添加直连路由（无候选）
        manager.add_direct_route(target, "10.0.0.2:9876".to_string());

        // 无候选节点，应失败
        let result = manager.find_alternative(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_find_alternative_with_candidates() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        let target = make_id(0xFF);
        let relay_b = make_id(0x03);

        // 通过 routes 字段直接插入带候选的路由
        {
            let routes = manager.routes.lock().unwrap();
            // 我们不受限：routes 是 Arc<Mutex<HashMap>>，可以 clone Arc
        }
        let routes = manager.routes.clone();
        routes.lock().unwrap().insert(
            target,
            MultiHopEntry::new(
                target,
                make_id(0x02), // 当前下一跳（模拟已失效）
                2,
                ConnectionType::Relay,
                vec![(relay_b, "10.0.0.3:9876".to_string())], // 替代
            ),
        );

        let result = manager.find_alternative(&target);
        assert!(result.is_ok(), "find_alternative failed: {:?}", result);

        let found = manager.find_route(&target);
        assert!(found.is_some());
        let entry = found.unwrap();
        // 下一跳应切换到 relay_b
        assert_eq!(entry.next_hop, relay_b);
    }

    // ── 路由表容量限制测试 ──

    #[test]
    fn test_route_table_capacity_limit() {
        let local = make_id(0x01);
        let mut manager = MultihopManager::new(local);
        // 使用小容量测试驱逐
        manager.max_entries = 5;

        // 添加 5 条路由
        for i in 0..5 {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x10 + i;
            let target = NodeID::from_bytes(&bytes);
            manager.add_direct_route(target, format!("10.0.0.{}:9876", i + 2));
        }
        assert_eq!(manager.route_count(), 5);

        // 添加第 6 条，应该驱逐最旧的一条
        let mut bytes = [0u8; 32];
        bytes[0] = 0x20;
        let new_target = NodeID::from_bytes(&bytes);
        manager.add_direct_route(new_target, "10.0.0.99:9876".to_string());

        // 应该有 5 条（最旧的被驱逐）
        assert_eq!(manager.route_count(), 5);

        // 新路由应存在
        assert!(manager.find_route(&new_target).is_some());
    }

    // ── 过期清理测试 ──

    #[test]
    fn test_cleanup_expired() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        // 添加路由
        let target1 = make_id(0x02);
        let target2 = make_id(0x03);
        manager.add_direct_route(target1, "10.0.0.2:9876".to_string());
        manager.add_direct_route(target2, "10.0.0.3:9876".to_string());
        assert_eq!(manager.route_count(), 2);

        // 标记 target1 为失效
        manager.mark_invalid(&target1);

        // 清理过期（第一次调用可能因为间隔限制被跳过，修改 last_cleanup）
        {
            let mut last = manager.last_cleanup.lock().unwrap();
            *last = Instant::now() - Duration::from_secs(CLEANUP_INTERVAL_SECS + 1);
        }

        let cleaned = manager.cleanup_expired();
        assert!(cleaned >= 1);
        assert_eq!(manager.route_count(), 1);
        assert!(manager.find_route(&target2).is_some());
    }

    #[test]
    fn test_cleanup_expired_skip_recent() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        // 刚清理过，再次调用应跳过
        let cleaned = manager.cleanup_expired();
        assert_eq!(cleaned, 0);
    }

    // ── 路由度量排序测试 ──

    #[test]
    fn test_route_metric_ordering() {
        // 直连（1跳）< 中继2跳 < 中继3跳
        let direct = MultiHopEntry::calculate_metric(1, ConnectionType::Lan);
        let relay2 = MultiHopEntry::calculate_metric(2, ConnectionType::Relay);
        let relay3 = MultiHopEntry::calculate_metric(3, ConnectionType::Relay);

        assert!(direct < relay2);
        assert!(relay2 < relay3);
    }

    // ── 刷新过时路由测试 ──

    #[test]
    fn test_refresh_stale_routes() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        // 添加一些路由并标记为过期
        let target1 = make_id(0x02);
        let target2 = make_id(0x03);
        manager.add_direct_route(target1, "10.0.0.2:9876".to_string());
        manager.add_direct_route(target2, "10.0.0.3:9876".to_string());

        // 初始状态路由有效
        assert!(manager.find_route(&target1).is_some());
        assert!(manager.find_route(&target2).is_some());

        // 标记过期
        manager.mark_invalid(&target1);
        manager.mark_invalid(&target2);

        // 过期后找不到
        assert!(manager.find_route(&target1).is_none());

        // 过期条目应仍在表中（只是标记为过期）
        {
            let routes = manager.routes.lock().unwrap();
            assert!(routes.contains_key(&target1));
        }

        // 刷新过时路由
        let refreshed = manager.refresh_stale_routes();
        // 由于没有绑定 DHT，会 fallback 延长过期时间，refreshed = 0
        assert_eq!(refreshed, 0);

        // 条目应保留（无法刷新时延长了过期时间）
    }

    // ── 多跳管理器：set_dht / set_relay 测试 ──

    #[test]
    fn test_set_dht_and_relay() {
        let local = make_id(0x01);
        let mut manager = MultihopManager::new(local);

        let dht = Arc::new(DhtManager::new(local));
        manager.set_dht(dht);

        // 验证 DHT 已绑定（通过 discover_route 不再报 "DHT not bound"）
        let target = make_id(0x02);
        let result = manager.discover_route(&target);
        // DHT 中无节点，报 NoRoute 而不是 "DHT not bound"
        assert!(result.is_err());
        assert!(!format!("{:?}", result).contains("DHT not bound"));
    }

    // ── 集成测试：发现 → 使用 → 失效 → 替代 ──

    #[test]
    fn test_discover_failover_integration() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let target = make_id(0xFF);
        let relay_a = make_id(0x02);
        let relay_b = make_id(0x03);

        dht.insert_node(relay_a, "10.0.0.2:9876".to_string()).unwrap();
        dht.insert_node(relay_b, "10.0.0.3:9876".to_string()).unwrap();

        let mut manager = MultihopManager::new(local);
        manager.set_dht(Arc::new(dht));

        // 1. 发现路由
        let result = manager.discover_route(&target);
        assert!(result.is_ok(), "initial discovery failed");

        #[allow(unused_variables)]
        let entry = manager.find_route(&target).unwrap();

        // 2. 标记当前下一跳失效
        manager.mark_invalid(&target);
        assert!(manager.find_route(&target).is_none());

        // 3. 找替代路径
        let alt_result = manager.find_alternative(&target);
        assert!(alt_result.is_ok(), "find_alternative failed");

        #[allow(unused_variables)]
        let _new_entry = manager.find_route(&target).unwrap();
        // 下一跳应该不同（如果有候选）
        // 注意：在 DHT 场景中，候选列表来自 discover_route 的 sorted[1..]
    }

    // ── 边界情况测试 ──

    #[test]
    fn test_empty_manager() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        assert_eq!(manager.route_count(), 0);
        assert!(manager.find_route(&make_id(0x02)).is_none());
        assert!(manager.next_hop(&make_id(0x02)).is_err());
    }

    #[test]
    fn test_route_count_after_operations() {
        let local = make_id(0x01);
        let manager = MultihopManager::new(local);

        assert_eq!(manager.route_count(), 0);

        // 添加
        manager.add_direct_route(make_id(0x02), "addr".to_string());
        assert_eq!(manager.route_count(), 1);

        manager.add_direct_route(make_id(0x03), "addr".to_string());
        assert_eq!(manager.route_count(), 2);

        // 移除
        manager.remove_route(&make_id(0x02));
        assert_eq!(manager.route_count(), 1);
    }

    // ── XOR 距离辅助函数测试 ──

    #[test]
    fn test_xor_distance_u128() {
        let a = make_id(0x00);
        let b = make_id(0x00);
        assert_eq!(xor_distance_u128(&a, &b), 0);

        let c = make_id(0xFF);
        let d = make_id(0x00);
        assert_eq!(xor_distance_u128(&c, &d), 0xFF000000000000000000000000000000_u128);
    }
}
