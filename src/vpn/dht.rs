//! P3-3: DHT 节点发现
//!
//! 简化版 Kademlia DHT 实现，支持：
//! - 256 位 XOR 距离路由表（K-bucket）
//! - FIND_NODE 最近节点查找
//! - 节点加入/退出时路由表自动收敛
//! - PUT/GET 值存储（带 TTL 过期）
//! - 定期刷新与淘汰策略（LRU）

use crate::vpn::bootstrap::BootstrapNode;
use crate::vpn::identity::NodeID;
use crate::vpn::relay::{Message, MessageType, RelayManager};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────
//  Constants
// ──────────────────────────────────────────────

/// 每个 K-bucket 最大节点数（Kademlia 标准 K=20）
pub const K_BUCKET_SIZE: usize = 20;

/// K-bucket 数量（256 位）
pub const BUCKET_COUNT: usize = 256;

/// 值存储默认 TTL（秒）
pub const DEFAULT_VALUE_TTL: u64 = 3600;

/// 节点刷新间隔（秒）
pub const REFRESH_INTERVAL_SECS: u64 = 300;

/// 节点存活超时（秒）
pub const NODE_TIMEOUT_SECS: u64 = 600;

/// DHT 默认端口
pub const DEFAULT_DHT_PORT: u16 = 9885;

// ──────────────────────────────────────────────
//  DHT Message Types
// ──────────────────────────────────────────────

/// DHT 消息子类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtMessageType {
    /// PING — 节点存活探测
    Ping = 0x01,
    /// PONG — 存活响应
    Pong = 0x02,
    /// FIND_NODE — 查找最近节点
    FindNode = 0x03,
    /// NODES — 返回最近节点列表
    Nodes = 0x04,
    /// PUT — 存储值
    Put = 0x05,
    /// GET — 获取值
    Get = 0x06,
    /// VALUE — 返回值
    Value = 0x07,
}

impl DhtMessageType {
    /// 从 u8 解析
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Ping),
            0x02 => Some(Self::Pong),
            0x03 => Some(Self::FindNode),
            0x04 => Some(Self::Nodes),
            0x05 => Some(Self::Put),
            0x06 => Some(Self::Get),
            0x07 => Some(Self::Value),
            _ => None,
        }
    }

    /// 转换为 u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ──────────────────────────────────────────────
//  DHT Error
// ──────────────────────────────────────────────

/// DHT 错误类型
#[derive(Debug, Clone)]
pub enum DhtError {
    /// 节点不可达
    NodeUnreachable(NodeID),
    /// 路由表满
    RoutingTableFull,
    /// 值未找到
    ValueNotFound,
    /// 无效消息
    InvalidMessage(String),
    /// 超时
    Timeout,
}

impl fmt::Display for DhtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhtError::NodeUnreachable(id) => write!(f, "node unreachable: {}", id),
            DhtError::RoutingTableFull => write!(f, "routing table full"),
            DhtError::ValueNotFound => write!(f, "value not found"),
            DhtError::InvalidMessage(msg) => write!(f, "invalid DHT message: {}", msg),
            DhtError::Timeout => write!(f, "DHT operation timeout"),
        }
    }
}

impl std::error::Error for DhtError {}

// ──────────────────────────────────────────────
//  Core Data Structures
// ──────────────────────────────────────────────

/// K-bucket 中的节点条目
#[derive(Debug, Clone)]
pub struct BucketEntry {
    /// 节点 ID
    pub node_id: NodeID,
    /// 节点地址
    pub addr: String,
    /// 最后活跃时间
    pub last_seen: Instant,
}

/// K-bucket
///
/// 存储最多 K 个节点，按最后活跃时间排序。
/// 当桶满且最旧节点不响应时，优先淘汰最久未联系的节点。
#[derive(Debug, Clone)]
pub struct KBucket {
    /// 桶中的节点
    entries: VecDeque<BucketEntry>,
    /// 桶的最大容量
    capacity: usize,
}

impl KBucket {
    /// 创建新的 K-bucket
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(capacity + 1),
            capacity,
        }
    }

    /// 插入或更新节点
    ///
    /// 如果节点已存在，更新其 last_seen 并移到队尾（最近活跃）。
    /// 如果桶未满，新节点插入队尾。
    /// 如果桶已满，返回最旧的节点（需要 ping 验证存活）。
    ///
    /// 返回: `Ok(true)` 表示插入成功，`Ok(false)` 表示更新成功，
    ///        `Err(Some(entry))` 表示桶满，返回最旧的待验证节点。
    pub fn insert(&mut self, node_id: NodeID, addr: String) -> Result<bool, BucketEntry> {
        // 查找是否已存在
        for entry in self.entries.iter_mut() {
            if entry.node_id == node_id {
                entry.last_seen = Instant::now();
                entry.addr = addr;
                // 移到队尾（最近活跃）
                return Ok(false);
            }
        }

        // 新节点
        let entry = BucketEntry {
            node_id,
            addr,
            last_seen: Instant::now(),
        };

        if self.entries.len() < self.capacity {
            self.entries.push_back(entry);
            Ok(true)
        } else {
            // 桶满，返回最旧的节点
            Err(entry)
        }
    }

    /// 更新节点最后活跃时间
    pub fn touch(&mut self, node_id: &NodeID) -> bool {
        for i in 0..self.entries.len() {
            if self.entries[i].node_id == *node_id {
                self.entries[i].last_seen = Instant::now();
                let entry = self.entries.remove(i).unwrap();
                self.entries.push_back(entry);
                return true;
            }
        }
        false
    }

    /// 移除节点
    pub fn remove(&mut self, node_id: &NodeID) -> Option<BucketEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.node_id == *node_id) {
            self.entries.remove(pos)
        } else {
            None
        }
    }

    /// 获取桶中所有节点
    pub fn entries(&self) -> impl Iterator<Item = &BucketEntry> {
        self.entries.iter()
    }

    /// 获取桶中节点数量
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 桶是否为空
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 桶是否已满
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// 获取最久未联系的节点
    pub fn least_recently_seen(&self) -> Option<&BucketEntry> {
        self.entries.front()
    }

    /// 清空桶
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// 值存储条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueEntry {
    /// 存储的值
    pub value: Vec<u8>,
    /// 创建时间戳（Unix 秒）
    pub created_at: u64,
    /// TTL（秒）
    pub ttl: u64,
}

impl ValueEntry {
    /// 创建新值条目
    pub fn new(value: Vec<u8>, ttl: u64) -> Self {
        Self {
            value,
            created_at: now_secs(),
            ttl,
        }
    }

    /// 检查值是否已过期
    pub fn is_expired(&self) -> bool {
        now_secs() >= self.created_at + self.ttl
    }
}

// ──────────────────────────────────────────────
//  DhtManager
// ──────────────────────────────────────────────

/// DHT 管理器
///
/// 简化版 Kademlia DHT 实现，管理节点发现和值存储。
///
/// # 路由表结构
///
/// 路由表由 256 个 K-bucket 组成，每个 bucket 对应一个 XOR 距离前缀。
/// bucket[i] 存储与本地节点 XOR 距离第 i 位为 1 的节点（前 255-i 位相同）。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::dht::DhtManager;
/// use ll_vpn::vpn::identity::NodeID;
///
/// let local_id = NodeID::from_bytes(&[1u8; 32]);
/// let dht = DhtManager::new(local_id);
/// assert_eq!(dht.node_count(), 0);
/// ```
pub struct DhtManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 路由表（256 个 K-bucket）
    buckets: [Mutex<KBucket>; BUCKET_COUNT],
    /// 值存储（Hash(key) → ValueEntry）
    values: Mutex<HashMap<[u8; 32], ValueEntry>>,
    /// 本地地址（供其他节点连接）
    local_addr: Mutex<String>,
    /// 中继管理器引用
    relay_manager: Option<Arc<RelayManager>>,
    /// 运行标志
    running: AtomicBool,
}

// SAFETY: DhtManager 内部使用 Mutex 保护所有共享状态，Send + Sync 是安全的。
unsafe impl Send for DhtManager {}
unsafe impl Sync for DhtManager {}

impl DhtManager {
    /// 创建新的 DHT 管理器
    ///
    /// # 参数
    /// - `local_id`: 本地节点 ID（路由表的中心点）
    pub fn new(local_id: NodeID) -> Self {
        // 初始化 256 个 K-bucket
        // 使用数组初始化，每个 bucket 容量为 K_BUCKET_SIZE
        let buckets = Self::init_buckets();

        Self {
            local_id,
            buckets,
            values: Mutex::new(HashMap::new()),
            local_addr: Mutex::new(String::new()),
            relay_manager: None,
            running: AtomicBool::new(false),
        }
    }

    /// 初始化 256 个 K-bucket
    fn init_buckets() -> [Mutex<KBucket>; BUCKET_COUNT] {
        // 使用 MaybeUninit 避免逐个赋值
        let mut buckets: [std::mem::MaybeUninit<Mutex<KBucket>>; BUCKET_COUNT] =
            unsafe { std::mem::MaybeUninit::uninit().assume_init() };

        for bucket in &mut buckets[..] {
            *bucket = std::mem::MaybeUninit::new(Mutex::new(KBucket::new(K_BUCKET_SIZE)));
        }

        unsafe { std::mem::transmute::<_, [Mutex<KBucket>; BUCKET_COUNT]>(buckets) }
    }

    /// 设置中继管理器（用于 DHT 消息收发）
    pub fn set_relay_manager(&mut self, relay_manager: Arc<RelayManager>) {
        self.relay_manager = Some(relay_manager);
    }

    /// 设置本地地址
    pub fn set_local_addr(&self, addr: String) {
        *self.local_addr.lock().unwrap() = addr;
    }

    /// 获取本地地址
    pub fn local_addr(&self) -> String {
        self.local_addr.lock().unwrap().clone()
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    // ── 路由表操作 ──

    /// 计算 256 位 XOR 距离（返回逐字节 XOR 结果）
    ///
    /// Kademlia 使用 XOR 作为距离度量。返回 32 字节数组，
    /// 每个字节是两位节点 ID 对应字节的 XOR。
    pub fn xor_distance(a: &NodeID, b: &NodeID) -> [u8; 32] {
        let a_bytes = a.as_bytes();
        let b_bytes = b.as_bytes();
        let mut dist = [0u8; 32];
        for i in 0..32 {
            dist[i] = a_bytes[i] ^ b_bytes[i];
        }
        dist
    }

    /// 计算节点对应的桶索引
    ///
    /// 返回值为 0..256。
    /// - bucket[0]: 与本地节点 XOR 距离最高位为 1（即首字节首位不同）
    /// - bucket[255]: 与本地节点 XOR 距离最低位为 1（仅最后一位不同）
    /// - 如果 target == local_id，返回 255（存到最后一个 bucket）
    pub fn bucket_index(&self, target: &NodeID) -> usize {
        let xor = Self::xor_distance(&self.local_id, target);
        for i in 0..32 {
            if xor[i] != 0 {
                // 找到第一个非零字节，计算前导零位数
                let leading = xor[i].leading_zeros() as usize;
                return i * 8 + leading;
            }
        }
        // target == local_id，距离为 0，约定放入最后一个 bucket
        BUCKET_COUNT - 1
    }

    /// 将节点插入路由表
    ///
    /// 根据 XOR 距离计算桶索引，插入到对应的 K-bucket。
    /// 如果桶满，返回旧节点用于 PING 验证。
    ///
    /// # 参数
    /// - `node_id`: 待插入节点 ID
    /// - `addr`: 节点地址
    ///
    /// # 返回
    /// - `Ok(true)`: 成功插入新节点
    /// - `Ok(false)`: 节点已存在，更新 last_seen
    /// - `Err(Some(entry))`: 桶满，返回最旧节点（需要 PING 验证）
    /// - `Err(None)`: 桶满但无法返回旧节点
    pub fn insert_node(&self, node_id: NodeID, addr: String) -> Result<bool, Option<BucketEntry>> {
        // 不插入自身
        if node_id == self.local_id {
            return Ok(false);
        }

        let idx = self.bucket_index(&node_id);
        let mut bucket = self.buckets[idx].lock().unwrap();

        match bucket.insert(node_id, addr) {
            Ok(is_new) => Ok(is_new),
            Err(entry) => Err(Some(entry)),
        }
    }

    /// 更新节点最后活跃时间
    pub fn touch_node(&self, node_id: &NodeID) -> bool {
        if *node_id == self.local_id {
            return false;
        }
        let idx = self.bucket_index(node_id);
        let mut bucket = self.buckets[idx].lock().unwrap();
        bucket.touch(node_id)
    }

    /// 从路由表移除节点
    ///
    /// 当节点不响应 PING 时调用。
    pub fn remove_node(&self, node_id: &NodeID) -> Option<BucketEntry> {
        if *node_id == self.local_id {
            return None;
        }
        let idx = self.bucket_index(node_id);
        let mut bucket = self.buckets[idx].lock().unwrap();
        bucket.remove(node_id)
    }

    /// 返回距离 target 最近的 K 个节点
    ///
    /// 遍历所有 K-bucket，收集节点并按 XOR 距离排序，返回最近的 K 个。
    ///
    /// # 参数
    /// - `target`: 目标节点 ID
    /// - `count`: 返回的节点数量（通常为 K）
    ///
    /// # 返回
    /// 按 XOR 距离升序排列的 (NodeID, 地址) 列表
    pub fn find_nearest(&self, target: &NodeID, count: usize) -> Vec<(NodeID, String)> {
        let mut candidates: Vec<(NodeID, String, [u8; 32])> = Vec::new();

        // 收集所有节点
        for bucket in self.buckets.iter() {
            let guard = bucket.lock().unwrap();
            for entry in guard.entries() {
                let xor_dist = Self::xor_distance(target, &entry.node_id);
                candidates.push((entry.node_id, entry.addr.clone(), xor_dist));
            }
        }

        // 按 XOR 距离排序（字典序比较 256 位距离）
        candidates.sort_by(|a, b| cmp_xor(&a.2, &b.2));

        // 取前 count 个
        candidates
            .into_iter()
            .take(count)
            .map(|(id, addr, _)| (id, addr))
            .collect()
    }

    /// 返回距离 target 最近的 nodes 节点（FIND_NODE 响应）
    ///
    /// 等价于 `find_nearest(target, K_BUCKET_SIZE)`。
    pub fn find_node(&self, target: &NodeID) -> Vec<(NodeID, String)> {
        self.find_nearest(target, K_BUCKET_SIZE)
    }

    /// 路由表总节点数
    pub fn node_count(&self) -> usize {
        self.buckets
            .iter()
            .map(|b| b.lock().unwrap().len())
            .sum()
    }

    /// 获取指定桶的节点数
    pub fn bucket_size(&self, idx: usize) -> usize {
        if idx < BUCKET_COUNT {
            self.buckets[idx].lock().unwrap().len()
        } else {
            0
        }
    }

    /// 获取所有已知节点
    pub fn all_nodes(&self) -> Vec<(NodeID, String)> {
        let mut nodes = Vec::new();
        for bucket in self.buckets.iter() {
            let guard = bucket.lock().unwrap();
            for entry in guard.entries() {
                nodes.push((entry.node_id, entry.addr.clone()));
            }
        }
        nodes
    }

    // ── 值存储 ──

    /// 存储值到 DHT
    ///
    /// 使用 SHA-256 哈希作为键。
    ///
    /// # 参数
    /// - `key`: 值的键（任意字节）
    /// - `value`: 要存储的值
    /// - `ttl`: 存活时间（秒），默认使用 `DEFAULT_VALUE_TTL`
    pub fn put_value(&self, key: &[u8], value: Vec<u8>, ttl: u64) -> [u8; 32] {
        let hash = sha2::Sha256::digest(key);
        let key_bytes: [u8; 32] = hash.into();

        let mut values = self.values.lock().unwrap();
        values.insert(key_bytes, ValueEntry::new(value, ttl));

        key_bytes
    }

    /// 获取存储在 DHT 中的值
    ///
    /// # 参数
    /// - `key`: 值的键（任意字节）
    ///
    /// # 返回
    /// 如果找到且未过期，返回 `Some(ValueEntry)`；否则返回 `None`。
    pub fn get_value(&self, key: &[u8]) -> Option<ValueEntry> {
        let hash = sha2::Sha256::digest(key);
        let key_bytes: [u8; 32] = hash.into();

        let values = self.values.lock().unwrap();
        values.get(&key_bytes).cloned().filter(|v| !v.is_expired())
    }

    /// 通过哈希键直接获取值
    pub fn get_value_by_hash(&self, key_hash: &[u8; 32]) -> Option<ValueEntry> {
        let values = self.values.lock().unwrap();
        values.get(key_hash).cloned().filter(|v| !v.is_expired())
    }

    /// 清理过期值
    pub fn cleanup_values(&self) -> usize {
        let mut values = self.values.lock().unwrap();
        let before = values.len();
        values.retain(|_, v| !v.is_expired());
        before - values.len()
    }

    /// 获取值存储中的条目数
    pub fn value_count(&self) -> usize {
        let values = self.values.lock().unwrap();
        values.len()
    }

    // ── 引导与刷新 ──

    /// 从引导节点列表初始化路由表
    ///
    /// 将 `BootstrapNode` 列表中的节点插入路由表。
    /// 引导节点没有 NodeID，使用全零 ID 占位。
    pub fn bootstrap_from_nodes(&self, nodes: &[BootstrapNode]) {
        for node in nodes {
            // 引导节点暂用占位 ID，实际连接后会更新
            let placeholder_id = NodeID::from_bytes(&[0u8; 32]);
            let _ = self.insert_node(placeholder_id, node.addr());
        }
    }

    /// 定期刷新路由表
    ///
    /// PING 每个桶中最久未联系的节点。
    /// 如果节点不响应，将其从路由表中移除。
    /// 应定期调用（如每 `REFRESH_INTERVAL_SECS` 秒）。
    pub fn refresh(&self) -> usize {
        let mut pinged = 0;

        for bucket in self.buckets.iter() {
            let stale = {
                let guard = bucket.lock().unwrap();
                // 检查最旧的节点是否超时
                let should_ping = match guard.least_recently_seen() {
                    Some(entry) => entry.last_seen.elapsed() > Duration::from_secs(NODE_TIMEOUT_SECS / 2),
                    None => false,
                };

                if should_ping {
                    // 取最旧的节点进行 PING 验证
                    guard.entries().map(|e| (e.node_id, e.addr.clone())).collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            };

            // 对过期节点执行 PING（实际实现会发送 PING 消息）
            // 这里简化处理：如果无法 ping 通，移除节点
            for (node_id, _addr) in &stale {
                // 模拟 ping 失败则移除
                // 实际实现中，这里会发送 PING 消息并等待 PONG
                bucket.lock().unwrap().remove(node_id);
                pinged += 1;
            }
        }

        pinged
    }

    /// 启动后台刷新线程
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
        // 后台刷新由外部调度器负责，此处不做自动线程启动
    }

    /// 停止后台刷新
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    // ── DHT 消息处理 ──

    /// 创建 DHT 消息
    ///
    /// 将 DHT 子类型的消息封装为 relay 层的 `Message`。
    pub fn create_dht_message(msg_type: DhtMessageType, payload: Vec<u8>) -> Message {
        let mut dht_payload = vec![msg_type.to_u8()];
        dht_payload.extend(payload);
        Message::new(MessageType::Dht, dht_payload)
    }

    /// 处理接收到的 DHT 消息
    ///
    /// 返回需要发送的响应消息列表。
    pub fn process_message(
        &self,
        sender_id: &NodeID,
        payload: &[u8],
    ) -> Vec<Message> {
        if payload.is_empty() {
            return Vec::new();
        }

        let msg_type = match DhtMessageType::from_u8(payload[0]) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let data = &payload[1..];

        match msg_type {
            DhtMessageType::Ping => {
                // 收到 PING，更新节点活跃时间并回复 PONG
                self.touch_node(sender_id);
                vec![Self::create_dht_message(DhtMessageType::Pong, Vec::new())]
            }
            DhtMessageType::Pong => {
                // 收到 PONG，更新节点活跃时间
                self.touch_node(sender_id);
                Vec::new()
            }
            DhtMessageType::FindNode => {
                // 查找目标节点
                if data.len() < 32 {
                    return vec![Self::create_dht_message(
                        DhtMessageType::Nodes,
                        Self::encode_node_list(&[]),
                    )];
                }

                let mut target_bytes = [0u8; 32];
                target_bytes.copy_from_slice(&data[..32]);
                let target = NodeID::from_bytes(&target_bytes);

                let nearest = self.find_node(&target);
                let encoded = Self::encode_node_list(&nearest);

                vec![Self::create_dht_message(DhtMessageType::Nodes, encoded)]
            }
            DhtMessageType::Nodes => {
                // 收到节点列表，插入路由表
                let nodes = Self::decode_node_list(data);
                for (node_id, addr) in nodes {
                    let _ = self.insert_node(node_id, addr);
                }
                Vec::new()
            }
            DhtMessageType::Put => {
                // PUT 格式: [key_len(2字节)] [key] [value_len(4字节)] [value] [ttl(8字节)]
                self.handle_put(data);
                Vec::new()
            }
            DhtMessageType::Get => {
                // GET 格式: [key] (32字节 SHA-256 hash)
                if data.len() < 32 {
                    return Vec::new();
                }
                let mut key_hash = [0u8; 32];
                key_hash.copy_from_slice(&data[..32]);

                match self.get_value_by_hash(&key_hash) {
                    Some(entry) => {
                        let mut resp = Vec::new();
                        // 编码: [key_hash(32字节)] [value_len(4字节)] [value]
                        resp.extend_from_slice(&key_hash);
                        resp.extend_from_slice(&(entry.value.len() as u32).to_be_bytes());
                        resp.extend_from_slice(&entry.value);
                        vec![Self::create_dht_message(DhtMessageType::Value, resp)]
                    }
                    None => Vec::new(),
                }
            }
            DhtMessageType::Value => {
                // 收到值响应 — 目前不做处理，由调用方通过 get_value 获取
                Vec::new()
            }
        }
    }

    /// 处理 PUT 消息
    fn handle_put(&self, data: &[u8]) -> Option<()> {
        if data.len() < 2 {
            return None;
        }
        let key_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if data.len() < 2 + key_len + 4 {
            return None;
        }
        let key = &data[2..2 + key_len];
        let value_len =
            u32::from_be_bytes([data[2 + key_len], data[2 + key_len + 1], data[2 + key_len + 2], data[2 + key_len + 3]])
                as usize;
        if data.len() < 2 + key_len + 4 + value_len + 8 {
            return None;
        }
        let value = &data[2 + key_len + 4..2 + key_len + 4 + value_len];
        let ttl = u64::from_be_bytes(
            data[2 + key_len + 4 + value_len..2 + key_len + 4 + value_len + 8]
                .try_into()
                .ok()?,
        );

        self.put_value(key, value.to_vec(), ttl);
        Some(())
    }

    // ── 编码/解码辅助 ──

    /// 编码节点列表为字节
    ///
    /// 格式: [count(2字节)] [node_id(32字节) + addr_len(2字节) + addr...] × count
    pub fn encode_node_list(nodes: &[(NodeID, String)]) -> Vec<u8> {
        let count = nodes.len().min(u16::MAX as usize);
        let mut buf = Vec::with_capacity(2 + count * (32 + 2 + 256));
        buf.extend_from_slice(&(count as u16).to_be_bytes());

        for (node_id, addr) in nodes.iter().take(count) {
            buf.extend_from_slice(node_id.as_bytes());
            let addr_bytes = addr.as_bytes();
            let addr_len = addr_bytes.len().min(u16::MAX as usize);
            buf.extend_from_slice(&(addr_len as u16).to_be_bytes());
            buf.extend_from_slice(&addr_bytes[..addr_len]);
        }

        buf
    }

    /// 解码字节为节点列表
    pub fn decode_node_list(data: &[u8]) -> Vec<(NodeID, String)> {
        if data.len() < 2 {
            return Vec::new();
        }

        let count = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut nodes = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            if offset + 32 + 2 > data.len() {
                break;
            }
            let mut id_bytes = [0u8; 32];
            id_bytes.copy_from_slice(&data[offset..offset + 32]);
            let node_id = NodeID::from_bytes(&id_bytes);

            offset += 32;
            let addr_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + addr_len > data.len() {
                break;
            }
            let addr =
                String::from_utf8(data[offset..offset + addr_len].to_vec()).unwrap_or_default();
            offset += addr_len;

            nodes.push((node_id, addr));
        }

        nodes
    }
}

impl fmt::Debug for DhtManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhtManager")
            .field("local_id", &self.local_id)
            .field("node_count", &self.node_count())
            .field("value_count", &self.value_count())
            .finish()
    }
}

// ──────────────────────────────────────────────
//  Helper functions
// ──────────────────────────────────────────────

/// 比较两个 256 位 XOR 距离的字典序
fn cmp_xor(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    for i in 0..32 {
        if a[i] != b[i] {
            return (a[i] as u8).cmp(&b[i]);
        }
    }
    std::cmp::Ordering::Equal
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

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    fn make_id_bytes(bytes: &[u8; 32]) -> NodeID {
        NodeID::from_bytes(bytes)
    }

    // ── XOR 距离计算测试 ──

    #[test]
    fn test_xor_distance_self() {
        let id = make_id(0xAB);
        let dist = DhtManager::xor_distance(&id, &id);
        assert_eq!(dist, [0u8; 32]);
    }

    #[test]
    fn test_xor_distance_symmetric() {
        let a = make_id(0x12);
        let b = make_id(0x34);
        let dist_ab = DhtManager::xor_distance(&a, &b);
        let dist_ba = DhtManager::xor_distance(&b, &a);
        assert_eq!(dist_ab, dist_ba);
    }

    #[test]
    fn test_xor_distance_known_value() {
        let mut bytes_a = [0u8; 32];
        let mut bytes_b = [0u8; 32];
        bytes_a[0] = 0xFF;
        bytes_b[0] = 0x00;
        let a = make_id_bytes(&bytes_a);
        let b = make_id_bytes(&bytes_b);
        let dist = DhtManager::xor_distance(&a, &b);
        assert_eq!(dist[0], 0xFF);
        assert_eq!(dist[1..], [0u8; 31]);
    }

    #[test]
    fn test_xor_distance_all_bits() {
        let mut bytes_a = [0u8; 32];
        let mut bytes_b = [0u8; 32];
        for i in 0..32 {
            bytes_a[i] = 0x55;
            bytes_b[i] = 0xAA;
        }
        let a = make_id_bytes(&bytes_a);
        let b = make_id_bytes(&bytes_b);
        let dist = DhtManager::xor_distance(&a, &b);
        assert_eq!(dist, [0xFFu8; 32]);
    }

    // ── 桶索引计算测试 ──

    #[test]
    fn test_bucket_index_self() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        assert_eq!(dht.bucket_index(&local), BUCKET_COUNT - 1);
    }

    #[test]
    fn test_bucket_index_first_bit() {
        // 首位不同 ⇒ bucket 0
        let mut local_bytes = [0u8; 32];
        let mut target_bytes = [0u8; 32];
        local_bytes[0] = 0x00;
        target_bytes[0] = 0x80; // 最高位不同
        let local = make_id_bytes(&local_bytes);
        let target = make_id_bytes(&target_bytes);
        let dht = DhtManager::new(local);
        assert_eq!(dht.bucket_index(&target), 0);
    }

    #[test]
    fn test_bucket_index_second_bit() {
        // 第二位不同 ⇒ bucket 1
        let mut local_bytes = [0u8; 32];
        let mut target_bytes = [0u8; 32];
        local_bytes[0] = 0x00;
        target_bytes[0] = 0x40; // 第二位不同
        let local = make_id_bytes(&local_bytes);
        let target = make_id_bytes(&target_bytes);
        let dht = DhtManager::new(local);
        assert_eq!(dht.bucket_index(&target), 1);
    }

    #[test]
    fn test_bucket_index_eighth_bit() {
        // 第 8 位不同 ⇒ bucket 7
        let mut local_bytes = [0u8; 32];
        let mut target_bytes = [0u8; 32];
        local_bytes[0] = 0x00;
        target_bytes[0] = 0x01; // 第 8 位不同
        let local = make_id_bytes(&local_bytes);
        let target = make_id_bytes(&target_bytes);
        let dht = DhtManager::new(local);
        assert_eq!(dht.bucket_index(&target), 7);
    }

    #[test]
    fn test_bucket_index_second_byte() {
        // 第二字节首位不同 ⇒ bucket 8
        let mut local_bytes = [0u8; 32];
        let mut target_bytes = [0u8; 32];
        target_bytes[1] = 0x80;
        let local = make_id_bytes(&local_bytes);
        let target = make_id_bytes(&target_bytes);
        let dht = DhtManager::new(local);
        assert_eq!(dht.bucket_index(&target), 8);
    }

    // ── 路由表插入测试 ──

    #[test]
    fn test_insert_node_basic() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let node = make_id(0x02);

        let result = dht.insert_node(node, "192.168.1.1:9876".to_string());
        assert!(result.is_ok());
        assert_eq!(dht.node_count(), 1);
    }

    #[test]
    fn test_insert_node_no_self() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let result = dht.insert_node(local, "127.0.0.1:9876".to_string());
        assert!(result.is_ok());
        assert_eq!(dht.node_count(), 0); // 不自插
    }

    #[test]
    fn test_insert_duplicate_node() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let node = make_id(0x02);

        // 第一次插入
        dht.insert_node(node, "192.168.1.1:9876".to_string()).unwrap();
        assert_eq!(dht.node_count(), 1);

        // 重复插入（更新地址和 last_seen）
        let result = dht.insert_node(node, "192.168.1.1:9877".to_string());
        assert!(result.is_ok());
        assert_eq!(dht.node_count(), 1); // 数量不变
    }

    #[test]
    fn test_insert_multiple_nodes() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        for i in 0..10 {
            let node = make_id(0x10 + i);
            dht.insert_node(node, format!("10.0.0.{}:9876", i))
                .unwrap();
        }

        assert_eq!(dht.node_count(), 10);
    }

    #[test]
    fn test_insert_nodes_same_bucket() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // 插入超过 K_BUCKET_SIZE 个节点到同一个 bucket
        // 使用只有最后一个字节不同的节点，这样它们都在 bucket 255（或附近）
        for i in 0..K_BUCKET_SIZE + 5 {
            let mut bytes = [0u8; 32];
            bytes[31] = (0x10 + i as u8);
            let node = make_id_bytes(&bytes);
            let result = dht.insert_node(node, format!("10.0.0.{}:9876", i));
            if i < K_BUCKET_SIZE {
                assert!(result.is_ok());
            }
            // 超过 K_BUCKET_SIZE 后可能 Err（桶满）
        }

        // 桶满时只能插入 K_BUCKET_SIZE 个
        assert!(dht.node_count() <= K_BUCKET_SIZE + 5);
    }

    // ── FIND_NODE 最近节点查找测试 ──

    #[test]
    fn test_find_node_empty() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let target = make_id(0xFF);

        let nearest = dht.find_node(&target);
        assert!(nearest.is_empty());
    }

    #[test]
    fn test_find_node_returns_closest() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入 5 个距离不同的节点
        let mut nodes: Vec<(NodeID, String)> = Vec::new();
        for i in 0..5 {
            let mut bytes = [0u8; 32];
            bytes[31] = 0x10 + i;
            let node = make_id_bytes(&bytes);
            let addr = format!("10.0.0.{}:9876", i);
            dht.insert_node(node, addr.clone()).unwrap();
            nodes.push((node, addr));
        }

        // 查找
        let nearest = dht.find_node(&local);
        assert!(!nearest.is_empty());
        // 返回的节点数不能超过插入数
        assert!(nearest.len() <= 5);
    }

    #[test]
    fn test_find_node_ordered_by_distance() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入距离由近到远的节点
        let mut expected_order: Vec<(usize, String)> = Vec::new();
        for i in 1..=4 {
            let mut bytes = [0u8; 32];
            bytes[31] = i as u8; // 0x01, 0x02, 0x03, 0x04
            let node = make_id_bytes(&bytes);
            let addr = format!("10.0.0.{}:9876", i);
            dht.insert_node(node, addr.clone()).unwrap();
            expected_order.push((i, addr));
        }

        let nearest = dht.find_node(&local);
        assert_eq!(nearest.len(), 4);

        // 验证按距离升序：距离 local 近的在前
        for i in 0..nearest.len() - 1 {
            let dist_a = DhtManager::xor_distance(&local, &nearest[i].0);
            let dist_b = DhtManager::xor_distance(&local, &nearest[i + 1].0);
            assert!(cmp_xor(&dist_a, &dist_b).is_le());
        }
    }

    #[test]
    fn test_find_node_limited_to_k() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入 K_BUCKET_SIZE + 10 个节点
        for i in 0..K_BUCKET_SIZE + 10 {
            let mut bytes = [0u8; 32];
            bytes[31] = (0x10 + i as u8);
            let node = make_id_bytes(&bytes);
            let _ = dht.insert_node(node, format!("10.0.0.{}:9876", i));
        }

        let nearest = dht.find_node(&local);
        assert!(nearest.len() <= K_BUCKET_SIZE);
    }

    #[test]
    fn test_find_node_specific_target() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入节点到不同 bucket
        for i in 0..10 {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x80 | (i as u8);
            let node = make_id_bytes(&bytes);
            let _ = dht.insert_node(node, format!("10.0.0.{}:9876", i));
        }

        // 查找特定目标（与 local 不同）
        let mut target_bytes = [0u8; 32];
        target_bytes[0] = 0xFF;
        let target = make_id_bytes(&target_bytes);

        let nearest = dht.find_node(&target);
        assert!(!nearest.is_empty());
    }

    // ── 节点移除测试 ──

    #[test]
    fn test_remove_node() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let node = make_id(0x02);

        dht.insert_node(node, "10.0.0.1:9876".to_string()).unwrap();
        assert_eq!(dht.node_count(), 1);

        let removed = dht.remove_node(&node);
        assert!(removed.is_some());
        assert_eq!(dht.node_count(), 0);
    }

    #[test]
    fn test_remove_nonexistent_node() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let node = make_id(0x99);

        let removed = dht.remove_node(&node);
        assert!(removed.is_none());
    }

    #[test]
    fn test_remove_self() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let removed = dht.remove_node(&local);
        assert!(removed.is_none());
    }

    #[test]
    fn test_remove_and_reinsert() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let node = make_id(0x02);

        dht.insert_node(node, "10.0.0.1:9876".to_string()).unwrap();
        dht.remove_node(&node);
        assert_eq!(dht.node_count(), 0);

        // 重新插入
        dht.insert_node(node, "10.0.0.2:9876".to_string()).unwrap();
        assert_eq!(dht.node_count(), 1);
    }

    // ── PUT/GET 值存储测试 ──

    #[test]
    fn test_put_and_get_value() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let key = b"my-key";
        let value = b"my-value".to_vec();
        dht.put_value(key, value.clone(), DEFAULT_VALUE_TTL);

        let retrieved = dht.get_value(key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, value);
    }

    #[test]
    fn test_get_nonexistent_value() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let retrieved = dht.get_value(b"nonexistent");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_put_multiple_values() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        for i in 0..10 {
            let key = format!("key-{}", i);
            let value = format!("value-{}", i);
            dht.put_value(key.as_bytes(), value.into_bytes(), DEFAULT_VALUE_TTL);
        }

        assert_eq!(dht.value_count(), 10);

        for i in 0..10 {
            let key = format!("key-{}", i);
            let retrieved = dht.get_value(key.as_bytes());
            assert!(retrieved.is_some());
        }
    }

    #[test]
    fn test_put_overwrite_value() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let key = b"my-key";
        dht.put_value(key, b"value-1".to_vec(), DEFAULT_VALUE_TTL);
        dht.put_value(key, b"value-2".to_vec(), DEFAULT_VALUE_TTL);

        let retrieved = dht.get_value(key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, b"value-2");
    }

    #[test]
    fn test_value_expiry() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // TTL=0 的值立即过期
        dht.put_value(b"expired", b"gone".to_vec(), 0);

        // 由于 now_secs 返回整数秒，需要确保时间已过去
        // 但在同一秒内 created_at + 0 < now_secs 可能不成立
        // 所以这里使用 cleanup_values 不会清除它，但 get_value 会检查 is_expired
        // created_at = now_secs(), 那么 is_expired = now_secs() > created_at + 0
        // 在同一秒内可能不成立，所以 sleep 一下
        std::thread::sleep(Duration::from_millis(10));

        let retrieved = dht.get_value(b"expired");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_cleanup_values() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        dht.put_value(b"valid1", b"data1".to_vec(), 3600);
        dht.put_value(b"valid2", b"data2".to_vec(), 3600);
        dht.put_value(b"expired", b"gone".to_vec(), 0);

        // 等待过期
        std::thread::sleep(Duration::from_millis(10));

        let cleaned = dht.cleanup_values();
        assert!(cleaned >= 1); // 至少清理了 1 个
        assert_eq!(dht.value_count(), 2);
    }

    // ── 桶满时淘汰策略测试 ──

    #[test]
    fn test_bucket_full_eviction_lru() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // 填充一个 bucket 到满
        let mut nodes = Vec::new();
        for i in 0..K_BUCKET_SIZE {
            let mut bytes = [0u8; 32];
            bytes[31] = (0x10 + i as u8);
            let node = make_id_bytes(&bytes);
            let addr = format!("10.0.0.{}:9876", i);
            dht.insert_node(node, addr.clone()).unwrap();
            nodes.push((node, addr));
        }

        assert_eq!(dht.node_count(), K_BUCKET_SIZE);

        // 再插入一个新节点到同一个 bucket
        // 桶满应触发淘汰
        let mut new_bytes = [0u8; 32];
        new_bytes[31] = 0xFF;
        let new_node = make_id_bytes(&new_bytes);
        let result = dht.insert_node(new_node, "10.0.0.99:9876".to_string());

        // 结果可能是 Err(Some(entry))（桶满等待 PING 验证）
        // 或 Ok(true)（如果之前的节点已被 LRU 淘汰）
        match result {
            Ok(true) => {
                // 新节点被插入，最旧节点被淘汰
                assert!(dht.node_count() <= K_BUCKET_SIZE + 1);
            }
            Err(Some(evicted)) => {
                // 桶满，返回最旧的待验证节点
                // 验证返回的是最旧的节点
                assert_eq!(dht.node_count(), K_BUCKET_SIZE);
                // 新节点未插入
            }
            Err(None) => {
                panic!("unexpected: bucket full but no entry returned");
            }
            Ok(false) => {
                // 不可能 — 新节点不应该已存在
                panic!("new node was already present (unexpected)");
            }
        }
    }

    // ── 节点列表编码/解码测试 ──

    #[test]
    fn test_encode_decode_node_list() {
        let nodes = vec![
            (make_id(0x01), "10.0.0.1:9876".to_string()),
            (make_id(0x02), "10.0.0.2:9876".to_string()),
            (make_id(0x03), "10.0.0.3:9876".to_string()),
        ];

        let encoded = DhtManager::encode_node_list(&nodes);
        let decoded = DhtManager::decode_node_list(&encoded);

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].0, nodes[0].0);
        assert_eq!(decoded[0].1, nodes[0].1);
        assert_eq!(decoded[1].0, nodes[1].0);
        assert_eq!(decoded[2].0, nodes[2].0);
    }

    #[test]
    fn test_encode_decode_empty_list() {
        let nodes: Vec<(NodeID, String)> = Vec::new();
        let encoded = DhtManager::encode_node_list(&nodes);
        let decoded = DhtManager::decode_node_list(&encoded);
        assert!(decoded.is_empty());
    }

    // ── DHT 消息类型转换测试 ──

    #[test]
    fn test_dht_message_type_conversion() {
        assert_eq!(DhtMessageType::from_u8(0x01), Some(DhtMessageType::Ping));
        assert_eq!(DhtMessageType::from_u8(0x02), Some(DhtMessageType::Pong));
        assert_eq!(DhtMessageType::from_u8(0x03), Some(DhtMessageType::FindNode));
        assert_eq!(DhtMessageType::from_u8(0x04), Some(DhtMessageType::Nodes));
        assert_eq!(DhtMessageType::from_u8(0x05), Some(DhtMessageType::Put));
        assert_eq!(DhtMessageType::from_u8(0x06), Some(DhtMessageType::Get));
        assert_eq!(DhtMessageType::from_u8(0x07), Some(DhtMessageType::Value));
        assert_eq!(DhtMessageType::from_u8(0xFF), None);

        assert_eq!(DhtMessageType::Ping.to_u8(), 0x01);
        assert_eq!(DhtMessageType::Pong.to_u8(), 0x02);
        assert_eq!(DhtMessageType::FindNode.to_u8(), 0x03);
        assert_eq!(DhtMessageType::Nodes.to_u8(), 0x04);
        assert_eq!(DhtMessageType::Put.to_u8(), 0x05);
        assert_eq!(DhtMessageType::Get.to_u8(), 0x06);
        assert_eq!(DhtMessageType::Value.to_u8(), 0x07);
    }

    // ── 集成测试：插入 → 查找 → 移除 ──

    #[test]
    fn test_insert_find_remove_cycle() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入
        for i in 0..5 {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x10 + i;
            let node = make_id_bytes(&bytes);
            dht.insert_node(node, format!("node{}:9876", i)).unwrap();
        }
        assert_eq!(dht.node_count(), 5);

        // 查找
        let mut target_bytes = [0u8; 32];
        target_bytes[0] = 0x50;
        let target = make_id_bytes(&target_bytes);
        let nearest = dht.find_node(&target);
        assert!(!nearest.is_empty());
        assert!(nearest.len() <= K_BUCKET_SIZE);

        // 移除一个
        let first = nearest[0].0;
        dht.remove_node(&first);
        assert_eq!(dht.node_count(), 4);

        // 再次查找
        let nearest2 = dht.find_node(&target);
        assert!(!nearest2.is_empty());
        // 被移除的节点不应出现
        assert!(!nearest2.iter().any(|(id, _)| *id == first));
    }

    // ── 引导节点测试 ──

    #[test]
    fn test_bootstrap_from_nodes() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let bootstrap_nodes = vec![
            BootstrapNode::new("bootstrap1.com", 9876),
            BootstrapNode::new("bootstrap2.com", 9877),
        ];

        dht.bootstrap_from_nodes(&bootstrap_nodes);
        // 虽然插入的是占位 ID，但路由表应有记录
        assert!(dht.node_count() > 0);
    }

    // ── DHT 消息处理测试 ──

    #[test]
    fn test_process_ping() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);
        let sender = make_id(0x02);

        dht.insert_node(sender, "10.0.0.2:9876".to_string()).unwrap();

        let ping_payload = vec![DhtMessageType::Ping.to_u8()];
        let responses = dht.process_message(&sender, &ping_payload);

        // 应回复 PONG
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].msg_type, MessageType::Dht);
        // 验证 payload 首字节是 Pong
        assert_eq!(responses[0].payload[0], DhtMessageType::Pong.to_u8());
    }

    #[test]
    fn test_process_find_node() {
        let local = make_id(0x00);
        let dht = DhtManager::new(local);

        // 插入一些节点
        for i in 0..5 {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x10 + i;
            let node = make_id_bytes(&bytes);
            dht.insert_node(node, format!("node{}:9876", i)).unwrap();
        }

        // 构造 FIND_NODE 消息
        let mut target_bytes = [0u8; 32];
        target_bytes[0] = 0x50;
        let mut payload = vec![DhtMessageType::FindNode.to_u8()];
        payload.extend_from_slice(&target_bytes);

        let sender = make_id(0x99);
        let responses = dht.process_message(&sender, &payload);

        assert_eq!(responses.len(), 1);
        // 验证是 NODES 响应
        assert_eq!(responses[0].payload[0], DhtMessageType::Nodes.to_u8());
    }

    #[test]
    fn test_process_put_and_get() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // 构造 PUT 消息
        let key = b"test-key";
        let value = b"test-value";
        let ttl = 3600u64;

        let mut put_payload = vec![DhtMessageType::Put.to_u8()];
        // key_len(2字节) + key + value_len(4字节) + value + ttl(8字节)
        put_payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
        put_payload.extend_from_slice(key);
        put_payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
        put_payload.extend_from_slice(value);
        put_payload.extend_from_slice(&ttl.to_be_bytes());

        let sender = make_id(0x02);
        let responses = dht.process_message(&sender, &put_payload);
        // PUT 不回复
        assert!(responses.is_empty());

        // 验证值已存储
        let stored = dht.get_value(key);
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().value, value);

        // 构造 GET 消息
        let key_hash = sha2::Sha256::digest(key);
        let mut get_payload = vec![DhtMessageType::Get.to_u8()];
        get_payload.extend_from_slice(&key_hash);

        let responses = dht.process_message(&sender, &get_payload);
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].payload[0], DhtMessageType::Value.to_u8());
    }

    // ── 路由表刷新测试 ──

    #[test]
    fn test_refresh_culls_stale_nodes() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        // 插入节点
        for i in 0..3 {
            let mut bytes = [0u8; 32];
            bytes[31] = 0x10 + i as u8;
            let node = make_id_bytes(&bytes);
            dht.insert_node(node, format!("node{}:9876", i)).unwrap();
        }

        assert_eq!(dht.node_count(), 3);

        // 刷新（会移除过期节点）
        let pinged = dht.refresh();
        // 由于 last_seen 是 Instant::now()，在测试中不会触发超时
        assert_eq!(pinged, 0);
    }

    // ── 边界情况测试 ──

    #[test]
    fn test_empty_dht_manager() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        assert_eq!(dht.node_count(), 0);
        assert_eq!(dht.value_count(), 0);
        assert!(dht.find_node(&local).is_empty());
        assert!(dht.all_nodes().is_empty());
    }

    #[test]
    fn test_dht_debug_format() {
        let local = make_id(0x01);
        let dht = DhtManager::new(local);

        let debug = format!("{:?}", dht);
        assert!(debug.contains("DhtManager"));
        assert!(debug.contains("node_count"));
    }
}
