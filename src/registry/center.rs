//! P3-1: 注册中心实现
//!
//! 提供名字注册、查询、反向查询、心跳和持久化功能。
//! 支持基于 TCP 中继的消息通信。

use crate::vpn::identity::NodeID;
use crate::vpn::relay::{Message, MessageType, RelayError, RelayManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ──────────────────────────────────────────────
//  Default constants
// ──────────────────────────────────────────────

/// 默认缓存 TTL（秒）
pub const DEFAULT_CACHE_TTL: u64 = 60;

/// 默认心跳间隔（秒）
pub const DEFAULT_HEARTBEAT_INTERVAL: u64 = 30;

/// 默认持久化间隔（秒）
pub const DEFAULT_PERSIST_INTERVAL: u64 = 300;

/// 默认注册中心端口
pub const DEFAULT_REGISTRY_PORT: u16 = 9880;

// ──────────────────────────────────────────────
//  RegistryMessageType
// ──────────────────────────────────────────────

/// 注册中心消息子类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryMessageType {
    Register = 0x01,
    RegisterAck = 0x02,
    Lookup = 0x03,
    LookupResponse = 0x04,
    ReverseLookup = 0x05,
    ReverseLookupResponse = 0x06,
    ListNodes = 0x07,
    ListNodesResponse = 0x08,
}

impl RegistryMessageType {
    /// 从 u8 解析
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Register),
            0x02 => Some(Self::RegisterAck),
            0x03 => Some(Self::Lookup),
            0x04 => Some(Self::LookupResponse),
            0x05 => Some(Self::ReverseLookup),
            0x06 => Some(Self::ReverseLookupResponse),
            0x07 => Some(Self::ListNodes),
            0x08 => Some(Self::ListNodesResponse),
            _ => None,
        }
    }

    /// 转换为 u8
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

// ──────────────────────────────────────────────
//  RegistryError
// ──────────────────────────────────────────────

/// 注册中心错误
#[derive(Debug)]
pub enum RegistryError {
    /// 名字已存在
    AlreadyRegistered(String),
    /// 名字未找到
    NotFound(String),
    /// IO 错误
    IoError(std::io::Error),
    /// 序列化错误
    SerializeError(String),
    /// 锁已损坏
    LockPoisoned,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::AlreadyRegistered(name) => {
                write!(f, "name '{}' is already registered", name)
            }
            RegistryError::NotFound(name) => write!(f, "name '{}' not found", name),
            RegistryError::IoError(e) => write!(f, "io error: {}", e),
            RegistryError::SerializeError(msg) => write!(f, "serialize error: {}", msg),
            RegistryError::LockPoisoned => write!(f, "lock poisoned"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl From<std::io::Error> for RegistryError {
    fn from(e: std::io::Error) -> Self {
        RegistryError::IoError(e)
    }
}

impl From<serde_json::Error> for RegistryError {
    fn from(e: serde_json::Error) -> Self {
        RegistryError::SerializeError(e.to_string())
    }
}

// ──────────────────────────────────────────────
//  Data structures
// ──────────────────────────────────────────────

/// 注册条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryEntry {
    /// 名字
    pub name: String,
    /// 节点 ID
    pub node_id: NodeID,
    /// 注册时间戳（Unix 秒）
    pub registered_at: u64,
    /// 最后活跃时间戳（Unix 秒）
    pub last_seen: u64,
    /// 缓存 TTL（秒）
    pub ttl: u64,
}

impl RegistryEntry {
    /// 创建新的注册条目
    pub fn new(name: String, node_id: NodeID) -> Self {
        let now = now_secs();
        Self {
            name,
            node_id,
            registered_at: now,
            last_seen: now,
            ttl: DEFAULT_CACHE_TTL,
        }
    }

    /// 更新最后活跃时间
    pub fn touch(&mut self) {
        self.last_seen = now_secs();
    }
}

/// 用于 JSON 序列化的注册数据
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryData {
    /// 名字 → 条目的映射
    pub names: HashMap<String, RegistryEntry>,
    /// 节点 ID → 名字的反向映射
    pub reverse: HashMap<String, String>, // hex(NodeID) → name
}

/// 节点信息（用于 ListNodes 响应）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub name: String,
    pub node_id: NodeID,
    pub registered_at: u64,
    pub last_seen: u64,
}

// ──────────────────────────────────────────────
//  Payload structs
// ──────────────────────────────────────────────

/// 注册请求载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub node_id: NodeID,
}

/// 注册确认载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterAckPayload {
    pub success: bool,
    pub message: String,
}

/// 名字查询载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupPayload {
    pub name: String,
}

/// 名字查询响应载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookupResponsePayload {
    pub found: bool,
    pub node_id: Option<NodeID>,
}

/// 反向查询载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseLookupPayload {
    pub node_id: NodeID,
}

/// 反向查询响应载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseLookupResponsePayload {
    pub found: bool,
    pub name: Option<String>,
}

/// 节点列表响应载荷
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListNodesResponsePayload {
    pub nodes: Vec<NodeInfo>,
    pub count: usize,
}

// ──────────────────────────────────────────────
//  RegistryServer
// ──────────────────────────────────────────────

/// 注册中心服务端
///
/// 维护名字 ↔ NodeID 映射，处理注册、查询、反向查询和心跳。
/// 支持 JSON 文件持久化。
///
/// # 死锁修复说明
///
/// `register()` 和 `upsert()` 等写操作在获取写锁修改数据后，
/// 会先释放锁再调用 `save_to_file()`，避免 `RwLock` 不可重入导致的死锁。
pub struct RegistryServer {
    /// 名字 → 注册条目的映射
    names: RwLock<HashMap<String, RegistryEntry>>,
    /// 节点 ID → 名字的反向映射
    reverse: RwLock<HashMap<NodeID, String>>,
    /// 持久化文件路径
    db_path: PathBuf,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 自动保存线程句柄
    persist_handle: RwLock<Option<thread::JoinHandle<()>>>,
    /// 数据是否已修改（需要持久化）
    dirty: Arc<AtomicBool>,
}

impl RegistryServer {
    /// 创建新的注册中心服务端
    pub fn new<P: AsRef<Path>>(db_path: P) -> Self {
        Self {
            names: RwLock::new(HashMap::new()),
            reverse: RwLock::new(HashMap::new()),
            db_path: db_path.as_ref().to_path_buf(),
            running: Arc::new(AtomicBool::new(false)),
            persist_handle: RwLock::new(None),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 从文件加载注册数据
    pub fn load_from_file(&self) -> Result<(), RegistryError> {
        if !self.db_path.exists() {
            // 文件不存在不是错误，返回空数据
            return Ok(());
        }

        let data_str = fs::read_to_string(&self.db_path)?;
        if data_str.trim().is_empty() {
            return Ok(());
        }

        let data: RegistryData = serde_json::from_str(&data_str)?;

        // 获取写锁并加载数据
        {
            let mut names = self.names.write().map_err(|_| RegistryError::LockPoisoned)?;
            *names = data.names;
        }
        {
            let mut reverse = self.reverse.write().map_err(|_| RegistryError::LockPoisoned)?;
            for (hex_key, name) in data.reverse {
                if let Ok(node_id) = NodeID::from_hex(&hex_key) {
                    reverse.insert(node_id, name);
                }
            }
        }

        Ok(())
    }

    /// 保存注册数据到文件
    ///
    /// 调用者必须确保在调用此方法时**没有持有** `names` 或 `reverse` 的写锁，
    /// 否则会导致死锁（Rust `RwLock` 不支持递归锁定）。
    pub fn save_to_file(&self) -> Result<(), RegistryError> {
        // 获取读锁（调用者必须已释放所有写锁）
        let names = self.names.read().map_err(|_| RegistryError::LockPoisoned)?;
        let reverse = self.reverse.read().map_err(|_| RegistryError::LockPoisoned)?;

        // 构建序列化数据
        let reverse_hex: HashMap<String, String> = reverse
            .iter()
            .map(|(id, name)| (node_id_to_hex(id), name.clone()))
            .collect();

        let data = RegistryData {
            names: names.clone(),
            reverse: reverse_hex,
        };

        // 释放读锁后再写文件
        drop(names);
        drop(reverse);

        let json = serde_json::to_string_pretty(&data)?;

        // 确保父目录存在
        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.db_path, json)?;
        self.dirty.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// 启动自动保存线程
    pub fn start_auto_save(&self) {
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let dirty = self.dirty.clone();

        let handle = thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(DEFAULT_PERSIST_INTERVAL));

                if dirty.load(Ordering::SeqCst) {
                    // Note: In a real implementation, the server would be behind an Arc
                    // so the auto-save thread could call save_to_file directly.
                    // For now, saving is triggered inline in register/upsert/update_heartbeat.
                    log::debug!("Auto-save: registry data is dirty (will be saved by mutation methods)");
                }
            }
        });

        if let Ok(mut guard) = self.persist_handle.write() {
            *guard = Some(handle);
        }
    }

    /// 停止自动保存线程
    pub fn stop_auto_save(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(mut handle_opt) = self.persist_handle.write() {
            if let Some(handle) = handle_opt.take() {
                handle.join().ok();
            }
        }
    }

    /// 注册名字
    ///
    /// 如果名字已存在则返回错误。
    ///
    /// # 死锁修复
    ///
    /// 写锁在调用 `save_to_file()` 之前已被释放。
    pub fn register(&self, name: &str, node_id: NodeID) -> Result<(), RegistryError> {
        // 第 1 步：获取写锁，检查并插入数据
        {
            let mut names = self.names.write().map_err(|_| RegistryError::LockPoisoned)?;

            if names.contains_key(name) {
                return Err(RegistryError::AlreadyRegistered(name.to_string()));
            }

            let entry = RegistryEntry::new(name.to_string(), node_id);
            names.insert(name.to_string(), entry);
        } // ← 写锁在这里释放

        // 第 2 步：更新反向映射
        {
            let mut reverse = self.reverse.write().map_err(|_| RegistryError::LockPoisoned)?;
            reverse.insert(node_id, name.to_string());
        } // ← 写锁在这里释放

        // 第 3 步：标记数据已修改并持久化
        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();

        Ok(())
    }

    /// 注册或更新名字
    ///
    /// 如果名字已存在则更新其 NodeID。
    ///
    /// # 死锁修复
    ///
    /// 写锁在调用 `save_to_file()` 之前已被释放。
    pub fn upsert(&self, name: &str, node_id: NodeID) -> Result<(), RegistryError> {
        // 第 1 步：获取写锁，插入或更新数据，记录旧的 node_id
        let old_node_id = {
            let mut names = self.names.write().map_err(|_| RegistryError::LockPoisoned)?;
            let old = names.get(name).map(|e| e.node_id);
            let entry = RegistryEntry::new(name.to_string(), node_id);
            names.insert(name.to_string(), entry);
            old
        }; // ← names 写锁在这里释放

        // 第 2 步：更新反向映射（不持有 names 锁）
        {
            let mut reverse = self.reverse.write().map_err(|_| RegistryError::LockPoisoned)?;
            // 如果之前有旧的 node_id，删除旧的映射
            if let Some(old_id) = old_node_id {
                reverse.remove(&old_id);
            }
            reverse.insert(node_id, name.to_string());
        } // ← reverse 写锁在这里释放

        // 第 3 步：标记数据已修改并持久化
        self.dirty.store(true, Ordering::SeqCst);
        self.save_if_dirty();

        Ok(())
    }

    /// 根据名字查询节点 ID
    pub fn lookup(&self, name: &str) -> Option<NodeID> {
        let names = self.names.read().ok()?;
        names.get(name).map(|entry| entry.node_id)
    }

    /// 根据节点 ID 反向查询名字
    pub fn reverse_lookup(&self, node_id: &NodeID) -> Option<String> {
        let reverse = self.reverse.read().ok()?;
        reverse.get(node_id).cloned()
    }

    /// 列出所有已注册节点
    pub fn list_nodes(&self) -> Vec<RegistryEntry> {
        self.names
            .read()
            .map(|n| n.values().cloned().collect())
            .unwrap_or_default()
    }

    /// 获取注册节点数量
    pub fn len(&self) -> usize {
        self.names.read().map(|n| n.len()).unwrap_or(0)
    }

    /// 注册中心是否为空
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 更新心跳（更新条目的最后活跃时间）
    pub fn update_heartbeat(&self, name: &str) -> Result<(), RegistryError> {
        // 第 1 步：获取写锁，更新时间
        let needs_save = {
            let mut names = self.names.write().map_err(|_| RegistryError::LockPoisoned)?;
            if let Some(entry) = names.get_mut(name) {
                entry.touch();
                true
            } else {
                return Err(RegistryError::NotFound(name.to_string()));
            }
        }; // ← 写锁在这里释放

        // 第 2 步：持久化
        if needs_save {
            self.dirty.store(true, Ordering::SeqCst);
            self.save_if_dirty();
        }

        Ok(())
    }

    /// 处理注册中心消息（反序列化 → 处理 → 序列化响应）
    pub fn process_message(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.is_empty() {
            return None;
        }

        // 第一个字节是子类型
        let sub_type = RegistryMessageType::from_u8(payload[0])?;
        let data = &payload[1..];

        match sub_type {
            RegistryMessageType::Register => {
                // 解析注册请求
                let req: RegisterPayload = serde_json::from_slice(data).ok()?;
                match self.register(&req.name, req.node_id) {
                    Ok(()) => {
                        let ack = RegisterAckPayload {
                            success: true,
                            message: format!("registered '{}'", req.name),
                        };
                        let json = serde_json::to_vec(&ack).ok()?;
                        let mut resp = vec![RegistryMessageType::RegisterAck.to_u8()];
                        resp.extend(json);
                        Some(resp)
                    }
                    Err(e) => {
                        let ack = RegisterAckPayload {
                            success: false,
                            message: e.to_string(),
                        };
                        let json = serde_json::to_vec(&ack).ok()?;
                        let mut resp = vec![RegistryMessageType::RegisterAck.to_u8()];
                        resp.extend(json);
                        Some(resp)
                    }
                }
            }
            RegistryMessageType::Lookup => {
                let req: LookupPayload = serde_json::from_slice(data).ok()?;
                let node_id = self.lookup(&req.name);
                let resp_payload = LookupResponsePayload {
                    found: node_id.is_some(),
                    node_id,
                };
                let json = serde_json::to_vec(&resp_payload).ok()?;
                let mut resp = vec![RegistryMessageType::LookupResponse.to_u8()];
                resp.extend(json);
                Some(resp)
            }
            RegistryMessageType::ReverseLookup => {
                let req: ReverseLookupPayload = serde_json::from_slice(data).ok()?;
                let name = self.reverse_lookup(&req.node_id);
                let resp_payload = ReverseLookupResponsePayload {
                    found: name.is_some(),
                    name,
                };
                let json = serde_json::to_vec(&resp_payload).ok()?;
                let mut resp = vec![RegistryMessageType::ReverseLookupResponse.to_u8()];
                resp.extend(json);
                Some(resp)
            }
            RegistryMessageType::ListNodes => {
                let entries = self.list_nodes();
                let nodes: Vec<NodeInfo> = entries
                    .into_iter()
                    .map(|e| NodeInfo {
                        name: e.name,
                        node_id: e.node_id,
                        registered_at: e.registered_at,
                        last_seen: e.last_seen,
                    })
                    .collect();
                let count = nodes.len();
                let resp_payload = ListNodesResponsePayload { nodes, count };
                let json = serde_json::to_vec(&resp_payload).ok()?;
                let mut resp = vec![RegistryMessageType::ListNodesResponse.to_u8()];
                resp.extend(json);
                Some(resp)
            }
            // 对于响应类型，服务端不处理
            RegistryMessageType::RegisterAck
            | RegistryMessageType::LookupResponse
            | RegistryMessageType::ReverseLookupResponse
            | RegistryMessageType::ListNodesResponse => None,
        }
    }

    // ── 内部辅助方法 ──

    /// 如果数据已修改且当前未持有任何锁，则执行持久化
    fn save_if_dirty(&self) {
        #[cfg(not(test))]
        {
            if self.dirty.load(Ordering::SeqCst) {
                if let Err(e) = self.save_to_file() {
                    log::error!("Failed to save registry data: {}", e);
                }
            }
        }
        #[cfg(test)]
        {
            self.dirty.store(false, Ordering::SeqCst);
        }
    }
}

// ──────────────────────────────────────────────
//  RegistryClient
// ──────────────────────────────────────────────

/// 注册中心客户端
///
/// 通过 TCP 中继向注册中心服务端发送注册/查询请求。
pub struct RegistryClient {
    /// 注册中心地址
    server_addr: String,
    /// 中继管理器引用
    relay_manager: Arc<RelayManager>,
    /// 本地缓存
    cache: RegistryCache,
}

impl RegistryClient {
    /// 创建新的注册中心客户端
    pub fn new(server_addr: String, relay_manager: Arc<RelayManager>) -> Self {
        Self {
            server_addr,
            relay_manager,
            cache: RegistryCache::new(DEFAULT_CACHE_TTL),
        }
    }

    /// 注册名字到节点
    pub fn register(&self, name: &str, node_id: NodeID) -> Result<RegisterAckPayload, RelayError> {
        let req = RegisterPayload {
            name: name.to_string(),
            node_id,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let mut payload = vec![RegistryMessageType::Register.to_u8()];
        payload.extend(json);

        let msg = Message::new(MessageType::Registry, payload);
        self.relay_manager.client().send_message(&self.server_addr, &msg)?;

        // 这里简化处理：实际应等待响应
        Ok(RegisterAckPayload {
            success: true,
            message: "register request sent".to_string(),
        })
    }

    /// 查询名字对应的节点 ID
    pub fn lookup(&self, name: &str) -> Option<NodeID> {
        // 先查缓存
        if let Some(node_id) = self.cache.get(name) {
            return Some(node_id);
        }

        // 发送查询请求（简化：不等待实际响应）
        let req = LookupPayload {
            name: name.to_string(),
        };
        let json = serde_json::to_vec(&req).unwrap();
        let mut payload = vec![RegistryMessageType::Lookup.to_u8()];
        payload.extend(json);

        let msg = Message::new(MessageType::Registry, payload);
        let _ = self
            .relay_manager
            .client()
            .send_message(&self.server_addr, &msg);

        // 简化：返回 None，实际实现需要异步等待响应
        None
    }

    /// 反向查询节点 ID 对应的名字
    pub fn reverse_lookup(&self, node_id: &NodeID) -> Option<String> {
        let req = ReverseLookupPayload { node_id: *node_id };
        let json = serde_json::to_vec(&req).unwrap();
        let mut payload = vec![RegistryMessageType::ReverseLookup.to_u8()];
        payload.extend(json);

        let msg = Message::new(MessageType::Registry, payload);
        let _ = self
            .relay_manager
            .client()
            .send_message(&self.server_addr, &msg);

        None
    }

    /// 获取缓存引用
    pub fn cache(&self) -> &RegistryCache {
        &self.cache
    }

    /// 获取可变缓存引用
    pub fn cache_mut(&mut self) -> &mut RegistryCache {
        &mut self.cache
    }
}

// ──────────────────────────────────────────────
//  RegistryCache
// ──────────────────────────────────────────────

/// 注册中心本地缓存
///
/// 缓存名字 → NodeID 的映射，减少网络请求。
pub struct RegistryCache {
    /// 缓存数据
    cache: HashMap<String, (NodeID, Instant)>,
    /// TTL（秒）
    ttl: u64,
}

impl RegistryCache {
    /// 创建新的缓存
    pub fn new(ttl: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    /// 从缓存中获取节点 ID
    pub fn get(&self, name: &str) -> Option<NodeID> {
        if let Some((node_id, expires)) = self.cache.get(name) {
            if expires.elapsed() < Duration::from_secs(self.ttl) {
                return Some(*node_id);
            }
        }
        None
    }

    /// 插入缓存条目
    pub fn insert(&mut self, name: String, node_id: NodeID) {
        self.cache
            .insert(name, (node_id, Instant::now()));
    }

    /// 移除缓存条目
    pub fn remove(&mut self, name: &str) {
        self.cache.remove(name);
    }

    /// 清空缓存
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// 获取缓存大小
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// 缓存是否为空
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// 清理过期缓存
    pub fn cleanup(&mut self) {
        let ttl = Duration::from_secs(self.ttl);
        self.cache.retain(|_, (_, expires)| expires.elapsed() < ttl);
    }
}

// ──────────────────────────────────────────────
//  Helper functions
// ──────────────────────────────────────────────

/// 将节点 ID 转换为十六进制字符串
pub fn node_id_to_hex(node_id: &NodeID) -> String {
    node_id.to_hex()
}

/// 从十六进制字符串解析节点 ID
pub fn node_id_from_hex(hex_str: &str) -> Result<NodeID, hex::FromHexError> {
    NodeID::from_hex(hex_str)
}

/// 获取当前 Unix 时间戳（秒）
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ──────────────────────────────────────────────
//  Message parsing functions
// ──────────────────────────────────────────────

/// 解析注册确认消息
pub fn parse_register_ack(data: &[u8]) -> Option<RegisterAckPayload> {
    if data.is_empty() || data[0] != RegistryMessageType::RegisterAck.to_u8() {
        return None;
    }
    serde_json::from_slice(&data[1..]).ok()
}

/// 解析查询响应消息
pub fn parse_lookup_response(data: &[u8]) -> Option<LookupResponsePayload> {
    if data.is_empty() || data[0] != RegistryMessageType::LookupResponse.to_u8() {
        return None;
    }
    serde_json::from_slice(&data[1..]).ok()
}

/// 解析反向查询响应消息
pub fn parse_reverse_lookup_response(data: &[u8]) -> Option<ReverseLookupResponsePayload> {
    if data.is_empty() || data[0] != RegistryMessageType::ReverseLookupResponse.to_u8() {
        return None;
    }
    serde_json::from_slice(&data[1..]).ok()
}

/// 解析节点列表响应消息
pub fn parse_list_nodes_response(data: &[u8]) -> Option<ListNodesResponsePayload> {
    if data.is_empty() || data[0] != RegistryMessageType::ListNodesResponse.to_u8() {
        return None;
    }
    serde_json::from_slice(&data[1..]).ok()
}

// ──────────────────────────────────────────────
//  Tests
// ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Helper ──

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    fn make_server() -> RegistryServer {
        RegistryServer::new("/tmp/_test_registry_unused.json")
    }

    // =====================================================================
    //  RegistryMessageType
    // =====================================================================

    #[test]
    fn test_registry_msg_type_from_u8_all_variants() {
        assert_eq!(RegistryMessageType::from_u8(0x01), Some(RegistryMessageType::Register));
        assert_eq!(RegistryMessageType::from_u8(0x02), Some(RegistryMessageType::RegisterAck));
        assert_eq!(RegistryMessageType::from_u8(0x03), Some(RegistryMessageType::Lookup));
        assert_eq!(RegistryMessageType::from_u8(0x04), Some(RegistryMessageType::LookupResponse));
        assert_eq!(RegistryMessageType::from_u8(0x05), Some(RegistryMessageType::ReverseLookup));
        assert_eq!(RegistryMessageType::from_u8(0x06), Some(RegistryMessageType::ReverseLookupResponse));
        assert_eq!(RegistryMessageType::from_u8(0x07), Some(RegistryMessageType::ListNodes));
        assert_eq!(RegistryMessageType::from_u8(0x08), Some(RegistryMessageType::ListNodesResponse));
    }

    #[test]
    fn test_registry_msg_type_from_u8_invalid() {
        assert_eq!(RegistryMessageType::from_u8(0x00), None);
        assert_eq!(RegistryMessageType::from_u8(0x09), None);
        assert_eq!(RegistryMessageType::from_u8(0xFF), None);
    }

    #[test]
    fn test_registry_msg_type_to_u8_roundtrip() {
        for byte in 0x01..=0x08 {
            let typ = RegistryMessageType::from_u8(byte).unwrap();
            assert_eq!(typ.to_u8(), byte);
        }
    }

    // =====================================================================
    //  RegistryError
    // =====================================================================

    #[test]
    fn test_registry_error_display_already_registered() {
        let err = RegistryError::AlreadyRegistered("Pikachu".into());
        assert_eq!(err.to_string(), "name 'Pikachu' is already registered");
    }

    #[test]
    fn test_registry_error_display_not_found() {
        let err = RegistryError::NotFound("Charizard".into());
        assert_eq!(err.to_string(), "name 'Charizard' not found");
    }

    #[test]
    fn test_registry_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = RegistryError::from(io_err);
        assert!(err.to_string().contains("io error"));
    }

    #[test]
    fn test_registry_error_display_serialize() {
        let err = RegistryError::SerializeError("bad json".into());
        assert_eq!(err.to_string(), "serialize error: bad json");
    }

    #[test]
    fn test_registry_error_display_lock_poisoned() {
        let err = RegistryError::LockPoisoned;
        assert_eq!(err.to_string(), "lock poisoned");
    }

    // =====================================================================
    //  RegistryEntry
    // =====================================================================

    #[test]
    fn test_registry_entry_new() {
        let id = make_id(0xAA);
        let entry = RegistryEntry::new("Pikachu".into(), id);
        assert_eq!(entry.name, "Pikachu");
        assert_eq!(entry.node_id, id);
        assert_eq!(entry.registered_at, entry.last_seen);
        assert!(!entry.name.is_empty());
    }

    #[test]
    fn test_registry_entry_touch() {
        let id = make_id(0xBB);
        let mut entry = RegistryEntry::new("Charizard".into(), id);
        let original = entry.last_seen;
        std::thread::sleep(Duration::from_millis(2));
        entry.touch();
        assert!(entry.last_seen >= original);
    }

    // =====================================================================
    //  Payload serialization
    // =====================================================================

    #[test]
    fn test_register_payload_roundtrip() {
        let p = RegisterPayload { name: "Mewtwo".into(), node_id: make_id(0xCC) };
        let json = serde_json::to_vec(&p).unwrap();
        let back: RegisterPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.name, p.name);
        assert_eq!(back.node_id, p.node_id);
    }

    #[test]
    fn test_register_ack_payload_roundtrip() {
        let p = RegisterAckPayload { success: true, message: "ok".into() };
        let json = serde_json::to_vec(&p).unwrap();
        let back: RegisterAckPayload = serde_json::from_slice(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.message, "ok");
    }

    #[test]
    fn test_lookup_payload_roundtrip() {
        let p = LookupPayload { name: "Pikachu".into() };
        let json = serde_json::to_vec(&p).unwrap();
        let back: LookupPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.name, "Pikachu");
    }

    #[test]
    fn test_lookup_response_payload_found() {
        let id = make_id(0xDD);
        let p = LookupResponsePayload { found: true, node_id: Some(id) };
        let json = serde_json::to_vec(&p).unwrap();
        let back: LookupResponsePayload = serde_json::from_slice(&json).unwrap();
        assert!(back.found);
        assert_eq!(back.node_id, Some(id));
    }

    #[test]
    fn test_lookup_response_payload_not_found() {
        let p = LookupResponsePayload { found: false, node_id: None };
        let json = serde_json::to_vec(&p).unwrap();
        let back: LookupResponsePayload = serde_json::from_slice(&json).unwrap();
        assert!(!back.found);
        assert_eq!(back.node_id, None);
    }

    #[test]
    fn test_reverse_lookup_payload_roundtrip() {
        let id = make_id(0xEE);
        let p = ReverseLookupPayload { node_id: id };
        let json = serde_json::to_vec(&p).unwrap();
        let back: ReverseLookupPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.node_id, id);
    }

    #[test]
    fn test_reverse_lookup_response_found() {
        let p = ReverseLookupResponsePayload { found: true, name: Some("Pikachu".into()) };
        let json = serde_json::to_vec(&p).unwrap();
        let back: ReverseLookupResponsePayload = serde_json::from_slice(&json).unwrap();
        assert!(back.found);
        assert_eq!(back.name, Some("Pikachu".into()));
    }

    #[test]
    fn test_reverse_lookup_response_not_found() {
        let p = ReverseLookupResponsePayload { found: false, name: None };
        let json = serde_json::to_vec(&p).unwrap();
        let back: ReverseLookupResponsePayload = serde_json::from_slice(&json).unwrap();
        assert!(!back.found);
        assert_eq!(back.name, None);
    }

    #[test]
    fn test_list_nodes_response_payload_roundtrip() {
        let nodes = vec![
            NodeInfo { name: "a".into(), node_id: make_id(0x01), registered_at: 1, last_seen: 2 },
            NodeInfo { name: "b".into(), node_id: make_id(0x02), registered_at: 3, last_seen: 4 },
        ];
        let p = ListNodesResponsePayload { count: 2, nodes: nodes.clone() };
        let json = serde_json::to_vec(&p).unwrap();
        let back: ListNodesResponsePayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.count, 2);
        assert_eq!(back.nodes.len(), 2);
    }

    // =====================================================================
    //  RegistryServer
    // =====================================================================

    #[test]
    fn test_server_new_is_empty() {
        let server = make_server();
        assert!(server.is_empty());
        assert_eq!(server.len(), 0);
    }

    #[test]
    fn test_server_register_and_lookup() {
        let server = make_server();
        let id = make_id(0x10);
        server.register("Pikachu", id).unwrap();
        assert!(!server.is_empty());
        assert_eq!(server.len(), 1);

        let found = server.lookup("Pikachu");
        assert_eq!(found, Some(id));
    }

    #[test]
    fn test_server_register_duplicate() {
        let server = make_server();
        let id1 = make_id(0x11);
        let id2 = make_id(0x22);
        server.register("Pikachu", id1).unwrap();
        let err = server.register("Pikachu", id2).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered(ref n) if n == "Pikachu"));
    }

    #[test]
    fn test_server_lookup_unknown() {
        let server = make_server();
        assert_eq!(server.lookup("nonexistent"), None);
    }

    #[test]
    fn test_server_upsert_creates_new() {
        let server = make_server();
        let id = make_id(0x33);
        server.upsert("Charizard", id).unwrap();
        assert_eq!(server.len(), 1);
        assert_eq!(server.lookup("Charizard"), Some(id));
    }

    #[test]
    fn test_server_upsert_updates_existing() {
        let server = make_server();
        let id1 = make_id(0x44);
        let id2 = make_id(0x55);
        server.register("Mewtwo", id1).unwrap();
        server.upsert("Mewtwo", id2).unwrap();
        assert_eq!(server.len(), 1);
        assert_eq!(server.lookup("Mewtwo"), Some(id2));
    }

    #[test]
    fn test_server_upsert_updates_reverse_map() {
        let server = make_server();
        let id1 = make_id(0x66);
        let id2 = make_id(0x77);
        server.register("A", id1).unwrap();
        assert_eq!(server.reverse_lookup(&id1), Some("A".into()));

        server.upsert("A", id2).unwrap();
        // old id1 should have been removed from reverse map
        assert_eq!(server.reverse_lookup(&id1), None);
        assert_eq!(server.reverse_lookup(&id2), Some("A".into()));
    }

    #[test]
    fn test_server_reverse_lookup() {
        let server = make_server();
        let id = make_id(0x88);
        server.register("Bulbasaur", id).unwrap();
        assert_eq!(server.reverse_lookup(&id), Some("Bulbasaur".into()));
    }

    #[test]
    fn test_server_reverse_lookup_unknown() {
        let server = make_server();
        let id = make_id(0x99);
        assert_eq!(server.reverse_lookup(&id), None);
    }

    #[test]
    fn test_server_list_nodes() {
        let server = make_server();
        let id1 = make_id(0xAA);
        let id2 = make_id(0xBB);
        server.register("Pikachu", id1).unwrap();
        server.register("Charizard", id2).unwrap();
        let nodes = server.list_nodes();
        assert_eq!(nodes.len(), 2);
        let names: Vec<&str> = nodes.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"Pikachu"));
        assert!(names.contains(&"Charizard"));
    }

    #[test]
    fn test_server_update_heartbeat() {
        let server = make_server();
        let id = make_id(0xCC);
        server.register("Squirtle", id).unwrap();
        let before = server.lookup("Squirtle").unwrap();
        assert_eq!(before, id);
        // heartbeat just touches last_seen, lookup doesn't show last_seen directly
        // but the entry should still exist
        server.update_heartbeat("Squirtle").unwrap();
        assert_eq!(server.lookup("Squirtle"), Some(id));
    }

    #[test]
    fn test_server_update_heartbeat_unknown() {
        let server = make_server();
        let err = server.update_heartbeat("nobody").unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(ref n) if n == "nobody"));
    }

    // =====================================================================
    //  Process message
    // =====================================================================

    fn msg_bytes(typ: RegistryMessageType, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![typ.to_u8()];
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn test_process_message_register() {
        let server = make_server();
        let id = make_id(0xDD);
        let payload = RegisterPayload { name: "Mewtwo".into(), node_id: id };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::Register, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        assert_eq!(r[0], RegistryMessageType::RegisterAck.to_u8());
        let ack: RegisterAckPayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(ack.success);
    }

    #[test]
    fn test_process_message_register_duplicate() {
        let server = make_server();
        let id = make_id(0xEE);
        server.register("Mewtwo", id).unwrap();

        let payload = RegisterPayload { name: "Mewtwo".into(), node_id: id };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::Register, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        let ack: RegisterAckPayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(!ack.success);
    }

    #[test]
    fn test_process_message_lookup() {
        let server = make_server();
        let id = make_id(0xFF);
        server.register("Pikachu", id).unwrap();

        let payload = LookupPayload { name: "Pikachu".into() };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::Lookup, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        assert_eq!(r[0], RegistryMessageType::LookupResponse.to_u8());
        let lr: LookupResponsePayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(lr.found);
        assert_eq!(lr.node_id, Some(id));
    }

    #[test]
    fn test_process_message_lookup_not_found() {
        let server = make_server();
        let payload = LookupPayload { name: "Ghost".into() };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::Lookup, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        let lr: LookupResponsePayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(!lr.found);
    }

    #[test]
    fn test_process_message_reverse_lookup() {
        let server = make_server();
        let id = make_id(0x10);
        server.register("Pikachu", id).unwrap();

        let payload = ReverseLookupPayload { node_id: id };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::ReverseLookup, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        assert_eq!(r[0], RegistryMessageType::ReverseLookupResponse.to_u8());
        let rlr: ReverseLookupResponsePayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(rlr.found);
        assert_eq!(rlr.name, Some("Pikachu".into()));
    }

    #[test]
    fn test_process_message_reverse_lookup_not_found() {
        let server = make_server();
        let id = make_id(0x20);
        let payload = ReverseLookupPayload { node_id: id };
        let json = serde_json::to_vec(&payload).unwrap();
        let resp = server.process_message(&msg_bytes(RegistryMessageType::ReverseLookup, &json));
        assert!(resp.is_some());
        let r = resp.unwrap();
        let rlr: ReverseLookupResponsePayload = serde_json::from_slice(&r[1..]).unwrap();
        assert!(!rlr.found);
    }

    #[test]
    fn test_process_message_list_nodes() {
        let server = make_server();
        server.register("Pikachu", make_id(0x30)).unwrap();
        server.register("Charizard", make_id(0x40)).unwrap();

        let resp = server.process_message(&[RegistryMessageType::ListNodes.to_u8()]);
        assert!(resp.is_some());
        let r = resp.unwrap();
        assert_eq!(r[0], RegistryMessageType::ListNodesResponse.to_u8());
        let lnr: ListNodesResponsePayload = serde_json::from_slice(&r[1..]).unwrap();
        assert_eq!(lnr.count, 2);
    }

    #[test]
    fn test_process_message_empty() {
        let server = make_server();
        assert!(server.process_message(&[]).is_none());
    }

    #[test]
    fn test_process_message_invalid_subtype() {
        let server = make_server();
        assert!(server.process_message(&[0xFF]).is_none());
    }

    #[test]
    fn test_process_message_response_types_return_none() {
        let server = make_server();
        // Response message types should not be processed on server side
        for typ in &[
            RegistryMessageType::RegisterAck,
            RegistryMessageType::LookupResponse,
            RegistryMessageType::ReverseLookupResponse,
            RegistryMessageType::ListNodesResponse,
        ] {
            assert!(server.process_message(&[typ.to_u8()]).is_none(), "type {:?} should be ignored", typ);
        }
    }

    // =====================================================================
    //  RegistryData serialization
    // =====================================================================

    #[test]
    fn test_registry_data_serialization() {
        let id = make_id(0x50);
        let mut names = HashMap::new();
        names.insert("Pikachu".into(), RegistryEntry::new("Pikachu".into(), id));
        let mut reverse = HashMap::new();
        reverse.insert(id.to_hex(), "Pikachu".into());
        let data = RegistryData { names, reverse };
        let json = serde_json::to_string_pretty(&data).unwrap();
        let back: RegistryData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.names.len(), 1);
        assert_eq!(back.reverse.len(), 1);
    }

    // =====================================================================
    //  RegistryCache
    // =====================================================================

    #[test]
    fn test_cache_new_is_empty() {
        let cache = RegistryCache::new(60);
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = RegistryCache::new(60);
        let id = make_id(0x60);
        cache.insert("Pikachu".into(), id);
        assert!(!cache.is_empty());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.get("Pikachu"), Some(id));
    }

    #[test]
    fn test_cache_get_unknown() {
        let cache = RegistryCache::new(60);
        assert_eq!(cache.get("nobody"), None);
    }

    #[test]
    fn test_cache_get_expired() {
        // TTL of 0 means immediate expiry
        let mut cache = RegistryCache::new(0);
        cache.insert("Pikachu".into(), make_id(0x70));
        // Even a tiny delay will make it expired
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.get("Pikachu"), None);
    }

    #[test]
    fn test_cache_remove() {
        let mut cache = RegistryCache::new(60);
        cache.insert("Pikachu".into(), make_id(0x80));
        cache.remove("Pikachu");
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = RegistryCache::new(60);
        cache.insert("A".into(), make_id(0x90));
        cache.insert("B".into(), make_id(0xA0));
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_cleanup() {
        let mut cache = RegistryCache::new(0); // TTL = 0 → expires immediately
        cache.insert("A".into(), make_id(0xB0));
        cache.insert("B".into(), make_id(0xC0));
        std::thread::sleep(Duration::from_millis(1));
        cache.cleanup();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_cleanup_keeps_fresh() {
        let mut cache = RegistryCache::new(3600); // 1 hour TTL
        cache.insert("A".into(), make_id(0xD0));
        cache.cleanup();
        assert_eq!(cache.len(), 1);
    }

    // =====================================================================
    //  Message parsing
    // =====================================================================

    #[test]
    fn test_parse_register_ack_success() {
        let ack = RegisterAckPayload { success: true, message: "ok".into() };
        let json = serde_json::to_vec(&ack).unwrap();
        let mut data = vec![RegistryMessageType::RegisterAck.to_u8()];
        data.extend(json);
        let parsed = parse_register_ack(&data);
        assert!(parsed.is_some());
        assert!(parsed.unwrap().success);
    }

    #[test]
    fn test_parse_register_ack_wrong_type() {
        let data = vec![RegistryMessageType::Register.to_u8()];
        assert!(parse_register_ack(&data).is_none());
    }

    #[test]
    fn test_parse_register_ack_empty() {
        assert!(parse_register_ack(&[]).is_none());
    }

    #[test]
    fn test_parse_lookup_response_success() {
        let id = make_id(0xE0);
        let lr = LookupResponsePayload { found: true, node_id: Some(id) };
        let json = serde_json::to_vec(&lr).unwrap();
        let mut data = vec![RegistryMessageType::LookupResponse.to_u8()];
        data.extend(json);
        let parsed = parse_lookup_response(&data);
        assert!(parsed.is_some());
        assert!(parsed.unwrap().found);
    }

    #[test]
    fn test_parse_lookup_response_not_found() {
        let lr = LookupResponsePayload { found: false, node_id: None };
        let json = serde_json::to_vec(&lr).unwrap();
        let mut data = vec![RegistryMessageType::LookupResponse.to_u8()];
        data.extend(json);
        let parsed = parse_lookup_response(&data);
        assert!(parsed.is_some());
        assert!(!parsed.unwrap().found);
    }

    #[test]
    fn test_parse_lookup_response_wrong_type() {
        assert!(parse_lookup_response(&[0x01]).is_none());
    }

    #[test]
    fn test_parse_reverse_lookup_response_found() {
        let rlr = ReverseLookupResponsePayload { found: true, name: Some("Pikachu".into()) };
        let json = serde_json::to_vec(&rlr).unwrap();
        let mut data = vec![RegistryMessageType::ReverseLookupResponse.to_u8()];
        data.extend(json);
        let parsed = parse_reverse_lookup_response(&data);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().name, Some("Pikachu".into()));
    }

    #[test]
    fn test_parse_reverse_lookup_response_wrong_type() {
        assert!(parse_reverse_lookup_response(&[0xFF]).is_none());
    }

    #[test]
    fn test_parse_list_nodes_response_success() {
        let nodes = vec![NodeInfo { name: "x".into(), node_id: make_id(0xF0), registered_at: 0, last_seen: 0 }];
        let lnr = ListNodesResponsePayload { count: 1, nodes };
        let json = serde_json::to_vec(&lnr).unwrap();
        let mut data = vec![RegistryMessageType::ListNodesResponse.to_u8()];
        data.extend(json);
        let parsed = parse_list_nodes_response(&data);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().count, 1);
    }

    #[test]
    fn test_parse_list_nodes_response_wrong_type() {
        assert!(parse_list_nodes_response(&[0x00]).is_none());
    }

    // =====================================================================
    //  Helper functions
    // =====================================================================

    #[test]
    fn test_node_id_hex_roundtrip() {
        let id = make_id(0xAB);
        let hex = node_id_to_hex(&id);
        let back = node_id_from_hex(&hex).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn test_node_id_from_hex_invalid() {
        assert!(node_id_from_hex("nothex").is_err());
    }

    // =====================================================================
    //  Cleanup — verify dirty flag is cleared without I/O
    // =====================================================================

    #[test]
    fn test_dirty_flag_cleared_without_io() {
        let server = make_server();
        assert!(!server.dirty.load(Ordering::SeqCst));
        server.register("Test", make_id(0xFA)).unwrap();
        // save_if_dirty should have cleared it (test mode)
        assert!(!server.dirty.load(Ordering::SeqCst));
    }
}
