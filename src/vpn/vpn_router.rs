//! P2-1: VPN 路由器
//!
//! 实现 Router trait 的 VPN 路由器，
//! 支持 LAN 直连优先、VPN 中继作为备选的路由策略。
//!
//! # 路由策略
//!
//! 1. 优先尝试 LAN 直连（通过 `LanRouter`）
//! 2. 若 LAN 不可达，回退到 VPN 中继（通过 `RelayManager`）
//!
//! # Receive Callback 机制
//!
//! 可以通过 `register_listener` 注册回调函数，
//! 当收到其他节点发来的数据时会自动调用所有已注册的监听器。

use crate::address::{AddressResolver, ParsedAddress};
use crate::lan_router::LanRouter;
use crate::router::{ConnectionType, NodeStatus, Router, RouterError, RouterStatus};
use crate::vpn::identity::NodeID;
use crate::vpn::relay::{Message, MessageType, RelayManager};
use crate::vpn::session::SessionManager;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 数据接收监听器类型
type DataListener = Box<dyn Fn(String, Vec<u8>) + Send + Sync>;

/// 已知节点信息类型
type KnownNodeInfo = (NodeID, ConnectionType, NodeStatus);

/// 默认 VPN 端口
pub const DEFAULT_VPN_PORT: u16 = 9877;

/// 接收循环轮询间隔（毫秒）
const POLL_INTERVAL_MS: u64 = 100;

/// VPN 路由器
///
/// 实现 `Router` trait，提供完整的 VPN 路由功能。
/// 内部协调 LAN 路由和 VPN 中继，自动选择最优路径。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::vpn_router::VpnRouter;
/// use ll_vpn::vpn::identity::NodeID;
/// use ll_vpn::vpn::relay::RelayManager;
/// use ll_vpn::address::MemAddressResolver;
/// use ll_vpn::lan_router::LanRouter;
/// use ll_vpn::router::Router;
/// use std::sync::Arc;
///
/// let node_id = NodeID::from_bytes(&[1u8; 32]);
/// let resolver = Arc::new(MemAddressResolver::new());
/// let relay = RelayManager::new(node_id, 19880);
/// let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);
/// assert_eq!(vpn.name(), "TestNode");
/// ```
pub struct VpnRouter {
    /// 本地节点名称
    local_name: String,
    /// 本地节点 ID
    local_id: NodeID,
    /// 监听端口
    port: u16,
    /// 地址解析器
    resolver: Arc<dyn AddressResolver + Send + Sync>,
    /// LAN 路由器（可选）
    lan_router: Option<Arc<LanRouter>>,
    /// 中继管理器
    relay_manager: Arc<RelayManager>,
    /// 会话管理器
    session_manager: Arc<SessionManager>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 数据接收监听器
    listeners: Arc<Mutex<Vec<DataListener>>>,
    /// 已知节点表：名字 → (NodeID, 连接类型, 状态)
    known_nodes: Arc<Mutex<HashMap<String, KnownNodeInfo>>>,
}

impl VpnRouter {
    /// 创建新的 VPN 路由器
    ///
    /// # 参数
    /// - `local_name`: 本地节点名称
    /// - `local_id`: 本地节点 ID
    /// - `resolver`: 地址解析器
    /// - `lan_router`: 可选的 LAN 路由器（用于 LAN 优先路由）
    /// - `relay_manager`: 中继管理器（用于 VPN 通信）
    pub fn new(
        local_name: &str,
        local_id: NodeID,
        resolver: Arc<dyn AddressResolver + Send + Sync>,
        lan_router: Option<Arc<LanRouter>>,
        relay_manager: RelayManager,
    ) -> Self {
        let port = DEFAULT_VPN_PORT;
        Self {
            local_name: local_name.to_string(),
            local_id,
            port,
            resolver,
            lan_router,
            relay_manager: Arc::new(relay_manager),
            session_manager: Arc::new(SessionManager::new(local_id)),
            running: Arc::new(AtomicBool::new(false)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            known_nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 指定端口创建 VPN 路由器
    pub fn with_port(
        local_name: &str,
        local_id: NodeID,
        resolver: Arc<dyn AddressResolver + Send + Sync>,
        lan_router: Option<Arc<LanRouter>>,
        relay_manager: RelayManager,
        port: u16,
    ) -> Self {
        Self {
            local_name: local_name.to_string(),
            local_id,
            port,
            resolver,
            lan_router,
            relay_manager: Arc::new(relay_manager),
            session_manager: Arc::new(SessionManager::new(local_id)),
            running: Arc::new(AtomicBool::new(false)),
            listeners: Arc::new(Mutex::new(Vec::new())),
            known_nodes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取解析器引用
    pub fn resolver(&self) -> &(dyn AddressResolver + Send + Sync) {
        &*self.resolver
    }

    /// 获取中继管理器引用
    pub fn relay_manager(&self) -> &RelayManager {
        &self.relay_manager
    }

    /// 注册数据接收监听器
    ///
    /// 当收到其他节点发来的数据时，会调用所有已注册的监听器。
    /// 监听器接收两个参数：发送方节点 ID 的十六进制字符串和原始数据。
    ///
    /// # 示例
    ///
    /// ```rust
    /// use ll_vpn::vpn::vpn_router::VpnRouter;
    /// use ll_vpn::vpn::identity::NodeID;
    /// use ll_vpn::vpn::relay::RelayManager;
    /// use ll_vpn::address::MemAddressResolver;
    /// use std::sync::Arc;
    ///
    /// let node_id = NodeID::from_bytes(&[1u8; 32]);
    /// let resolver = Arc::new(MemAddressResolver::new());
    /// let relay = RelayManager::new(node_id, 19881);
    /// let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);
    ///
    /// vpn.register_listener(|from, data| {
    ///     println!("Received {} bytes from {}", data.len(), from);
    /// });
    /// ```
    pub fn register_listener<F>(&self, listener: F)
    where
        F: Fn(String, Vec<u8>) + Send + Sync + 'static,
    {
        self.listeners.lock().unwrap().push(Box::new(listener));
    }

    /// 获取已知节点信息列表
    ///
    /// 返回: Vec<(名字, NodeID, 连接类型, 节点状态)>
    pub fn known_nodes_info(&self) -> Vec<(String, NodeID, ConnectionType, NodeStatus)> {
        self.known_nodes
            .lock()
            .unwrap()
            .iter()
            .map(|(name, (id, ct, ns))| (name.clone(), *id, *ct, *ns))
            .collect()
    }

    /// 获取已知节点数量
    pub fn known_nodes_count(&self) -> usize {
        self.known_nodes.lock().unwrap().len()
    }

    /// 启动 VPN 路由器
    ///
    /// 启动中继管理器并开始接收数据。
    pub fn start(&self) -> Result<(), RouterError> {
        self.relay_manager
            .start()
            .map_err(|e| RouterError::SendFailed(format!("relay start failed: {}", e)))?;

        self.running.store(true, Ordering::SeqCst);
        self.start_receive_loop();
        Ok(())
    }

    /// 停止 VPN 路由器
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.relay_manager.stop();
    }

    /// 启动后台接收线程
    ///
    /// 轮询中继服务器的接收队列，将数据分发给所有注册的监听器。
    fn start_receive_loop(&self) {
        let running = self.running.clone();
        let listeners = self.listeners.clone();
        let server = self.relay_manager.clone();

        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                let received = server.server().take_received();
                for (sender_id, msg) in received {
                    if msg.msg_type == MessageType::Data {
                        let guard = listeners.lock().unwrap();
                        for listener in guard.iter() {
                            listener(sender_id.to_hex(), msg.payload.clone());
                        }
                    }
                }
                thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
        });
    }

    /// 更新已知节点状态
    fn update_node(
        &self,
        name: &str,
        id: NodeID,
        conn_type: ConnectionType,
        status: NodeStatus,
    ) {
        let mut nodes = self.known_nodes.lock().unwrap();
        nodes.insert(name.to_string(), (id, conn_type, status));
    }

    /// 向目标节点发送 PING 并等待响应
    ///
    /// 返回往返时间（RTT）。
    pub fn ping_node(&self, target: &str) -> Result<Duration, RouterError> {
        let parsed =
            ParsedAddress::parse(target).map_err(|e| RouterError::InvalidData(e.to_string()))?;
        let node_id = self
            .resolver
            .resolve(&parsed.name)
            .map_err(|e| RouterError::Unreachable(e.to_string()))?;

        use std::sync::mpsc;
        let (tx, rx) = mpsc::channel();
        let ping_id = format!("ping-{}", rand::random::<u64>());

        // 注册临时监听器
        let tx_clone = tx.clone();
        let ping_id_clone = ping_id.clone();
        let listener = move |from: String, data: Vec<u8>| {
            if let Ok(msg_str) = String::from_utf8(data) {
                if msg_str.starts_with("PONG:") && msg_str.trim_end() == format!("PONG:{}", ping_id_clone) {
                    let _ = tx_clone.send(from);
                }
            }
        };
        self.listeners.lock().unwrap().push(Box::new(listener));

        // 发送 PING 消息
        let ping_payload = format!("PING:{}", ping_id).into_bytes();
        let msg = Message::new(MessageType::Data, ping_payload);
        let start = Instant::now();

        // 尝试 LAN 直连
        if let Some(lan) = &self.lan_router {
            if lan.send(target, &msg.to_bytes()).is_ok() {
                self.update_node(&parsed.name, node_id, ConnectionType::Lan, NodeStatus::Online);
                // 等待响应（简化：假设 LAN 直连成功即视为可到达）
                return Ok(start.elapsed());
            }
        }

        // VPN 中继
        self.relay_manager
            .send(&node_id, &msg)
            .map_err(|e| RouterError::SendFailed(e.to_string()))?;

        // 等待 PONG 响应，超时 5 秒
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(_) => {
                self.update_node(&parsed.name, node_id, ConnectionType::Vpn, NodeStatus::Online);
                Ok(start.elapsed())
            }
            Err(_) => Err(RouterError::Timeout),
        }
    }
}

impl Router for VpnRouter {
    fn send(&self, target: &str, data: &[u8]) -> Result<(), RouterError> {
        // 1. 解析地址
        let parsed =
            ParsedAddress::parse(target).map_err(|e| RouterError::InvalidData(e.to_string()))?;

        // 2. 解析名字到 NodeID
        let node_id = self
            .resolver
            .resolve(&parsed.name)
            .map_err(|e| RouterError::Unreachable(e.to_string()))?;

        // 3. LAN 直连优先
        if let Some(lan_router) = &self.lan_router {
            match lan_router.send(target, data) {
                Ok(()) => {
                    self.update_node(&parsed.name, node_id, ConnectionType::Lan, NodeStatus::Online);
                    return Ok(());
                }
                Err(e) => {
                    log::info!("LAN send failed, falling back to VPN: {}", e);
                }
            }
        }

        // 4. VPN 中继备选
        let msg = Message::new(MessageType::Data, data.to_vec());
        self.relay_manager
            .send(&node_id, &msg)
            .map_err(|e| RouterError::SendFailed(e.to_string()))?;

        self.update_node(&parsed.name, node_id, ConnectionType::Vpn, NodeStatus::Online);
        Ok(())
    }

    fn status(&self) -> RouterStatus {
        let known = self.known_nodes_count();
        let active_routes = self
            .known_nodes
            .lock()
            .unwrap()
            .values()
            .filter(|(_, _, status)| *status == NodeStatus::Online)
            .count();
        let session_count = self.session_manager.session_count();

        RouterStatus {
            node_status: if self.running.load(Ordering::SeqCst) {
                NodeStatus::Online
            } else {
                NodeStatus::Offline
            },
            connection_type: ConnectionType::Vpn,
            known_nodes: known + session_count,
            active_routes,
            last_update: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn name(&self) -> &str {
        &self.local_name
    }
}

impl fmt::Debug for VpnRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnRouter")
            .field("name", &self.local_name)
            .field("port", &self.port)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::MemAddressResolver;

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    #[test]
    fn test_vpn_router_creation() {
        let node_id = make_id(1);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19882);
        let vpn = VpnRouter::new("Pikachu", node_id, resolver, None, relay);
        assert_eq!(vpn.name(), "Pikachu");
        assert_eq!(*vpn.local_id(), node_id);
    }

    #[test]
    fn test_vpn_router_with_port() {
        let node_id = make_id(2);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19883);
        let vpn = VpnRouter::with_port("Charizard", node_id, resolver, None, relay, 12345);
        assert_eq!(vpn.name(), "Charizard");
    }

    #[test]
    fn test_vpn_router_status() {
        let node_id = make_id(3);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19884);
        let vpn = VpnRouter::new("Mewtwo", node_id, resolver, None, relay);
        let status = vpn.status();
        assert_eq!(status.connection_type, ConnectionType::Vpn);
        assert_eq!(status.node_status, NodeStatus::Offline);
    }

    #[test]
    fn test_vpn_router_known_nodes() {
        let node_id = make_id(4);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19885);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        assert_eq!(vpn.known_nodes_count(), 0);

        vpn.update_node("Pikachu", make_id(5), ConnectionType::Lan, NodeStatus::Online);
        assert_eq!(vpn.known_nodes_count(), 1);

        let info = vpn.known_nodes_info();
        assert_eq!(info[0].0, "Pikachu");
        assert_eq!(info[0].2, ConnectionType::Lan);
    }

    #[test]
    fn test_vpn_router_send_invalid_address() {
        let node_id = make_id(6);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19886);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        let result = vpn.send("invalid-format", b"test");
        assert!(result.is_err());
        match result {
            Err(RouterError::InvalidData(msg)) => {
                assert!(msg.contains("invalid address format"));
            }
            _ => panic!("expected InvalidData error"),
        }
    }

    #[test]
    fn test_vpn_router_send_unknown_node() {
        let node_id = make_id(7);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19887);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        let result = vpn.send("node:NonExistent", b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_vpn_router_register_listener() {
        let node_id = make_id(8);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19888);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();
        vpn.register_listener(move |_from, _data| {
            called_clone.store(true, Ordering::SeqCst);
        });

        // 验证监听器已注册
        assert_eq!(vpn.listeners.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_vpn_router_with_lan_router() {
        let node_id = make_id(9);
        let resolver = Arc::new(MemAddressResolver::new());
        let lan = Arc::new(LanRouter::with_port("LanNode", node_id, 19889));
        let relay = RelayManager::new(node_id, 19890);
        let vpn = VpnRouter::new("HybridNode", node_id, resolver, Some(lan), relay);

        assert_eq!(vpn.name(), "HybridNode");
    }

    #[test]
    fn test_vpn_router_debug_format() {
        let node_id = make_id(10);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19891);
        let vpn = VpnRouter::new("DebugNode", node_id, resolver, None, relay);
        let debug = format!("{:?}", vpn);
        assert!(debug.contains("DebugNode"));
    }

    #[test]
    fn test_vpn_router_name() {
        let node_id = make_id(11);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19892);
        let vpn = VpnRouter::new("NameTest", node_id, resolver, None, relay);
        assert_eq!(Router::name(&vpn), "NameTest");
    }

    #[test]
    fn test_vpn_router_send_with_resolved_node() {
        let node_id = make_id(12);
        let resolver = Arc::new(MemAddressResolver::new());
        let peer_id = make_id(13);
        resolver.add_static_mapping("Pikachu", peer_id);

        let relay = RelayManager::new(node_id, 19893);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        // 目标节点已存在于解析器但不可达，应返回错误
        let result = vpn.send("node:Pikachu", b"hello");
        // 可能是 unreachable 或 sendfailed
        assert!(result.is_err());
    }

    #[test]
    fn test_vpn_router_ping_unknown() {
        let node_id = make_id(14);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19894);
        let vpn = VpnRouter::new("TestNode", node_id, resolver, None, relay);

        let result = vpn.ping_node("node:NonExistent");
        assert!(result.is_err());
    }
}
