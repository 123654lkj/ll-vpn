//! P0-3: LAN 路由适配层
//!
//! 将局域网 UDP 发现逻辑包装为 `Router` trait 实现。
//! 使用 UDP 9876 端口进行节点发现和数据传输。

use crate::address::{MemAddressResolver, ParsedAddress};
use crate::router::{ConnectionType, NodeStatus, Router, RouterError, RouterStatus};
use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 默认 UDP 端口
pub const DEFAULT_PORT: u16 = 9876;

/// 广播地址
pub const BROADCAST_ADDR: &str = "255.255.255.255";

/// UDP 消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMessageType {
    /// 节点发现广播
    Discover,
    /// 发现响应
    DiscoverReply,
    /// 数据消息
    Data,
    /// 心跳
    Heartbeat,
}

impl UdpMessageType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Discover),
            0x02 => Some(Self::DiscoverReply),
            0x03 => Some(Self::Data),
            0x04 => Some(Self::Heartbeat),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Discover => 0x01,
            Self::DiscoverReply => 0x02,
            Self::Data => 0x03,
            Self::Heartbeat => 0x04,
        }
    }
}

/// UDP 消息帧格式:
/// +--------+--------+-----------+
/// | 1 byte | 1 byte | variable  |
/// | type   | name_l | payload   |
/// +--------+--------+-----------+
///
/// 更详细地:
/// [type:1][name_len:1][name:N][node_id:32][data_len:2][data:M]
///
/// 对于 Discover 消息:
/// [type:1][name_len:1][name:N][node_id:32]
///
/// 对于 DiscoverReply:
/// [type:1][name_len:1][name:N][node_id:32]
///
/// 对于 Data:
/// [type:1][name_len:1][name:N][node_id:32][data_len:2][data:M]

const HEADER_SIZE: usize = 1 + 1; // type + name_len
const NODE_ID_SIZE: usize = 32;
const DATA_LEN_SIZE: usize = 2;

/// 构造 Discover 消息
fn build_discover_msg(name: &str, node_id: &NodeID) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(HEADER_SIZE + name_bytes.len() + NODE_ID_SIZE);
    buf.push(UdpMessageType::Discover.to_u8());
    buf.push(name_bytes.len() as u8);
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(node_id.as_bytes());
    buf
}

/// 构造 DiscoverReply 消息
fn build_discover_reply(name: &str, node_id: &NodeID) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(HEADER_SIZE + name_bytes.len() + NODE_ID_SIZE);
    buf.push(UdpMessageType::DiscoverReply.to_u8());
    buf.push(name_bytes.len() as u8);
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(node_id.as_bytes());
    buf
}

/// 构造 Data 消息
fn build_data_msg(name: &str, node_id: &NodeID, data: &[u8]) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let mut buf = Vec::with_capacity(
        HEADER_SIZE + name_bytes.len() + NODE_ID_SIZE + DATA_LEN_SIZE + data.len(),
    );
    buf.push(UdpMessageType::Data.to_u8());
    buf.push(name_bytes.len() as u8);
    buf.extend_from_slice(name_bytes);
    buf.extend_from_slice(node_id.as_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// 解析 UDP 消息帧
fn parse_udp_frame(buf: &[u8]) -> Option<(UdpMessageType, String, NodeID, Option<Vec<u8>>)> {
    if buf.len() < HEADER_SIZE + NODE_ID_SIZE {
        return None;
    }

    let msg_type = UdpMessageType::from_u8(buf[0])?;
    let name_len = buf[1] as usize;

    if buf.len() < HEADER_SIZE + name_len + NODE_ID_SIZE {
        return None;
    }

    let name = String::from_utf8(buf[HEADER_SIZE..HEADER_SIZE + name_len].to_vec()).ok()?;

    let mut id_bytes = [0u8; 32];
    let id_start = HEADER_SIZE + name_len;
    id_bytes.copy_from_slice(&buf[id_start..id_start + NODE_ID_SIZE]);
    let node_id = NodeID::from_bytes(&id_bytes);

    let data = match msg_type {
        UdpMessageType::Data => {
            let data_offset = id_start + NODE_ID_SIZE;
            if buf.len() < data_offset + DATA_LEN_SIZE {
                return None;
            }
            let data_len = u16::from_be_bytes([buf[data_offset], buf[data_offset + 1]]) as usize;
            let data_start = data_offset + DATA_LEN_SIZE;
            if buf.len() < data_start + data_len {
                return None;
            }
            Some(buf[data_start..data_start + data_len].to_vec())
        }
        _ => None,
    };

    Some((msg_type, name, node_id, data))
}

/// LAN 节点信息
#[derive(Debug, Clone)]
pub struct LanNode {
    /// 节点名字
    pub name: String,
    /// 节点 ID
    pub id: NodeID,
    /// 节点地址（IP:Port）
    pub addr: SocketAddr,
    /// 最后活跃时间
    pub last_seen: Instant,
    /// 节点状态
    pub status: NodeStatus,
}

impl LanNode {
    /// 节点是否在线（5 秒内有心跳）
    pub fn is_online(&self) -> bool {
        self.last_seen.elapsed() < Duration::from_secs(5)
    }
}

/// LAN 路由器
///
/// 实现 Router trait，通过 UDP 9876 端口进行局域网通信。
/// 支持节点自动发现和心跳检测。
pub struct LanRouter {
    /// 本节点名字
    local_name: String,
    /// 本节点 ID
    local_id: NodeID,
    /// UDP 端口
    port: u16,
    /// 已发现的 LAN 节点
    nodes: Arc<Mutex<HashMap<String, LanNode>>>,
    /// 地址解析器
    resolver: Arc<MemAddressResolver>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 接收到的数据（用于测试和上层读取）
    received_data: Arc<Mutex<Vec<(String, Vec<u8>)>>>,
    /// UDP socket（绑定后存储）
    socket: Arc<Mutex<Option<UdpSocket>>>,
}

impl LanRouter {
    /// 创建新的 LAN 路由器
    pub fn new(local_name: &str, local_id: NodeID) -> Self {
        Self {
            local_name: local_name.to_string(),
            local_id,
            port: DEFAULT_PORT,
            nodes: Arc::new(Mutex::new(HashMap::new())),
            resolver: Arc::new(MemAddressResolver::new()),
            running: Arc::new(AtomicBool::new(false)),
            received_data: Arc::new(Mutex::new(Vec::new())),
            socket: Arc::new(Mutex::new(None)),
        }
    }

    /// 指定端口创建
    pub fn with_port(local_name: &str, local_id: NodeID, port: u16) -> Self {
        Self {
            local_name: local_name.to_string(),
            local_id,
            port,
            nodes: Arc::new(Mutex::new(HashMap::new())),
            resolver: Arc::new(MemAddressResolver::new()),
            running: Arc::new(AtomicBool::new(false)),
            received_data: Arc::new(Mutex::new(Vec::new())),
            socket: Arc::new(Mutex::new(None)),
        }
    }

    /// 获取地址解析器引用
    pub fn resolver(&self) -> &MemAddressResolver {
        &self.resolver
    }

    /// 获取已发现的节点列表
    pub fn discovered_nodes(&self) -> Vec<LanNode> {
        self.nodes.lock().unwrap().values().cloned().collect()
    }

    /// 获取在线节点数量
    pub fn online_node_count(&self) -> usize {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|n| n.is_online())
            .collect::<Vec<_>>()
            .len()
    }

    /// 获取接收到的数据（消费式读取）
    pub fn take_received_data(&self) -> Vec<(String, Vec<u8>)> {
        std::mem::take(&mut *self.received_data.lock().unwrap())
    }

    /// 启动 LAN 路由器
    ///
    /// - 绑定 UDP 端口
    /// - 启动监听线程
    /// - 发送发现广播
    pub fn start(&self) -> Result<(), RouterError> {
        let addr = format!("0.0.0.0:{}", self.port);
        let socket = UdpSocket::bind(&addr)
            .map_err(|e| RouterError::SendFailed(format!("failed to bind UDP {}: {}", addr, e)))?;
        socket
            .set_broadcast(true)
            .map_err(|e| RouterError::SendFailed(format!("set_broadcast failed: {}", e)))?;

        *self.socket.lock().unwrap() = Some(
            socket
                .try_clone()
                .map_err(|e| RouterError::SendFailed(format!("socket clone failed: {}", e)))?,
        );

        self.running.store(true, Ordering::SeqCst);

        // 启动接收线程
        let running = self.running.clone();
        let nodes = self.nodes.clone();
        let received_data = self.received_data.clone();
        let local_name = self.local_name.clone();
        let local_id = self.local_id;
        let reply_socket = socket
            .try_clone()
            .map_err(|e| RouterError::SendFailed(format!("socket clone failed: {}", e)))?;

        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while running.load(Ordering::SeqCst) {
                socket.set_read_timeout(Some(Duration::from_secs(1))).ok();
                match socket.recv_from(&mut buf) {
                    Ok((len, from)) => {
                        if let Some((msg_type, name, node_id, data)) = parse_udp_frame(&buf[..len])
                        {
                            match msg_type {
                                UdpMessageType::Discover => {
                                    // 收到发现请求，回复
                                    let reply = build_discover_reply(&local_name, &local_id);
                                    reply_socket.send_to(&reply, from).ok();

                                    // 也记录这个节点
                                    if name != local_name {
                                        let mut nodes_guard = nodes.lock().unwrap();
                                        nodes_guard.insert(
                                            name.clone(),
                                            LanNode {
                                                name: name.clone(),
                                                id: node_id,
                                                addr: from,
                                                last_seen: Instant::now(),
                                                status: NodeStatus::Online,
                                            },
                                        );
                                    }
                                }
                                UdpMessageType::DiscoverReply => {
                                    // 收到发现响应
                                    if name != local_name {
                                        let mut nodes_guard = nodes.lock().unwrap();
                                        nodes_guard.insert(
                                            name.clone(),
                                            LanNode {
                                                name: name.clone(),
                                                id: node_id,
                                                addr: from,
                                                last_seen: Instant::now(),
                                                status: NodeStatus::Online,
                                            },
                                        );
                                    }
                                }
                                UdpMessageType::Data => {
                                    // 记录接收到的数据
                                    if let Some(d) = data {
                                        received_data.lock().unwrap().push((name, d));
                                    }
                                }
                                UdpMessageType::Heartbeat => {
                                    // 更新节点活跃时间
                                    let mut nodes_guard = nodes.lock().unwrap();
                                    if let Some(node) = nodes_guard.get_mut(&name) {
                                        node.last_seen = Instant::now();
                                        node.status = NodeStatus::Online;
                                    }
                                }
                            }
                        }
                    }
                    Err(ref e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => {
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }
                }
            }
        });

        // 发送发现广播
        self.broadcast_discover()?;

        Ok(())
    }

    /// 停止 LAN 路由器
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 发送发现广播到局域网
    pub fn broadcast_discover(&self) -> Result<(), RouterError> {
        let socket_guard = self.socket.lock().unwrap();
        let socket = socket_guard
            .as_ref()
            .ok_or_else(|| RouterError::SendFailed("socket not initialized".to_string()))?;

        let msg = build_discover_msg(&self.local_name, &self.local_id);
        let broadcast = format!("{}:{}", BROADCAST_ADDR, self.port);
        socket
            .send_to(&msg, &broadcast)
            .map_err(|e| RouterError::SendFailed(format!("broadcast failed: {}", e)))?;

        Ok(())
    }

    /// 更新节点状态（标记离线节点）
    pub fn update_node_status(&self) {
        let mut nodes = self.nodes.lock().unwrap();
        for node in nodes.values_mut() {
            if !node.is_online() {
                node.status = NodeStatus::Offline;
            }
        }
    }

    /// 通过名字查找节点信息
    pub fn find_node(&self, name: &str) -> Option<LanNode> {
        self.nodes.lock().unwrap().get(name).cloned()
    }
}

impl Router for LanRouter {
    fn send(&self, target: &str, data: &[u8]) -> Result<(), RouterError> {
        // 解析地址
        let parsed =
            ParsedAddress::parse(target).map_err(|e| RouterError::InvalidData(format!("{}", e)))?;

        // 查找目标节点
        let node = {
            let nodes = self.nodes.lock().unwrap();
            nodes.get(&parsed.name).cloned()
        };

        let node = match node {
            Some(n) => n,
            None => {
                // 尝试广播发现
                self.broadcast_discover()?;
                thread::sleep(Duration::from_millis(500));
                self.nodes
                    .lock()
                    .unwrap()
                    .get(&parsed.name)
                    .cloned()
                    .ok_or_else(|| {
                        RouterError::Unreachable(format!("node not found: {}", parsed.name))
                    })?
            }
        };

        // 获取目标端口（默认使用 LAN 路由器端口）
        let target_port = parsed.port.unwrap_or(self.port);
        let target_addr = format!("{}:{}", node.addr.ip(), target_port);

        // 构造并发送数据消息
        let msg = build_data_msg(&self.local_name, &self.local_id, data);
        let socket_guard = self.socket.lock().unwrap();
        let socket = socket_guard
            .as_ref()
            .ok_or_else(|| RouterError::SendFailed("socket not initialized".to_string()))?;

        socket.send_to(&msg, &target_addr).map_err(|e| {
            RouterError::SendFailed(format!("send to {} failed: {}", target_addr, e))
        })?;

        Ok(())
    }

    fn status(&self) -> RouterStatus {
        let nodes = self.nodes.lock().unwrap();
        let known_nodes = nodes.len();
        let active_routes = nodes.values().filter(|n| n.is_online()).count();

        RouterStatus {
            node_status: if self.running.load(Ordering::SeqCst) {
                NodeStatus::Online
            } else {
                NodeStatus::Offline
            },
            connection_type: ConnectionType::Lan,
            known_nodes,
            active_routes,
            last_update: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    fn name(&self) -> &str {
        &self.local_name
    }
}

impl fmt::Debug for LanRouter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LanRouter")
            .field("name", &self.local_name)
            .field("port", &self.port)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_message_type_roundtrip() {
        assert_eq!(
            UdpMessageType::from_u8(0x01),
            Some(UdpMessageType::Discover)
        );
        assert_eq!(
            UdpMessageType::from_u8(0x02),
            Some(UdpMessageType::DiscoverReply)
        );
        assert_eq!(UdpMessageType::from_u8(0x03), Some(UdpMessageType::Data));
        assert_eq!(
            UdpMessageType::from_u8(0x04),
            Some(UdpMessageType::Heartbeat)
        );
        assert_eq!(UdpMessageType::from_u8(0xFF), None);
    }

    #[test]
    fn test_build_and_parse_discover() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let msg = build_discover_msg("Pikachu", &id);
        assert_eq!(msg[0], UdpMessageType::Discover.to_u8());
        assert_eq!(msg[1], 7); // "Pikachu" length

        let parsed = parse_udp_frame(&msg).unwrap();
        assert_eq!(parsed.0, UdpMessageType::Discover);
        assert_eq!(parsed.1, "Pikachu");
        assert_eq!(parsed.2, id);
        assert!(parsed.3.is_none());
    }

    #[test]
    fn test_build_and_parse_discover_reply() {
        let id = NodeID::from_bytes(&[2u8; 32]);
        let msg = build_discover_reply("Charizard", &id);
        let parsed = parse_udp_frame(&msg).unwrap();
        assert_eq!(parsed.0, UdpMessageType::DiscoverReply);
        assert_eq!(parsed.1, "Charizard");
        assert_eq!(parsed.2, id);
    }

    #[test]
    fn test_build_and_parse_data() {
        let id = NodeID::from_bytes(&[3u8; 32]);
        let data = b"hello world";
        let msg = build_data_msg("Mewtwo", &id, data);
        let parsed = parse_udp_frame(&msg).unwrap();
        assert_eq!(parsed.0, UdpMessageType::Data);
        assert_eq!(parsed.1, "Mewtwo");
        assert_eq!(parsed.2, id);
        assert_eq!(parsed.3.unwrap(), data);
    }

    #[test]
    fn test_parse_frame_too_short() {
        assert!(parse_udp_frame(&[0x01]).is_none());
        assert!(parse_udp_frame(&[]).is_none());
    }

    #[test]
    fn test_parse_frame_invalid_type() {
        let mut buf = vec![0xFF, 4];
        buf.extend_from_slice(b"test");
        buf.extend_from_slice(&[0u8; 32]);
        assert!(parse_udp_frame(&buf).is_none());
    }

    #[test]
    fn test_parse_frame_invalid_name_length() {
        let buf = vec![0x01, 255]; // name_len 255 but not enough data
        assert!(parse_udp_frame(&buf).is_none());
    }

    #[test]
    fn test_lan_router_creation() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::new("Pikachu", id);
        assert_eq!(router.name(), "Pikachu");
        assert_eq!(router.port, DEFAULT_PORT);
    }

    #[test]
    fn test_lan_router_custom_port() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::with_port("Pikachu", id, 12345);
        assert_eq!(router.port, 12345);
    }

    #[test]
    fn test_lan_router_status() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::new("Pikachu", id);
        let status = router.status();
        assert_eq!(status.connection_type, ConnectionType::Lan);
        assert_eq!(status.known_nodes, 0);
        assert_eq!(status.node_status, NodeStatus::Offline); // not started
    }

    #[test]
    fn test_lan_node_is_online() {
        let node = LanNode {
            name: "Pikachu".to_string(),
            id: NodeID::from_bytes(&[1u8; 32]),
            addr: "127.0.0.1:9876".parse().unwrap(),
            last_seen: Instant::now(),
            status: NodeStatus::Online,
        };
        assert!(node.is_online());
    }

    #[test]
    fn test_lan_node_is_offline() {
        let node = LanNode {
            name: "Pikachu".to_string(),
            id: NodeID::from_bytes(&[1u8; 32]),
            addr: "127.0.0.1:9876".parse().unwrap(),
            last_seen: Instant::now() - Duration::from_secs(10),
            status: NodeStatus::Online,
        };
        assert!(!node.is_online());
    }

    #[test]
    fn test_udp_socket_binding() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::with_port("TestNode", id, 19876);

        // 使用不同端口避免冲突
        let result = router.start();
        assert!(result.is_ok());

        let status = router.status();
        assert_eq!(status.node_status, NodeStatus::Online);

        router.stop();
    }

    #[test]
    fn test_broadcast_discover() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::with_port("TestNode", id, 19877);

        let result = router.start();
        assert!(result.is_ok());

        // 广播发现不应该失败
        let result = router.broadcast_discover();
        assert!(result.is_ok());

        router.stop();
    }

    #[test]
    fn test_send_to_unknown_node() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::with_port("TestNode", id, 19878);

        let result = router.start();
        assert!(result.is_ok());

        // 发送到不存在的节点
        let result = router.send("node:NonExistent", b"test");
        assert!(result.is_err());

        router.stop();
    }

    #[test]
    fn test_router_name() {
        let id = NodeID::from_bytes(&[1u8; 32]);
        let router = LanRouter::new("Charizard", id);
        assert_eq!(router.name(), "Charizard");
    }
}
