//! P1-4: TCP 中继通信
//!
//! 实现 TCP 服务端和客户端，支持消息帧协议：
//! +--------+--------+------------------+
//! | 4 bytes| 1 byte | variable length  |
//! | length | type   | payload          |
//! +--------+--------+------------------+
//!
//! 消息类型：HANDSHAKE, DATA, ACK, HEARTBEAT, RELAY

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 默认 TCP 端口
pub const DEFAULT_TCP_PORT: u16 = 9876;

/// 默认连接池大小
pub const DEFAULT_POOL_SIZE: usize = 10;

/// 消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// 握手
    Handshake,
    /// 数据
    Data,
    /// 确认
    Ack,
    /// 心跳
    Heartbeat,
    /// 中继
    Relay,
    /// 注册中心消息
    Registry,
    /// DHT 发现消息
    Dht,
    /// 多跳路由消息
    Route,
    /// 自愈消息
    SelfHeal,
}

impl MessageType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Handshake),
            0x02 => Some(Self::Data),
            0x03 => Some(Self::Ack),
            0x04 => Some(Self::Heartbeat),
            0x05 => Some(Self::Relay),
            0x06 => Some(Self::Registry),
            0x07 => Some(Self::Dht),
            0x08 => Some(Self::Route),
            0x09 => Some(Self::SelfHeal),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Handshake => 0x01,
            Self::Data => 0x02,
            Self::Ack => 0x03,
            Self::Heartbeat => 0x04,
            Self::Relay => 0x05,
            Self::Registry => 0x06,
            Self::Dht => 0x07,
            Self::Route => 0x08,
            Self::SelfHeal => 0x09,
        }
    }
}

/// 中继错误类型
#[derive(Debug)]
pub enum RelayError {
    /// IO 错误
    IoError(std::io::Error),
    /// 连接错误
    ConnectionError(String),
    /// 消息解析错误
    ParseError(String),
    /// 连接池满
    PoolFull,
    /// 节点不可达
    Unreachable(String),
    /// 超时
    Timeout,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::IoError(e) => write!(f, "io error: {}", e),
            RelayError::ConnectionError(msg) => write!(f, "connection error: {}", msg),
            RelayError::ParseError(msg) => write!(f, "parse error: {}", msg),
            RelayError::PoolFull => write!(f, "connection pool full"),
            RelayError::Unreachable(addr) => write!(f, "unreachable: {}", addr),
            RelayError::Timeout => write!(f, "timeout"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<std::io::Error> for RelayError {
    fn from(e: std::io::Error) -> Self {
        RelayError::IoError(e)
    }
}

/// 消息帧
#[derive(Debug, Clone)]
pub struct Message {
    /// 消息类型
    pub msg_type: MessageType,
    /// 载荷数据
    pub payload: Vec<u8>,
}

impl Message {
    /// 创建新消息
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(5 + self.payload.len());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.push(self.msg_type.to_u8());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节反序列化
    pub fn from_bytes(data: &[u8]) -> Result<Self, RelayError> {
        if data.len() < 5 {
            return Err(RelayError::ParseError("message too short".to_string()));
        }

        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let msg_type = MessageType::from_u8(data[4])
            .ok_or_else(|| RelayError::ParseError(format!("invalid message type: {}", data[4])))?;

        if data.len() < 5 + len {
            return Err(RelayError::ParseError(format!(
                "payload too short: expected {} bytes",
                len
            )));
        }

        let payload = data[5..5 + len].to_vec();
        Ok(Self { msg_type, payload })
    }
}

/// 连接池中的连接
struct PooledConnection {
    stream: TcpStream,
    peer_id: Option<NodeID>,
    last_used: Instant,
    in_use: bool,
}

impl PooledConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            peer_id: None,
            last_used: Instant::now(),
            in_use: false,
        }
    }

    fn is_idle(&self, max_idle: Duration) -> bool {
        !self.in_use && self.last_used.elapsed() > max_idle
    }
}

/// 连接池
pub struct ConnectionPool {
    /// 连接池：地址 → 连接列表
    connections: Arc<Mutex<HashMap<String, Vec<PooledConnection>>>>,
    /// 最大池大小
    max_size: usize,
    /// 最大空闲时间
    max_idle: Duration,
    /// 活跃连接数
    active_count: Arc<AtomicUsize>,
}

impl ConnectionPool {
    /// 创建新的连接池
    pub fn new(max_size: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            max_size,
            max_idle: Duration::from_secs(60),
            active_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 获取或创建连接
    pub fn get_connection(&self, addr: &str) -> Result<TcpStream, RelayError> {
        let mut connections = self.connections.lock().unwrap();
        let pool = connections.entry(addr.to_string()).or_insert_with(Vec::new);

        // 尝试获取空闲连接
        for conn in pool.iter_mut() {
            if !conn.in_use && conn.stream.peer_addr().is_ok() {
                conn.in_use = true;
                conn.last_used = Instant::now();
                self.active_count.fetch_add(1, Ordering::SeqCst);
                return conn.stream.try_clone().map_err(RelayError::IoError);
            }
        }

        // 如果池未满，创建新连接
        if pool.len() < self.max_size {
            let stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(30)))?;
            stream.set_write_timeout(Some(Duration::from_secs(30)))?;

            let mut conn = PooledConnection::new(stream.try_clone()?);
            conn.in_use = true;
            pool.push(conn);
            self.active_count.fetch_add(1, Ordering::SeqCst);

            return Ok(stream);
        }

        Err(RelayError::PoolFull)
    }

    /// 归还连接
    pub fn return_connection(&self, addr: &str, mut stream: TcpStream) {
        let mut connections = self.connections.lock().unwrap();
        if let Some(pool) = connections.get_mut(addr) {
            for conn in pool.iter_mut() {
                if conn.in_use && conn.stream.peer_addr().is_ok() {
                    conn.in_use = false;
                    conn.last_used = Instant::now();
                    self.active_count.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
            }
        }
        // 如果没有找到，丢弃连接
        drop(stream);
        self.active_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// 清理空闲连接
    pub fn cleanup_idle(&self) {
        let mut connections = self.connections.lock().unwrap();
        for pool in connections.values_mut() {
            pool.retain(|conn| !conn.is_idle(self.max_idle));
        }
    }

    /// 获取活跃连接数
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }

    /// 清空连接池
    pub fn clear(&self) {
        let mut connections = self.connections.lock().unwrap();
        connections.clear();
        self.active_count.store(0, Ordering::SeqCst);
    }
}

/// TCP 服务端
pub struct TcpServer {
    /// 监听地址
    listen_addr: String,
    /// 本地节点 ID
    local_id: NodeID,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 接收到的消息
    received: Arc<Mutex<Vec<(NodeID, Message)>>>,
    /// 消息回调
    handler: Option<Arc<dyn Fn(NodeID, Message) + Send + Sync>>,
}

impl TcpServer {
    /// 创建新的 TCP 服务端
    pub fn new(local_id: NodeID, port: u16) -> Self {
        Self {
            listen_addr: format!("0.0.0.0:{}", port),
            local_id,
            running: Arc::new(AtomicBool::new(false)),
            received: Arc::new(Mutex::new(Vec::new())),
            handler: None,
        }
    }

    /// 启动服务端
    pub fn start(&self) -> Result<(), RelayError> {
        let listener = TcpListener::bind(&self.listen_addr)?;
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let received = self.received.clone();
        let local_id = self.local_id;

        thread::spawn(move || {
            listener.set_nonblocking(true).ok();
            while running.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, addr)) => {
                        log::info!("Accepted connection from {}", addr);
                        let running = running.clone();
                        let received = received.clone();
                        let local_id = local_id;

                        thread::spawn(move || {
                            Self::handle_connection(stream, running, received, local_id);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        log::error!("Accept error: {}", e);
                    }
                }
            }
        });

        Ok(())
    }

    /// 停止服务端
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 处理单个连接
    fn handle_connection(
        mut stream: TcpStream,
        running: Arc<AtomicBool>,
        received: Arc<Mutex<Vec<(NodeID, Message)>>>,
        local_id: NodeID,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .ok();

        while running.load(Ordering::SeqCst) {
            match Self::read_message(&mut stream) {
                Ok(Some((sender_id, msg))) => {
                    log::debug!("Received {:?} from {}", msg.msg_type, sender_id);
                    received.lock().unwrap().push((sender_id, msg));
                }
                Ok(None) => {
                    // 连接关闭
                    break;
                }
                Err(e) => {
                    log::error!("Read error: {}", e);
                    break;
                }
            }
        }
    }

    /// 读取消息
    fn read_message(stream: &mut TcpStream) -> Result<Option<(NodeID, Message)>, RelayError> {
        // 读取长度（4字节）
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            // 最大 1MB
            return Err(RelayError::ParseError("message too large".to_string()));
        }

        // 读取消息类型（1字节）
        let mut type_buf = [0u8; 1];
        stream.read_exact(&mut type_buf)?;

        // 读取载荷
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload)?;

        let msg = Message {
            msg_type: MessageType::from_u8(type_buf[0])
                .ok_or_else(|| RelayError::ParseError(format!("invalid type: {}", type_buf[0])))?,
            payload,
        };

        // 这里简化处理，实际需要从消息中提取发送者 ID
        let sender_id = NodeID::from_bytes(&[0u8; 32]); // 占位

        Ok(Some((sender_id, msg)))
    }

    /// 发送消息
    pub fn send(stream: &mut TcpStream, msg: &Message) -> Result<(), RelayError> {
        let data = msg.to_bytes();
        stream.write_all(&data)?;
        stream.flush()?;
        Ok(())
    }

    /// 获取接收到的消息
    pub fn take_received(&self) -> Vec<(NodeID, Message)> {
        std::mem::take(&mut *self.received.lock().unwrap())
    }
}

/// TCP 客户端
pub struct TcpClient {
    /// 本地节点 ID
    local_id: NodeID,
    /// 连接池
    pool: Arc<ConnectionPool>,
}

impl TcpClient {
    /// 创建新的 TCP 客户端
    pub fn new(local_id: NodeID) -> Self {
        Self {
            local_id,
            pool: Arc::new(ConnectionPool::new(DEFAULT_POOL_SIZE)),
        }
    }

    /// 连接到目标节点
    pub fn connect(&self, addr: &str) -> Result<TcpStream, RelayError> {
        self.pool.get_connection(addr)
    }

    /// 归还连接
    pub fn return_connection(&self, addr: &str, stream: TcpStream) {
        self.pool.return_connection(addr, stream);
    }

    /// 发送消息
    pub fn send_message(&self, addr: &str, msg: &Message) -> Result<(), RelayError> {
        let mut stream = self.pool.get_connection(addr)?;
        let result = TcpServer::send(&mut stream, msg);
        self.pool.return_connection(addr, stream);
        result
    }

    /// 获取连接池引用
    pub fn pool(&self) -> &ConnectionPool {
        &self.pool
    }
}

/// 中继管理器
///
/// 管理节点间的消息转发
pub struct RelayManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// TCP 服务端
    server: Arc<TcpServer>,
    /// TCP 客户端
    client: Arc<TcpClient>,
    /// 已知节点：NodeID → 地址
    known_nodes: Arc<Mutex<HashMap<NodeID, String>>>,
    /// 中继表：目标 NodeID → 下一跳地址
    relay_table: Arc<Mutex<HashMap<NodeID, String>>>,
}

impl RelayManager {
    /// 创建新的中继管理器
    pub fn new(local_id: NodeID, port: u16) -> Self {
        Self {
            local_id,
            server: Arc::new(TcpServer::new(local_id, port)),
            client: Arc::new(TcpClient::new(local_id)),
            known_nodes: Arc::new(Mutex::new(HashMap::new())),
            relay_table: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 启动中继管理器
    pub fn start(&self) -> Result<(), RelayError> {
        self.server.start()
    }

    /// 停止中继管理器
    pub fn stop(&self) {
        self.server.stop();
    }

    /// 注册已知节点
    pub fn register_node(&self, id: NodeID, addr: String) {
        self.known_nodes.lock().unwrap().insert(id, addr);
    }

    /// 获取节点地址
    pub fn get_node_addr(&self, id: &NodeID) -> Option<String> {
        self.known_nodes.lock().unwrap().get(id).cloned()
    }

    /// 设置中继路由
    pub fn set_relay(&self, target: NodeID, next_hop: String) {
        self.relay_table.lock().unwrap().insert(target, next_hop);
    }

    /// 发送消息到目标节点
    pub fn send(&self, target: &NodeID, msg: &Message) -> Result<(), RelayError> {
        // 直接连接
        if let Some(addr) = self.get_node_addr(target) {
            return self.client.send_message(&addr, msg);
        }

        // 通过中继
        if let Some(next_hop) = self.relay_table.lock().unwrap().get(target) {
            let relay_msg = Message::new(
                MessageType::Relay,
                target.as_bytes().to_vec(),
            );
            return self.client.send_message(next_hop, &relay_msg);
        }

        Err(RelayError::Unreachable(target.to_hex()))
    }

    /// 中继转发消息
    pub fn relay(&self, target: &NodeID, payload: &[u8]) -> Result<(), RelayError> {
        let addr = self.get_node_addr(target)
            .ok_or_else(|| RelayError::Unreachable(target.to_hex()))?;

        let msg = Message::new(MessageType::Data, payload.to_vec());
        self.client.send_message(&addr, &msg)
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取服务端引用
    pub fn server(&self) -> &TcpServer {
        &self.server
    }

    /// 获取客户端引用
    pub fn client(&self) -> &TcpClient {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_conversion() {
        assert_eq!(MessageType::from_u8(0x01), Some(MessageType::Handshake));
        assert_eq!(MessageType::from_u8(0x02), Some(MessageType::Data));
        assert_eq!(MessageType::from_u8(0x03), Some(MessageType::Ack));
        assert_eq!(MessageType::from_u8(0x04), Some(MessageType::Heartbeat));
        assert_eq!(MessageType::from_u8(0x05), Some(MessageType::Relay));
        assert_eq!(MessageType::from_u8(0x06), Some(MessageType::Registry));
        assert_eq!(MessageType::from_u8(0x07), Some(MessageType::Dht));
        assert_eq!(MessageType::from_u8(0x08), Some(MessageType::Route));
        assert_eq!(MessageType::from_u8(0x09), Some(MessageType::SelfHeal));
        assert_eq!(MessageType::from_u8(0xFF), None);

        assert_eq!(MessageType::Handshake.to_u8(), 0x01);
        assert_eq!(MessageType::Data.to_u8(), 0x02);
        assert_eq!(MessageType::Ack.to_u8(), 0x03);
        assert_eq!(MessageType::Heartbeat.to_u8(), 0x04);
        assert_eq!(MessageType::Relay.to_u8(), 0x05);
        assert_eq!(MessageType::Registry.to_u8(), 0x06);
        assert_eq!(MessageType::Dht.to_u8(), 0x07);
        assert_eq!(MessageType::Route.to_u8(), 0x08);
        assert_eq!(MessageType::SelfHeal.to_u8(), 0x09);
    }

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::new(MessageType::Data, b"hello world".to_vec());
        let bytes = msg.to_bytes();
        let recovered = Message::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.msg_type, MessageType::Data);
        assert_eq!(recovered.payload, b"hello world");
    }

    #[test]
    fn test_message_too_short() {
        let result = Message::from_bytes(&[0, 0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_invalid_type() {
        let mut bytes = vec![0, 0, 0, 1]; // len = 1
        bytes.push(0xFF); // invalid type
        bytes.push(0);

        let result = Message::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_payload_too_short() {
        let bytes = vec![0, 0, 0, 10, 0x02]; // len = 10, but no payload
        let result = Message::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_connection_pool_new() {
        let pool = ConnectionPool::new(5);
        assert_eq!(pool.active_count(), 0);
    }

    #[test]
    fn test_relay_error_display() {
        let err = RelayError::ConnectionError("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = RelayError::ParseError("bad".to_string());
        assert!(format!("{}", err).contains("bad"));

        let err = RelayError::Unreachable("node".to_string());
        assert!(format!("{}", err).contains("node"));

        let err = RelayError::PoolFull;
        assert!(format!("{}", err).contains("pool full"));

        let err = RelayError::Timeout;
        assert!(format!("{}", err).contains("timeout"));
    }

    #[test]
    fn test_tcp_server_new() {
        let (id, _) = NodeID::generate();
        let server = TcpServer::new(id, 19876);
        assert!(!server.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_tcp_client_new() {
        let (id, _) = NodeID::generate();
        let client = TcpClient::new(id);
        assert_eq!(client.pool.active_count(), 0);
    }

    #[test]
    fn test_relay_manager_new() {
        let (id, _) = NodeID::generate();
        let manager = RelayManager::new(id, 19877);
        assert_eq!(*manager.local_id(), id);
    }

    #[test]
    fn test_relay_manager_register_node() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let manager = RelayManager::new(local_id, 19878);
        manager.register_node(remote_id, "127.0.0.1:9876".to_string());

        assert_eq!(
            manager.get_node_addr(&remote_id),
            Some("127.0.0.1:9876".to_string())
        );
    }

    #[test]
    fn test_relay_manager_set_relay() {
        let (local_id, _) = NodeID::generate();
        let (target_id, _) = NodeID::generate();

        let manager = RelayManager::new(local_id, 19879);
        manager.set_relay(target_id, "192.168.1.1:9876".to_string());

        let relay = manager.relay_table.lock().unwrap();
        assert_eq!(
            relay.get(&target_id),
            Some(&"192.168.1.1:9876".to_string())
        );
    }

    #[test]
    fn test_relay_manager_send_unreachable() {
        let (local_id, _) = NodeID::generate();
        let (unknown_id, _) = NodeID::generate();

        let manager = RelayManager::new(local_id, 19880);
        let msg = Message::new(MessageType::Data, b"test".to_vec());

        let result = manager.send(&unknown_id, &msg);
        assert!(result.is_err());
    }
}
