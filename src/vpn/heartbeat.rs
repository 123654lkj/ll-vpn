//! P1-5: 心跳与保活
//!
//! 实现心跳发送和响应机制：
//! - 默认 5 秒间隔发送心跳
//! - 节点存活检测（3 次无响应判定离线）
//! - 事件回调：OnNodeOnline, OnNodeOffline

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 默认心跳间隔（5秒）
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 5;

/// 默认离线判定阈值（3次无响应）
pub const DEFAULT_OFFLINE_THRESHOLD: u32 = 3;

/// 心跳错误类型
#[derive(Debug)]
pub enum HeartbeatError {
    /// 发送失败
    SendFailed(String),
    /// 节点未找到
    NodeNotFound(String),
    /// 心跳超时
    Timeout(String),
}

impl fmt::Display for HeartbeatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeartbeatError::SendFailed(msg) => write!(f, "heartbeat send failed: {}", msg),
            HeartbeatError::NodeNotFound(msg) => write!(f, "node not found: {}", msg),
            HeartbeatError::Timeout(msg) => write!(f, "heartbeat timeout: {}", msg),
        }
    }
}

impl std::error::Error for HeartbeatError {}

/// 心跳消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatMsgType {
    /// 心跳请求
    Request,
    /// 心跳响应
    Response,
}

impl HeartbeatMsgType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Request),
            0x02 => Some(Self::Response),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Request => 0x01,
            Self::Response => 0x02,
        }
    }
}

/// 心跳消息
#[derive(Debug, Clone)]
pub struct HeartbeatMessage {
    /// 消息类型
    pub msg_type: HeartbeatMsgType,
    /// 发送方节点 ID
    pub sender_id: NodeID,
    /// 时间戳
    pub timestamp: u64,
    /// 序列号
    pub sequence: u64,
}

impl HeartbeatMessage {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 8 + 8);
        buf.push(self.msg_type.to_u8());
        buf.extend_from_slice(self.sender_id.as_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf
    }

    /// 从字节反序列化
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 32 + 8 + 8 {
            return None;
        }

        let msg_type = HeartbeatMsgType::from_u8(data[0])?;
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&data[1..33]);
        let sender_id = NodeID::from_bytes(&id_bytes);
        let timestamp = u64::from_be_bytes(data[33..41].try_into().ok()?);
        let sequence = u64::from_be_bytes(data[41..49].try_into().ok()?);

        Some(Self {
            msg_type,
            sender_id,
            timestamp,
            sequence,
        })
    }
}

/// 节点心跳状态
#[derive(Debug, Clone)]
pub struct NodeHeartbeatState {
    /// 节点 ID
    pub node_id: NodeID,
    /// 最后收到心跳时间
    pub last_heartbeat: Instant,
    /// 连续未响应次数
    pub missed_count: u32,
    /// 是否在线
    pub is_online: bool,
    /// 发送序列号
    pub send_sequence: u64,
    /// 接收序列号
    pub recv_sequence: u64,
}

impl NodeHeartbeatState {
    /// 创建新的节点心跳状态
    pub fn new(node_id: NodeID) -> Self {
        Self {
            node_id,
            last_heartbeat: Instant::now(),
            missed_count: 0,
            is_online: true,
            send_sequence: 0,
            recv_sequence: 0,
        }
    }

    /// 检查是否应该判定为离线
    pub fn should_be_offline(&self, threshold: u32) -> bool {
        self.missed_count >= threshold
    }
}

/// 心跳事件回调 trait
pub trait HeartbeatCallback: Send + Sync {
    /// 节点上线回调
    fn on_node_online(&self, node_id: &NodeID);
    /// 节点离线回调
    fn on_node_offline(&self, node_id: &NodeID);
    /// 心跳发送回调
    fn on_heartbeat_sent(&self, node_id: &NodeID, sequence: u64);
    /// 心跳接收回调
    fn on_heartbeat_received(&self, node_id: &NodeID, sequence: u64);
}

/// 空回调实现
pub struct NoopCallback;

impl HeartbeatCallback for NoopCallback {
    fn on_node_online(&self, _node_id: &NodeID) {}
    fn on_node_offline(&self, _node_id: &NodeID) {}
    fn on_heartbeat_sent(&self, _node_id: &NodeID, _sequence: u64) {}
    fn on_heartbeat_received(&self, _node_id: &NodeID, _sequence: u64) {}
}

/// 心跳管理器
pub struct HeartbeatManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 心跳间隔
    interval: Duration,
    /// 离线判定阈值
    offline_threshold: u32,
    /// 节点状态表
    nodes: Arc<Mutex<HashMap<NodeID, NodeHeartbeatState>>>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 心跳发送函数
    send_fn: Arc<dyn Fn(NodeID, HeartbeatMessage) -> Result<(), HeartbeatError> + Send + Sync>,
    /// 事件回调
    callback: Arc<dyn HeartbeatCallback>,
}

impl HeartbeatManager {
    /// 创建新的心跳管理器
    pub fn new<F>(local_id: NodeID, send_fn: F) -> Self
    where
        F: Fn(NodeID, HeartbeatMessage) -> Result<(), HeartbeatError> + Send + Sync + 'static,
    {
        Self {
            local_id,
            interval: Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS),
            offline_threshold: DEFAULT_OFFLINE_THRESHOLD,
            nodes: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            send_fn: Arc::new(send_fn),
            callback: Arc::new(NoopCallback),
        }
    }

    /// 创建带自定义间隔的心跳管理器
    pub fn with_interval<F>(local_id: NodeID, interval: Duration, send_fn: F) -> Self
    where
        F: Fn(NodeID, HeartbeatMessage) -> Result<(), HeartbeatError> + Send + Sync + 'static,
    {
        let mut manager = Self::new(local_id, send_fn);
        manager.interval = interval;
        manager
    }

    /// 设置离线判定阈值
    pub fn set_offline_threshold(&mut self, threshold: u32) {
        self.offline_threshold = threshold;
    }

    /// 设置事件回调
    pub fn set_callback<C: HeartbeatCallback + 'static>(&mut self, callback: C) {
        self.callback = Arc::new(callback);
    }

    /// 添加监控节点
    pub fn add_node(&self, node_id: NodeID) {
        let mut nodes = self.nodes.lock().unwrap();
        if !nodes.contains_key(&node_id) {
            nodes.insert(node_id, NodeHeartbeatState::new(node_id));
        }
    }

    /// 移除监控节点
    pub fn remove_node(&self, node_id: &NodeID) {
        self.nodes.lock().unwrap().remove(node_id);
    }

    /// 获取节点状态
    pub fn get_node_state(&self, node_id: &NodeID) -> Option<NodeHeartbeatState> {
        self.nodes.lock().unwrap().get(node_id).cloned()
    }

    /// 获取所有节点状态
    pub fn get_all_states(&self) -> Vec<NodeHeartbeatState> {
        self.nodes.lock().unwrap().values().cloned().collect()
    }

    /// 获取在线节点列表
    pub fn online_nodes(&self) -> Vec<NodeID> {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.is_online)
            .map(|s| s.node_id)
            .collect()
    }

    /// 获取离线节点列表
    pub fn offline_nodes(&self) -> Vec<NodeID> {
        self.nodes
            .lock()
            .unwrap()
            .values()
            .filter(|s| !s.is_online)
            .map(|s| s.node_id)
            .collect()
    }

    /// 启动心跳
    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let nodes = self.nodes.clone();
        let interval = self.interval;
        let local_id = self.local_id;
        let send_fn = self.send_fn.clone();
        let callback = self.callback.clone();
        let threshold = self.offline_threshold;

        thread::spawn(move || {
            let mut sequence = 0u64;

            while running.load(Ordering::SeqCst) {
                // 发送心跳到所有监控节点
                let node_ids: Vec<NodeID> = {
                    let nodes_guard = nodes.lock().unwrap();
                    nodes_guard.keys().cloned().collect()
                };

                for node_id in node_ids {
                    let msg = HeartbeatMessage {
                        msg_type: HeartbeatMsgType::Request,
                        sender_id: local_id,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        sequence,
                    };

                    if let Err(e) = send_fn(node_id, msg) {
                        log::error!("Failed to send heartbeat to {}: {}", node_id, e);
                    } else {
                        callback.on_heartbeat_sent(&node_id, sequence);

                        // 更新发送序列号
                        if let Some(state) = nodes.lock().unwrap().get_mut(&node_id) {
                            state.send_sequence = sequence;
                        }
                    }
                }

                sequence += 1;

                // 检查未响应的心跳
                {
                    let mut nodes_guard = nodes.lock().unwrap();
                    for state in nodes_guard.values_mut() {
                        if state.is_online && state.last_heartbeat.elapsed() > interval * 2 {
                            state.missed_count += 1;

                            if state.should_be_offline(threshold) {
                                state.is_online = false;
                                callback.on_node_offline(&state.node_id);
                                log::info!("Node {} marked offline", state.node_id);
                            }
                        }
                    }
                }

                thread::sleep(interval);
            }
        });
    }

    /// 停止心跳
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// 处理收到的心跳消息
    pub fn handle_heartbeat(&self, msg: &HeartbeatMessage) -> Result<(), HeartbeatError> {
        let mut nodes = self.nodes.lock().unwrap();

        // 获取或创建节点状态
        let state = nodes
            .entry(msg.sender_id)
            .or_insert_with(|| NodeHeartbeatState::new(msg.sender_id));

        // 更新状态
        let was_offline = !state.is_online;
        state.last_heartbeat = Instant::now();
        state.missed_count = 0;
        state.is_online = true;
        state.recv_sequence = msg.sequence;

        // 如果节点刚上线，触发回调
        if was_offline {
            self.callback.on_node_online(&msg.sender_id);
            log::info!("Node {} came online", msg.sender_id);
        }

        self.callback
            .on_heartbeat_received(&msg.sender_id, msg.sequence);

        Ok(())
    }

    /// 手动发送心跳响应
    pub fn send_response(&self, target: NodeID, sequence: u64) -> Result<(), HeartbeatError> {
        let msg = HeartbeatMessage {
            msg_type: HeartbeatMsgType::Response,
            sender_id: self.local_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            sequence,
        };

        (self.send_fn)(target, msg)
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取心跳间隔
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// 获取离线阈值
    pub fn offline_threshold(&self) -> u32 {
        self.offline_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// 测试用回调
    struct TestCallback {
        online_count: Arc<AtomicUsize>,
        offline_count: Arc<AtomicUsize>,
        sent_count: Arc<AtomicUsize>,
        received_count: Arc<AtomicUsize>,
    }

    impl TestCallback {
        fn new() -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
            let online = Arc::new(AtomicUsize::new(0));
            let offline = Arc::new(AtomicUsize::new(0));
            let sent = Arc::new(AtomicUsize::new(0));
            let received = Arc::new(AtomicUsize::new(0));

            (
                Self {
                    online_count: online.clone(),
                    offline_count: offline.clone(),
                    sent_count: sent.clone(),
                    received_count: received.clone(),
                },
                online,
                offline,
                sent,
                received,
            )
        }
    }

    impl HeartbeatCallback for TestCallback {
        fn on_node_online(&self, _node_id: &NodeID) {
            self.online_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_node_offline(&self, _node_id: &NodeID) {
            self.offline_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_heartbeat_sent(&self, _node_id: &NodeID, _sequence: u64) {
            self.sent_count.fetch_add(1, Ordering::SeqCst);
        }

        fn on_heartbeat_received(&self, _node_id: &NodeID, _sequence: u64) {
            self.received_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_heartbeat_msg_type_conversion() {
        assert_eq!(HeartbeatMsgType::from_u8(0x01), Some(HeartbeatMsgType::Request));
        assert_eq!(HeartbeatMsgType::from_u8(0x02), Some(HeartbeatMsgType::Response));
        assert_eq!(HeartbeatMsgType::from_u8(0xFF), None);

        assert_eq!(HeartbeatMsgType::Request.to_u8(), 0x01);
        assert_eq!(HeartbeatMsgType::Response.to_u8(), 0x02);
    }

    #[test]
    fn test_heartbeat_message_roundtrip() {
        let (sender_id, _) = NodeID::generate();
        let msg = HeartbeatMessage {
            msg_type: HeartbeatMsgType::Request,
            sender_id,
            timestamp: 1234567890,
            sequence: 42,
        };

        let bytes = msg.to_bytes();
        let recovered = HeartbeatMessage::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.msg_type, HeartbeatMsgType::Request);
        assert_eq!(recovered.sender_id, sender_id);
        assert_eq!(recovered.timestamp, 1234567890);
        assert_eq!(recovered.sequence, 42);
    }

    #[test]
    fn test_heartbeat_message_too_short() {
        let result = HeartbeatMessage::from_bytes(&[0u8; 40]);
        assert!(result.is_none());
    }

    #[test]
    fn test_node_heartbeat_state_new() {
        let (node_id, _) = NodeID::generate();
        let state = NodeHeartbeatState::new(node_id);

        assert_eq!(state.node_id, node_id);
        assert!(state.is_online);
        assert_eq!(state.missed_count, 0);
    }

    #[test]
    fn test_node_heartbeat_state_should_be_offline() {
        let (node_id, _) = NodeID::generate();
        let mut state = NodeHeartbeatState::new(node_id);

        assert!(!state.should_be_offline(3));

        state.missed_count = 2;
        assert!(!state.should_be_offline(3));

        state.missed_count = 3;
        assert!(state.should_be_offline(3));

        state.missed_count = 4;
        assert!(state.should_be_offline(3));
    }

    #[test]
    fn test_heartbeat_manager_new() {
        let (local_id, _) = NodeID::generate();
        let manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        assert_eq!(*manager.local_id(), local_id);
        assert_eq!(manager.interval(), Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS));
        assert_eq!(manager.offline_threshold(), DEFAULT_OFFLINE_THRESHOLD);
    }

    #[test]
    fn test_heartbeat_manager_add_remove_node() {
        let (local_id, _) = NodeID::generate();
        let (node_id, _) = NodeID::generate();
        let manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        manager.add_node(node_id);
        assert!(manager.get_node_state(&node_id).is_some());

        manager.remove_node(&node_id);
        assert!(manager.get_node_state(&node_id).is_none());
    }

    #[test]
    fn test_heartbeat_manager_handle_request() {
        let (local_id, _) = NodeID::generate();
        let (sender_id, _) = NodeID::generate();
        let manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        manager.add_node(sender_id);

        let msg = HeartbeatMessage {
            msg_type: HeartbeatMsgType::Request,
            sender_id,
            timestamp: 1234567890,
            sequence: 1,
        };

        manager.handle_heartbeat(&msg).unwrap();

        let state = manager.get_node_state(&sender_id).unwrap();
        assert!(state.is_online);
        assert_eq!(state.recv_sequence, 1);
    }

    #[test]
    fn test_heartbeat_manager_online_offline_nodes() {
        let (local_id, _) = NodeID::generate();
        let (node1, _) = NodeID::generate();
        let (node2, _) = NodeID::generate();
        let manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        manager.add_node(node1);
        manager.add_node(node2);

        // node1 在线
        let msg1 = HeartbeatMessage {
            msg_type: HeartbeatMsgType::Request,
            sender_id: node1,
            timestamp: 1234567890,
            sequence: 1,
        };
        manager.handle_heartbeat(&msg1).unwrap();

        let online = manager.online_nodes();
        assert!(online.contains(&node1));

        // node2 没有心跳，应该离线（通过修改状态模拟）
        {
            let mut nodes = manager.nodes.lock().unwrap();
            if let Some(state) = nodes.get_mut(&node2) {
                state.is_online = false;
            }
        }

        let offline = manager.offline_nodes();
        assert!(offline.contains(&node2));
    }

    #[test]
    fn test_heartbeat_error_display() {
        let err = HeartbeatError::SendFailed("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = HeartbeatError::NodeNotFound("node".to_string());
        assert!(format!("{}", err).contains("node"));

        let err = HeartbeatError::Timeout("timeout".to_string());
        assert!(format!("{}", err).contains("timeout"));
    }

    #[test]
    fn test_heartbeat_manager_set_offline_threshold() {
        let (local_id, _) = NodeID::generate();
        let mut manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        assert_eq!(manager.offline_threshold(), DEFAULT_OFFLINE_THRESHOLD);

        manager.set_offline_threshold(5);
        assert_eq!(manager.offline_threshold(), 5);
    }

    #[test]
    fn test_heartbeat_manager_set_callback() {
        let (local_id, _) = NodeID::generate();
        let mut manager = HeartbeatManager::new(local_id, |_, _| Ok(()));

        let (callback, _, _, _, _) = TestCallback::new();
        manager.set_callback(callback);

        // 回调已设置，不会 panic
    }
}
