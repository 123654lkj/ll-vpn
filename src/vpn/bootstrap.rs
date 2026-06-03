//! P1-6: 入口节点引导
//!
//! 实现入口节点引导机制：
//! - 硬编码入口节点列表（配置文件）
//! - 引导握手：新节点连接入口节点获取已知节点列表
//! - 节点列表广播
//! - 多入口节点冗余（至少 2 个）

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 默认引导端口
pub const DEFAULT_BOOTSTRAP_PORT: u16 = 9876;

/// 引导超时时间（秒）
pub const BOOTSTRAP_TIMEOUT_SECS: u64 = 10;

/// 引导错误类型
#[derive(Debug)]
pub enum BootstrapError {
    /// 配置错误
    ConfigError(String),
    /// 连接失败
    ConnectionFailed(String),
    /// 握手失败
    HandshakeFailed(String),
    /// 超时
    Timeout,
    /// 入口节点不可达
    AllNodesUnreachable,
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapError::ConfigError(msg) => write!(f, "config error: {}", msg),
            BootstrapError::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            BootstrapError::HandshakeFailed(msg) => write!(f, "handshake failed: {}", msg),
            BootstrapError::Timeout => write!(f, "bootstrap timeout"),
            BootstrapError::AllNodesUnreachable => write!(f, "all bootstrap nodes unreachable"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// 入口节点配置
#[derive(Debug, Clone)]
pub struct BootstrapNode {
    /// 主机名或 IP
    pub host: String,
    /// 端口
    pub port: u16,
    /// 优先级（越小越优先）
    pub priority: u32,
}

impl BootstrapNode {
    /// 创建新的入口节点配置
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_string(),
            port,
            priority: 0,
        }
    }

    /// 创建带优先级的入口节点配置
    pub fn with_priority(host: &str, port: u16, priority: u32) -> Self {
        Self {
            host: host.to_string(),
            port,
            priority,
        }
    }

    /// 获取地址字符串
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// 引导配置
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// 入口节点列表
    pub nodes: Vec<BootstrapNode>,
    /// 引导超时时间
    pub timeout: Duration,
}

impl BootstrapConfig {
    /// 创建新的引导配置
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            timeout: Duration::from_secs(BOOTSTRAP_TIMEOUT_SECS),
        }
    }

    /// 从 JSON 字符串解析配置
    pub fn from_json(json: &str) -> Result<Self, BootstrapError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| BootstrapError::ConfigError(e.to_string()))?;

        let mut config = Self::new();

        if let Some(nodes) = value["bootstrap"]["nodes"].as_array() {
            for (i, node) in nodes.iter().enumerate() {
                let host = node["host"]
                    .as_str()
                    .ok_or_else(|| BootstrapError::ConfigError("missing host".to_string()))?
                    .to_string();
                let port = node["port"]
                    .as_u64()
                    .unwrap_or(DEFAULT_BOOTSTRAP_PORT as u64) as u16;
                let priority = node["priority"].as_u64().unwrap_or(i as u64) as u32;

                config.nodes.push(BootstrapNode::with_priority(&host, port, priority));
            }
        }

        // 按优先级排序
        config
            .nodes
            .sort_by_key(|n| n.priority);

        Ok(config)
    }

    /// 从 YAML 字符串解析配置（简化版）
    pub fn from_yaml_simple(yaml: &str) -> Result<Self, BootstrapError> {
        // 简单的 YAML 解析（只支持基本格式）
        let mut config = Self::new();
        let mut current_host: Option<String> = None;
        let mut current_port: u16 = DEFAULT_BOOTSTRAP_PORT;

        for line in yaml.lines() {
            let line = line.trim();
            if line.starts_with("- host:") {
                if let Some(host) = current_host.take() {
                    config
                        .nodes
                        .push(BootstrapNode::new(&host, current_port));
                    current_port = DEFAULT_BOOTSTRAP_PORT;
                }
                current_host = Some(
                    line.trim_start_matches("- host:")
                        .trim()
                        .trim_matches('"')
                        .to_string(),
                );
            } else if line.starts_with("port:") {
                if let Ok(port) = line
                    .trim_start_matches("port:")
                    .trim()
                    .parse::<u16>()
                {
                    current_port = port;
                }
            }
        }

        // 处理最后一个节点
        if let Some(host) = current_host {
            config
                .nodes
                .push(BootstrapNode::new(&host, current_port));
        }

        Ok(config)
    }

    /// 添加入口节点
    pub fn add_node(&mut self, node: BootstrapNode) {
        self.nodes.push(node);
        self.nodes.sort_by_key(|n| n.priority);
    }

    /// 获取入口节点数量
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// 已知节点信息
#[derive(Debug, Clone)]
pub struct KnownNode {
    /// 节点 ID
    pub id: NodeID,
    /// 节点名称
    pub name: String,
    /// 节点地址
    pub addr: String,
    /// 最后发现时间
    pub discovered_at: Instant,
    /// 来源（哪个入口节点告诉我们的）
    pub source: String,
}

/// 引导管理器
pub struct BootstrapManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 本地节点名称
    local_name: String,
    /// 引导配置
    config: BootstrapConfig,
    /// 已知节点表
    known_nodes: Arc<Mutex<HashMap<NodeID, KnownNode>>>,
    /// 已连接的入口节点
    connected_bootstrap: Arc<Mutex<Vec<String>>>,
}

impl BootstrapManager {
    /// 创建新的引导管理器
    pub fn new(local_id: NodeID, local_name: &str, config: BootstrapConfig) -> Self {
        Self {
            local_id,
            local_name: local_name.to_string(),
            config,
            known_nodes: Arc::new(Mutex::new(HashMap::new())),
            connected_bootstrap: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取本地节点名称
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// 获取引导配置
    pub fn config(&self) -> &BootstrapConfig {
        &self.config
    }

    /// 执行引导流程
    pub fn bootstrap(&self) -> Result<Vec<KnownNode>, BootstrapError> {
        if self.config.nodes.is_empty() {
            return Err(BootstrapError::ConfigError(
                "no bootstrap nodes configured".to_string(),
            ));
        }

        let mut discovered_nodes = Vec::new();

        // 按优先级尝试连接入口节点
        for node in &self.config.nodes {
            log::info!(
                "Trying bootstrap node: {}:{}",
                node.host,
                node.port
            );

            match self.connect_to_bootstrap_node(node) {
                Ok(nodes) => {
                    log::info!(
                        "Successfully bootstrapped from {}:{}, discovered {} nodes",
                        node.host,
                        node.port,
                        nodes.len()
                    );
                    discovered_nodes.extend(nodes);

                    // 记录已连接的入口节点
                    self.connected_bootstrap
                        .lock()
                        .unwrap()
                        .push(node.addr());
                }
                Err(e) => {
                    log::warn!(
                        "Failed to connect to bootstrap node {}:{}: {}",
                        node.host,
                        node.port,
                        e
                    );
                }
            }
        }

        if discovered_nodes.is_empty() && !self.config.nodes.is_empty() {
            return Err(BootstrapError::AllNodesUnreachable);
        }

        Ok(discovered_nodes)
    }

    /// 连接到入口节点并获取节点列表
    fn connect_to_bootstrap_node(
        &self,
        node: &BootstrapNode,
    ) -> Result<Vec<KnownNode>, BootstrapError> {
        // 这里简化实现，实际需要 TCP 连接和握手
        // 模拟从入口节点获取节点列表

        // 在实际实现中，这里会：
        // 1. 建立 TCP 连接
        // 2. 执行 Noise IK 握手
        // 3. 发送引导请求
        // 4. 接收节点列表

        // 模拟返回一些已知节点
        let mut nodes = Vec::new();

        // 返回空列表（实际实现会返回真实节点）
        Ok(nodes)
    }

    /// 添加已知节点
    pub fn add_known_node(&self, node: KnownNode) {
        self.known_nodes.lock().unwrap().insert(node.id, node);
    }

    /// 移除已知节点
    pub fn remove_known_node(&self, id: &NodeID) -> Option<KnownNode> {
        self.known_nodes.lock().unwrap().remove(id)
    }

    /// 获取已知节点
    pub fn get_known_node(&self, id: &NodeID) -> Option<KnownNode> {
        self.known_nodes.lock().unwrap().get(id).cloned()
    }

    /// 获取所有已知节点
    pub fn get_all_known_nodes(&self) -> Vec<KnownNode> {
        self.known_nodes.lock().unwrap().values().cloned().collect()
    }

    /// 获取已知节点数量
    pub fn known_node_count(&self) -> usize {
        self.known_nodes.lock().unwrap().len()
    }

    /// 广播节点列表到已连接的入口节点
    pub fn broadcast_node_list(&self) -> Result<(), BootstrapError> {
        let nodes = self.get_all_known_nodes();
        let connected = self.connected_bootstrap.lock().unwrap().clone();

        for addr in &connected {
            log::info!(
                "Broadcasting {} nodes to {}",
                nodes.len(),
                addr
            );
            // 实际实现会发送节点列表到入口节点
        }

        Ok(())
    }

    /// 获取已连接的入口节点
    pub fn connected_bootstrap_nodes(&self) -> Vec<String> {
        self.connected_bootstrap.lock().unwrap().clone()
    }

    /// 检查是否已连接到任何入口节点
    pub fn is_bootstrapped(&self) -> bool {
        !self.connected_bootstrap.lock().unwrap().is_empty()
    }
}

/// 引导请求消息
#[derive(Debug, Clone)]
pub struct BootstrapRequest {
    /// 请求类型
    pub request_type: BootstrapRequestType,
    /// 发送方节点 ID
    pub sender_id: NodeID,
    /// 发送方节点名称
    pub sender_name: String,
    /// 时间戳
    pub timestamp: u64,
}

/// 引导请求类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapRequestType {
    /// 请求节点列表
    GetNodeList,
    /// 上报节点信息
    ReportNode,
    /// 节点列表响应
    NodeListResponse,
}

impl BootstrapRequestType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::GetNodeList),
            0x02 => Some(Self::ReportNode),
            0x03 => Some(Self::NodeListResponse),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::GetNodeList => 0x01,
            Self::ReportNode => 0x02,
            Self::NodeListResponse => 0x03,
        }
    }
}

impl BootstrapRequest {
    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.sender_name.as_bytes();
        let mut buf = Vec::with_capacity(1 + 32 + 1 + name_bytes.len() + 8);
        buf.push(self.request_type.to_u8());
        buf.extend_from_slice(self.sender_id.as_bytes());
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    /// 从字节反序列化
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 32 + 1 + 8 {
            return None;
        }

        let request_type = BootstrapRequestType::from_u8(data[0])?;
        let mut id_bytes = [0u8; 32];
        id_bytes.copy_from_slice(&data[1..33]);
        let sender_id = NodeID::from_bytes(&id_bytes);
        let name_len = data[33] as usize;

        if data.len() < 34 + name_len + 8 {
            return None;
        }

        let sender_name =
            String::from_utf8(data[34..34 + name_len].to_vec()).ok()?;
        let timestamp =
            u64::from_be_bytes(data[34 + name_len..42 + name_len].try_into().ok()?);

        Some(Self {
            request_type,
            sender_id,
            sender_name,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_node_new() {
        let node = BootstrapNode::new("example.com", 9876);
        assert_eq!(node.host, "example.com");
        assert_eq!(node.port, 9876);
        assert_eq!(node.priority, 0);
        assert_eq!(node.addr(), "example.com:9876");
    }

    #[test]
    fn test_bootstrap_node_with_priority() {
        let node = BootstrapNode::with_priority("example.com", 9876, 5);
        assert_eq!(node.priority, 5);
    }

    #[test]
    fn test_bootstrap_config_new() {
        let config = BootstrapConfig::new();
        assert!(config.nodes.is_empty());
        assert_eq!(config.node_count(), 0);
    }

    #[test]
    fn test_bootstrap_config_add_node() {
        let mut config = BootstrapConfig::new();
        config.add_node(BootstrapNode::new("node1.com", 9876));
        config.add_node(BootstrapNode::with_priority("node2.com", 9876, 1));

        assert_eq!(config.node_count(), 2);
        // 应该按优先级排序（数值小的优先）
        assert_eq!(config.nodes[0].host, "node1.com");
        assert_eq!(config.nodes[1].host, "node2.com");
    }

    #[test]
    fn test_bootstrap_config_from_json() {
        let json = r#"
        {
            "bootstrap": {
                "nodes": [
                    {"host": "node1.com", "port": 9876},
                    {"host": "node2.com", "port": 9877, "priority": 1}
                ]
            }
        }
        "#;

        let config = BootstrapConfig::from_json(json).unwrap();
        assert_eq!(config.node_count(), 2);
        // 按优先级排序（数值小的优先）
        assert_eq!(config.nodes[0].host, "node1.com");
        assert_eq!(config.nodes[1].host, "node2.com");
    }

    #[test]
    fn test_bootstrap_config_from_json_invalid() {
        let json = "invalid json";
        let result = BootstrapConfig::from_json(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_bootstrap_config_from_yaml_simple() {
        let yaml = r#"
        bootstrap:
          nodes:
            - host: "node1.com"
              port: 9876
            - host: "node2.com"
              port: 9877
        "#;

        let config = BootstrapConfig::from_yaml_simple(yaml).unwrap();
        assert_eq!(config.node_count(), 2);
        assert_eq!(config.nodes[0].host, "node1.com");
        assert_eq!(config.nodes[1].host, "node2.com");
    }

    #[test]
    fn test_bootstrap_manager_new() {
        let (local_id, _) = NodeID::generate();
        let config = BootstrapConfig::new();
        let manager = BootstrapManager::new(local_id, "TestNode", config);

        assert_eq!(*manager.local_id(), local_id);
        assert_eq!(manager.local_name(), "TestNode");
        assert!(!manager.is_bootstrapped());
    }

    #[test]
    fn test_bootstrap_manager_add_known_node() {
        let (local_id, _) = NodeID::generate();
        let (node_id, _) = NodeID::generate();
        let config = BootstrapConfig::new();
        let manager = BootstrapManager::new(local_id, "TestNode", config);

        let node = KnownNode {
            id: node_id,
            name: "RemoteNode".to_string(),
            addr: "192.168.1.1:9876".to_string(),
            discovered_at: Instant::now(),
            source: "bootstrap".to_string(),
        };

        manager.add_known_node(node.clone());
        assert_eq!(manager.known_node_count(), 1);

        let retrieved = manager.get_known_node(&node_id).unwrap();
        assert_eq!(retrieved.name, "RemoteNode");
    }

    #[test]
    fn test_bootstrap_manager_remove_known_node() {
        let (local_id, _) = NodeID::generate();
        let (node_id, _) = NodeID::generate();
        let config = BootstrapConfig::new();
        let manager = BootstrapManager::new(local_id, "TestNode", config);

        let node = KnownNode {
            id: node_id,
            name: "RemoteNode".to_string(),
            addr: "192.168.1.1:9876".to_string(),
            discovered_at: Instant::now(),
            source: "bootstrap".to_string(),
        };

        manager.add_known_node(node);
        assert_eq!(manager.known_node_count(), 1);

        manager.remove_known_node(&node_id);
        assert_eq!(manager.known_node_count(), 0);
    }

    #[test]
    fn test_bootstrap_manager_empty_config() {
        let (local_id, _) = NodeID::generate();
        let config = BootstrapConfig::new();
        let manager = BootstrapManager::new(local_id, "TestNode", config);

        let result = manager.bootstrap();
        assert!(result.is_err());
    }

    #[test]
    fn test_bootstrap_request_type_conversion() {
        assert_eq!(
            BootstrapRequestType::from_u8(0x01),
            Some(BootstrapRequestType::GetNodeList)
        );
        assert_eq!(
            BootstrapRequestType::from_u8(0x02),
            Some(BootstrapRequestType::ReportNode)
        );
        assert_eq!(
            BootstrapRequestType::from_u8(0x03),
            Some(BootstrapRequestType::NodeListResponse)
        );
        assert_eq!(BootstrapRequestType::from_u8(0xFF), None);

        assert_eq!(BootstrapRequestType::GetNodeList.to_u8(), 0x01);
        assert_eq!(BootstrapRequestType::ReportNode.to_u8(), 0x02);
        assert_eq!(BootstrapRequestType::NodeListResponse.to_u8(), 0x03);
    }

    #[test]
    fn test_bootstrap_request_roundtrip() {
        let (sender_id, _) = NodeID::generate();
        let request = BootstrapRequest {
            request_type: BootstrapRequestType::GetNodeList,
            sender_id,
            sender_name: "TestNode".to_string(),
            timestamp: 1234567890,
        };

        let bytes = request.to_bytes();
        let recovered = BootstrapRequest::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.request_type, BootstrapRequestType::GetNodeList);
        assert_eq!(recovered.sender_id, sender_id);
        assert_eq!(recovered.sender_name, "TestNode");
        assert_eq!(recovered.timestamp, 1234567890);
    }

    #[test]
    fn test_bootstrap_request_too_short() {
        let result = BootstrapRequest::from_bytes(&[0u8; 40]);
        assert!(result.is_none());
    }

    #[test]
    fn test_bootstrap_error_display() {
        let err = BootstrapError::ConfigError("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = BootstrapError::ConnectionFailed("connect".to_string());
        assert!(format!("{}", err).contains("connect"));

        let err = BootstrapError::HandshakeFailed("handshake".to_string());
        assert!(format!("{}", err).contains("handshake"));

        let err = BootstrapError::Timeout;
        assert!(format!("{}", err).contains("timeout"));

        let err = BootstrapError::AllNodesUnreachable;
        assert!(format!("{}", err).contains("unreachable"));
    }
}
