//! P0-1: 路由接口定义
//!
//! 定义 Router trait 和路由表结构，
//! 为后续 LAN/VPN 路由器实现提供统一接口。

use crate::vpn::identity::NodeID;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// 路由错误类型
#[derive(Debug, Clone)]
pub enum RouterError {
    /// 目标节点不可达
    Unreachable(String),
    /// 连接超时
    Timeout,
    /// 路由表中无可用路由
    NoRoute(NodeID),
    /// 发送失败
    SendFailed(String),
    /// 节点离线
    NodeOffline(NodeID),
    /// 无效数据
    InvalidData(String),
}

impl fmt::Display for RouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouterError::Unreachable(target) => write!(f, "target unreachable: {}", target),
            RouterError::Timeout => write!(f, "connection timeout"),
            RouterError::NoRoute(id) => write!(f, "no route to node: {}", id),
            RouterError::SendFailed(msg) => write!(f, "send failed: {}", msg),
            RouterError::NodeOffline(id) => write!(f, "node offline: {}", id),
            RouterError::InvalidData(msg) => write!(f, "invalid data: {}", msg),
        }
    }
}

impl std::error::Error for RouterError {}

/// 连接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionType {
    /// 局域网直连
    Lan,
    /// VPN 网络
    Vpn,
    /// 中继转发
    Relay,
    /// 未知
    Unknown,
}

impl fmt::Display for ConnectionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionType::Lan => write!(f, "LAN"),
            ConnectionType::Vpn => write!(f, "VPN"),
            ConnectionType::Relay => write!(f, "Relay"),
            ConnectionType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// 节点状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeStatus {
    /// 在线
    Online,
    /// 离线
    Offline,
    /// 连接中
    Connecting,
    /// 错误状态
    Error,
}

impl fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "online"),
            NodeStatus::Offline => write!(f, "offline"),
            NodeStatus::Connecting => write!(f, "connecting"),
            NodeStatus::Error => write!(f, "error"),
        }
    }
}

/// 路由器状态信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterStatus {
    /// 节点状态
    pub node_status: NodeStatus,
    /// 连接类型
    pub connection_type: ConnectionType,
    /// 已知节点数量
    pub known_nodes: usize,
    /// 活跃路由数量
    pub active_routes: usize,
    /// 最后更新时间（Unix 时间戳）
    pub last_update: u64,
}

/// 路由表条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// 目标节点
    pub target: NodeID,
    /// 下一跳节点
    pub next_hop: NodeID,
    /// 连接类型
    pub connection_type: ConnectionType,
    /// 路由度量（越小越好）
    pub metric: u32,
    /// 最后活跃时间
    pub last_active: u64,
}

/// 路由表：目标节点 → 路由器映射
#[derive(Debug, Clone, Default)]
pub struct RouteTable {
    /// 路由条目：目标 NodeID → RouteEntry
    routes: HashMap<NodeID, RouteEntry>,
}

impl RouteTable {
    /// 创建空路由表
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// 添加或更新路由
    pub fn upsert(&mut self, entry: RouteEntry) {
        self.routes.insert(entry.target, entry);
    }

    /// 移除路由
    pub fn remove(&mut self, target: &NodeID) -> Option<RouteEntry> {
        self.routes.remove(target)
    }

    /// 查找目标路由
    pub fn lookup(&self, target: &NodeID) -> Option<&RouteEntry> {
        self.routes.get(target)
    }

    /// 获取所有路由
    pub fn entries(&self) -> Vec<&RouteEntry> {
        self.routes.values().collect()
    }

    /// 获取路由数量
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// 路由表是否为空
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// 清空路由表
    pub fn clear(&mut self) {
        self.routes.clear();
    }

    /// 获取最佳路由（metric 最小）
    pub fn best_route(&self, target: &NodeID) -> Option<&RouteEntry> {
        self.routes
            .values()
            .filter(|e| &e.target == target)
            .min_by_key(|e| e.metric)
    }
}

/// 路由器 trait：定义统一的路由接口
///
/// 实现此 trait 可以创建不同类型的路由器（LAN、VPN 等）。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::router::{Router, RouterStatus, RouterError, ConnectionType, NodeStatus};
///
/// struct MyRouter;
///
/// impl Router for MyRouter {
///     fn send(&self, _target: &str, _data: &[u8]) -> Result<(), RouterError> {
///         Ok(())
///     }
///
///     fn status(&self) -> RouterStatus {
///         RouterStatus {
///             node_status: NodeStatus::Online,
///             connection_type: ConnectionType::Lan,
///             known_nodes: 0,
///             active_routes: 0,
///             last_update: 0,
///         }
///     }
///
///     fn name(&self) -> &str {
///         "MyRouter"
///     }
/// }
/// ```
pub trait Router {
    /// 发送数据到目标节点
    ///
    /// # 参数
    /// - `target`: 目标节点地址（如 "node:Pikachu"）
    /// - `data`: 要发送的数据
    ///
    /// # 返回
    /// - `Ok(())`: 发送成功
    /// - `Err(RouterError)`: 发送失败
    fn send(&self, target: &str, data: &[u8]) -> Result<(), RouterError>;

    /// 获取路由器状态
    fn status(&self) -> RouterStatus;

    /// 获取路由器名称
    fn name(&self) -> &str;
}

/// 路由管理器：管理多个路由器和路由表
pub struct RouterManager {
    /// 路由表
    route_table: RouteTable,
    /// 路由器名称
    name: String,
}

impl RouterManager {
    /// 创建新的路由管理器
    pub fn new(name: &str) -> Self {
        Self {
            route_table: RouteTable::new(),
            name: name.to_string(),
        }
    }

    /// 获取路由表引用
    pub fn route_table(&self) -> &RouteTable {
        &self.route_table
    }

    /// 获取路由表可变引用
    pub fn route_table_mut(&mut self) -> &mut RouteTable {
        &mut self.route_table
    }

    /// 添加路由
    pub fn add_route(&mut self, entry: RouteEntry) {
        self.route_table.upsert(entry);
    }

    /// 移除路由
    pub fn remove_route(&mut self, target: &NodeID) -> Option<RouteEntry> {
        self.route_table.remove(target)
    }

    /// 查找路由
    pub fn find_route(&self, target: &NodeID) -> Option<&RouteEntry> {
        self.route_table.lookup(target)
    }

    /// 获取管理器名称
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn::identity::NodeID;

    /// 测试用的 Mock 路由器
    struct MockRouter {
        name: String,
        should_fail: bool,
    }

    impl MockRouter {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_fail: false,
            }
        }

        fn with_failure(name: &str) -> Self {
            Self {
                name: name.to_string(),
                should_fail: true,
            }
        }
    }

    impl Router for MockRouter {
        fn send(&self, _target: &str, _data: &[u8]) -> Result<(), RouterError> {
            if self.should_fail {
                Err(RouterError::SendFailed("mock failure".to_string()))
            } else {
                Ok(())
            }
        }

        fn status(&self) -> RouterStatus {
            RouterStatus {
                node_status: NodeStatus::Online,
                connection_type: ConnectionType::Lan,
                known_nodes: 1,
                active_routes: 0,
                last_update: 0,
            }
        }

        fn name(&self) -> &str {
            &self.name
        }
    }

    #[test]
    fn test_mock_router_send_success() {
        let router = MockRouter::new("test");
        let result = router.send("node:Pikachu", b"hello");
        assert!(result.is_ok());
    }

    #[test]
    fn test_mock_router_send_failure() {
        let router = MockRouter::with_failure("test");
        let result = router.send("node:Pikachu", b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_route_table_upsert_and_lookup() {
        let mut table = RouteTable::new();
        let target = NodeID::from_bytes(&[1u8; 32]);
        let next_hop = NodeID::from_bytes(&[2u8; 32]);

        let entry = RouteEntry {
            target,
            next_hop,
            connection_type: ConnectionType::Lan,
            metric: 10,
            last_active: 0,
        };

        table.upsert(entry);
        assert_eq!(table.len(), 1);

        let found = table.lookup(&target);
        assert!(found.is_some());
        assert_eq!(found.unwrap().metric, 10);
    }

    #[test]
    fn test_route_table_remove() {
        let mut table = RouteTable::new();
        let target = NodeID::from_bytes(&[1u8; 32]);

        let entry = RouteEntry {
            target,
            next_hop: NodeID::from_bytes(&[2u8; 32]),
            connection_type: ConnectionType::Vpn,
            metric: 5,
            last_active: 0,
        };

        table.upsert(entry);
        assert_eq!(table.len(), 1);

        let removed = table.remove(&target);
        assert!(removed.is_some());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_route_table_best_route() {
        let mut table = RouteTable::new();
        let target = NodeID::from_bytes(&[1u8; 32]);

        // 添加两条路由，metric 不同
        table.upsert(RouteEntry {
            target,
            next_hop: NodeID::from_bytes(&[2u8; 32]),
            connection_type: ConnectionType::Lan,
            metric: 20,
            last_active: 0,
        });
        table.upsert(RouteEntry {
            target,
            next_hop: NodeID::from_bytes(&[3u8; 32]),
            connection_type: ConnectionType::Vpn,
            metric: 5,
            last_active: 0,
        });

        let best = table.best_route(&target);
        assert!(best.is_some());
        assert_eq!(best.unwrap().metric, 5);
    }

    #[test]
    fn test_route_table_is_empty() {
        let table = RouteTable::new();
        assert!(table.is_empty());

        let mut table = RouteTable::new();
        let target = NodeID::from_bytes(&[1u8; 32]);
        table.upsert(RouteEntry {
            target,
            next_hop: NodeID::from_bytes(&[2u8; 32]),
            connection_type: ConnectionType::Lan,
            metric: 1,
            last_active: 0,
        });
        assert!(!table.is_empty());
    }

    #[test]
    fn test_route_table_clear() {
        let mut table = RouteTable::new();
        for i in 0..10 {
            let target = NodeID::from_bytes(&[i; 32]);
            table.upsert(RouteEntry {
                target,
                next_hop: NodeID::from_bytes(&[i + 1; 32]),
                connection_type: ConnectionType::Lan,
                metric: i as u32,
                last_active: 0,
            });
        }
        assert_eq!(table.len(), 10);

        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn test_router_manager() {
        let mut manager = RouterManager::new("TestManager");
        assert_eq!(manager.name(), "TestManager");

        let target = NodeID::from_bytes(&[1u8; 32]);
        let entry = RouteEntry {
            target,
            next_hop: NodeID::from_bytes(&[2u8; 32]),
            connection_type: ConnectionType::Vpn,
            metric: 15,
            last_active: 0,
        };

        manager.add_route(entry);
        assert_eq!(manager.route_table().len(), 1);

        let found = manager.find_route(&target);
        assert!(found.is_some());

        manager.remove_route(&target);
        assert!(manager.route_table().is_empty());
    }

    #[test]
    fn test_router_status_display() {
        let status = RouterStatus {
            node_status: NodeStatus::Online,
            connection_type: ConnectionType::Lan,
            known_nodes: 5,
            active_routes: 3,
            last_update: 1234567890,
        };

        assert_eq!(format!("{}", status.connection_type), "LAN");
        assert_eq!(format!("{}", status.node_status), "online");
    }

    #[test]
    fn test_router_error_display() {
        let err = RouterError::Unreachable("node:Pikachu".to_string());
        assert!(format!("{}", err).contains("unreachable"));

        let err = RouterError::NoRoute(NodeID::from_bytes(&[1u8; 32]));
        assert!(format!("{}", err).contains("no route"));
    }
}
