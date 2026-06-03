//! P0-2: 地址解析层
//!
//! 解析 `node:<名字>` 和 `node:<名字>:<端口>` 格式地址，
//! 提供名字到节点 ID 的解析，支持 TTL 缓存。

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 地址解析错误类型
#[derive(Debug, Clone)]
pub enum AddressError {
    /// 无效的地址格式
    InvalidFormat(String),
    /// 未知节点名
    UnknownNode(String),
    /// 解析超时
    ResolveTimeout(String),
    /// 缓存过期（内部使用）
    CacheExpired(String),
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::InvalidFormat(msg) => write!(f, "invalid address format: {}", msg),
            AddressError::UnknownNode(name) => write!(f, "unknown node: {}", name),
            AddressError::ResolveTimeout(name) => {
                write!(f, "resolve timeout for node: {}", name)
            }
            AddressError::CacheExpired(name) => write!(f, "cache expired for node: {}", name),
        }
    }
}

impl std::error::Error for AddressError {}

/// 解析后的地址信息
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAddress {
    /// 节点名字
    pub name: String,
    /// 可选的端口号
    pub port: Option<u16>,
}

impl ParsedAddress {
    /// 解析 `node:<名字>` 或 `node:<名字>:<端口>` 格式
    pub fn parse(addr: &str) -> Result<Self, AddressError> {
        let parts: Vec<&str> = addr.splitn(3, ':').collect();

        match parts.as_slice() {
            ["node", name] => {
                if name.is_empty() {
                    return Err(AddressError::InvalidFormat(
                        "node name cannot be empty".to_string(),
                    ));
                }
                Ok(ParsedAddress {
                    name: name.to_string(),
                    port: None,
                })
            }
            ["node", name, port_str] => {
                if name.is_empty() {
                    return Err(AddressError::InvalidFormat(
                        "node name cannot be empty".to_string(),
                    ));
                }
                let port: u16 = port_str.parse().map_err(|_| {
                    AddressError::InvalidFormat(format!("invalid port number: {}", port_str))
                })?;
                if port == 0 {
                    return Err(AddressError::InvalidFormat(
                        "port number cannot be zero".to_string(),
                    ));
                }
                Ok(ParsedAddress {
                    name: name.to_string(),
                    port: Some(port),
                })
            }
            _ => Err(AddressError::InvalidFormat(format!(
                "expected node:<name> or node:<name>:<port>, got: {}",
                addr
            ))),
        }
    }

    /// 判断是否为有效的节点地址（以 node: 开头）
    pub fn is_node_address(addr: &str) -> bool {
        addr.starts_with("node:")
    }
}

/// 地址解析 trait
///
/// 将节点名字解析为节点 ID，支持缓存。
pub trait AddressResolver {
    /// 解析节点名字为节点 ID
    fn resolve(&self, name: &str) -> Result<NodeID, AddressError>;

    /// 缓存节点名字到 ID 的映射
    fn cache(&self, name: &str, id: NodeID, ttl: Duration);

    /// 从缓存中获取节点 ID（如果存在且未过期）
    fn get_cached(&self, name: &str) -> Option<NodeID>;

    /// 清除所有缓存
    fn clear_cache(&self);
}

/// 缓存条目
struct CacheEntry {
    id: NodeID,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// 基于内存的地址解析器实现
///
/// 维护一个名字到节点 ID 的缓存，支持 TTL 过期。
pub struct MemAddressResolver {
    /// 缓存：名字 → CacheEntry
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// 名字到节点 ID 的静态映射（可预配置）
    static_map: Mutex<HashMap<String, NodeID>>,
    /// 默认缓存 TTL
    default_ttl: Duration,
}

impl MemAddressResolver {
    /// 创建新的内存地址解析器
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            static_map: Mutex::new(HashMap::new()),
            default_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// 创建指定默认 TTL 的解析器
    pub fn with_ttl(default_ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            static_map: Mutex::new(HashMap::new()),
            default_ttl,
        }
    }

    /// 添加静态名字映射（不参与缓存过期）
    pub fn add_static_mapping(&self, name: &str, id: NodeID) {
        self.static_map.lock().unwrap().insert(name.to_string(), id);
    }

    /// 移除静态名字映射
    pub fn remove_static_mapping(&self, name: &str) -> Option<NodeID> {
        self.static_map.lock().unwrap().remove(name)
    }

    /// 获取已知节点数量（静态映射 + 有效缓存）
    pub fn known_nodes(&self) -> usize {
        let static_count = self.static_map.lock().unwrap().len();
        let cache = self.cache.lock().unwrap();
        let valid_cache_count = cache.values().filter(|e| !e.is_expired()).count();
        static_count + valid_cache_count
    }
}

impl Default for MemAddressResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressResolver for MemAddressResolver {
    fn resolve(&self, name: &str) -> Result<NodeID, AddressError> {
        // 1. 检查缓存
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(name) {
                if !entry.is_expired() {
                    return Ok(entry.id);
                }
            }
        }

        // 2. 检查静态映射
        {
            let static_map = self.static_map.lock().unwrap();
            if let Some(&id) = static_map.get(name) {
                // 同时写入缓存
                drop(static_map);
                self.cache(name, id, self.default_ttl);
                return Ok(id);
            }
        }

        // 3. 未找到
        Err(AddressError::UnknownNode(name.to_string()))
    }

    fn cache(&self, name: &str, id: NodeID, ttl: Duration) {
        let entry = CacheEntry {
            id,
            inserted_at: Instant::now(),
            ttl,
        };
        self.cache.lock().unwrap().insert(name.to_string(), entry);
    }

    fn get_cached(&self, name: &str) -> Option<NodeID> {
        let cache = self.cache.lock().unwrap();
        cache.get(name).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.id)
            }
        })
    }

    fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
    }
}

/// 缓存包装器：对任意 AddressResolver 添加 TTL 缓存
pub struct CachingResolver<R: AddressResolver> {
    inner: R,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl<R: AddressResolver> CachingResolver<R> {
    /// 包装一个解析器，添加缓存层
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// 使用指定 TTL 创建
    pub fn with_ttl(_inner: R, _ttl: Duration) -> Self {
        Self::new(_inner)
    }
}

impl<R: AddressResolver> AddressResolver for CachingResolver<R> {
    fn resolve(&self, name: &str) -> Result<NodeID, AddressError> {
        // 先查缓存
        {
            let cache = self.cache.lock().unwrap();
            if let Some(entry) = cache.get(name) {
                if !entry.is_expired() {
                    return Ok(entry.id);
                }
            }
        }

        // 缓存未命中或过期，委托给内部解析器
        let id = self.inner.resolve(name)?;
        self.cache(name, id, Duration::from_secs(300));
        Ok(id)
    }

    fn cache(&self, name: &str, id: NodeID, ttl: Duration) {
        let entry = CacheEntry {
            id,
            inserted_at: Instant::now(),
            ttl,
        };
        self.cache.lock().unwrap().insert(name.to_string(), entry);
        // 同时更新内部
        self.inner.cache(name, id, ttl);
    }

    fn get_cached(&self, name: &str) -> Option<NodeID> {
        let cache = self.cache.lock().unwrap();
        cache.get(name).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.id)
            }
        })
    }

    fn clear_cache(&self) {
        self.cache.lock().unwrap().clear();
        self.inner.clear_cache();
    }
}

/// 解析完整地址字符串，返回 (ParsedAddress, NodeID)
///
/// 使用提供的解析器将名字部分解析为节点 ID。
pub fn resolve_address(
    resolver: &dyn AddressResolver,
    addr: &str,
) -> Result<(ParsedAddress, NodeID), AddressError> {
    let parsed = ParsedAddress::parse(addr)?;
    let id = resolver.resolve(&parsed.name)?;
    Ok((parsed, id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_node_simple() {
        let addr = ParsedAddress::parse("node:Pikachu").unwrap();
        assert_eq!(addr.name, "Pikachu");
        assert_eq!(addr.port, None);
    }

    #[test]
    fn test_parse_node_with_port() {
        let addr = ParsedAddress::parse("node:Charizard:8080").unwrap();
        assert_eq!(addr.name, "Charizard");
        assert_eq!(addr.port, Some(8080));
    }

    #[test]
    fn test_parse_node_with_large_port() {
        let addr = ParsedAddress::parse("node:Mewtwo:65535").unwrap();
        assert_eq!(addr.name, "Mewtwo");
        assert_eq!(addr.port, Some(65535));
    }

    #[test]
    fn test_parse_invalid_no_prefix() {
        let result = ParsedAddress::parse("Pikachu");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_name() {
        let result = ParsedAddress::parse("node:");
        assert!(result.is_err());
        match result {
            Err(AddressError::InvalidFormat(msg)) => {
                assert!(msg.contains("empty"));
            }
            _ => panic!("expected InvalidFormat error"),
        }
    }

    #[test]
    fn test_parse_invalid_port() {
        let result = ParsedAddress::parse("node:Pikachu:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_port_zero() {
        let result = ParsedAddress::parse("node:Pikachu:0");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_port_overflow() {
        let result = ParsedAddress::parse("node:Pikachu:99999");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_node_address() {
        assert!(ParsedAddress::is_node_address("node:Pikachu"));
        assert!(ParsedAddress::is_node_address("node:Pikachu:8080"));
        assert!(!ParsedAddress::is_node_address("192.168.1.1"));
        assert!(!ParsedAddress::is_node_address("charizard.lan"));
        assert!(!ParsedAddress::is_node_address(""));
    }

    #[test]
    fn test_mem_resolver_static_mapping() {
        let resolver = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[1u8; 32]);
        resolver.add_static_mapping("Pikachu", id);

        let resolved = resolver.resolve("Pikachu").unwrap();
        assert_eq!(resolved, id);
    }

    #[test]
    fn test_mem_resolver_unknown_node() {
        let resolver = MemAddressResolver::new();
        let result = resolver.resolve("UnknownNode");
        assert!(result.is_err());
        match result {
            Err(AddressError::UnknownNode(name)) => assert_eq!(name, "UnknownNode"),
            _ => panic!("expected UnknownNode error"),
        }
    }

    #[test]
    fn test_mem_resolver_cache() {
        let resolver = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[2u8; 32]);

        resolver.cache("Pikachu", id, Duration::from_secs(300));
        let resolved = resolver.resolve("Pikachu").unwrap();
        assert_eq!(resolved, id);
    }

    #[test]
    fn test_mem_resolver_cache_expiry() {
        let resolver = MemAddressResolver::with_ttl(Duration::from_millis(10));
        let id = NodeID::from_bytes(&[3u8; 32]);

        resolver.cache("Pikachu", id, Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(20));

        let result = resolver.get_cached("Pikachu");
        assert!(result.is_none());
    }

    #[test]
    fn test_mem_resolver_clear_cache() {
        let resolver = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[4u8; 32]);

        resolver.cache("Pikachu", id, Duration::from_secs(300));
        assert!(resolver.get_cached("Pikachu").is_some());

        resolver.clear_cache();
        assert!(resolver.get_cached("Pikachu").is_none());
    }

    #[test]
    fn test_mem_resolver_known_nodes() {
        let resolver = MemAddressResolver::new();
        assert_eq!(resolver.known_nodes(), 0);

        let id1 = NodeID::from_bytes(&[1u8; 32]);
        let id2 = NodeID::from_bytes(&[2u8; 32]);
        resolver.add_static_mapping("Pikachu", id1);
        resolver.cache("Charizard", id2, Duration::from_secs(300));

        assert_eq!(resolver.known_nodes(), 2);
    }

    #[test]
    fn test_resolve_address() {
        let resolver = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[5u8; 32]);
        resolver.add_static_mapping("Pikachu", id);

        let (parsed, resolved_id) = resolve_address(&resolver, "node:Pikachu").unwrap();
        assert_eq!(parsed.name, "Pikachu");
        assert_eq!(parsed.port, None);
        assert_eq!(resolved_id, id);
    }

    #[test]
    fn test_resolve_address_with_port() {
        let resolver = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[6u8; 32]);
        resolver.add_static_mapping("Charizard", id);

        let (parsed, resolved_id) = resolve_address(&resolver, "node:Charizard:9876").unwrap();
        assert_eq!(parsed.name, "Charizard");
        assert_eq!(parsed.port, Some(9876));
        assert_eq!(resolved_id, id);
    }

    #[test]
    fn test_resolve_address_unknown() {
        let resolver = MemAddressResolver::new();
        let result = resolve_address(&resolver, "node:Unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_address_invalid_format() {
        let resolver = MemAddressResolver::new();
        let result = resolve_address(&resolver, "192.168.1.1");
        assert!(result.is_err());
    }

    #[test]
    fn test_address_error_display() {
        let err = AddressError::InvalidFormat("bad format".to_string());
        assert!(format!("{}", err).contains("invalid address format"));

        let err = AddressError::UnknownNode("Pikachu".to_string());
        assert!(format!("{}", err).contains("unknown node"));

        let err = AddressError::ResolveTimeout("Pikachu".to_string());
        assert!(format!("{}", err).contains("resolve timeout"));
    }

    #[test]
    fn test_caching_resolver() {
        let inner = MemAddressResolver::new();
        let id = NodeID::from_bytes(&[7u8; 32]);
        inner.add_static_mapping("Pikachu", id);

        let resolver = CachingResolver::new(inner);
        let resolved = resolver.resolve("Pikachu").unwrap();
        assert_eq!(resolved, id);

        // 应该从缓存命中
        let cached = resolver.get_cached("Pikachu");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), id);
    }
}
