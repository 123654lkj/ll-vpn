//! P0-4: 集成测试
//!
//! 测试地址解析 + LAN 路由的完整流程，
//! 验证 `ll ping`, `ll cmd`, `ll file` 功能的路由层支持。

use ll_vpn::address::{resolve_address, AddressResolver, MemAddressResolver};
use ll_vpn::lan_router::{LanRouter, UdpMessageType};
use ll_vpn::router::{ConnectionType, NodeStatus, Router, RouterError, RouterStatus};
use ll_vpn::vpn::identity::NodeID;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// ===================== 地址解析集成测试 =====================

#[test]
fn test_full_address_pipeline_simple() {
    let resolver = MemAddressResolver::new();
    let id = NodeID::from_bytes(&[0xAB; 32]);
    resolver.add_static_mapping("Pikachu", id);

    // 完整流程：解析地址字符串 -> 获取节点 ID
    let (parsed, resolved_id) = resolve_address(&resolver, "node:Pikachu").unwrap();
    assert_eq!(parsed.name, "Pikachu");
    assert_eq!(parsed.port, None);
    assert_eq!(resolved_id, id);
}

#[test]
fn test_full_address_pipeline_with_port() {
    let resolver = MemAddressResolver::new();
    let id = NodeID::from_bytes(&[0xCD; 32]);
    resolver.add_static_mapping("Charizard", id);

    let (parsed, resolved_id) = resolve_address(&resolver, "node:Charizard:8080").unwrap();
    assert_eq!(parsed.name, "Charizard");
    assert_eq!(parsed.port, Some(8080));
    assert_eq!(resolved_id, id);
}

#[test]
fn test_multiple_node_resolution() {
    let resolver = MemAddressResolver::new();

    let pikachu_id = NodeID::from_bytes(&[1; 32]);
    let charizard_id = NodeID::from_bytes(&[2; 32]);
    let mewtwo_id = NodeID::from_bytes(&[3; 32]);

    resolver.add_static_mapping("Pikachu", pikachu_id);
    resolver.add_static_mapping("Charizard", charizard_id);
    resolver.add_static_mapping("Mewtwo", mewtwo_id);

    // 解析所有节点
    let (_, id1) = resolve_address(&resolver, "node:Pikachu").unwrap();
    let (_, id2) = resolve_address(&resolver, "node:Charizard").unwrap();
    let (_, id3) = resolve_address(&resolver, "node:Mewtwo").unwrap();

    assert_eq!(id1, pikachu_id);
    assert_eq!(id2, charizard_id);
    assert_eq!(id3, mewtwo_id);
}

#[test]
fn test_address_resolution_with_cache() {
    let resolver = MemAddressResolver::new();
    let id = NodeID::from_bytes(&[0xEF; 32]);

    // 先缓存
    resolver.cache("Eevee", id, Duration::from_secs(300));

    // 解析应该从缓存命中
    let (_, resolved) = resolve_address(&resolver, "node:Eevee").unwrap();
    assert_eq!(resolved, id);

    // 未注册的节点应该失败
    assert!(resolve_address(&resolver, "node:Unknown").is_err());
}

#[test]
fn test_address_resolution_error_messages() {
    let resolver = MemAddressResolver::new();

    // 无效格式
    let err = resolve_address(&resolver, "192.168.1.1").unwrap_err();
    assert!(format!("{}", err).contains("invalid address format"));

    // 未知节点
    let err = resolve_address(&resolver, "node:NonExistent").unwrap_err();
    assert!(format!("{}", err).contains("unknown node"));
}

#[test]
fn test_cache_invalidation() {
    let resolver = MemAddressResolver::with_ttl(Duration::from_millis(50));
    let id = NodeID::from_bytes(&[0x11; 32]);

    resolver.cache("Pikachu", id, Duration::from_millis(50));

    // 立即应该可以查到
    assert!(resolver.get_cached("Pikachu").is_some());

    // 等待过期
    thread::sleep(Duration::from_millis(100));
    assert!(resolver.get_cached("Pikachu").is_none());

    // 缓存过期后，静态映射仍然有效
    resolver.add_static_mapping("Pikachu", id);
    let resolved = resolver.resolve("Pikachu").unwrap();
    assert_eq!(resolved, id);
}

// ===================== LAN 路由器集成测试 =====================

#[test]
fn test_lan_router_lifecycle() {
    let id = NodeID::from_bytes(&[0x22; 32]);
    let router = LanRouter::with_port("TestNode", id, 19900);

    // 启动
    let result = router.start();
    assert!(result.is_ok());

    // 检查状态
    let status = router.status();
    assert_eq!(status.node_status, NodeStatus::Online);
    assert_eq!(status.connection_type, ConnectionType::Lan);

    // 停止
    router.stop();
    thread::sleep(Duration::from_millis(100));

    let status = router.status();
    assert_eq!(status.node_status, NodeStatus::Offline);
}

#[test]
fn test_lan_router_discovery() {
    let id1 = NodeID::from_bytes(&[0x31; 32]);
    let id2 = NodeID::from_bytes(&[0x32; 32]);

    // 两个路由器使用不同端口
    let router_a = LanRouter::with_port("NodeA", id1, 19910);
    let router_b = LanRouter::with_port("NodeB", id2, 19911);

    router_a.start().unwrap();
    router_b.start().unwrap();

    // 两个路由器应该都在线
    assert_eq!(router_a.status().node_status, NodeStatus::Online);
    assert_eq!(router_b.status().node_status, NodeStatus::Online);

    router_a.stop();
    router_b.stop();
    thread::sleep(Duration::from_millis(200));
}

#[test]
fn test_lan_router_send_invalid_address() {
    let id = NodeID::from_bytes(&[0x42; 32]);
    let router = LanRouter::with_port("TestNode", id, 19920);
    router.start().unwrap();

    // 发送到无效地址
    let result = router.send("invalid-address", b"test");
    assert!(result.is_err());
    match result {
        Err(RouterError::InvalidData(msg)) => {
            assert!(msg.contains("invalid address format"));
        }
        _ => panic!("expected InvalidData error"),
    }

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_lan_router_send_unknown_node() {
    let id = NodeID::from_bytes(&[0x43; 32]);
    let router = LanRouter::with_port("TestNode", id, 19930);
    router.start().unwrap();

    // 发送到不存在的节点
    let result = router.send("node:Ghost", b"test data");
    assert!(result.is_err());
    match result {
        Err(RouterError::Unreachable(msg)) => {
            assert!(msg.contains("not found"));
        }
        _ => panic!("expected Unreachable error"),
    }

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_lan_router_resolved_node_send() {
    let id = NodeID::from_bytes(&[0x44; 32]);
    let resolver = MemAddressResolver::new();
    resolver.add_static_mapping("TestPeer", NodeID::from_bytes(&[0x45; 32]));

    let router = LanRouter::with_port("TestNode", id, 19940);
    router.start().unwrap();

    // 即使节点存在于解析器中，LAN 中没有该节点的 UDP 地址也会失败
    let result = router.send("node:TestPeer", b"hello");
    assert!(result.is_err());

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

// ===================== 端到端集成测试 =====================

#[test]
fn test_end_to_end_address_to_send() {
    // 模拟完整流程：解析地址 -> 查找节点 -> 尝试发送
    let resolver = MemAddressResolver::new();
    let local_id = NodeID::from_bytes(&[0x50; 32]);
    let peer_id = NodeID::from_bytes(&[0x51; 32]);

    resolver.add_static_mapping("Pikachu", local_id);
    resolver.add_static_mapping("Charizard", peer_id);

    // 解析目标地址
    let (parsed, target_id) = resolve_address(&resolver, "node:Charizard").unwrap();
    assert_eq!(parsed.name, "Charizard");
    assert_eq!(target_id, peer_id);

    // 创建路由器并尝试发送（会在发现阶段失败，因为不在同一 LAN）
    let router = LanRouter::with_port("Pikachu", local_id, 19950);
    router.start().unwrap();

    let result = router.send("node:Charizard", b"ping");
    // 预期失败（不在 LAN 中）
    assert!(result.is_err());

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_router_trait_compliance() {
    let id = NodeID::from_bytes(&[0x60; 32]);
    let router = LanRouter::with_port("TraitTest", id, 19960);

    // 验证 Router trait 方法
    let name: &str = Router::name(&router);
    assert_eq!(name, "TraitTest");

    let status: RouterStatus = Router::status(&router);
    assert_eq!(status.connection_type, ConnectionType::Lan);
    assert_eq!(status.known_nodes, 0);
    assert_eq!(status.active_routes, 0);
}

#[test]
fn test_concurrent_access() {
    let id = NodeID::from_bytes(&[0x70; 32]);
    let router = Arc::new(LanRouter::with_port("Concurrent", id, 19970));
    router.start().unwrap();

    let mut handles = vec![];

    // 并发读取状态
    for _ in 0..5 {
        let r = router.clone();
        handles.push(thread::spawn(move || {
            let status = r.status();
            assert_eq!(status.connection_type, ConnectionType::Lan);
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    router.stop();
    thread::sleep(Duration::from_millis(200));
}

// ===================== 协议兼容性测试 =====================

#[test]
fn test_udp_message_type_display() {
    // 验证消息类型可以正常使用
    assert_eq!(UdpMessageType::Discover.to_u8(), 0x01);
    assert_eq!(UdpMessageType::DiscoverReply.to_u8(), 0x02);
    assert_eq!(UdpMessageType::Data.to_u8(), 0x03);
    assert_eq!(UdpMessageType::Heartbeat.to_u8(), 0x04);

    assert!(UdpMessageType::from_u8(0x01).is_some());
    assert!(UdpMessageType::from_u8(0xFF).is_none());
}

#[test]
fn test_node_name_unicode() {
    let resolver = MemAddressResolver::new();
    let id = NodeID::from_bytes(&[0x90; 32]);

    // 测试 unicode 名字（如宝可梦中文名）
    resolver.add_static_mapping("皮卡丘", id);
    let resolved = resolver.resolve("皮卡丘").unwrap();
    assert_eq!(resolved, id);

    // 解析 unicode 名字地址
    let (parsed, _) = resolve_address(&resolver, "node:皮卡丘").unwrap();
    assert_eq!(parsed.name, "皮卡丘");
}

#[test]
fn test_empty_data_transmission() {
    let id = NodeID::from_bytes(&[0xA0; 32]);
    let router = LanRouter::with_port("EmptyTest", id, 19980);
    router.start().unwrap();

    // 发送空数据应该可以构建消息（虽然目标不存在会失败）
    let result = router.send("node:NonExistent", b"");
    assert!(result.is_err()); // 目标不存在

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_multiple_resolvers_independence() {
    let resolver1 = MemAddressResolver::new();
    let resolver2 = MemAddressResolver::new();

    let id1 = NodeID::from_bytes(&[0xB1; 32]);
    let id2 = NodeID::from_bytes(&[0xB2; 32]);

    resolver1.add_static_mapping("Pikachu", id1);
    resolver2.add_static_mapping("Pikachu", id2); // 同名不同 ID

    let r1 = resolver1.resolve("Pikachu").unwrap();
    let r2 = resolver2.resolve("Pikachu").unwrap();

    assert_eq!(r1, id1);
    assert_eq!(r2, id2);
    assert_ne!(r1, r2);
}

#[test]
fn test_full_pipeline_address_resolve_and_router_send() {
    // 模拟 ll cmd node:Pikachu "uptime" 的完整路由流程
    let resolver = MemAddressResolver::new();
    let local_id = NodeID::from_bytes(&[0xC0; 32]);
    let peer_id = NodeID::from_bytes(&[0xC1; 32]);

    resolver.add_static_mapping("Pikachu", local_id);
    resolver.add_static_mapping("Charizard", peer_id);

    let router = LanRouter::with_port("Pikachu", local_id, 19990);
    router.start().unwrap();

    // Step 1: 解析地址
    let addr = "node:Charizard";
    let (parsed, target_id) = resolve_address(&resolver, addr).unwrap();
    assert_eq!(parsed.name, "Charizard");
    assert_eq!(target_id, peer_id);

    // Step 2: 通过路由发送（预期失败，因为 Charizard 不在同一 LAN）
    let cmd_data = b"uptime";
    let result = router.send(addr, cmd_data);
    assert!(result.is_err()); // 不在 LAN 中

    // Step 3: 验证路由器状态
    let status = router.status();
    assert_eq!(status.connection_type, ConnectionType::Lan);
    assert_eq!(status.known_nodes, 0);

    router.stop();
    thread::sleep(Duration::from_millis(100));
}

#[test]
fn test_lan_router_debug_format() {
    let id = NodeID::from_bytes(&[0xD0; 32]);
    let router = LanRouter::with_port("DebugTest", id, 19991);
    let debug_str = format!("{:?}", router);
    assert!(debug_str.contains("DebugTest"));
    assert!(debug_str.contains("19991"));
}
