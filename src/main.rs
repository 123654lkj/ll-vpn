//! P2-2: LL VPN CLI 入口
//!
//! 命令行接口，支持子命令：
//! - `ll cmd node:<name> <command>` — 远程执行命令
//! - `ll ping node:<name>` — 测试连通性
//! - `ll nodes` — 列出已知节点
//! - `ll status` — 显示本机信息

use ll_vpn::address::MemAddressResolver;
use ll_vpn::lan_router::LanRouter;
use ll_vpn::vpn::command;
use ll_vpn::vpn::identity::NodeID;
use ll_vpn::vpn::relay::RelayManager;
use ll_vpn::vpn::vpn_router::VpnRouter;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// 默认 LAN 端口
const LAN_PORT: u16 = 9876;
/// 默认 VPN 端口
const VPN_PORT: u16 = 9877;

/// 默认本地节点名称
const LOCAL_NODE_NAME: &str = "LocalNode";

/// 预配置的静态节点映射（用于演示和开发）
fn setup_static_nodes(resolver: &MemAddressResolver) {
    // 预配置一些示例节点
    let pikachu_id = NodeID::from_bytes(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
    ]);
    resolver.add_static_mapping("Pikachu", pikachu_id);

    let charizard_id = NodeID::from_bytes(&[
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F,
    ]);
    resolver.add_static_mapping("Charizard", charizard_id);
}

fn main() {
    // 环境变量覆盖端口
    let lan_port: u16 = std::env::var("LL_VPN_LAN_PORT").ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(LAN_PORT);
    let vpn_port: u16 = std::env::var("LL_VPN_PORT").ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(VPN_PORT);

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    // 初始化节点标识
    let (node_id, _signing_key) = NodeID::generate();

    // 初始化地址解析器
    let resolver = Arc::new(MemAddressResolver::new());
    setup_static_nodes(&resolver);

    // 初始化 LAN 路由器
    let lan_router = Arc::new(LanRouter::with_port(LOCAL_NODE_NAME, node_id, lan_port));

    // 初始化中继管理器
    let relay_manager = RelayManager::new(node_id, vpn_port);

    // 初始化 VPN 路由器
    let vpn_router = VpnRouter::new(
        LOCAL_NODE_NAME,
        node_id,
        resolver.clone(),
        Some(lan_router.clone()),
        relay_manager,
    );

    // 启动路由器
    if let Err(e) = lan_router.start() {
        eprintln!("Warning: LAN router start failed: {}", e);
    }

    if let Err(e) = vpn_router.start() {
        eprintln!("Warning: VPN router start failed: {}", e);
    }

    // 短暂等待路由器初始化
    thread::sleep(Duration::from_millis(100));

    // 注册数据接收监听器（打印收到的数据）
    vpn_router.register_listener(|from, data| {
        if let Ok(msg) = String::from_utf8(data) {
            if let Some(cmd) = msg.strip_prefix("CMD:") {
                println!("[{}] Remote command received: {}", from, cmd);
            } else if msg.starts_with("PING:") {
                // PING 消息由 ping_node 内部处理
            } else if msg.starts_with("BACKUP_CHUNK:") {
                let payload = &msg["BACKUP_CHUNK:".len()..];
                println!("[{}] Backup chunk received: {} bytes of metadata", from, payload.len());
                // In production, store to disk
            } else if msg.starts_with("BACKUP_META:") {
                let payload = &msg["BACKUP_META:".len()..];
                println!("[{}] Backup metadata received: {} bytes", from, payload.len());
                // In production, register in MetadataStore
            } else if msg.starts_with("RESTORE_GET_META:") {
                println!("[{}] Restore metadata request received", from);
                // In production, look up MetadataStore and respond
            } else if msg.starts_with("RESTORE_GET_CHUNK:") {
                println!("[{}] Restore chunk request received", from);
                // In production, look up stored chunk and respond
            } else {
                println!("[{}] Data received: {} bytes", from, msg.len());
            }
        }
    });

    // 解析并执行命令
    match command::execute_cmd(&args[1..], &resolver, &vpn_router) {
        Ok(output) => println!("{}", output),
        Err(e) => eprintln!("Error: {}", e),
    }

    // 清理
    vpn_router.stop();
    lan_router.stop();
}

/// 打印使用说明
fn print_usage() {
    println!("LL VPN - Decentralized VPN for Lan-Link");
    println!();
    println!("Usage:");
    println!("  ll cmd node:<name> <command>    Execute command on remote node");
    println!("  ll ping node:<name>             Test connectivity to node");
    println!("  ll nodes                        List known nodes");
    println!("  ll status                       Show local node information");
    println!("  ll backup <path> node:<name>    Backup file to remote node");
    println!("  ll restore node:<name>:<path>   Restore file from remote node");
    println!();
    println!("Examples:");
    println!("  ll ping node:Pikachu");
    println!("  ll cmd node:Charizard uptime");
    println!("  ll backup /etc/config.yaml node:Pikachu");
    println!("  ll restore node:Pikachu:/backup/config.yaml ./restored.yaml");
    println!("  ll nodes");
    println!("  ll status");
}

#[cfg(test)]
mod tests {
    use ll_vpn::address::AddressResolver;
    use ll_vpn::address::MemAddressResolver;

    #[test]
    fn test_setup_static_nodes() {
        let resolver = MemAddressResolver::new();
        super::setup_static_nodes(&resolver);

        let pikachu = resolver.resolve("Pikachu");
        assert!(pikachu.is_ok());

        let charizard = resolver.resolve("Charizard");
        assert!(charizard.is_ok());
    }

    #[test]
    fn test_static_node_ids_consistent() {
        let resolver = MemAddressResolver::new();
        super::setup_static_nodes(&resolver);

        let pikachu1 = resolver.resolve("Pikachu").unwrap();
        let pikachu2 = resolver.resolve("Pikachu").unwrap();
        assert_eq!(pikachu1, pikachu2);
    }
}
