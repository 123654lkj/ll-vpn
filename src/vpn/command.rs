//! P2-2/P2-3: 命令解析与执行
//!
//! 提供 CLI 命令的解析和执行功能，支持以下子命令：
//!
//! - `ll cmd node:<name> <command>` — 在远程节点上执行命令
//! - `ll ping node:<name>` — 测试到目标节点的连通性
//! - `ll nodes` — 列出所有已知节点
//! - `ll status` — 显示本机信息
//!
//! 所有命令输出到 stdout，错误输出到 stderr。

use crate::address::{resolve_address, MemAddressResolver, ParsedAddress};
use crate::router::{NodeStatus, Router, RouterError};
use crate::vpn::identity::NodeID;
use crate::vpn::vpn_router::VpnRouter;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// 已解析的命令
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// 远程执行命令: ll cmd node:xxx <command>
    Cmd {
        /// 目标地址
        target: String,
        /// 要执行的命令
        command: String,
    },
    /// 连通性测试: ll ping node:xxx
    Ping {
        /// 目标地址
        target: String,
    },
    /// 列出已知节点: ll nodes
    Nodes,
    /// 显示本机信息: ll status
    Status,
}

/// 解析命令行参数为命令
///
/// # 参数
/// - `args`: 命令行参数（不包含程序名）
///
/// # 返回
/// - `Ok(Command)`: 成功解析的命令
/// - `Err(String)`: 解析错误信息
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::command::parse_command;
///
/// let cmd = parse_command(&["ll".into(), "ping".into(), "node:Pikachu".into()]).unwrap();
/// assert!(format!("{:?}", cmd).contains("Ping"));
/// ```
pub fn parse_command(args: &[String]) -> Result<Command, String> {
    // 跳过程序名（args[0]），从 args[1..] 开始解析
    // 但为了灵活性，允许各种调用方式

    // 查找 "ll" 的位置
    let ll_pos = args.iter().position(|a| a == "ll");

    let cmd_args = match ll_pos {
        Some(pos) => &args[pos..],
        None => {
            // 如果没找到 "ll"，尝试直接解析子命令
            if args.is_empty() {
                return Err("empty command. Usage: ll <cmd|ping|nodes|status> [args]".to_string());
            }
            // 可能是 "cmd", "ping" 等形式
            return parse_short_command(args);
        }
    };

    if cmd_args.len() < 2 {
        return Err(
            "expected subcommand after 'll'. Usage: ll <cmd|ping|nodes|status>".to_string(),
        );
    }

    match cmd_args[1].as_str() {
        "cmd" => {
            if cmd_args.len() < 4 {
                return Err(
                    "usage: ll cmd node:<name> <command>".to_string(),
                );
            }
            let target = cmd_args[2].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            let command = cmd_args[3..].join(" ");
            Ok(Command::Cmd { target, command })
        }
        "ping" => {
            if cmd_args.len() < 3 {
                return Err("usage: ll ping node:<name>".to_string());
            }
            let target = cmd_args[2].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Ping { target })
        }
        "nodes" => Ok(Command::Nodes),
        "status" => Ok(Command::Status),
        sub => Err(format!(
            "unknown subcommand '{}'. Available: cmd, ping, nodes, status",
            sub
        )),
    }
}

/// 解析短格式命令（没有 "ll" 前缀）
fn parse_short_command(args: &[String]) -> Result<Command, String> {
    if args.is_empty() {
        return Err("empty command".to_string());
    }

    match args[0].as_str() {
        "cmd" => {
            if args.len() < 3 {
                return Err("usage: cmd node:<name> <command>".to_string());
            }
            let target = args[1].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            let command = args[2..].join(" ");
            Ok(Command::Cmd { target, command })
        }
        "ping" => {
            if args.len() < 2 {
                return Err("usage: ping node:<name>".to_string());
            }
            let target = args[1].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Ping { target })
        }
        "nodes" => Ok(Command::Nodes),
        "status" => Ok(Command::Status),
        _ => Err(format!(
            "unknown command '{}'. Available: ll cmd, ll ping, ll nodes, ll status",
            args[0]
        )),
    }
}

/// 执行命令
///
/// # 参数
/// - `args`: 完整的命令行参数
/// - `resolver`: 地址解析器
/// - `vpn`: VPN 路由器实例
///
/// # 返回
/// - `Ok(String)`: 命令输出
/// - `Err(String)`: 错误信息
///
/// # 示例
///
/// ```rust
/// use ll_vpn::address::MemAddressResolver;
/// use ll_vpn::vpn::vpn_router::VpnRouter;
/// use ll_vpn::vpn::identity::NodeID;
/// use ll_vpn::vpn::relay::RelayManager;
/// use ll_vpn::vpn::command::execute_cmd;
/// use std::sync::Arc;
///
/// let node_id = NodeID::from_bytes(&[1u8; 32]);
/// let resolver = Arc::new(MemAddressResolver::new());
/// let relay = RelayManager::new(node_id, 19895);
/// let vpn = VpnRouter::new("TestNode", node_id, resolver.clone(), None, relay);
///
/// let result = execute_cmd(&["ll".into(), "status".into()], &*resolver, &vpn);
/// assert!(result.is_ok());
/// ```
pub fn execute_cmd(
    args: &[String],
    resolver: &MemAddressResolver,
    vpn: &VpnRouter,
) -> Result<String, String> {
    let cmd = parse_command(args)?;

    match cmd {
        Command::Cmd { target, command } => execute_cmd_subcommand(&target, &command, resolver, vpn),
        Command::Ping { target } => execute_ping(&target, vpn),
        Command::Nodes => execute_nodes(vpn),
        Command::Status => execute_status(vpn),
    }
}

/// 执行远程命令
fn execute_cmd_subcommand(
    target: &str,
    command: &str,
    resolver: &MemAddressResolver,
    vpn: &VpnRouter,
) -> Result<String, String> {
    // 验证地址可解析
    let (parsed, node_id) =
        resolve_address(resolver, target).map_err(|e| format!("address resolution failed: {}", e))?;

    // 打包命令数据
    let cmd_data = format!("CMD:{}", command).into_bytes();

    // 通过路由器发送
    vpn.send(target, &cmd_data)
        .map_err(|e| format!("send failed: {}", e))?;

    Ok(format!(
        "Command sent to {} ({}): {}",
        parsed.name,
        node_id.to_hex(),
        command
    ))
}

/// 执行 ping 命令
fn execute_ping(target: &str, vpn: &VpnRouter) -> Result<String, String> {
    let start = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    match vpn.ping_node(target) {
        Ok(rtt) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            Ok(format!(
                "PONG from {}: time={:.1}ms seq=1 ttl=64 time={}s",
                target,
                rtt_ms,
                now - start
            ))
        }
        Err(RouterError::Timeout) => Err(format!("Request timeout for {}", target)),
        Err(e) => Err(format!("Ping failed for {}: {}", target, e)),
    }
}

/// 列出已知节点
fn execute_nodes(vpn: &VpnRouter) -> Result<String, String> {
    let nodes = vpn.known_nodes_info();
    if nodes.is_empty() {
        return Ok("No known nodes.".to_string());
    }

    let mut output = String::from("Known nodes:\n");
    output.push_str(&format!("{:<20} {:<20} {:<10} {:<10}\n", "Name", "Node ID", "Type", "Status"));
    output.push_str(&"-".repeat(60));
    output.push('\n');

    for (name, id, conn_type, status) in nodes {
        let id_short = &id.to_hex()[..16];
        output.push_str(&format!(
            "{:<20} {:<20} {:<10} {:<10}\n",
            name,
            id_short,
            conn_type,
            status
        ));
    }

    Ok(output)
}

/// 显示本机状态
fn execute_status(vpn: &VpnRouter) -> Result<String, String> {
    let router_status = vpn.status();
    let nodes = vpn.known_nodes_info();
    let online_count = nodes.iter().filter(|(_, _, _, s)| *s == NodeStatus::Online).count();

    let mut output = String::from("=== VPN Status ===\n");
    output.push_str(&format!("Node Name:     {}\n", vpn.name()));
    output.push_str(&format!("Node ID:       {}\n", vpn.local_id().to_hex()));
    output.push_str(&format!("Status:        {}\n", router_status.node_status));
    output.push_str(&format!("Connection:    {}\n", router_status.connection_type));
    output.push_str(&format!("Known Nodes:   {}\n", router_status.known_nodes));
    output.push_str(&format!("Online Nodes:  {}\n", online_count));
    output.push_str(&format!("Active Routes: {}\n", router_status.active_routes));
    output.push_str(&format!(
        "Last Update:   {}\n",
        router_status.last_update
    ));

    Ok(output)
}

/// 检查目标节点是否可达
///
/// 通过发送 ping 消息测试连通性。
pub fn ping_node(vpn: &VpnRouter, addr: &str) -> Result<String, String> {
    execute_ping(addr, vpn)
}

/// 获取已知节点列表
pub fn list_nodes(vpn: &VpnRouter) -> Result<String, String> {
    execute_nodes(vpn)
}

/// 获取本机状态
pub fn get_status(vpn: &VpnRouter) -> Result<String, String> {
    execute_status(vpn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressResolver;
    use crate::vpn::relay::RelayManager;
    use std::sync::Arc;

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    fn make_vpn(name: &str, byte: u8) -> (VpnRouter, Arc<MemAddressResolver>) {
        let node_id = make_id(byte);
        let resolver = Arc::new(MemAddressResolver::new());
        let relay = RelayManager::new(node_id, 19900 + byte as u16);
        let vpn = VpnRouter::new(name, node_id, resolver.clone() as Arc<dyn AddressResolver + Send + Sync>, None, relay);
        (vpn, resolver)
    }

    // ====== parse_command 测试 ======

    #[test]
    fn test_parse_cmd() {
        let args = vec![
            "ll".to_string(),
            "cmd".to_string(),
            "node:Pikachu".to_string(),
            "uptime".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Cmd {
                target: "node:Pikachu".to_string(),
                command: "uptime".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_cmd_with_spaces() {
        let args = vec![
            "ll".to_string(),
            "cmd".to_string(),
            "node:Charizard".to_string(),
            "ls".to_string(),
            "-la".to_string(),
            "/tmp".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Cmd {
                target: "node:Charizard".to_string(),
                command: "ls -la /tmp".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_ping() {
        let args = vec![
            "ll".to_string(),
            "ping".to_string(),
            "node:Pikachu".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Ping {
                target: "node:Pikachu".to_string()
            }
        );
    }

    #[test]
    fn test_parse_nodes() {
        let args = vec!["ll".to_string(), "nodes".to_string()];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(cmd, Command::Nodes);
    }

    #[test]
    fn test_parse_status() {
        let args = vec!["ll".to_string(), "status".to_string()];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(cmd, Command::Status);
    }

    #[test]
    fn test_parse_short_format() {
        let args = vec![
            "ping".to_string(),
            "node:Pikachu".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Ping {
                target: "node:Pikachu".to_string()
            }
        );
    }

    #[test]
    fn test_parse_empty() {
        let result = parse_command(&[] as &[String]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_subcommand() {
        let args = vec!["ll".to_string(), "fly".to_string()];
        let result = parse_command(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown subcommand"));
    }

    #[test]
    fn test_parse_cmd_invalid_target() {
        let args = vec![
            "ll".to_string(),
            "cmd".to_string(),
            "Pikachu".to_string(),
            "uptime".to_string(),
        ];
        let result = parse_command(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid target"));
    }

    #[test]
    fn test_parse_cmd_missing_args() {
        let args = vec!["ll".to_string(), "cmd".to_string(), "node:Pikachu".to_string()];
        let result = parse_command(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ping_invalid_target() {
        let args = vec!["ll".to_string(), "ping".to_string(), "192.168.1.1".to_string()];
        let result = parse_command(&args);
        assert!(result.is_err());
    }

    // ====== execute_* 测试 ======

    #[test]
    fn test_execute_status() {
        let (vpn, _resolver) = make_vpn("StatusTest", 0x50);
        let result = execute_status(&vpn);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("StatusTest"));
        assert!(output.contains("VPN Status"));
    }

    #[test]
    fn test_execute_nodes_empty() {
        let (vpn, _resolver) = make_vpn("NodeTest", 0x51);
        let result = execute_nodes(&vpn);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No known nodes"));
    }

    #[test]
    fn test_execute_ping_invalid_target() {
        let (vpn, _resolver) = make_vpn("PingTest", 0x52);
        let result = execute_ping("node:NonExistent", &vpn);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_cmd_invalid_target() {
        let (vpn, resolver) = make_vpn("CmdTest", 0x53);
        let result = execute_cmd_subcommand("node:NonExistent", "uptime", &*resolver, &vpn);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("address resolution"));
    }

    #[test]
    fn test_execute_cmd_unknown_node() {
        let (vpn, resolver) = make_vpn("CmdTest2", 0x54);
        // 节点在解析器中不存在
        let result = execute_cmd_subcommand("node:Ghost", "uptime", &*resolver, &vpn);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_cmd_invalid_address() {
        let (vpn, resolver) = make_vpn("CmdTest3", 0x55);
        // 当解析器中有这个节点但不可达
        let peer_id = make_id(0x56);
        resolver.add_static_mapping("RemoteNode", peer_id);

        let result = execute_cmd_subcommand("node:RemoteNode", "ls", &*resolver, &vpn);
        assert!(result.is_err());
        // 不可达
    }

    // ====== 完整执行流程 ======

    #[test]
    fn test_execute_cmd_full_flow() {
        let (vpn, resolver) = make_vpn("FlowTest", 0x60);
        let peer_id = make_id(0x61);
        resolver.add_static_mapping("Pikachu", peer_id);

        let args = vec![
            "ll".to_string(),
            "cmd".to_string(),
            "node:Pikachu".to_string(),
            "uptime".to_string(),
        ];
        let result = execute_cmd(&args, &*resolver, &vpn);
        // 节点不可达，应返回错误
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_ping_full_flow() {
        let (vpn, resolver) = make_vpn("PingFlow", 0x62);
        let peer_id = make_id(0x63);
        resolver.add_static_mapping("Charizard", peer_id);

        let args = vec![
            "ll".to_string(),
            "ping".to_string(),
            "node:Charizard".to_string(),
        ];
        let result = execute_cmd(&args, &*resolver, &vpn);
        // 节点不可达，应返回错误
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_nodes_full_flow() {
        let (vpn, resolver) = make_vpn("NodeFlow", 0x64);
        let args = vec!["ll".to_string(), "nodes".to_string()];
        let result = execute_cmd(&args, &*resolver, &vpn);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("No known nodes"));
    }
}
