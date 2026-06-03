//! P2-2: 命令层（占位）
//!
//! 完整的命令解析和执行为 P2-2 任务，此处仅为编译占位。

use crate::address::MemAddressResolver;
use crate::vpn::vpn_router::VpnRouter;

/// 解析并执行命令
pub fn execute_cmd(args: &[String], _resolver: &MemAddressResolver, _vpn: &VpnRouter) -> Result<String, String> {
    if args.is_empty() {
        return Err("empty command".to_string());
    }
    Err(format!("unknown command or not yet implemented: {:?}", args))
}
