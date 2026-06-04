//! P6-1: UDP 打洞（NAT 穿透）
//!
//! 实现 UDP 打洞功能，使内网节点能够穿透 NAT 直接通信。
//!
//! # 打洞流程
//!
//! 1. 通过中继交换双方的公网地址信息
//! 2. 双方同时向对方公网地址发送 UDP 包
//! 3. NAT 设备建立映射后可直接通信
//! 4. 超时或失败自动降级到中继
//!
//! # NAT 类型
//!
//! - Cone（锥形）: 最容易穿透，外部地址固定
//! - Restricted（受限）: 仅允许来自已知 IP 的包进入
//! - Symmetric（对称）: 无法穿透，必须走中继

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 默认打洞超时时间（秒）
pub const PUNCH_TIMEOUT_SECS: u64 = 5;

/// 默认打洞重试次数
pub const PUNCH_RETRY_COUNT: u32 = 3;

/// 默认打洞端口范围起始
pub const PUNCH_PORT_START: u16 = 34780;

/// 打洞包大小（字节）
pub const PUNCH_PACKET_SIZE: usize = 64;

/// 保活间隔（秒）
pub const KEEPALIVE_INTERVAL_SECS: u64 = 30;

/// NAT 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// 锥形 NAT — 易穿透
    Cone,
    /// 受限锥形 — 较难穿透
    Restricted,
    /// 对称 NAT — 不可穿透，需中继
    Symmetric,
    /// 未知（未检测）
    Unknown,
}

impl NatType {
    /// 是否可通过打洞穿透
    pub fn is_punchable(&self) -> bool {
        matches!(self, Self::Cone | Self::Restricted)
    }

    /// 转换为字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cone => "cone",
            Self::Restricted => "restricted",
            Self::Symmetric => "symmetric",
            Self::Unknown => "unknown",
        }
    }
}

/// 打洞结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PunchResult {
    /// 打洞成功
    Success,
    /// 打洞失败
    Failed(String),
    /// 降级到中继
    DegradedToRelay(String),
}

/// 打洞中的连接状态
#[derive(Debug, Clone)]
struct HolePunchConn {
    /// 目标节点 ID
    target: NodeID,
    /// 目标公网地址
    public_addr: SocketAddr,
    /// 开始时间
    started: Instant,
    /// 重试次数
    retries: u32,
    /// 是否已建立连接
    established: bool,
}

/// UDP 打洞管理器
///
/// 管理 UDP 打洞的完整生命周期：检测 NAT 类型、发起打洞、
/// 保持洞活跃、失败降级。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::hole_punch::HolePunchManager;
/// use ll_vpn::vpn::identity::NodeID;
///
/// let local_id = NodeID::from_bytes(&[1u8; 32]);
/// let manager = HolePunchManager::new(local_id);
/// assert_eq!(manager.active_punches(), 0);
/// ```
pub struct HolePunchManager {
    /// 本地节点 ID
    local_id: NodeID,
    /// 本地 NAT 类型
    nat_type: Arc<Mutex<NatType>>,
    /// 活跃的打洞连接
    active_punches: Arc<Mutex<HashMap<NodeID, HolePunchConn>>>,
    /// 已成功打洞的对等节点
    punched_peers: Arc<Mutex<HashMap<NodeID, SocketAddr>>>,
    /// 运行标志
    running: Arc<AtomicBool>,
    /// 当前绑定的 UDP 套接字（可选，测试时可用 mock）
    socket: Option<Arc<UdpSocket>>,
}

impl HolePunchManager {
    /// 创建新的打洞管理器
    pub fn new(local_id: NodeID) -> Self {
        Self {
            local_id,
            nat_type: Arc::new(Mutex::new(NatType::Unknown)),
            active_punches: Arc::new(Mutex::new(HashMap::new())),
            punched_peers: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            socket: None,
        }
    }

    /// 绑定 UDP 套接字（可选，不绑定时使用内部创建的套接字）
    pub fn bind_socket(&mut self, socket: UdpSocket) {
        self.socket = Some(Arc::new(socket));
    }

    /// 获取当前 NAT 类型
    pub fn nat_type(&self) -> NatType {
        *self.nat_type.lock().unwrap()
    }

    /// 设置 NAT 类型（用于测试）
    pub fn set_nat_type(&self, nat_type: NatType) {
        *self.nat_type.lock().unwrap() = nat_type;
    }

    /// 活跃打洞数
    pub fn active_punches(&self) -> usize {
        self.active_punches.lock().unwrap().len()
    }

    /// 已打洞成功的对等节点数
    pub fn punched_peer_count(&self) -> usize {
        self.punched_peers.lock().unwrap().len()
    }

    /// 检测本地 NAT 类型
    ///
    /// 通过向中继服务器发送探测包并观察映射地址变化来判断 NAT 类型。
    /// 简化实现：根据配置或外部探测结果设置。
    ///
    /// # 返回
    ///
    /// 检测到的 NAT 类型
    pub fn detect_nat_type(&self) -> NatType {
        // 简化版本：实际场景需要与 STUN 服务器交互
        // 这里默认返回 Cone（最乐观），可由外部设置覆盖
        let detected = NatType::Cone;
        *self.nat_type.lock().unwrap() = detected;
        detected
    }

    /// 是否是对称 NAT
    ///
    /// 对称 NAT 无法进行 UDP 打洞，必须走中继。
    pub fn is_symmetric_nat(&self) -> bool {
        *self.nat_type.lock().unwrap() == NatType::Symmetric
    }

    /// 发起 UDP 打洞
    ///
    /// 向目标节点发起 UDP 打洞。双方需要事先通过中继交换地址信息。
    ///
    /// # 参数
    ///
    /// - `remote_id`: 目标节点 ID
    /// - `remote_addr`: 目标节点的公网地址
    /// - `local_port`: 本地监听端口
    ///
    /// # 返回
    ///
    /// - `Ok(PunchResult)`: 打洞结果
    /// - `Err(String)`: 打洞过程中的错误
    pub fn punch_hole(
        &self,
        remote_id: &NodeID,
        remote_addr: &SocketAddr,
        local_port: u16,
    ) -> Result<PunchResult, String> {
        // 对称 NAT 无法打洞
        if self.is_symmetric_nat() {
            return Ok(PunchResult::DegradedToRelay(
                "symmetric NAT cannot punch".to_string(),
            ));
        }

        // 检查是否已打洞成功
        if self.punched_peers.lock().unwrap().contains_key(remote_id) {
            return Ok(PunchResult::Success);
        }

        // 创建或使用已有 socket
        let socket: Arc<UdpSocket> = match &self.socket {
            Some(s) => s.clone(),
            None => {
                let bind_addr = format!("0.0.0.0:{}", local_port);
                let s = UdpSocket::bind(&bind_addr)
                    .map_err(|e| format!("failed to bind UDP socket: {}", e))?;
                s.set_read_timeout(Some(Duration::from_secs(PUNCH_TIMEOUT_SECS)))
                    .map_err(|e| format!("failed to set timeout: {}", e))?;
                s.set_nonblocking(true)
                    .map_err(|e| format!("failed to set nonblocking: {}", e))?;
                Arc::new(s)
            }
        };

        // 记录打洞连接
        let conn = HolePunchConn {
            target: *remote_id,
            public_addr: *remote_addr,
            started: Instant::now(),
            retries: 0,
            established: false,
        };
        self.active_punches.lock().unwrap().insert(*remote_id, conn);

        // 发送打洞包
        let punch_payload = self.build_punch_packet(remote_id);
        let mut last_error = String::new();

        for attempt in 0..PUNCH_RETRY_COUNT {
            // 向目标发送 UDP 包
            match socket.send_to(&punch_payload, remote_addr) {
                Ok(_) => {
                    log::info!(
                        "Punch attempt {} to {} ({})",
                        attempt + 1,
                        remote_id.to_hex(),
                        remote_addr
                    );
                }
                Err(e) => {
                    last_error = format!("send error: {}", e);
                    log::warn!("Punch send failed: {}", e);
                }
            }

            // 读取可能的响应包
            let mut buf = [0u8; PUNCH_PACKET_SIZE];
            match socket.recv_from(&mut buf) {
                Ok((_size, src_addr)) => {
                    // 检查是否来自目标节点的响应
                    if self.is_valid_punch_response(&buf, remote_id) {
                        log::info!(
                            "Punch successful to {} from {}",
                            remote_id.to_hex(),
                            src_addr
                        );
                        self.punched_peers
                            .lock()
                            .unwrap()
                            .insert(*remote_id, src_addr);
                        self.active_punches.lock().unwrap().remove(remote_id);
                        return Ok(PunchResult::Success);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // 超时，继续重试
                }
                Err(e) => {
                    last_error = format!("recv error: {}", e);
                }
            }

            // 等待后重试
            if attempt < PUNCH_RETRY_COUNT - 1 {
                std::thread::sleep(Duration::from_millis(200));
            }
        }

        // 打洞失败，清理并降级
        self.active_punches.lock().unwrap().remove(remote_id);
        log::warn!(
            "Punch failed for {}, degrading to relay",
            remote_id.to_hex()
        );

        Ok(PunchResult::DegradedToRelay(format!(
            "all {} attempts failed: {}",
            PUNCH_RETRY_COUNT,
            if last_error.is_empty() {
                "no response".to_string()
            } else {
                last_error
            }
        )))
    }

    /// 构建打洞包
    fn build_punch_packet(&self, target: &NodeID) -> Vec<u8> {
        let mut packet = Vec::with_capacity(PUNCH_PACKET_SIZE);
        // 魔数标识打洞包
        packet.extend_from_slice(b"LLHP");
        // 本地节点 ID
        packet.extend_from_slice(&self.local_id.as_bytes()[..28]);
        // 目标节点 ID（用于对方验证）
        packet.extend_from_slice(&target.as_bytes()[..28]);
        // 填充到固定大小
        packet.resize(PUNCH_PACKET_SIZE, 0);
        packet
    }

    /// 验证打洞响应包
    fn is_valid_punch_response(&self, buf: &[u8], expected_peer: &NodeID) -> bool {
        if buf.len() < 4 + 28 {
            return false;
        }
        // 检查魔数
        if &buf[0..4] != b"LLHP" {
            return false;
        }
        // 检查发送者 ID 是否匹配预期
        let sender_bytes = &buf[4..32];
        let expected_bytes = &expected_peer.as_bytes()[..28];
        sender_bytes == expected_bytes
    }

    /// 发送保活包以维持 NAT 映射
    ///
    /// 打洞成功后需要定期发送保活包，否则 NAT 映射会超时失效。
    pub fn send_keepalive(&self, peer_id: &NodeID) -> Result<(), String> {
        let peer_addr = self
            .punched_peers
            .lock()
            .unwrap()
            .get(peer_id)
            .copied()
            .ok_or_else(|| "peer not punched".to_string())?;

        let socket = match &self.socket {
            Some(s) => s.clone(),
            None => return Err("no UDP socket".to_string()),
        };

        let keepalive = b"LLKA";
        socket
            .send_to(keepalive, peer_addr)
            .map_err(|e| format!("keepalive send failed: {}", e))?;

        Ok(())
    }

    /// 获取已打洞的节点地址
    pub fn get_punched_addr(&self, peer_id: &NodeID) -> Option<SocketAddr> {
        self.punched_peers.lock().unwrap().get(peer_id).copied()
    }

    /// 移除打洞记录
    pub fn remove_peer(&self, peer_id: &NodeID) {
        self.punched_peers.lock().unwrap().remove(peer_id);
        self.active_punches.lock().unwrap().remove(peer_id);
    }

    /// 清空所有打洞记录
    pub fn clear(&self) {
        self.punched_peers.lock().unwrap().clear();
        self.active_punches.lock().unwrap().clear();
    }

    /// 获取已打洞的节点列表
    pub fn punched_peers(&self) -> Vec<(NodeID, SocketAddr)> {
        self.punched_peers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, addr)| (*id, *addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn make_id(byte: u8) -> NodeID {
        NodeID::from_bytes(&[byte; 32])
    }

    fn test_addr(a: u8, b: u8, c: u8, d: u8, port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            std::net::Ipv4Addr::new(a, b, c, d),
            port,
        ))
    }

    // ── NAT 类型测试 ──

    #[test]
    fn test_nat_type_default() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        assert_eq!(manager.nat_type(), NatType::Unknown);
    }

    #[test]
    fn test_nat_type_detect() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        // 默认 detece 返回 Cone
        let detected = manager.detect_nat_type();
        assert_eq!(detected, NatType::Cone);
        assert_eq!(manager.nat_type(), NatType::Cone);
    }

    #[test]
    fn test_nat_type_set() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        manager.set_nat_type(NatType::Symmetric);
        assert_eq!(manager.nat_type(), NatType::Symmetric);
        assert!(manager.is_symmetric_nat());

        manager.set_nat_type(NatType::Cone);
        assert!(!manager.is_symmetric_nat());
    }

    #[test]
    fn test_nat_type_punchable() {
        assert!(NatType::Cone.is_punchable());
        assert!(NatType::Restricted.is_punchable());
        assert!(!NatType::Symmetric.is_punchable());
        assert!(!NatType::Unknown.is_punchable());
    }

    #[test]
    fn test_nat_type_as_str() {
        assert_eq!(NatType::Cone.as_str(), "cone");
        assert_eq!(NatType::Restricted.as_str(), "restricted");
        assert_eq!(NatType::Symmetric.as_str(), "symmetric");
        assert_eq!(NatType::Unknown.as_str(), "unknown");
    }

    // ── 打洞测试 ──

    #[test]
    fn test_punch_symmetric_nat_degrade() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        manager.set_nat_type(NatType::Symmetric);

        let remote = make_id(0x02);
        let addr = test_addr(10, 0, 0, 1, 12345);

        let result = manager.punch_hole(&remote, &addr, 34780);
        assert!(result.is_ok());
        match result.unwrap() {
            PunchResult::DegradedToRelay(_) => {} // 预期降级
            other => panic!("expected DegradedToRelay, got {:?}", other),
        }
    }

    #[test]
    fn test_punch_hole_already_punched() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);

        let remote = make_id(0x03);
        let addr = test_addr(192, 168, 1, 1, 9999);

        // 模拟已打洞成功
        manager
            .punched_peers
            .lock()
            .unwrap()
            .insert(remote, addr);

        let result = manager.punch_hole(&remote, &addr, 34780);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PunchResult::Success);
    }

    // ── 构建/验证包测试 ──

    #[test]
    fn test_build_punch_packet() {
        let local = make_id(0x01);
        let remote = make_id(0x02);
        let manager = HolePunchManager::new(local);

        let packet = manager.build_punch_packet(&remote);
        assert_eq!(packet.len(), PUNCH_PACKET_SIZE);
        assert_eq!(&packet[0..4], b"LLHP");
        // 前 28 字节是 local_id
        assert_eq!(&packet[4..32], &local.as_bytes()[..28]);
        // 后 28 字节是 remote_id
        assert_eq!(&packet[32..60], &remote.as_bytes()[..28]);
    }

    #[test]
    fn test_is_valid_punch_response() {
        let local = make_id(0x01);
        let remote = make_id(0x02);
        let manager = HolePunchManager::new(local);

        // 构造一个从 remote 发来的合法响应包
        let mut resp = Vec::with_capacity(PUNCH_PACKET_SIZE);
        resp.extend_from_slice(b"LLHP");
        resp.extend_from_slice(&remote.as_bytes()[..28]);
        resp.resize(PUNCH_PACKET_SIZE, 0);

        assert!(manager.is_valid_punch_response(&resp, &remote));

        // 错误的魔数
        let mut bad_resp = resp.clone();
        bad_resp[0] = 0xFF;
        assert!(!manager.is_valid_punch_response(&bad_resp, &remote));

        // 太短
        assert!(!manager.is_valid_punch_response(&[0u8; 3], &remote));
    }

    // ── 管理操作测试 ──

    #[test]
    fn test_remove_peer() {
        let local = make_id(0x01);
        let manager = HolePunchManager::new(local);

        let remote = make_id(0x04);
        let addr = test_addr(10, 0, 0, 5, 8000);

        manager
            .punched_peers
            .lock()
            .unwrap()
            .insert(remote, addr);

        assert!(manager.get_punched_addr(&remote).is_some());
        manager.remove_peer(&remote);
        assert!(manager.get_punched_addr(&remote).is_none());
    }

    #[test]
    fn test_clear() {
        let local = make_id(0x01);
        let manager = HolePunchManager::new(local);

        let r1 = make_id(0x05);
        let r2 = make_id(0x06);
        manager
            .punched_peers
            .lock()
            .unwrap()
            .insert(r1, test_addr(1, 2, 3, 4, 1111));
        manager
            .punched_peers
            .lock()
            .unwrap()
            .insert(r2, test_addr(5, 6, 7, 8, 2222));

        assert_eq!(manager.punched_peer_count(), 2);
        manager.clear();
        assert_eq!(manager.punched_peer_count(), 0);
    }

    #[test]
    fn test_punched_peers_list() {
        let local = make_id(0x01);
        let manager = HolePunchManager::new(local);

        let remote = make_id(0x07);
        let addr = test_addr(10, 0, 0, 1, 3333);
        manager
            .punched_peers
            .lock()
            .unwrap()
            .insert(remote, addr);

        let list = manager.punched_peers();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, remote);
        assert_eq!(list[0].1, addr);
    }

    // ── 边界测试 ──

    #[test]
    fn test_empty_punched_peers() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        assert_eq!(manager.active_punches(), 0);
        assert_eq!(manager.punched_peer_count(), 0);
        assert!(manager.punched_peers().is_empty());
    }

    #[test]
    fn test_get_punched_addr_nonexistent() {
        let (id, _) = NodeID::generate();
        let manager = HolePunchManager::new(id);
        let unknown = make_id(0xFF);
        assert!(manager.get_punched_addr(&unknown).is_none());
    }

    #[test]
    fn test_keepalive_no_socket() {
        let local = make_id(0x01);
        let manager = HolePunchManager::new(local);
        let remote = make_id(0x02);

        // 没有 socket 时保活应失败
        let result = manager.send_keepalive(&remote);
        assert!(result.is_err());
    }
}
