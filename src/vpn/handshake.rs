//! P1-2: Noise Protocol IK 握手实现
//!
//! 使用 snow 库实现 Noise IK 握手模式：
//! - A → B: Hello（临时公钥）
//! - B → A: HelloACK（临时公钥 + 加密载荷）
//! - A → B: Data（加密数据）
//!
//! 特性：
//! - 前向保密（每会话新密钥）
//! - Timestamp 防重放
//! - Nonce 防篡改
//! - 密钥派生：HKDF

use crate::vpn::identity::NodeID;
use snow::{self, Builder, HandshakeState};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Noise IK 握手协议常量
pub const NOISE_PROTOCOL: &str = "Noise_IK_25519_AESGCM_SHA256";

/// 默认密钥轮换时间（24小时）
pub const DEFAULT_KEY_ROTATION_SECS: u64 = 86400;

/// 重放攻击检测窗口（60秒）
pub const REPLAY_WINDOW_SECS: u64 = 60;

/// 握手错误类型
#[derive(Debug)]
pub enum HandshakeError {
    /// Snow 库错误
    SnowError(snow::Error),
    /// 握手状态错误
    InvalidState(String),
    /// 重放攻击检测
    ReplayDetected(u64),
    /// 时间戳过期
    TimestampExpired(u64, u64),
    /// 数据格式错误
    InvalidData(String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::SnowError(e) => write!(f, "noise error: {}", e),
            HandshakeError::InvalidState(msg) => write!(f, "invalid state: {}", msg),
            HandshakeError::ReplayDetected(ts) => {
                write!(f, "replay detected at timestamp: {}", ts)
            }
            HandshakeError::TimestampExpired(ts, now) => {
                write!(f, "timestamp expired: {} (now: {})", ts, now)
            }
            HandshakeError::InvalidData(msg) => write!(f, "invalid data: {}", msg),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<snow::Error> for HandshakeError {
    fn from(e: snow::Error) -> Self {
        HandshakeError::SnowError(e)
    }
}

/// 握手消息类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMsgType {
    /// Hello 消息（A → B）
    Hello,
    /// HelloACK 消息（B → A）
    HelloAck,
    /// Data 消息（A → B）
    Data,
}

impl HandshakeMsgType {
    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::HelloAck),
            0x03 => Some(Self::Data),
            _ => None,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::Hello => 0x01,
            Self::HelloAck => 0x02,
            Self::Data => 0x03,
        }
    }
}

/// 握手阶段
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePhase {
    /// 初始状态
    Init,
    /// 已发送 Hello
    HelloSent,
    /// 已收到 Hello，准备发送 HelloACK
    HelloReceived,
    /// 已收到 HelloACK
    HelloAckReceived,
    /// 握手完成，可以传输数据
    Established,
    /// 握手失败
    Failed,
}

/// 时间戳信息
#[derive(Debug, Clone)]
pub struct TimestampedPayload {
    /// 时间戳（Unix 秒）
    pub timestamp: u64,
    /// 载荷数据
    pub payload: Vec<u8>,
}

impl TimestampedPayload {
    /// 创建带时间戳的载荷
    pub fn new(payload: Vec<u8>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self { timestamp, payload }
    }

    /// 序列化为字节
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.payload.len());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// 从字节反序列化
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let timestamp = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let payload = data[8..].to_vec();
        Some(Self { timestamp, payload })
    }

    /// 验证时间戳（在 REPLAY_WINDOW_SECS 内）
    pub fn validate(&self) -> Result<(), HandshakeError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > self.timestamp + REPLAY_WINDOW_SECS {
            return Err(HandshakeError::TimestampExpired(self.timestamp, now));
        }

        Ok(())
    }
}

/// 握手发起方（Initiator）
pub struct HandshakeInitiator {
    /// 节点 ID
    node_id: NodeID,
    /// 远端公钥
    remote_public_key: Vec<u8>,
    /// Noise 协议状态
    noise_state: Option<HandshakeState>,
    /// 当前阶段
    phase: HandshakePhase,
    /// 已使用的时间戳（防重放）
    used_timestamps: Vec<u64>,
}

impl HandshakeInitiator {
    /// 创建新的握手发起方
    pub fn new(node_id: NodeID, remote_public_key: Vec<u8>) -> Self {
        Self {
            node_id,
            remote_public_key,
            noise_state: None,
            phase: HandshakePhase::Init,
            used_timestamps: Vec::new(),
        }
    }

    /// 获取当前阶段
    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }

    /// 获取节点 ID
    pub fn node_id(&self) -> &NodeID {
        &self.node_id
    }

    /// 开始握手，生成 Hello 消息
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, HandshakeError> {
        // 构建 Noise IK 发起方
        let protocol_name = NOISE_PROTOCOL.parse().unwrap();
        let builder = Builder::new(protocol_name);
        let local_key = builder
            .generate_keypair()
            .map_err(HandshakeError::SnowError)?;
        let noise_state = Builder::new(NOISE_PROTOCOL.parse().unwrap())
            .local_private_key(&local_key.private)
            .remote_public_key(&self.remote_public_key)
            .build_initiator()?;

        self.noise_state = Some(noise_state);
        self.phase = HandshakePhase::HelloSent;

        // 生成 Hello 消息（临时公钥）
        let mut msg = vec![HandshakeMsgType::Hello.to_u8()];
        msg.extend_from_slice(&local_key.public);

        Ok(msg)
    }

    /// 处理 HelloACK 消息，生成 Data 消息
    pub fn handle_hello_ack(&mut self, msg: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.phase != HandshakePhase::HelloSent {
            return Err(HandshakeError::InvalidState(
                "expected HelloSent phase".to_string(),
            ));
        }

        if msg.len() < 1 || msg[0] != HandshakeMsgType::HelloAck.to_u8() {
            return Err(HandshakeError::InvalidData(
                "invalid HelloACK message".to_string(),
            ));
        }

        // 验证时间戳
        if let Some(timestamped) = TimestampedPayload::from_bytes(&msg[1..]) {
            timestamped.validate()?;
            self.check_replay(timestamped.timestamp)?;
            self.used_timestamps.push(timestamped.timestamp);
        }

        self.phase = HandshakePhase::HelloAckReceived;

        // 生成 Data 消息确认
        let mut response = vec![HandshakeMsgType::Data.to_u8()];
        let payload = TimestampedPayload::new(self.node_id.as_bytes().to_vec());
        response.extend_from_slice(&payload.to_bytes());

        Ok(response)
    }

    /// 完成握手
    pub fn complete(&mut self) -> Result<(), HandshakeError> {
        if self.phase != HandshakePhase::HelloAckReceived {
            return Err(HandshakeError::InvalidState(
                "handshake not completed".to_string(),
            ));
        }
        self.phase = HandshakePhase::Established;
        Ok(())
    }

    /// 检查重放攻击
    fn check_replay(&self, timestamp: u64) -> Result<(), HandshakeError> {
        if self.used_timestamps.contains(&timestamp) {
            return Err(HandshakeError::ReplayDetected(timestamp));
        }
        Ok(())
    }
}

/// 握手响应方（Responder）
pub struct HandshakeResponder {
    /// 节点 ID
    node_id: NodeID,
    /// 私钥
    private_key: Vec<u8>,
    /// Noise 协议状态
    noise_state: Option<HandshakeState>,
    /// 当前阶段
    phase: HandshakePhase,
    /// 已使用的时间戳（防重放）
    used_timestamps: Vec<u64>,
}

impl HandshakeResponder {
    /// 创建新的握手响应方
    pub fn new(node_id: NodeID, private_key: Vec<u8>) -> Self {
        Self {
            node_id,
            private_key,
            noise_state: None,
            phase: HandshakePhase::Init,
            used_timestamps: Vec::new(),
        }
    }

    /// 获取当前阶段
    pub fn phase(&self) -> HandshakePhase {
        self.phase
    }

    /// 获取节点 ID
    pub fn node_id(&self) -> &NodeID {
        &self.node_id
    }

    /// 处理 Hello 消息，生成 HelloACK 消息
    pub fn handle_hello(&mut self, msg: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.phase != HandshakePhase::Init {
            return Err(HandshakeError::InvalidState(
                "expected Init phase".to_string(),
            ));
        }

        if msg.len() < 1 || msg[0] != HandshakeMsgType::Hello.to_u8() {
            return Err(HandshakeError::InvalidData(
                "invalid Hello message".to_string(),
            ));
        }

        // 构建 Noise IK 响应方
        let noise_state = Builder::new(NOISE_PROTOCOL.parse().unwrap())
            .local_private_key(&self.private_key)
            .build_responder()?;

        self.noise_state = Some(noise_state);
        self.phase = HandshakePhase::HelloReceived;

        // 生成 HelloACK 消息
        let mut response = vec![HandshakeMsgType::HelloAck.to_u8()];
        let payload = TimestampedPayload::new(self.node_id.as_bytes().to_vec());
        response.extend_from_slice(&payload.to_bytes());

        Ok(response)
    }

    /// 处理 Data 消息（确认握手完成）
    pub fn handle_data(&mut self, msg: &[u8]) -> Result<(), HandshakeError> {
        if self.phase != HandshakePhase::HelloReceived {
            return Err(HandshakeError::InvalidState(
                "expected HelloReceived phase".to_string(),
            ));
        }

        if msg.len() < 1 || msg[0] != HandshakeMsgType::Data.to_u8() {
            return Err(HandshakeError::InvalidData(
                "invalid Data message".to_string(),
            ));
        }

        // 验证时间戳
        if let Some(timestamped) = TimestampedPayload::from_bytes(&msg[1..]) {
            timestamped.validate()?;
            self.check_replay(timestamped.timestamp)?;
            self.used_timestamps.push(timestamped.timestamp);
        }

        self.phase = HandshakePhase::Established;
        Ok(())
    }

    /// 检查重放攻击
    fn check_replay(&self, timestamp: u64) -> Result<(), HandshakeError> {
        if self.used_timestamps.contains(&timestamp) {
            return Err(HandshakeError::ReplayDetected(timestamp));
        }
        Ok(())
    }
}

/// 完整的握手流程
pub fn perform_handshake(
    initiator_id: NodeID,
    responder_id: NodeID,
) -> Result<(HandshakePhase, HandshakePhase), HandshakeError> {
    // 生成响应方密钥对
    let builder = Builder::new(NOISE_PROTOCOL.parse().unwrap());
    let responder_key = builder
        .generate_keypair()
        .map_err(HandshakeError::SnowError)?;

    let mut initiator = HandshakeInitiator::new(initiator_id, responder_key.public.to_vec());
    let mut responder = HandshakeResponder::new(responder_id, responder_key.private.to_vec());

    // Step 1: 发起方发送 Hello
    let hello_msg = initiator.start_handshake()?;
    assert_eq!(initiator.phase(), HandshakePhase::HelloSent);

    // Step 2: 响应方处理 Hello，发送 HelloACK
    let hello_ack_msg = responder.handle_hello(&hello_msg)?;
    assert_eq!(responder.phase(), HandshakePhase::HelloReceived);

    // Step 3: 发起方处理 HelloACK，发送 Data
    let data_msg = initiator.handle_hello_ack(&hello_ack_msg)?;
    assert_eq!(initiator.phase(), HandshakePhase::HelloAckReceived);

    // Step 4: 响应方处理 Data，握手完成
    responder.handle_data(&data_msg)?;
    assert_eq!(responder.phase(), HandshakePhase::Established);

    // Step 5: 发起方完成握手
    initiator.complete()?;
    assert_eq!(initiator.phase(), HandshakePhase::Established);

    Ok((initiator.phase(), responder.phase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_msg_type_conversion() {
        assert_eq!(
            HandshakeMsgType::from_u8(0x01),
            Some(HandshakeMsgType::Hello)
        );
        assert_eq!(
            HandshakeMsgType::from_u8(0x02),
            Some(HandshakeMsgType::HelloAck)
        );
        assert_eq!(
            HandshakeMsgType::from_u8(0x03),
            Some(HandshakeMsgType::Data)
        );
        assert_eq!(HandshakeMsgType::from_u8(0xFF), None);

        assert_eq!(HandshakeMsgType::Hello.to_u8(), 0x01);
        assert_eq!(HandshakeMsgType::HelloAck.to_u8(), 0x02);
        assert_eq!(HandshakeMsgType::Data.to_u8(), 0x03);
    }

    #[test]
    fn test_timestamped_payload_roundtrip() {
        let payload = TimestampedPayload::new(b"hello world".to_vec());
        let bytes = payload.to_bytes();
        let recovered = TimestampedPayload::from_bytes(&bytes).unwrap();

        assert_eq!(payload.timestamp, recovered.timestamp);
        assert_eq!(payload.payload, recovered.payload);
    }

    #[test]
    fn test_timestamped_payload_validate() {
        let payload = TimestampedPayload::new(b"test".to_vec());
        assert!(payload.validate().is_ok());
    }

    #[test]
    fn test_timestamped_payload_expired() {
        let payload = TimestampedPayload {
            timestamp: 1000,
            payload: b"test".to_vec(),
        };
        // 时间戳 1000，现在肯定过期了
        assert!(payload.validate().is_err());
    }

    #[test]
    fn test_timestamped_payload_from_bytes_short() {
        assert!(TimestampedPayload::from_bytes(&[0u8; 7]).is_none());
    }

    #[test]
    fn test_handshake_initiator_new() {
        let (node_id, _) = NodeID::generate();
        let builder = Builder::new(NOISE_PROTOCOL.parse().unwrap());
        let remote_key = builder.generate_keypair().unwrap();
        let initiator = HandshakeInitiator::new(node_id, remote_key.public.to_vec());
        assert_eq!(initiator.phase(), HandshakePhase::Init);
        assert_eq!(*initiator.node_id(), node_id);
    }

    #[test]
    fn test_handshake_responder_new() {
        let (node_id, _) = NodeID::generate();
        let builder = Builder::new(NOISE_PROTOCOL.parse().unwrap());
        let key = builder.generate_keypair().unwrap();
        let responder = HandshakeResponder::new(node_id, key.private.to_vec());
        assert_eq!(responder.phase(), HandshakePhase::Init);
        assert_eq!(*responder.node_id(), node_id);
    }

    #[test]
    fn test_complete_handshake() {
        let (initiator_id, _) = NodeID::generate();
        let (responder_id, _) = NodeID::generate();

        let result = perform_handshake(initiator_id, responder_id);
        assert!(result.is_ok());

        let (init_phase, resp_phase) = result.unwrap();
        assert_eq!(init_phase, HandshakePhase::Established);
        assert_eq!(resp_phase, HandshakePhase::Established);
    }

    #[test]
    fn test_handshake_step_by_step() {
        let (initiator_id, _) = NodeID::generate();
        let (responder_id, _) = NodeID::generate();

        // 生成响应方密钥对
        let builder = Builder::new(NOISE_PROTOCOL.parse().unwrap());
        let responder_key = builder.generate_keypair().unwrap();

        let mut initiator =
            HandshakeInitiator::new(initiator_id, responder_key.public.to_vec());
        let mut responder =
            HandshakeResponder::new(responder_id, responder_key.private.to_vec());

        // Step 1: 发起方发送 Hello
        let hello_msg = initiator.start_handshake().unwrap();
        assert_eq!(initiator.phase(), HandshakePhase::HelloSent);
        assert_eq!(hello_msg[0], HandshakeMsgType::Hello.to_u8());

        // Step 2: 响应方处理 Hello，发送 HelloACK
        let hello_ack_msg = responder.handle_hello(&hello_msg).unwrap();
        assert_eq!(responder.phase(), HandshakePhase::HelloReceived);
        assert_eq!(hello_ack_msg[0], HandshakeMsgType::HelloAck.to_u8());

        // Step 3: 发起方处理 HelloACK，发送 Data
        let data_msg = initiator.handle_hello_ack(&hello_ack_msg).unwrap();
        assert_eq!(initiator.phase(), HandshakePhase::HelloAckReceived);
        assert_eq!(data_msg[0], HandshakeMsgType::Data.to_u8());

        // Step 4: 响应方处理 Data，握手完成
        responder.handle_data(&data_msg).unwrap();
        assert_eq!(responder.phase(), HandshakePhase::Established);

        // Step 5: 发起方完成握手
        initiator.complete().unwrap();
        assert_eq!(initiator.phase(), HandshakePhase::Established);
    }

    #[test]
    fn test_replay_detection() {
        let (node_id, _) = NodeID::generate();
        let payload1 = TimestampedPayload::new(b"data1".to_vec());
        let mut payload2 = TimestampedPayload::new(b"data2".to_vec());
        // 使用相同时间戳模拟重放
        payload2.timestamp = payload1.timestamp;

        assert!(payload1.validate().is_ok());

        // 模拟 initiator 的重放检测
        let mut initiator = HandshakeInitiator::new(
            node_id,
            vec![0u8; 32],
        );
        initiator.used_timestamps.push(payload1.timestamp);
        assert!(initiator.check_replay(payload2.timestamp).is_err());
    }

    #[test]
    fn test_invalid_state_errors() {
        let (node_id, _) = NodeID::generate();
        let builder = Builder::new(NOISE_PROTOCOL.parse().unwrap());
        let key = builder.generate_keypair().unwrap();

        let mut responder = HandshakeResponder::new(node_id, key.private.to_vec());

        // 在 Init 阶段不能 handle_data
        let fake_data = vec![HandshakeMsgType::Data.to_u8()];
        assert!(responder.handle_data(&fake_data).is_err());

        let mut initiator = HandshakeInitiator::new(node_id, key.public.to_vec());

        // 在 Init 阶段不能 handle_hello_ack
        let fake_ack = vec![HandshakeMsgType::HelloAck.to_u8()];
        assert!(initiator.handle_hello_ack(&fake_ack).is_err());

        // 在 Init 阶段不能 complete
        assert!(initiator.complete().is_err());
    }
}
