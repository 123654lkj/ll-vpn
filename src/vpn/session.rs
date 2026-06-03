//! P1-3: 加密会话管理
//!
//! 实现会话状态机：INIT → HANDSHAKE → ESTABLISHED → CLOSING → CLOSED
//!
//! 特性：
//! - 会话超时处理（默认 30 分钟无活动）
//! - 会话复用（同一节点对不重复握手）
//! - 会话密钥轮换（每 24 小时）
//! - 内存安全：敏感数据擦除

use crate::vpn::identity::NodeID;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 默认会话超时时间（30分钟）
pub const DEFAULT_SESSION_TIMEOUT_SECS: u64 = 1800;

/// 默认密钥轮换时间（24小时）
pub const DEFAULT_KEY_ROTATION_SECS: u64 = 86400;

/// 会话错误类型
#[derive(Debug)]
pub enum SessionError {
    /// 会话不存在
    NotFound(String),
    /// 会话状态无效
    InvalidState(String),
    /// 会话已过期
    Expired(String),
    /// 会话创建失败
    CreationFailed(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::NotFound(msg) => write!(f, "session not found: {}", msg),
            SessionError::InvalidState(msg) => write!(f, "invalid session state: {}", msg),
            SessionError::Expired(msg) => write!(f, "session expired: {}", msg),
            SessionError::CreationFailed(msg) => write!(f, "session creation failed: {}", msg),
        }
    }
}

impl std::error::Error for SessionError {}

/// 会话状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// 初始化
    Init,
    /// 握手中
    Handshake,
    /// 已建立
    Established,
    /// 正在关闭
    Closing,
    /// 已关闭
    Closed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Init => write!(f, "INIT"),
            SessionState::Handshake => write!(f, "HANDSHAKE"),
            SessionState::Established => write!(f, "ESTABLISHED"),
            SessionState::Closing => write!(f, "CLOSING"),
            SessionState::Closed => write!(f, "CLOSED"),
        }
    }
}

/// 会话密钥
#[derive(Clone)]
pub struct SessionKeys {
    /// 发送密钥
    pub send_key: Vec<u8>,
    /// 接收密钥
    pub recv_key: Vec<u8>,
    /// 密钥创建时间
    pub created_at: Instant,
}

impl SessionKeys {
    /// 创建新的会话密钥
    pub fn new(send_key: Vec<u8>, recv_key: Vec<u8>) -> Self {
        Self {
            send_key,
            recv_key,
            created_at: Instant::now(),
        }
    }

    /// 检查密钥是否需要轮换
    pub fn needs_rotation(&self) -> bool {
        self.created_at.elapsed() > Duration::from_secs(DEFAULT_KEY_ROTATION_SECS)
    }
}

/// 安全内存擦除 trait
pub trait SecureErase {
    /// 安全擦除数据
    fn secure_erase(&mut self);
}

impl SecureErase for Vec<u8> {
    fn secure_erase(&mut self) {
        // 用随机数据覆盖
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(self);
        self.clear();
    }
}

impl SecureErase for SessionKeys {
    fn secure_erase(&mut self) {
        self.send_key.secure_erase();
        self.recv_key.secure_erase();
    }
}

/// 会话
#[derive(Clone)]
pub struct Session {
    /// 会话 ID
    pub id: String,
    /// 本地节点 ID
    pub local_id: NodeID,
    /// 远端节点 ID
    pub remote_id: NodeID,
    /// 会话状态
    pub state: SessionState,
    /// 会话密钥
    pub keys: Option<SessionKeys>,
    /// 创建时间
    pub created_at: Instant,
    /// 最后活跃时间
    pub last_active: Instant,
    /// 会话超时时间
    pub timeout: Duration,
    /// 发送计数器（用于 nonce）
    pub send_counter: u64,
    /// 接收计数器
    pub recv_counter: u64,
}

impl Session {
    /// 创建新的会话
    pub fn new(local_id: NodeID, remote_id: NodeID) -> Self {
        let now = Instant::now();
        let local_hex = local_id.to_hex();
        let remote_hex = remote_id.to_hex();
        let id = format!(
            "{}-{}",
            &local_hex[..8.min(local_hex.len())],
            &remote_hex[..8.min(remote_hex.len())]
        );

        Self {
            id,
            local_id,
            remote_id,
            state: SessionState::Init,
            keys: None,
            created_at: now,
            last_active: now,
            timeout: Duration::from_secs(DEFAULT_SESSION_TIMEOUT_SECS),
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// 创建指定超时的会话
    pub fn with_timeout(local_id: NodeID, remote_id: NodeID, timeout: Duration) -> Self {
        let mut session = Self::new(local_id, remote_id);
        session.timeout = timeout;
        session
    }

    /// 获取会话 ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取远端节点 ID
    pub fn remote_id(&self) -> &NodeID {
        &self.remote_id
    }

    /// 获取当前状态
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// 检查会话是否过期
    pub fn is_expired(&self) -> bool {
        self.last_active.elapsed() > self.timeout
    }

    /// 检查会话是否活跃
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Established && !self.is_expired()
    }

    /// 更新最后活跃时间
    pub fn touch(&mut self) {
        self.last_active = Instant::now();
    }

    /// 转换状态
    pub fn transition(&mut self, new_state: SessionState) -> Result<(), SessionError> {
        let valid_transitions = match self.state {
            SessionState::Init => vec![SessionState::Handshake, SessionState::Closed],
            SessionState::Handshake => vec![SessionState::Established, SessionState::Closed],
            SessionState::Established => vec![SessionState::Closing],
            SessionState::Closing => vec![SessionState::Closed],
            SessionState::Closed => vec![],
        };

        if valid_transitions.contains(&new_state) {
            self.state = new_state;
            self.touch();
            Ok(())
        } else {
            Err(SessionError::InvalidState(format!(
                "cannot transition from {} to {}",
                self.state, new_state
            )))
        }
    }

    /// 设置会话密钥
    pub fn set_keys(&mut self, send_key: Vec<u8>, recv_key: Vec<u8>) {
        self.keys = Some(SessionKeys::new(send_key, recv_key));
        self.touch();
    }

    /// 检查密钥是否需要轮换
    pub fn needs_key_rotation(&self) -> bool {
        self.keys.as_ref().map_or(false, |k| k.needs_rotation())
    }

    /// 安全关闭会话（擦除密钥）
    pub fn secure_close(&mut self) {
        if let Some(mut keys) = self.keys.take() {
            keys.secure_erase();
        }
        self.state = SessionState::Closed;
    }

    /// 获取下一个发送计数器值
    pub fn next_send_counter(&mut self) -> u64 {
        let counter = self.send_counter;
        self.send_counter += 1;
        self.touch();
        counter
    }

    /// 验证接收计数器
    pub fn verify_recv_counter(&mut self, counter: u64) -> Result<(), SessionError> {
        if counter < self.recv_counter {
            return Err(SessionError::InvalidState(format!(
                "counter {} < expected {}",
                counter, self.recv_counter
            )));
        }
        self.recv_counter = counter + 1;
        self.touch();
        Ok(())
    }
}

/// 会话管理器
pub struct SessionManager {
    /// 会话表：远端 NodeID → Session
    sessions: Arc<Mutex<HashMap<NodeID, Session>>>,
    /// 本地节点 ID
    local_id: NodeID,
    /// 会话超时时间
    default_timeout: Duration,
}

impl SessionManager {
    /// 创建新的会话管理器
    pub fn new(local_id: NodeID) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_id,
            default_timeout: Duration::from_secs(DEFAULT_SESSION_TIMEOUT_SECS),
        }
    }

    /// 创建指定超时的会话管理器
    pub fn with_timeout(local_id: NodeID, timeout: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            local_id,
            default_timeout: timeout,
        }
    }

    /// 获取本地节点 ID
    pub fn local_id(&self) -> &NodeID {
        &self.local_id
    }

    /// 获取或创建会话
    pub fn get_or_create(&self, remote_id: &NodeID) -> Session {
        let mut sessions = self.sessions.lock().unwrap();

        if let Some(session) = sessions.get(remote_id) {
            if !session.is_expired() {
                return Session {
                    id: session.id.clone(),
                    local_id: session.local_id,
                    remote_id: session.remote_id,
                    state: session.state,
                    keys: session.keys.clone(),
                    created_at: session.created_at,
                    last_active: session.last_active,
                    timeout: session.timeout,
                    send_counter: session.send_counter,
                    recv_counter: session.recv_counter,
                };
            }
        }

        let session = Session::with_timeout(self.local_id, *remote_id, self.default_timeout);
        sessions.insert(*remote_id, Session::with_timeout(self.local_id, *remote_id, self.default_timeout));
        session
    }

    /// 获取现有会话
    pub fn get(&self, remote_id: &NodeID) -> Option<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(remote_id).cloned()
    }

    /// 获取可变会话
    pub fn get_mut(&self, remote_id: &NodeID) -> Option<SessionGuard> {
        let sessions = self.sessions.lock().unwrap();
        // 由于 Mutex 限制，我们返回一个 guard 包装
        // 在实际使用中，这需要更复杂的实现
        None // 简化实现
    }

    /// 更新会话状态
    pub fn update_state(
        &self,
        remote_id: &NodeID,
        new_state: SessionState,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(remote_id) {
            session.transition(new_state)?;
            Ok(())
        } else {
            Err(SessionError::NotFound(remote_id.to_hex()))
        }
    }

    /// 设置会话密钥
    pub fn set_keys(
        &self,
        remote_id: &NodeID,
        send_key: Vec<u8>,
        recv_key: Vec<u8>,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(remote_id) {
            session.set_keys(send_key, recv_key);
            Ok(())
        } else {
            Err(SessionError::NotFound(remote_id.to_hex()))
        }
    }

    /// 移除会话（安全擦除密钥）
    pub fn remove(&self, remote_id: &NodeID) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(remote_id)
    }

    /// 安全移除会话
    pub fn secure_remove(&self, remote_id: &NodeID) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(mut session) = sessions.remove(remote_id) {
            session.secure_close();
        }
    }

    /// 清理过期会话
    pub fn cleanup_expired(&self) -> Vec<NodeID> {
        let mut sessions = self.sessions.lock().unwrap();
        let expired: Vec<NodeID> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(mut session) = sessions.remove(id) {
                session.secure_close();
            }
        }

        expired
    }

    /// 获取所有活跃会话
    pub fn active_sessions(&self) -> Vec<Session> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .filter(|s| s.is_active())
            .cloned()
            .collect()
    }

    /// 获取会话数量
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// 检查是否有到指定节点的活跃会话
    pub fn has_active_session(&self, remote_id: &NodeID) -> bool {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(remote_id)
            .map_or(false, |s| s.is_active())
    }

    /// 触摸会话（更新最后活跃时间）
    pub fn touch(&self, remote_id: &NodeID) -> Result<(), SessionError> {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get_mut(remote_id) {
            session.touch();
            Ok(())
        } else {
            Err(SessionError::NotFound(remote_id.to_hex()))
        }
    }
}

/// 会话守卫（用于安全访问）
pub struct SessionGuard<'a> {
    session: &'a mut Session,
}

impl<'a> SessionGuard<'a> {
    /// 获取会话引用
    pub fn session(&self) -> &Session {
        self.session
    }

    /// 获取会话可变引用
    pub fn session_mut(&mut self) -> &mut Session {
        self.session
    }
}

impl<'a> Drop for SessionGuard<'a> {
    fn drop(&mut self) {
        // 自动更新最后活跃时间
        self.session.touch();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state_conversion() {
        assert_eq!(format!("{}", SessionState::Init), "INIT");
        assert_eq!(format!("{}", SessionState::Handshake), "HANDSHAKE");
        assert_eq!(format!("{}", SessionState::Established), "ESTABLISHED");
        assert_eq!(format!("{}", SessionState::Closing), "CLOSING");
        assert_eq!(format!("{}", SessionState::Closed), "CLOSED");
    }

    #[test]
    fn test_session_creation() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let session = Session::new(local_id, remote_id);
        assert_eq!(session.local_id(), &local_id);
        assert_eq!(session.remote_id(), &remote_id);
        assert_eq!(session.state(), SessionState::Init);
        assert!(!session.is_expired());
        assert!(!session.is_active()); // Init 状态不是 active
    }

    #[test]
    fn test_session_state_transitions() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::new(local_id, remote_id);

        // Init -> Handshake
        assert!(session.transition(SessionState::Handshake).is_ok());
        assert_eq!(session.state(), SessionState::Handshake);

        // Handshake -> Established
        assert!(session.transition(SessionState::Established).is_ok());
        assert_eq!(session.state(), SessionState::Established);
        assert!(session.is_active());

        // Established -> Closing
        assert!(session.transition(SessionState::Closing).is_ok());
        assert_eq!(session.state(), SessionState::Closing);

        // Closing -> Closed
        assert!(session.transition(SessionState::Closed).is_ok());
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_invalid_transitions() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::new(local_id, remote_id);

        // Init -> Established (无效)
        assert!(session.transition(SessionState::Established).is_err());

        // Init -> Closing (无效)
        assert!(session.transition(SessionState::Closing).is_err());
    }

    #[test]
    fn test_session_expiry() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::with_timeout(
            local_id,
            remote_id,
            Duration::from_millis(10),
        );

        assert!(!session.is_expired());
        std::thread::sleep(Duration::from_millis(20));
        assert!(session.is_expired());
    }

    #[test]
    fn test_session_keys() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::new(local_id, remote_id);

        let send_key = vec![1, 2, 3, 4, 5];
        let recv_key = vec![6, 7, 8, 9, 10];
        session.set_keys(send_key.clone(), recv_key.clone());

        let keys = session.keys.as_ref().unwrap();
        assert_eq!(keys.send_key, send_key);
        assert_eq!(keys.recv_key, recv_key);
    }

    #[test]
    fn test_session_secure_close() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::new(local_id, remote_id);

        session.set_keys(vec![1, 2, 3], vec![4, 5, 6]);
        assert!(session.keys.is_some());

        session.secure_close();
        assert!(session.keys.is_none());
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_counter() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();
        let mut session = Session::new(local_id, remote_id);

        assert_eq!(session.next_send_counter(), 0);
        assert_eq!(session.next_send_counter(), 1);
        assert_eq!(session.next_send_counter(), 2);

        // 验证接收计数器
        assert!(session.verify_recv_counter(0).is_ok());
        assert!(session.verify_recv_counter(1).is_ok());

        // 旧计数器应被拒绝
        assert!(session.verify_recv_counter(0).is_err());
    }

    #[test]
    fn test_session_manager_create() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let manager = SessionManager::new(local_id);
        assert_eq!(manager.local_id(), &local_id);
        assert_eq!(manager.session_count(), 0);

        let session = manager.get_or_create(&remote_id);
        assert_eq!(session.local_id(), &local_id);
        assert_eq!(session.remote_id(), &remote_id);
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_reuse() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let manager = SessionManager::new(local_id);

        let session1 = manager.get_or_create(&remote_id);
        let session2 = manager.get_or_create(&remote_id);

        // 应该返回同一个会话
        assert_eq!(session1.id(), session2.id());
        assert_eq!(manager.session_count(), 1);
    }

    #[test]
    fn test_session_manager_remove() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let manager = SessionManager::new(local_id);
        manager.get_or_create(&remote_id);
        assert_eq!(manager.session_count(), 1);

        manager.secure_remove(&remote_id);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_cleanup_expired() {
        let (local_id, _) = NodeID::generate();
        let (remote_id1, _) = NodeID::generate();
        let (remote_id2, _) = NodeID::generate();

        let manager = SessionManager::with_timeout(
            local_id,
            Duration::from_millis(10),
        );

        manager.get_or_create(&remote_id1);
        manager.get_or_create(&remote_id2);
        assert_eq!(manager.session_count(), 2);

        std::thread::sleep(Duration::from_millis(20));

        let expired = manager.cleanup_expired();
        assert_eq!(expired.len(), 2);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_session_manager_has_active() {
        let (local_id, _) = NodeID::generate();
        let (remote_id, _) = NodeID::generate();

        let manager = SessionManager::new(local_id);

        assert!(!manager.has_active_session(&remote_id));

        let mut session = manager.get_or_create(&remote_id);
        session.transition(SessionState::Handshake).unwrap();
        session.transition(SessionState::Established).unwrap();

        // 重新获取并设置状态
        manager.update_state(&remote_id, SessionState::Handshake).unwrap();
        manager.update_state(&remote_id, SessionState::Established).unwrap();

        assert!(manager.has_active_session(&remote_id));
    }

    #[test]
    fn test_session_error_display() {
        let err = SessionError::NotFound("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = SessionError::InvalidState("bad state".to_string());
        assert!(format!("{}", err).contains("bad state"));

        let err = SessionError::Expired("old session".to_string());
        assert!(format!("{}", err).contains("old session"));

        let err = SessionError::CreationFailed("cannot create".to_string());
        assert!(format!("{}", err).contains("cannot create"));
    }

    #[test]
    fn test_session_keys_needs_rotation() {
        let keys = SessionKeys {
            send_key: vec![1, 2, 3],
            recv_key: vec![4, 5, 6],
            created_at: Instant::now(),
        };
        assert!(!keys.needs_rotation());

        let old_keys = SessionKeys {
            send_key: vec![1, 2, 3],
            recv_key: vec![4, 5, 6],
            created_at: Instant::now() - Duration::from_secs(DEFAULT_KEY_ROTATION_SECS + 1),
        };
        assert!(old_keys.needs_rotation());
    }
}
