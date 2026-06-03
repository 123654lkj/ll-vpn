//! P3-1: 名字注册中心
//!
//! 提供去中心化的名字 → NodeID 映射服务。
//! 包含注册中心服务端、客户端、缓存和消息序列化。
//!
//! P3-2: 注册中心自动选举机制
//!
//! 基于 Raft 思想的注册中心选举，确保注册中心高可用。

pub mod center;
pub mod election;
pub use center::*;
pub use election::*;
