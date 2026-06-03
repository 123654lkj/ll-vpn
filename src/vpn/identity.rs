//! P0-pre: 节点 ID 生成
//!
//! 基于 Ed25519 公钥生成 32 字节节点 ID，
//! 用于 Yggdrasil 路由算法的坐标计算。

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::Path;

/// 32 字节节点 ID，基于 Ed25519 公钥的 SHA-256 哈希
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeID([u8; 32]);

impl NodeID {
    /// 从 Ed25519 公钥生成节点 ID
    pub fn from_public_key(key: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&hash);
        NodeID(id)
    }

    /// 从原始字节数组创建节点 ID
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        NodeID(*bytes)
    }

    /// 转换为十六进制字符串（便于调试和显示）
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// 计算两个节点 ID 之间的距离（用于 Yggdrasil 路由）
    /// 使用 XOR 距离，返回浮点数便于比较
    pub fn distance(&self, other: &NodeID) -> f64 {
        let mut dist: u128 = 0;
        for i in 0..32 {
            dist = (dist << 8) | (self.0[i] ^ other.0[i]) as u128;
        }
        dist as f64
    }

    /// 获取原始字节引用
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 从十六进制字符串解析节点 ID
    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(NodeID(id))
    }

    /// 生成新的随机节点 ID（配合 Ed25519 密钥对使用）
    pub fn generate() -> (Self, ed25519_dalek::SigningKey) {
        use rand::rngs::OsRng;
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let node_id = Self::from_public_key(&verifying_key);
        (node_id, signing_key)
    }

    /// 持久化节点 ID 和密钥到文件
    pub fn save(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        path: &Path,
    ) -> std::io::Result<()> {
        let data = serde_json::json!({
            "node_id": self.to_hex(),
            "secret_key": hex::encode(signing_key.to_bytes()),
        });
        fs::write(path, serde_json::to_string_pretty(&data).unwrap())
    }

    /// 从文件加载节点 ID 和密钥
    pub fn load(path: &Path) -> std::io::Result<(Self, ed25519_dalek::SigningKey)> {
        let data = fs::read_to_string(path)?;
        let json: serde_json::Value = serde_json::from_str(&data)?;

        let node_id_hex = json["node_id"].as_str().unwrap();
        let secret_hex = json["secret_key"].as_str().unwrap();

        let node_id = NodeID::from_hex(node_id_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let secret_bytes = hex::decode(secret_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&secret_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);

        Ok((node_id, signing_key))
    }
}

impl fmt::Debug for NodeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeID({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for NodeID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_from_public_key() {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let node_id = NodeID::from_public_key(&verifying_key);

        assert_eq!(node_id.as_bytes().len(), 32);
        assert!(!node_id.to_hex().is_empty());
    }

    #[test]
    fn test_node_id_hex_roundtrip() {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let node_id = NodeID::from_public_key(&verifying_key);

        let hex_str = node_id.to_hex();
        let recovered = NodeID::from_hex(&hex_str).unwrap();
        assert_eq!(node_id, recovered);
    }

    #[test]
    fn test_node_id_distance_symmetric() {
        let mut bytes1 = [0u8; 32];
        let mut bytes2 = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes1);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes2);
        let sk1 = ed25519_dalek::SigningKey::from_bytes(&bytes1);
        let sk2 = ed25519_dalek::SigningKey::from_bytes(&bytes2);

        let id1 = NodeID::from_public_key(&sk1.verifying_key());
        let id2 = NodeID::from_public_key(&sk2.verifying_key());

        assert_eq!(id1.distance(&id2), id2.distance(&id1));
    }

    #[test]
    fn test_node_id_distance_self_zero() {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let id = NodeID::from_public_key(&sk.verifying_key());

        assert_eq!(id.distance(&id), 0.0);
    }

    #[test]
    fn test_node_id_generate_and_save_load() {
        use std::env;
        let (node_id, signing_key) = NodeID::generate();
        let path = env::temp_dir().join("test_node_id.json");

        node_id.save(&signing_key, &path).unwrap();
        let (loaded_id, loaded_key) = NodeID::load(&path).unwrap();

        assert_eq!(node_id, loaded_id);
        assert_eq!(
            signing_key.verifying_key().to_bytes(),
            loaded_key.verifying_key().to_bytes()
        );

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_node_id_deterministic_from_key() {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let vk = sk.verifying_key();

        let id1 = NodeID::from_public_key(&vk);
        let id2 = NodeID::from_public_key(&vk);

        assert_eq!(id1, id2);
    }
}
