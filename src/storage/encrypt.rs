//! Encrypted chunk storage — AES-256-GCM authenticated encryption for block data.
//!
//! # Overview
//!
//! [`Encryptor`] encrypts and decrypts chunk data using AES-256-GCM (Galois/Counter
//! Mode).  Each chunk receives a **unique nonce** derived from its zero-based index
//! plus random bytes, ensuring that identical plaintext chunks produce distinct
//! ciphertexts.
//!
//! Backup nodes only ever see ciphertext — the encryption key lives exclusively in
//! the owner's memory and is never persisted.
//!
//! # Encryption format (per chunk)
//!
//! | Field      | Size   | Description                                |
//! |------------|--------|--------------------------------------------|
//! | nonce      | 12 B   | 4-byte LE chunk index + 8 random bytes     |
//! | ciphertext | var    | AES-256-GCM encrypted output (+ 16 B tag)  |
//!
//! The 12-byte nonce is stored alongside the ciphertext — it is **not secret**
//! and is required for decryption.  The 16-byte GCM authentication tag is
//! appended to the ciphertext by the underlying implementation and verified
//! during decryption.
//!
//! # Security properties
//!
//! * **Confidentiality** — AES-256 encrypts the payload.
//! * **Integrity + authentication** — GCM produces a 16-byte tag that detects
//!   any tampering with the ciphertext.
//! * **Nonce uniqueness** — Each chunk uses a different nonce because the chunk
//!   index is embedded in the first 4 bytes.  The 8 random bytes make the nonce
//!   effectively unique even if indices are reused across different files.
//! * **Key isolation** — The [`Encryptor`] holds the key in memory only; it is
//!   never serialized, logged, or written to disk.
//!
//! # Example
//!
//! ```ignore
//! use ll_vpn::storage::encrypt::Encryptor;
//!
//! let key = Encryptor::generate_key();
//! let enc = Encryptor::new(key);
//!
//! let plaintext = b"Hello, LL VPN!";
//! let encrypted = enc.encrypt(0, plaintext);
//! let decrypted = enc.decrypt(0, &encrypted).unwrap();
//! assert_eq!(decrypted, plaintext);
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    aead::generic_array::GenericArray,
    Aes256Gcm,
};
use rand::RngCore;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the AES-256 key in bytes (32 bytes = 256 bits).
pub const KEY_LEN: usize = 32;

/// Size of the GCM nonce in bytes (12 bytes = 96 bits, the standard for GCM).
pub const NONCE_LEN: usize = 12;

/// Size of the GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Number of random bytes in the nonce (the remainder after the chunk index).
const NONCE_RANDOM_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// A 256-bit AES key.
pub type Key = [u8; KEY_LEN];

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Encrypted chunk data with its nonce.
///
/// This struct holds everything needed to decrypt a chunk: the 12-byte nonce
/// (which embeds the chunk index for verification) and the ciphertext (which
/// includes the 16-byte GCM authentication tag appended by the encryptor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedChunk {
    /// 12-byte nonce: bytes 0..4 = chunk index (little-endian),
    /// bytes 4..12 = cryptographically random bytes.
    pub nonce: [u8; NONCE_LEN],

    /// Encrypted chunk data that includes the 16-byte GCM authentication tag
    /// appended at the end.  Total length = plaintext_len + [`TAG_LEN`].
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Encryptor
// ---------------------------------------------------------------------------

/// AES-256-GCM encryptor/decryptor for chunk-level data.
///
/// Holds a 256-bit key in memory and provides `encrypt` / `decrypt` methods
/// that operate on individual chunks identified by their zero-based index.
///
/// # Key management
///
/// Use [`Encryptor::generate_key`] to produce a cryptographically secure random
/// key.  The key is stored in a plain `[u8; 32]` and is **never serialized** by
/// this module — callers are responsible for keeping it secret.
#[derive(Debug, Clone)]
pub struct Encryptor {
    /// The AES-256 key, stored in memory only.
    key: Key,
}

impl Encryptor {
    /// Create a new [`Encryptor`] with the given 256-bit key.
    ///
    /// # Panics
    ///
    /// Panics at construction time if the cipher fails to initialise (this
    /// should never happen with a valid 32-byte key).
    pub fn new(key: Key) -> Self {
        // Validate the key by attempting to create a cipher instance.
        // This is a zero-cost sanity check — Aes256Gcm::new accepts any
        // 32-byte slice without fallible operations, but we run it here
        // to document the contract.
        let _cipher = Aes256Gcm::new_from_slice(&key)
            .expect("AES-256-GCM cipher initialisation with a 32-byte key");
        Self { key }
    }

    /// Generate a cryptographically secure random AES-256 key.
    ///
    /// Uses the OS-provided CSPRNG via `rand::rngs::OsRng`.
    pub fn generate_key() -> Key {
        let mut key = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt a chunk's plaintext data.
    ///
    /// `chunk_index` is the zero-based index of this chunk in the file.  It is
    /// embedded into the nonce so that every chunk gets a unique nonce (even
    /// when chunks hold identical data) and can be verified on decryption.
    ///
    /// Returns an [`EncryptedChunk`] containing the nonce and ciphertext
    /// (with the GCM authentication tag appended).
    ///
    /// # Panics
    ///
    /// Panics if AES-256-GCM encryption fails (should never happen with valid
    /// inputs).
    pub fn encrypt(&self, chunk_index: u32, plaintext: &[u8]) -> EncryptedChunk {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .expect("AES-256-GCM cipher initialisation");

        // Build nonce: 4 bytes LE chunk_index + 8 random bytes.
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..4].copy_from_slice(&chunk_index.to_le_bytes());
        rand::rngs::OsRng.fill_bytes(&mut nonce[4..]);

        let nonce_ref = GenericArray::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(nonce_ref, plaintext)
            .expect("AES-256-GCM encryption should never fail with valid parameters");

        EncryptedChunk {
            nonce,
            data: ciphertext,
        }
    }

    /// Decrypt an [`EncryptedChunk`], verifying its authentication tag.
    ///
    /// `chunk_index` is the expected zero-based chunk index.  It is checked
    /// against the index embedded in the nonce as a defence-in-depth measure.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The embedded chunk index in the nonce does not match `chunk_index`.
    /// - The GCM authentication tag is invalid (data tampered or wrong key).
    pub fn decrypt(
        &self,
        chunk_index: u32,
        encrypted: &EncryptedChunk,
    ) -> Result<Vec<u8>, String> {
        // Defence-in-depth: verify the chunk index embedded in the nonce.
        let stored_index = u32::from_le_bytes([
            encrypted.nonce[0],
            encrypted.nonce[1],
            encrypted.nonce[2],
            encrypted.nonce[3],
        ]);
        if stored_index != chunk_index {
            return Err(format!(
                "chunk index mismatch: nonce has {}, expected {}",
                stored_index, chunk_index
            ));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .expect("AES-256-GCM cipher initialisation");

        let nonce_ref = GenericArray::from_slice(&encrypted.nonce);
        cipher
            .decrypt(nonce_ref, encrypted.data.as_ref())
            .map_err(|_| {
                "decryption failed: authentication tag mismatch or wrong key".to_string()
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: generate deterministic test data of the requested length.
    fn test_data(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251) as u8).collect()
    }

    // -----------------------------------------------------------------------
    // Basic encrypt / decrypt round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let plaintext = b"Hello, LL VPN! This is a secret message.";
        let encrypted = enc.encrypt(0, plaintext);
        let decrypted = enc.decrypt(0, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_multiple_chunks() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let chunks = vec![
            b"First chunk data".to_vec(),
            b"Second chunk with different content".to_vec(),
            b"Third chunk! #$%^&*()".to_vec(),
        ];

        let encrypted: Vec<_> = chunks
            .iter()
            .enumerate()
            .map(|(i, data)| enc.encrypt(i as u32, data))
            .collect();

        for (i, expected) in chunks.iter().enumerate() {
            let decrypted = enc.decrypt(i as u32, &encrypted[i]).unwrap();
            assert_eq!(&decrypted, expected, "chunk {} mismatch", i);
        }
    }

    // -----------------------------------------------------------------------
    // Different key → cannot decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn different_key_cannot_decrypt() {
        let key1 = Encryptor::generate_key();
        let key2 = Encryptor::generate_key();
        let enc1 = Encryptor::new(key1);
        let enc2 = Encryptor::new(key2);

        let plaintext = b"Secret data";
        let encrypted = enc1.encrypt(0, plaintext);

        let result = enc2.decrypt(0, &encrypted);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    // -----------------------------------------------------------------------
    // Tampered ciphertext → authentication failure
    // -----------------------------------------------------------------------

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let plaintext = b"Important data -- do not modify";
        let mut encrypted = enc.encrypt(0, plaintext);

        // Flip a bit in the middle of the ciphertext.
        let mid = encrypted.data.len() / 2;
        encrypted.data[mid] ^= 0xFF;

        let result = enc.decrypt(0, &encrypted);
        assert!(result.is_err(), "decryption of tampered data should fail");
    }

    #[test]
    fn tampered_nonce_fails_auth() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let plaintext = b"More secret data";
        let mut encrypted = enc.encrypt(0, plaintext);

        // Flip a bit in the random portion of the nonce.
        encrypted.nonce[5] ^= 0x01;

        let result = enc.decrypt(0, &encrypted);
        assert!(
            result.is_err(),
            "decryption with tampered nonce should fail"
        );
    }

    // -----------------------------------------------------------------------
    // Different chunks have different nonces
    // -----------------------------------------------------------------------

    #[test]
    fn different_chunks_have_different_nonces() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let data = b"Same plaintext for all chunks";
        let encrypted_chunks: Vec<_> = (0..5)
            .map(|i| enc.encrypt(i, data))
            .collect();

        // Nonces should all differ (even with identical plaintext).
        for i in 0..encrypted_chunks.len() {
            for j in (i + 1)..encrypted_chunks.len() {
                assert_ne!(
                    encrypted_chunks[i].nonce, encrypted_chunks[j].nonce,
                    "chunks {} and {} have identical nonces", i, j
                );
            }
        }
    }

    #[test]
    fn different_chunks_have_embedded_index() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let data = b"check embedded index";
        for i in 0..10 {
            let encrypted = enc.encrypt(i, data);
            let stored_index = u32::from_le_bytes([
                encrypted.nonce[0],
                encrypted.nonce[1],
                encrypted.nonce[2],
                encrypted.nonce[3],
            ]);
            assert_eq!(stored_index, i, "embedded index mismatch for chunk {}", i);
        }
    }

    // -----------------------------------------------------------------------
    // Chunk index mismatch detected on decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn decrypt_wrong_index_fails() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let encrypted = enc.encrypt(5, b"data for chunk 5");

        // Try to decrypt with index 3 instead of 5.
        let result = enc.decrypt(3, & encrypted);
        assert!(result.is_err(), "decrypt with wrong index should fail");
        assert!(
            result.unwrap_err().contains("chunk index mismatch"),
            "error should mention index mismatch"
        );
    }

    // -----------------------------------------------------------------------
    // Empty data
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_empty_data() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let encrypted = enc.encrypt(0, b"");
        let decrypted = enc.decrypt(0, &encrypted).unwrap();

        assert!(decrypted.is_empty());
        // An empty plaintext should still produce a ciphertext with the tag.
        assert_eq!(encrypted.data.len(), TAG_LEN);
    }

    // -----------------------------------------------------------------------
    // Large data (1 MiB)
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_decrypt_large_data() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let plaintext = test_data(1024 * 1024); // 1 MiB
        let encrypted = enc.encrypt(0, &plaintext);
        let decrypted = enc.decrypt(0, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
        // Ciphertext = plaintext_len + TAG_LEN.
        assert_eq!(encrypted.data.len(), plaintext.len() + TAG_LEN);
    }

    // -----------------------------------------------------------------------
    // Key derivation consistency: same key → same ability to encrypt/decrypt
    // -----------------------------------------------------------------------

    #[test]
    fn same_key_consistent() {
        // Use a fixed, known key for reproducibility.
        let key: Key = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let enc1 = Encryptor::new(key);
        let enc2 = Encryptor::new(key);

        let plaintext = b"Consistency check";
        let encrypted = enc1.encrypt(0, plaintext);
        let decrypted = enc2.decrypt(0, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    // -----------------------------------------------------------------------
    // Encryptor::generate_key produces non-zero keys
    // -----------------------------------------------------------------------

    #[test]
    fn generate_key_produces_non_zero() {
        let key = Encryptor::generate_key();
        assert!(
            key.iter().any(|&b| b != 0),
            "generated key should not be all zeros"
        );
    }

    #[test]
    fn generate_key_produces_unique_keys() {
        let key1 = Encryptor::generate_key();
        let key2 = Encryptor::generate_key();
        assert_ne!(key1, key2, "two generated keys should be different");
    }

    // -----------------------------------------------------------------------
    // EncryptedChunk sizes
    // -----------------------------------------------------------------------

    #[test]
    fn encrypted_chunk_size_is_plaintext_plus_tag() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        for len in [0, 1, 100, 1000, 10_000] {
            let plaintext = vec![0xABu8; len];
            let encrypted = enc.encrypt(42, &plaintext);
            assert_eq!(
                encrypted.data.len(),
                len + TAG_LEN,
                "ciphertext length mismatch for plaintext len {}",
                len
            );
        }
    }

    // -----------------------------------------------------------------------
    // Nonce length is correct
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_length_is_twelve_bytes() {
        let key = Encryptor::generate_key();
        let enc = Encryptor::new(key);

        let encrypted = enc.encrypt(0, b"test");
        assert_eq!(encrypted.nonce.len(), NONCE_LEN);
    }
}
