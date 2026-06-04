//! Storage module — data persistence and chunk management for LL VPN.
//!
//! This module provides the chunking layer that splits files into fixed-size
//! blocks, tracks them via a content-addressed manifest, and supports
//! integrity verification.  It is the foundation for distributed file storage
//! over the DHT layer.

pub mod chunk;
pub mod diff;
pub mod download;
pub mod encrypt;
pub mod gc;
pub mod incremental;
pub mod metadata;
pub mod version;
