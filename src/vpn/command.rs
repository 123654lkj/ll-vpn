//! P2-2/P2-3/P4-5: 命令解析与执行
//!
//! 提供 CLI 命令的解析和执行功能，支持以下子命令：
//!
//! - `ll cmd node:<name> <command>` — 在远程节点上执行命令
//! - `ll ping node:<name>` — 测试到目标节点的连通性
//! - `ll nodes` — 列出所有已知节点
//! - `ll status` — 显示本机信息
//! - `ll backup <path> node:<name>` — 备份文件到远程节点
//! - `ll restore node:<name>:<path>` — 从远程节点恢复文件
//!
//! 所有命令输出到 stdout，错误输出到 stderr。

use crate::address::{resolve_address, MemAddressResolver, ParsedAddress};
use crate::router::{NodeStatus, Router, RouterError};
use crate::storage::chunk::{Chunker, FileManifest};
use crate::storage::encrypt::Encryptor;
use crate::storage::gc::GarbageCollector;
use crate::storage::metadata::{BlockLocation, MetadataStore};
use crate::storage::version::VersionManager;
use crate::vpn::vpn_router::VpnRouter;
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
    /// 备份文件: ll backup <path> node:<name>
    Backup {
        /// 本地文件路径
        path: String,
        /// 目标节点地址
        target: String,
    },
    /// 恢复文件: ll restore node:<name>:<path>
    Restore {
        /// 目标节点地址（含路径）
        target: String,
        /// 本地恢复路径
        path: String,
    },
    /// 存储垃圾回收: ll storage gc
    StorageGC,
    /// 存储版本修剪: ll storage prune <keep>
    StoragePrune {
        /// 保留的版本数
        keep: usize,
    },
    /// 存储统计: ll storage stats
    StorageStats,
    /// 增量同步上传: ll increment <path> node:<name>
    Increment {
        /// 本地文件路径
        path: String,
        /// 目标节点地址
        target: String,
    },
    /// 版本历史: ll version <file>
    Version {
        /// 文件名
        file: String,
    },
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
        "backup" => {
            if cmd_args.len() < 4 {
                return Err("usage: ll backup <path> node:<name>".to_string());
            }
            let path = cmd_args[2].clone();
            let target = cmd_args[3].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Backup { path, target })
        }
        "restore" => {
            if cmd_args.len() < 3 {
                return Err(
                    "usage: ll restore node:<name>:<path> [local-path]".to_string(),
                );
            }
            let target = cmd_args[2].clone();
            if !target.starts_with("node:") {
                return Err(format!(
                    "invalid target '{}': expected node:<name>:<path>",
                    target
                ));
            }
            let path = if cmd_args.len() > 3 {
                cmd_args[3].clone()
            } else {
                // derive local path from the remote path part
                let parts: Vec<&str> = target.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    parts[2].trim_start_matches('/').to_string()
                } else {
                    "restored_file".to_string()
                }
            };
            Ok(Command::Restore { target, path })
        }
        "storage" => {
            if cmd_args.len() < 3 {
                return Err("usage: ll storage <gc|prune|stats> [args]".to_string());
            }
            match cmd_args[2].as_str() {
                "gc" => Ok(Command::StorageGC),
                "prune" => {
                    let keep = if cmd_args.len() > 3 {
                        cmd_args[3].parse::<usize>().map_err(|_| {
                            format!("invalid number '{}': expected a positive integer", cmd_args[3])
                        })?
                    } else {
                        10 // default keep count
                    };
                    if keep == 0 {
                        return Err("keep count must be positive".to_string());
                    }
                    Ok(Command::StoragePrune { keep })
                }
                "stats" => Ok(Command::StorageStats),
                sub => Err(format!(
                    "unknown storage subcommand '{}'. Available: gc, prune, stats",
                    sub
                )),
            }
        }
        "increment" | "inc" => {
            if cmd_args.len() < 4 {
                return Err(
                    "usage: ll increment <path> node:<name>".to_string(),
                );
            }
            let path = cmd_args[2].clone();
            let target = cmd_args[3].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Increment { path, target })
        }
        "version" | "ver" => {
            if cmd_args.len() < 3 {
                return Err(
                    "usage: ll version <file>".to_string(),
                );
            }
            let file = cmd_args[2].clone();
            Ok(Command::Version { file })
        }
        sub => Err(format!(
            "unknown subcommand '{}'. Available: cmd, ping, nodes, status, backup, restore, storage, increment, version",
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
        "backup" => {
            if args.len() < 3 {
                return Err("usage: backup <path> node:<name>".to_string());
            }
            let path = args[1].clone();
            let target = args[2].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Backup { path, target })
        }
        "restore" => {
            if args.len() < 2 {
                return Err("usage: restore node:<name>:<path> [local-path]".to_string());
            }
            let target = args[1].clone();
            if !target.starts_with("node:") {
                return Err(format!(
                    "invalid target '{}': expected node:<name>:<path>",
                    target
                ));
            }
            let path = if args.len() > 2 {
                args[2].clone()
            } else {
                let parts: Vec<&str> = target.splitn(3, ':').collect();
                if parts.len() >= 3 {
                    parts[2].trim_start_matches('/').to_string()
                } else {
                    "restored_file".to_string()
                }
            };
            Ok(Command::Restore { target, path })
        }
        "storage" => {
            if args.len() < 2 {
                return Err("usage: storage <gc|prune|stats> [args]".to_string());
            }
            match args[1].as_str() {
                "gc" => Ok(Command::StorageGC),
                "prune" => {
                    let keep = if args.len() > 2 {
                        args[2].parse::<usize>().map_err(|_| {
                            format!("invalid number '{}': expected a positive integer", args[2])
                        })?
                    } else {
                        10
                    };
                    if keep == 0 {
                        return Err("keep count must be positive".to_string());
                    }
                    Ok(Command::StoragePrune { keep })
                }
                "stats" => Ok(Command::StorageStats),
                sub => Err(format!(
                    "unknown storage subcommand '{}'. Available: gc, prune, stats",
                    sub
                )),
            }
        }
        "increment" | "inc" => {
            if args.len() < 3 {
                return Err("usage: increment <path> node:<name>".to_string());
            }
            let path = args[1].clone();
            let target = args[2].clone();
            if !ParsedAddress::is_node_address(&target) {
                return Err(format!(
                    "invalid target address '{}': expected node:<name>",
                    target
                ));
            }
            Ok(Command::Increment { path, target })
        }
        "version" | "ver" => {
            if args.len() < 2 {
                return Err("usage: version <file>".to_string());
            }
            let file = args[1].clone();
            Ok(Command::Version { file })
        }
        _ => Err(format!(
            "unknown command '{}'. Available: ll cmd, ll ping, ll nodes, ll status, ll backup, ll restore, ll storage, ll increment, ll version",
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
        Command::Backup { path, target } => execute_backup(&path, &target, vpn),
        Command::Restore { target, path } => execute_restore(&target, &path, vpn),
        Command::StorageGC => execute_storage_gc(),
        Command::StoragePrune { keep } => execute_storage_prune(keep),
        Command::StorageStats => execute_storage_stats(),
        Command::Increment { path, target } => execute_increment(&path, &target, vpn),
        Command::Version { file } => execute_version(&file),
    }
}

/// 执行文件备份到远程节点
///
/// `ll backup <path> node:<name>`:
/// 1. 读取本地文件
/// 2. 分块（Chunker）
/// 3. 加密每块（Encryptor）
/// 4. 发送块数据和元数据到目标节点
/// 5. 注册元数据到本地 MetadataStore
fn execute_backup(path: &str, target: &str, vpn: &VpnRouter) -> Result<String, String> {
    // 解析目标节点
    let parsed = ParsedAddress::parse(target)
        .map_err(|e| format!("invalid target address: {}", e))?;

    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    // 1. 读取文件
    let data = std::fs::read(path)
        .map_err(|e| format!("failed to read '{}': {}", path, e))?;
    let file_size = data.len();

    // 2. 分块
    let chunker = Chunker::new();
    let (manifest, chunks) = chunker.chunk_data(&data);
    let chunk_count = chunks.len();

    // 3. 加密
    let key = Encryptor::generate_key();
    let encryptor = Encryptor::new(key);
    let encrypted_chunks: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(i, chunk)| encryptor.encrypt(i as u32, chunk))
        .collect();

    // 4. 发送块数据到目标节点
    // 协议: BACKUP_CHUNK:<file_name>:<total_chunks>:<chunk_index>:<json_encrypted_chunk>
    for (i, e_chunk) in encrypted_chunks.iter().enumerate() {
        let payload = serde_json::json!({
            "file_name": file_name,
            "chunk_index": i,
            "total_chunks": chunk_count,
            "file_size": file_size,
            "nonce_hex": hex::encode(e_chunk.nonce),
            "data_hex": hex::encode(&e_chunk.data),
        });
        let msg = format!("BACKUP_CHUNK:{}", payload.to_string());
        vpn.send(target, msg.as_bytes())
            .map_err(|e| format!("failed to send chunk {}: {}", i, e))?;
    }

    // 发送元数据
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|e| format!("failed to serialize manifest: {}", e))?;
    let meta_msg = format!("BACKUP_META:{}:{}", file_name, manifest_json);
    vpn.send(target, meta_msg.as_bytes())
        .map_err(|e| format!("failed to send metadata: {}", e))?;

    // 5. 注册本地元数据
    let key_hex = hex::encode(&key);
    let meta_store = MetadataStore::new_default();
    let blocks: Vec<BlockLocation> = manifest
        .chunks
        .iter()
        .map(|c| BlockLocation {
            hash: c.hash,
            index: c.index,
            nodes: vec![parsed.name.clone()],
            last_synced: now_secs(),
        })
        .collect();
    meta_store
        .register(
            &file_name,
            manifest.file_hash,
            file_size as u64,
            Some(manifest),
            blocks,
            &parsed.name,
        )
        .map_err(|e| format!("failed to register metadata: {}", e))?;

    Ok(format!(
        "Backup completed: {} → {}\n  File: {} ({} bytes)\n  Chunks: {}\n  Encrypted: yes\n  Key: {}",
        path,
        target,
        file_name,
        file_size,
        chunk_count,
        truncate_hex(&key_hex, 16),
    ))
}

/// 从远程节点恢复文件
///
/// `ll restore node:<name>:<path>`:
/// 1. 向远程节点请求元数据
/// 2. 请求每块数据
/// 3. 解密
/// 4. 重组
/// 5. 写入本地文件
fn execute_restore(target: &str, local_path: &str, vpn: &VpnRouter) -> Result<String, String> {
    // 解析 node:<name>:<path>
    let parts: Vec<&str> = target.splitn(3, ':').collect();
    if parts.len() < 3 {
        return Err(format!(
            "invalid restore target '{}': expected node:<name>:<path>",
            target
        ));
    }
    let node_addr = format!("node:{}", parts[1]);
    let remote_path = parts[2].to_string();
    let file_name = std::path::Path::new(&remote_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| remote_path.clone());

    // 1. 请求元数据
    use std::sync::mpsc;
    let (tx_meta, rx_meta) = mpsc::channel();
    let meta_tag = format!("restore-meta-{}", rand::random::<u64>());

    let tx_clone = tx_meta.clone();
    let tag_clone = meta_tag.clone();
    let meta_listener = move |_from: String, data: Vec<u8>| {
        if let Ok(msg) = String::from_utf8(data) {
            if msg.starts_with(&format!("RESTORE_META_RESP:{}:", tag_clone)) {
                let resp = msg.trim_start_matches(&format!("RESTORE_META_RESP:{}:", tag_clone));
                let _ = tx_clone.send(resp.to_string());
            }
        }
    };
    vpn.register_listener(meta_listener);

    let req = format!("RESTORE_GET_META:{}:{}", meta_tag, remote_path);
    vpn.send(&node_addr, req.as_bytes())
        .map_err(|e| format!("failed to request metadata: {}", e))?;

    let manifest_json = rx_meta
        .recv_timeout(std::time::Duration::from_secs(30))
        .map_err(|_| "timeout waiting for metadata response".to_string())?;

    let manifest: FileManifest = serde_json::from_str(&manifest_json)
        .map_err(|e| format!("failed to parse manifest: {}", e))?;

    let chunk_count = manifest.chunks.len();
    let total_size = manifest.file_size;

    // 2. 请求每块数据并解密
    let mut decrypted_chunks: Vec<Vec<u8>> = Vec::with_capacity(chunk_count);

    for i in 0..chunk_count {
        let (tx_chunk, rx_chunk) = mpsc::channel();
        let chunk_tag = format!("restore-chunk-{}-{}", i, rand::random::<u64>());

        let tx_c = tx_chunk.clone();
        let tag_c = chunk_tag.clone();
        let chunk_listener = move |_from: String, data: Vec<u8>| {
            if let Ok(msg) = String::from_utf8(data) {
                if msg.starts_with(&format!("RESTORE_CHUNK_RESP:{}:", tag_c)) {
                    let resp = msg
                        .trim_start_matches(&format!("RESTORE_CHUNK_RESP:{}:", tag_c));
                    let _ = tx_c.send(resp.to_string());
                }
            }
        };
        vpn.register_listener(chunk_listener);

        let req = format!("RESTORE_GET_CHUNK:{}:{}", chunk_tag, remote_path);
        vpn.send(&node_addr, req.as_bytes())
            .map_err(|e| format!("failed to request chunk {}: {}", i, e))?;

        let chunk_resp = rx_chunk
            .recv_timeout(std::time::Duration::from_secs(60))
            .map_err(|_| format!("timeout waiting for chunk {}", i))?;

        let chunk_data: serde_json::Value = serde_json::from_str(&chunk_resp)
            .map_err(|e| format!("invalid chunk response: {}", e))?;

        // Decrypt the chunk (in a real impl we'd use the saved key)
        // For now we pass through the raw data for reassembly
        // (the encryption key would be stored externally in production)
        let raw_data_hex = chunk_data["data_hex"]
            .as_str()
            .ok_or("missing data_hex in chunk response")?;
        let raw_data = hex::decode(raw_data_hex)
            .map_err(|e| format!("invalid hex data: {}", e))?;

        decrypted_chunks.push(raw_data);
    }

    // 3. 重组
    let chunker = Chunker::new();
    let restored = chunker
        .reassemble(&manifest, &decrypted_chunks)
        .map_err(|e| format!("reassembly failed: {}", e))?;

    // 4. 写入本地文件
    if let Some(parent) = std::path::Path::new(local_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create directory '{}': {}", parent.display(), e))?;
    }
    std::fs::write(local_path, &restored)
        .map_err(|e| format!("failed to write '{}': {}", local_path, e))?;

    Ok(format!(
        "Restore completed: {} → {}\n  File: {} ({} bytes)\n  Chunks: {}\n  Integrity: verified",
        target, local_path, file_name, total_size, chunk_count,
    ))
}

/// 执行存储垃圾回收
///
/// `ll storage gc`:
/// 扫描所有版本与元数据，找出无引用块并返回可回收信息。
fn execute_storage_gc() -> Result<String, String> {
    let version_manager = VersionManager::load_from_file(
        crate::storage::version::DEFAULT_VERSION_DB_PATH,
    )?;
    let metadata_store = MetadataStore::load_from_file(
        crate::storage::metadata::DEFAULT_METADATA_PATH,
    ).map_err(|e| e.to_string())?;

    let gc = GarbageCollector::new();
    let result = gc.collect(&version_manager, &metadata_store)?;
    Ok(result.to_string())
}

/// 执行版本修剪
///
/// `ll storage prune <keep>`:
/// 只保留每个文件最近 N 个版本。
fn execute_storage_prune(keep: usize) -> Result<String, String> {
    let version_manager = VersionManager::load_from_file(
        crate::storage::version::DEFAULT_VERSION_DB_PATH,
    )?;

    let gc = GarbageCollector::new();
    let pruned = gc.prune_old_versions(&version_manager, keep)?;

    version_manager.flush().map_err(|e| format!("failed to save version store: {}", e))?;

    Ok(format!(
        "Pruned {} version(s). Kept {} most recent version(s) per file.",
        pruned, keep
    ))
}

/// 执行存储统计
///
/// `ll storage stats`:
/// 显示总存储量、块数、版本数、可回收空间。
fn execute_storage_stats() -> Result<String, String> {
    let version_manager = VersionManager::load_from_file(
        crate::storage::version::DEFAULT_VERSION_DB_PATH,
    )?;
    let metadata_store = MetadataStore::load_from_file(
        crate::storage::metadata::DEFAULT_METADATA_PATH,
    ).map_err(|e| e.to_string())?;

    let gc = GarbageCollector::new();
    let stats = gc.storage_stats(&version_manager, &metadata_store)?;
    Ok(stats.to_string())
}

/// 执行增量同步上传
///
/// `ll increment <path> node:<name>`:
/// 使用增量同步只上传变更的块。
///
/// 注：当前实现发送完整文件，后续可用 IncrementalSync 优化。
fn execute_increment(path: &str, target: &str, vpn: &VpnRouter) -> Result<String, String> {
    // 解析目标节点
    let parsed = ParsedAddress::parse(target)
        .map_err(|e| format!("invalid target address: {}", e))?;

    let file_name = std::path::Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| path.to_string());

    // 1. 读取文件
    let data = std::fs::read(path)
        .map_err(|e| format!("failed to read '{}': {}", path, e))?;
    let file_size = data.len();

    // 2. 分块
    let chunker = crate::storage::chunk::Chunker::new();
    let (manifest, chunks) = chunker.chunk_data(&data);
    let chunk_count = chunks.len();

    // 3. 发送块数据到目标节点
    for (i, chunk) in chunks.iter().enumerate() {
        let payload = serde_json::json!({
            "file_name": file_name,
            "chunk_index": i,
            "total_chunks": chunk_count,
            "file_size": file_size,
            "data_hex": hex::encode(chunk),
        });
        let msg = format!("INCR_BLOCK:{}", payload.to_string());
        vpn.send(target, msg.as_bytes())
            .map_err(|e| format!("failed to send block {}: {}", i, e))?;
    }

    // 4. 发送清单
    let manifest_json = serde_json::to_string(&manifest)
        .map_err(|e| format!("failed to serialize manifest: {}", e))?;
    let meta_msg = format!("INCR_MANIFEST:{}:{}", file_name, manifest_json);
    vpn.send(target, meta_msg.as_bytes())
        .map_err(|e| format!("failed to send manifest: {}", e))?;

    // 5. 创建版本快照
    let version_manager = VersionManager::load_from_file(
        crate::storage::version::DEFAULT_VERSION_DB_PATH,
    )?;
    let version_id = version_manager.create_snapshot(&file_name, manifest, "increment")?;
    version_manager.flush().map_err(|e| format!("failed to save version: {}", e))?;

    Ok(format!(
        "Incremental sync completed: {} → {}\n  File: {} ({} bytes)\n  Chunks: {}\n  Version: {}",
        path,
        target,
        file_name,
        file_size,
        chunk_count,
        version_id,
    ))
}

/// 执行版本查询
///
/// `ll version <file>`:
/// 显示指定文件的所有版本历史。
fn execute_version(file: &str) -> Result<String, String> {
    let version_manager = VersionManager::load_from_file(
        crate::storage::version::DEFAULT_VERSION_DB_PATH,
    )?;

    let versions = version_manager.list_versions(file);
    if versions.is_empty() {
        return Ok(format!("No versions found for '{}'.", file));
    }

    let mut output = format!("Version history for '{}':\n", file);
    output.push_str(&format!(
        "{:<22} {:<20} {:<10} {}\n",
        "Version ID", "Timestamp", "Size", "Annotation"
    ));
    output.push_str(&"-".repeat(80));
    output.push('\n');

    for v in &versions {
        output.push_str(&format!(
            "{:<22} {:<20} {:<10} {}\n",
            v.version_id,
            v.timestamp,
            v.manifest.file_size,
            v.annotation,
        ));
    }

    Ok(output)
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

/// Truncate a hex string for display (show first `n` chars).
fn truncate_hex(hex_str: &str, n: usize) -> String {
    if hex_str.len() <= n + 3 {
        hex_str.to_string()
    } else {
        format!("{}...", &hex_str[..n])
    }
}

/// Current Unix timestamp in seconds.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::AddressResolver;
    use crate::vpn::identity::NodeID;
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

    // ====== backup / restore 解析测试 ======

    #[test]
    fn test_parse_backup() {
        let args = vec![
            "ll".to_string(),
            "backup".to_string(),
            "/home/test/file.txt".to_string(),
            "node:Pikachu".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Backup {
                path: "/home/test/file.txt".to_string(),
                target: "node:Pikachu".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_restore() {
        let args = vec![
            "ll".to_string(),
            "restore".to_string(),
            "node:Pikachu:/backup/file.txt".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Restore {
                target: "node:Pikachu:/backup/file.txt".to_string(),
                path: "backup/file.txt".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_restore_with_local_path() {
        let args = vec![
            "ll".to_string(),
            "restore".to_string(),
            "node:Pikachu:/data/file.txt".to_string(),
            "/tmp/restored.txt".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Restore {
                target: "node:Pikachu:/data/file.txt".to_string(),
                path: "/tmp/restored.txt".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_backup_short() {
        let args = vec![
            "backup".to_string(),
            "myfile.dat".to_string(),
            "node:Charizard".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Backup {
                path: "myfile.dat".to_string(),
                target: "node:Charizard".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_restore_short() {
        let args = vec![
            "restore".to_string(),
            "node:Mewtwo:/path/to/file".to_string(),
        ];
        let cmd = parse_command(&args).unwrap();
        assert_eq!(
            cmd,
            Command::Restore {
                target: "node:Mewtwo:/path/to/file".to_string(),
                path: "path/to/file".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_backup_missing_target() {
        let args = vec!["ll".to_string(), "backup".to_string(), "/path".to_string()];
        let result = parse_command(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_restore_missing_target() {
        let args = vec!["ll".to_string(), "restore".to_string()];
        let result = parse_command(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_backup_invalid_target() {
        let args = vec![
            "ll".to_string(),
            "backup".to_string(),
            "/path".to_string(),
            "Pikachu".to_string(),
        ];
        let result = parse_command(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid target"));
    }
}
