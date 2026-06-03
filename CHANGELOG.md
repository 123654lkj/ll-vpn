# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **P2-1**: VpnRouter — VPN 路由器实现 Router trait (#1705e58)
- **P2-2/P2-3**: 命令层适配与状态命令 — `ll cmd node:xxx`, `ll nodes`, `ll status` (#7fd6e00)
- **P3-1**: 名字注册中心 — center.rs 1,482 行，63 测试，含 save_if_dirty test-mode guard (#9cc9cca)
- **P4-3**: 元数据管理 — MetadataStore 1,020 行，26 测试 (#1764954)
- **P4-4**: 多源并行下载 — DownloadManager + ReorderBuffer + 进度跟踪 (#00155c1)

### Fixed

- **fix**: 补全截断的 handshake.rs 并修复测试 (#8383e57)
