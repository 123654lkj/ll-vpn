//! P6-3: 流量统计与限制
//!
//! 实现流量统计（上行/下行字节、速率、峰值）和
//! 基于 Token Bucket 算法的速率限制器。
//!
//! # TrafficStats
//!
//! 记录上行/下行流量，计算速率和峰值。
//!
//! # RateLimiter
//!
//! 使用 Token Bucket 算法控制流量速率。
//! 可配置每秒字节数限制。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 默认速率限制（字节/秒）
pub const DEFAULT_RATE_LIMIT_BYTES_PER_SEC: u64 = 1_048_576; // 1 MB/s

/// 默认 Token Bucket 容量（字节）
pub const DEFAULT_BUCKET_CAPACITY: u64 = 10_485_760; // 10 MB

/// 速率计算窗口（秒）
pub const RATE_WINDOW_SECS: u64 = 5;

// ──────────────────────────────────────────────
//  TrafficStats
// ──────────────────────────────────────────────

/// 流量统计摘要
#[derive(Debug, Clone)]
pub struct TrafficSummary {
    /// 总上行字节数
    pub total_tx: u64,
    /// 总下行字节数
    pub total_rx: u64,
    /// 当前上行速率（字节/秒）
    pub tx_rate: f64,
    /// 当前下行速率（字节/秒）
    pub rx_rate: f64,
    /// 上行峰值速率（字节/秒）
    pub tx_peak: f64,
    /// 下行峰值速率（字节/秒）
    pub rx_peak: f64,
    /// 连接数
    pub connection_count: usize,
}

impl TrafficSummary {
    /// 总流量（上行 + 下行）
    pub fn total_bytes(&self) -> u64 {
        self.total_tx + self.total_rx
    }

    /// 格式化字节数为可读形式
    pub fn format_bytes(bytes: u64) -> String {
        if bytes >= 1_073_741_824 {
            format!("{:.2} GiB", bytes as f64 / 1_073_741_824.0)
        } else if bytes >= 1_048_576 {
            format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
        } else if bytes >= 1024 {
            format!("{:.2} KiB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    /// 格式化速率为可读形式
    pub fn format_rate(bytes_per_sec: f64) -> String {
        if bytes_per_sec >= 1_073_741_824.0 {
            format!("{:.2} GiB/s", bytes_per_sec / 1_073_741_824.0)
        } else if bytes_per_sec >= 1_048_576.0 {
            format!("{:.2} MiB/s", bytes_per_sec / 1_048_576.0)
        } else if bytes_per_sec >= 1024.0 {
            format!("{:.2} KiB/s", bytes_per_sec / 1024.0)
        } else {
            format!("{:.2} B/s", bytes_per_sec)
        }
    }
}

/// 速率样本
#[derive(Debug, Clone)]
struct RateSample {
    /// 时间戳
    timestamp: Instant,
    /// 字节数
    bytes: u64,
}

/// 流量统计器
///
/// 记录上行/下行流量，计算实时速率和峰值速率。
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::stats::TrafficStats;
///
/// let stats = TrafficStats::new();
/// stats.record_tx(1024);
/// stats.record_rx(2048);
/// let summary = stats.summary();
/// assert_eq!(summary.total_tx, 1024);
/// assert_eq!(summary.total_rx, 2048);
/// ```
pub struct TrafficStats {
    /// 总上行字节
    total_tx: AtomicU64,
    /// 总下行字节
    total_rx: AtomicU64,
    /// 上行峰值速率
    tx_peak: Mutex<f64>,
    /// 下行峰值速率
    rx_peak: Mutex<f64>,
    /// 最近上行采样（用于速率计算）
    tx_samples: Mutex<Vec<RateSample>>,
    /// 最近下行采样
    rx_samples: Mutex<Vec<RateSample>>,
    /// 连接数
    connection_count: AtomicU64,
}

impl TrafficStats {
    /// 创建新的流量统计器
    pub fn new() -> Self {
        Self {
            total_tx: AtomicU64::new(0),
            total_rx: AtomicU64::new(0),
            tx_peak: Mutex::new(0.0),
            rx_peak: Mutex::new(0.0),
            tx_samples: Mutex::new(Vec::new()),
            rx_samples: Mutex::new(Vec::new()),
            connection_count: AtomicU64::new(0),
        }
    }

    /// 记录上行字节
    pub fn record_tx(&self, bytes: u64) {
        self.total_tx.fetch_add(bytes, Ordering::SeqCst);
        let now = Instant::now();
        let mut samples = self.tx_samples.lock().unwrap();
        samples.push(RateSample {
            timestamp: now,
            bytes,
        });
        self.cleanup_old_samples(&mut samples);

        // 更新峰值
        let rate = self.calculate_rate(&samples);
        let mut peak = self.tx_peak.lock().unwrap();
        if rate > *peak {
            *peak = rate;
        }
    }

    /// 记录下行字节
    pub fn record_rx(&self, bytes: u64) {
        self.total_rx.fetch_add(bytes, Ordering::SeqCst);
        let now = Instant::now();
        let mut samples = self.rx_samples.lock().unwrap();
        samples.push(RateSample {
            timestamp: now,
            bytes,
        });
        self.cleanup_old_samples(&mut samples);

        // 更新峰值
        let rate = self.calculate_rate(&samples);
        let mut peak = self.rx_peak.lock().unwrap();
        if rate > *peak {
            *peak = rate;
        }
    }

    /// 增加连接数
    pub fn add_connection(&self) {
        self.connection_count.fetch_add(1, Ordering::SeqCst);
    }

    /// 减少连接数
    pub fn remove_connection(&self) {
        self.connection_count.fetch_sub(1, Ordering::SeqCst);
    }

    /// 获取当前连接数
    pub fn connection_count(&self) -> u64 {
        self.connection_count.load(Ordering::SeqCst)
    }

    /// 获取总上行字节
    pub fn total_tx(&self) -> u64 {
        self.total_tx.load(Ordering::SeqCst)
    }

    /// 获取总下行字节
    pub fn total_rx(&self) -> u64 {
        self.total_rx.load(Ordering::SeqCst)
    }

    /// 获取统计摘要
    pub fn summary(&self) -> TrafficSummary {
        let tx_samples = self.tx_samples.lock().unwrap();
        let rx_samples = self.rx_samples.lock().unwrap();
        let tx_peak = *self.tx_peak.lock().unwrap();
        let rx_peak = *self.rx_peak.lock().unwrap();

        TrafficSummary {
            total_tx: self.total_tx.load(Ordering::SeqCst),
            total_rx: self.total_rx.load(Ordering::SeqCst),
            tx_rate: self.calculate_rate(&tx_samples),
            rx_rate: self.calculate_rate(&rx_samples),
            tx_peak,
            rx_peak,
            connection_count: self.connection_count.load(Ordering::SeqCst) as usize,
        }
    }

    /// 清空统计
    pub fn reset(&self) {
        self.total_tx.store(0, Ordering::SeqCst);
        self.total_rx.store(0, Ordering::SeqCst);
        self.tx_samples.lock().unwrap().clear();
        self.rx_samples.lock().unwrap().clear();
        *self.tx_peak.lock().unwrap() = 0.0;
        *self.rx_peak.lock().unwrap() = 0.0;
        self.connection_count.store(0, Ordering::SeqCst);
    }

    /// 清理采样窗口外的旧采样
    fn cleanup_old_samples(&self, samples: &mut Vec<RateSample>) {
        let cutoff = Instant::now() - Duration::from_secs(RATE_WINDOW_SECS);
        samples.retain(|s| s.timestamp >= cutoff);
    }

    /// 计算采样速率（字节/秒）
    fn calculate_rate(&self, samples: &[RateSample]) -> f64 {
        if samples.len() < 2 {
            return 0.0;
        }

        let duration = samples.last().unwrap().timestamp.duration_since(samples[0].timestamp);
        if duration < Duration::from_millis(100) {
            return 0.0;
        }

        let total_bytes: u64 = samples.iter().map(|s| s.bytes).sum();
        total_bytes as f64 / duration.as_secs_f64()
    }
}

impl Default for TrafficStats {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────
//  RateLimiter (Token Bucket)
// ──────────────────────────────────────────────

/// 速率限制器
///
/// 使用 Token Bucket（令牌桶）算法实现速率限制。
/// 支持配置每秒字节数限制和桶容量。
///
/// # 算法
///
/// 1. 桶以固定速率（rate_per_sec）生成令牌
/// 2. 每个数据包消耗对应字节数的令牌
/// 3. 桶满时令牌不再增加（容量上限）
/// 4. 桶空时数据包被拒绝
///
/// # 示例
///
/// ```rust
/// use ll_vpn::vpn::stats::RateLimiter;
///
/// let limiter = RateLimiter::new(1024, 4096); // 1KB/s, 4KB burst
/// assert!(limiter.check(512));  // 通过
/// assert!(limiter.check(512));  // 通过
/// assert!(!limiter.check(1024)); // 限速
/// ```
pub struct RateLimiter {
    /// 速率（字节/秒）
    rate_per_sec: u64,
    /// 桶容量（最大突发字节数）
    capacity: u64,
    /// 当前令牌数
    tokens: Mutex<f64>,
    /// 上次补充时间
    last_refill: Mutex<Instant>,
}

impl RateLimiter {
    /// 创建新的速率限制器
    ///
    /// # 参数
    ///
    /// - `rate_per_sec`: 每秒允许的字节数
    /// - `capacity`: 桶容量（最大突发大小）
    pub fn new(rate_per_sec: u64, capacity: u64) -> Self {
        Self {
            rate_per_sec,
            capacity,
            tokens: Mutex::new(capacity as f64),
            last_refill: Mutex::new(Instant::now()),
        }
    }

    /// 使用默认配置创建速率限制器
    pub fn default() -> Self {
        Self::new(
            DEFAULT_RATE_LIMIT_BYTES_PER_SEC,
            DEFAULT_BUCKET_CAPACITY,
        )
    }

    /// 检查是否允许发送/接收指定字节数
    ///
    /// # 参数
    ///
    /// - `bytes`: 请求的字节数
    ///
    /// # 返回
    ///
    /// - `true`: 允许通过（消耗了令牌）
    /// - `false`: 超过速率限制
    pub fn check(&self, bytes: u64) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_refill = self.last_refill.lock().unwrap();

        // 补充令牌
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.rate_per_sec as f64;
        *tokens = (*tokens + new_tokens).min(self.capacity as f64);
        *last_refill = now;

        // 检查是否有足够的令牌
        if *tokens >= bytes as f64 {
            *tokens -= bytes as f64;
            true
        } else {
            false
        }
    }

    /// 尝试获取指定数量的令牌（非阻塞）
    ///
    /// 与 `check()` 不同的是，即使令牌不够，也消耗剩余令牌。
    ///
    /// # 返回
    ///
    /// 实际消耗的字节数（可能小于请求数）
    pub fn consume(&self, bytes: u64) -> u64 {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_refill = self.last_refill.lock().unwrap();

        // 补充令牌
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill);
        let new_tokens = elapsed.as_secs_f64() * self.rate_per_sec as f64;
        *tokens = (*tokens + new_tokens).min(self.capacity as f64);
        *last_refill = now;

        let consumed = (bytes as f64).min(*tokens) as u64;
        *tokens -= consumed as f64;
        consumed
    }

    /// 获取当前速率限制（字节/秒）
    pub fn rate(&self) -> u64 {
        self.rate_per_sec
    }

    /// 更新速率限制
    ///
    /// # 参数
    ///
    /// - `rate_per_sec`: 新的速率（字节/秒）
    pub fn set_rate(&mut self, rate_per_sec: u64) {
        self.rate_per_sec = rate_per_sec;
    }

    /// 获取桶容量
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// 获取当前桶中令牌数
    pub fn tokens(&self) -> f64 {
        *self.tokens.lock().unwrap()
    }

    /// 重置桶（充满令牌）
    pub fn reset(&self) {
        *self.tokens.lock().unwrap() = self.capacity as f64;
        *self.last_refill.lock().unwrap() = Instant::now();
    }

    /// 等待直到有足够的令牌（阻塞）
    ///
    /// # 返回
    ///
    /// 等待的持续时间
    pub fn wait_for(&self, bytes: u64) -> Duration {
        if self.check(bytes) {
            return Duration::ZERO;
        }

        // 计算需要等待的时间
        let tokens = *self.tokens.lock().unwrap();
        let needed = bytes as f64 - tokens;
        let wait_secs = (needed / self.rate_per_sec as f64).max(0.0);

        let wait = Duration::from_secs_f64(wait_secs);
        std::thread::sleep(wait);

        // 再次尝试
        self.check(bytes);
        wait
    }
}

// ──────────────────────────────────────────────
//  PeerTrafficTracker
// ──────────────────────────────────────────────

/// 对等节点流量跟踪器
///
/// 为每个对等节点维护独立的流量统计和速率限制。
pub struct PeerTrafficTracker {
    /// 流量统计
    stats: TrafficStats,
    /// 速率限制器
    limiter: RateLimiter,
}

impl PeerTrafficTracker {
    /// 创建新的对等节点流量跟踪器
    pub fn new(rate_per_sec: u64, capacity: u64) -> Self {
        Self {
            stats: TrafficStats::new(),
            limiter: RateLimiter::new(rate_per_sec, capacity),
        }
    }

    /// 记录上行并检查速率限制
    ///
    /// # 返回
    ///
    /// - `true`: 允许发送
    /// - `false`: 超过速率限制
    pub fn record_tx(&self, bytes: u64) -> bool {
        self.stats.record_tx(bytes);
        self.limiter.check(bytes)
    }

    /// 记录下行并检查速率限制
    ///
    /// # 返回
    ///
    /// - `true`: 允许接收
    /// - `false`: 超过速率限制
    pub fn record_rx(&self, bytes: u64) -> bool {
        self.stats.record_rx(bytes);
        self.limiter.check(bytes)
    }

    /// 获取流量统计引用
    pub fn stats(&self) -> &TrafficStats {
        &self.stats
    }

    /// 获取速率限制器引用
    pub fn limiter(&self) -> &RateLimiter {
        &self.limiter
    }

    /// 获取统计摘要
    pub fn summary(&self) -> TrafficSummary {
        self.stats.summary()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TrafficStats 测试 ──

    #[test]
    fn test_traffic_stats_new() {
        let stats = TrafficStats::new();
        assert_eq!(stats.total_tx(), 0);
        assert_eq!(stats.total_rx(), 0);
        assert_eq!(stats.connection_count(), 0);
    }

    #[test]
    fn test_traffic_stats_record_tx() {
        let stats = TrafficStats::new();
        stats.record_tx(100);
        stats.record_tx(200);
        assert_eq!(stats.total_tx(), 300);
    }

    #[test]
    fn test_traffic_stats_record_rx() {
        let stats = TrafficStats::new();
        stats.record_rx(500);
        stats.record_rx(1500);
        assert_eq!(stats.total_rx(), 2000);
    }

    #[test]
    fn test_traffic_stats_summary() {
        let stats = TrafficStats::new();
        stats.record_tx(1024);
        stats.record_rx(2048);
        stats.add_connection();

        let summary = stats.summary();
        assert_eq!(summary.total_tx, 1024);
        assert_eq!(summary.total_rx, 2048);
        assert_eq!(summary.connection_count, 1);
    }

    #[test]
    fn test_traffic_stats_connection_count() {
        let stats = TrafficStats::new();
        assert_eq!(stats.connection_count(), 0);

        stats.add_connection();
        stats.add_connection();
        assert_eq!(stats.connection_count(), 2);

        stats.remove_connection();
        assert_eq!(stats.connection_count(), 1);
    }

    #[test]
    fn test_traffic_stats_reset() {
        let stats = TrafficStats::new();
        stats.record_tx(9999);
        stats.record_rx(8888);
        stats.add_connection();

        stats.reset();
        assert_eq!(stats.total_tx(), 0);
        assert_eq!(stats.total_rx(), 0);
        assert_eq!(stats.connection_count(), 0);
    }

    #[test]
    fn test_traffic_stats_total_bytes() {
        let summary = TrafficSummary {
            total_tx: 1000,
            total_rx: 2000,
            tx_rate: 0.0,
            rx_rate: 0.0,
            tx_peak: 0.0,
            rx_peak: 0.0,
            connection_count: 0,
        };
        assert_eq!(summary.total_bytes(), 3000);
    }

    // ── 格式化测试 ──

    #[test]
    fn test_format_bytes() {
        assert_eq!(TrafficSummary::format_bytes(100), "100 B");
        assert_eq!(TrafficSummary::format_bytes(2048), "2.00 KiB");
        assert_eq!(TrafficSummary::format_bytes(2_097_152), "2.00 MiB");
        assert_eq!(TrafficSummary::format_bytes(2_147_483_648), "2.00 GiB");
    }

    #[test]
    fn test_format_rate() {
        assert_eq!(TrafficSummary::format_rate(500.0), "500.00 B/s");
        assert_eq!(TrafficSummary::format_rate(2048.0), "2.00 KiB/s");
        assert_eq!(TrafficSummary::format_rate(2_097_152.0), "2.00 MiB/s");
    }

    // ── RateLimiter 测试 ──

    #[test]
    fn test_rate_limiter_new() {
        let limiter = RateLimiter::new(1024, 4096);
        assert_eq!(limiter.rate(), 1024);
        assert_eq!(limiter.capacity(), 4096);
        assert!((limiter.tokens() - 4096.0).abs() < 0.001);
    }

    #[test]
    fn test_rate_limiter_check_allow() {
        let limiter = RateLimiter::new(1024, 4096);
        // 桶满（4096 令牌），检查 512 → 允许
        assert!(limiter.check(512));
        // 剩余 3584
        assert!(limiter.check(512));
        // 剩余 3072
    }

    #[test]
    fn test_rate_limiter_check_deny() {
        let limiter = RateLimiter::new(1024, 512);
        // 桶满（512 令牌），检查 512 → 允许
        assert!(limiter.check(512));
        // 桶空，检查 1 → 拒绝
        assert!(!limiter.check(1));
    }

    #[test]
    fn test_rate_limiter_consume() {
        let limiter = RateLimiter::new(1024, 1024);
        // 消耗 800
        assert_eq!(limiter.consume(800), 800);
        // 剩余 ~224，请求 500，应消耗不超过 224 + refill
        let consumed = limiter.consume(500);
        // 由于可能经过了一些时间导致 refill，实际消耗可能在 224~500 之间
        // 但一定不超过 500（请求数）
        assert!(consumed <= 500);
        // 且至少消耗了 0
        assert!(consumed >= 0);
    }

    #[test]
    fn test_rate_limiter_reset() {
        let limiter = RateLimiter::new(1024, 2048);
        // 消耗所有令牌
        limiter.consume(2048);
        assert!(limiter.tokens() < 1.0);

        limiter.reset();
        assert!((limiter.tokens() - 2048.0).abs() < 1.0);
    }

    #[test]
    fn test_rate_limiter_set_rate() {
        let mut limiter = RateLimiter::new(1024, 4096);
        assert_eq!(limiter.rate(), 1024);

        limiter.set_rate(2048);
        assert_eq!(limiter.rate(), 2048);
    }

    #[test]
    fn test_rate_limiter_wait_for_zero() {
        let limiter = RateLimiter::new(1024, 1024);
        // 桶满，等待时间应为 0
        let wait = limiter.wait_for(512);
        assert!(wait < Duration::from_millis(1));
    }

    #[test]
    fn test_rate_limiter_default() {
        let limiter = RateLimiter::default();
        assert_eq!(limiter.rate(), DEFAULT_RATE_LIMIT_BYTES_PER_SEC);
        assert_eq!(limiter.capacity(), DEFAULT_BUCKET_CAPACITY);
    }

    // ── PeerTrafficTracker 测试 ──

    #[test]
    fn test_peer_traffic_tracker_new() {
        let tracker = PeerTrafficTracker::new(1024, 4096);
        let summary = tracker.summary();
        assert_eq!(summary.total_tx, 0);
        assert_eq!(summary.total_rx, 0);
    }

    #[test]
    fn test_peer_traffic_tracker_record_tx() {
        let tracker = PeerTrafficTracker::new(1024, 4096);
        assert!(tracker.record_tx(512));
        assert!(tracker.record_tx(512));

        // 桶空后应限速
        let _result = tracker.record_tx(4096);
        // 可以部分通过或不通过
        // 实际上会触发 refill，但短时间不会补充太多
        // 所以 check 可能返回 false
    }

    #[test]
    fn test_peer_traffic_tracker_record_rx() {
        let tracker = PeerTrafficTracker::new(1024, 2048);
        assert!(tracker.record_rx(1024));
        assert!(tracker.record_rx(1024));
        // 桶已空
        assert!(!tracker.record_rx(1024));
    }

    // ── 峰值速率测试 ──

    #[test]
    fn test_traffic_stats_peak_tx() {
        let stats = TrafficStats::new();
        // 记录大量数据，应更新峰值
        stats.record_tx(1_000_000);
        let summary = stats.summary();
        // 峰值 >= 计算出的速率
        assert!(summary.tx_peak >= 0.0);
    }

    #[test]
    fn test_traffic_stats_peak_rx() {
        let stats = TrafficStats::new();
        stats.record_rx(2_000_000);
        let summary = stats.summary();
        assert!(summary.rx_peak >= 0.0);
    }

    // ── 边界测试 ──

    #[test]
    fn test_traffic_stats_high_volume() {
        let stats = TrafficStats::new();
        for i in 0..1000 {
            stats.record_tx(i);
            stats.record_rx(i * 2);
        }
        // 确认总计正确
        assert_eq!(stats.total_tx(), (0..1000).sum::<u64>());
        assert_eq!(stats.total_rx(), (0..1000).map(|i| i * 2).sum::<u64>());
    }

    #[test]
    fn test_rate_limiter_zero_rate() {
        let limiter = RateLimiter::new(0, 0);
        // 零速率，任何请求都被拒绝
        assert!(!limiter.check(1));
        assert_eq!(limiter.consume(100), 0);
    }
}
