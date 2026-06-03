# LL VPN 架构设计文档（V3）

## 项目定位

LL 全称"局域网管理工具"。
加了 VPN 之后，变成"你的设备管理工具"。

- 局域网是 LL 的一种连接方式
- VPN 是 LL 的另一种连接方式
- 分块存储是 LL 的第三种能力

**命令不变，体验不变，设备在哪都能管**

---

## 核心架构

```
┌─────────────────────────────────────────────┐
│           LL 命令层                          │
│  ll ping / ll cmd / ll file / ll backup    │
├─────────────────────────────────────────────┤
│           地址解析层                         │
│  node:Pikachu → 节点 ID → 坐标             │
├─────────────────────────────────────────────┤
│           路由决策层                         │
│  目标在哪 → 走哪条路                       │
├───────────┬───────────┬────────────────────┤
│ LAN 直连   │ Mesh 网络  │ 分块存储层           │
│            │           │                    │
│ UDP 9876   │ P2P+中继   │ 加密分块+多源下载   │
└───────────┴───────────┴────────────────────┘
```

---

## 一、地址系统：宝可梦命名

每个节点一个宝可梦名字，简单、好记、有趣。

```
Pikachu   → 你的主力笔记本
Charizard → 家里的 NAS
Mewtwo    → VPS 服务器
Eevee     → 手机
```

### 地址格式

```
node:<名字>              → 访问节点
node:<名字>:<端口>       → 指定端口

示例:
  ll cmd node:Charizard "uptime"
  ll file get node:Mewtwo:/config.yaml
  ll ping node:Eevee
```

### 节点注册

```yaml
# config.yaml
node:
  name: "Pikachu"        # 你的名字

nodes:
  Pikachu:
    name: "Pikachu"
    role: "laptop"
  Charizard:
    name: "Charizard"
    role: "nas"
  Mewtwo:
    name: "Mewtwo"
    role: "vps"
```

---

## 二、名字注册中心：去中心化选举

### 核心思路

1. 默认有一个主注册中心（A）
2. A 挂了，通过随机算法选出新注册中心（B）
3. A 回来后，告知它已经下线
4. 注册中心自动轮换，无单点故障

### 选举机制

```
A 下线检测:
  所有节点定期向 A 心跳
  连续 3 次无响应 → 判定 A 下线

选举新注册中心:
  所有在线节点参与
  随机算法选一个节点（基于节点 ID hash）
  多数节点同意 → 新注册中心生效

新注册中心职责:
  接管名字注册
  广播新注册中心地址
  其他节点更新配置
```

### 选举流程

```
阶段 1: 检测注册中心下线
  所有节点 ──心跳──→ 注册中心 A
  无响应... 无响应... 无响应...
  判定: A 下线

阶段 2: 发起选举
  发现 A 下线的节点 → 广播 "选举请求"
  所有节点收到 → 参与投票

阶段 3: 投票
  每个节点选一个候选（基于随机算法）
  投票结果汇总
  得票最多者当选

阶段 4: 通知
  新注册中心当选 → 广播 "新注册中心"
  所有节点更新配置
  名字注册继续
```

### 注册中心回来

```
A 恢复上线:
1. A 重新连接网络
2. A 发现新注册中心 B 已经在运行
3. A 向 B 发送 "我回来了"
4. B 告知 A: "你已经下线了，现在我是注册中心"
5. A 变成普通节点
6. A 的名字映射表同步到 B
```

### 配置

```yaml
registry:
  centers:
    - name: "Mewtwo"        # VPS
      priority: 1
    - name: "Charizard"     # NAS
      priority: 2
    - name: "Pikachu"       # 笔记本
      priority: 3
  
  heartbeat: 5s
  offline_threshold: 3
  
  election:
    enabled: true
    random_seed: true
    min_voters: 2
```

---

## 三、Mesh 网络：去中心化网状组网

### 核心原则

- 每个节点都是平等的（客户端 + 服务端 + 路由器）
- 没有"服务器"概念
- 互相为跳板，互相转发
- 没有中心，没有单点故障

### 架构图

```
传统 VPN（中心化）:
           ┌─────────┐
     ┌─────┤  服务器  ├─────┐
     │     └─────────┘     │
   [A]       [B]         [C]

我们的方案（去中心化网状）:
   [A]════════[B]
    ║ ╲      ╱ ║
    ║   ╲  ╱   ║
    ║    ╲╱    ║
    ║    ╱╲    ║
    ║  ╱    ╲  ║
   [D]════════[C]
```

### 节点角色

每个节点同时承担：

- **节点发现者**：帮助新节点找到其他节点
- **路径探测者**：测试各条路径的延迟和质量
- **数据中继者**：帮助无法直连的节点转发数据
- **流量贡献者**：为网络贡献带宽

### 连接建立

```
优先直连（UDP 打洞）
  A ──── C

不行就找邻居帮忙
  A ── B ── C
  A ── D ── C

还不行就多跳
  A ── B ── D ── C

自动选择延迟最低的路径
```

### NAT 穿透

```
两个都在 NAT 后的节点如何连通？

1. UDP 打洞
   双方同时发 UDP 包
   NAT 设备建立映射
   之后可以直接通信

2. 打洞失败？
   找一个公网节点帮忙中继

3. 对称 NAT？
   只能走中继，性能稍差但能用
```

### 网络自愈

```
节点离线：
  其他节点自动绕过
  路径自动切换

路径失效：
  自动探测新路径
  无感知切换

网络分区：
  各分区独立工作
  恢复后自动合并
```

---

## 四、多路径并行传输

### 核心原理

```
单路径:    A ═══════════════════ B    带宽 = 10Mbps

多路径:    A ═══ M1 ═══ B            带宽 = 8Mbps
           A ═══ M2 ═══ B            带宽 = 6Mbps
           A ───────── B             带宽 = 10Mbps
                                      ─────────
                               总带宽 = 24Mbps (理论)
```

### 数据分片 + 并行发送

```
发送方 A:                    接收方 B:
    │                           │
    │  chunk1 (seq=1) → Path1   │
    │  chunk2 (seq=2) → Path2   │
    │  chunk3 (seq=3) → Path1   │
    │  chunk4 (seq=4) → Path3   │
    │                           │
    │  ┌─────────────────────┐  │
    │  │   重排序缓冲区      │  │
    │  │   按 seq 输出       │  │
    │  └─────────────────────┘  │
    │                           │
    │  ACK1 ← Path1            │
    │  ACK2 ← Path2            │
    │  ACK3 ← Path1            │
    │  ACK4 ← Path3            │
```

### 路径评分

```
路径评分 = 延迟 × 0.7 + 跳数 × 100 × 0.3

延迟越低越好，跳数越少越好
```

---

## 五、路由发现：Yggdrasil Scalar Coordinate

### 核心思想

- 每个节点有个坐标（16字节）
- 其他节点按坐标距离选下一跳
- 每一步都是贪心选择最近坐标
- 不需要全局拓扑信息

### 优势

- 比距离向量更轻量
- 比链路状态更简单
- 适合小规模网络

### 实现

- 直接用 Yggdrasil 的 scalar coordinate 算法
- 不自己发明

---

## 六、加密通信

### Noise Protocol Framework

```
A → B:  Hello (ephemeral pubkey)
B → A:  HelloACK (ephemeral pubkey + encrypted payload)
A → B:  Data (encrypted)

每包都带:
- Timestamp (防重放)
- Nonce (防篡改)
- Payload (加密数据)
```

### 端到端加密

- 使用 Noise IK 握手
- 前向保密
- 每个中继节点只知道上一跳和下一跳
- 中间节点看不到内容

---

## 七、分块存储

### 块结构

```
文件 "video.mp4"（假设 13MB）
├── block_0 (4MB)  ← 内容 hash: abc123...
├── block_1 (4MB)  ← 内容 hash: def456...
├── block_2 (4MB)  ← 内容 hash: ghi789...
└── block_3 (1MB)  ← 内容 hash: jkl012...

元数据清单（也加密存储）：
{
  "file": "video.mp4",
  "size": 13651488,
  "blocks": [
    { "hash": "abc123...", "size": 4194304,  "nodes": ["Charizard", "Mewtwo"] },
    { "hash": "def456...", "size": 4194304,  "nodes": ["Charizard"] },
    { "hash": "ghi789...", "size": 4194304,  "nodes": ["Mewtwo"] },
    { "hash": "jkl012...", "size": 1197464,  "nodes": ["Charizard", "Mewtwo"] }
  ]
}
```

### 多源并行下载

```
请求文件 video.mp4
  → 获取元数据清单
  → 并行向各节点请求缺失的块
  → 同时从 Charizard 和 Mewtwo 下载
  → 拼装所有块
  → 用用户密钥解密
  → 输出完整文件
```

### 加密存储

```
文件内容 → AES-256-GCM（用户密钥）→ 加密分块 → 存储到备份节点
备份节点只存密文，无法解密任何内容。
```

---

## 八、LL Router Shim

### 核心思想

在现有 LL 代码里加一层 Router，接收命令后判断目标在哪个网络，再走对应路径。

### 实现

```
ll cmd node:Charizard "uptime"
  → Router 判断 Charizard 不在局域网
  → Router 查 VPN 路由表，找 Charizard 的节点 ID
  → 走 mesh 路径发送命令

这层 shim 建好了，后面加什么新协议都不需要动 LL 上层。
```

---

## 九、中继机制

### 中继不是免费的

中继节点帮别人转发流量，有代价（带宽、CPU、流量费用）。

### 解决方案

- 只允许同密钥环内的节点互相中继
- 对中继流量做速率限制
- 优先级：自己的流量 > 密钥环内 > 其他

---

## 十、Phase 划分

| Phase | 内容 | 交付物 |
|-------|------|--------|
| P1 | Mesh 核心：节点 ID、Noise 握手、TCP 中继、入口节点引导 | 两个节点能可靠通信 |
| P2 | 路由 Shim：地址解析层、适配现有命令、新增 VPN 命令 | ll cmd node:xxx 可用 |
| P3 | 网状组网：中继转发、多跳路由、DHT 节点发现 | 多节点自动组网 |
| P4 | 分块存储：块切割、hash 命名、端到端加密、多节点冗余、多源并行 | 备份和恢复 |
| P5 | 增量备份：块差异对比、只传变化部分、版本历史、按时间点恢复 | 增量同步 |
| P6 | 高级功能：打洞优化、多路径并行、流量统计 | 性能优化 |

---

## 十一、实现优先级

| 优先级 | 做什么 | 原因 |
|--------|--------|------|
| P0 | 路由 Shim | 改动最小，隔离网络层 |
| P1 | 入口节点 + 节点 ID | 必须有，才能开始组网 |
| P2 | Noise 握手 + 中继路径 | 可靠通信，比打洞稳定 |
| P3 | DHT/路由发现 | 自动化，不需要手动配置 |
| P4 | 打洞优化 | 中继不可达时的备选 |
| P5 | 多路径 | 等前面稳了再做 |

---

## 十二、文件结构

```
lan-link/
├── ll.go                 # 主入口
├── lan.go                # 局域网模块
├── router.go             # 路由 Shim
├── address.go            # 地址解析（宝可梦名字）
├── vpn/
│   ├── identity.go       # 节点 ID 生成
│   ├── handshake.go      # Noise 握手
│   ├── relay.go          # 中继通信
│   ├── dht.go            # 路由发现
│   ├── hole_punch.go     # 打洞优化
│   └── multipath.go      # 多路径
├── storage/
│   ├── chunk.go          # 分块逻辑
│   ├── encrypt.go        # 加密逻辑
│   ├── metadata.go       # 元数据管理
│   └── restore.go        # 恢复逻辑
├── registry/
│   ├── center.go         # 注册中心
│   └── election.go       # 选举逻辑
├── config.yaml
└── docs/
    └── vpn.md
```

---

## 十三、使用示例

```bash
# 查看所有节点
ll nodes
NAME        ROLE    STATUS
Pikachu     laptop  online
Charizard   nas     online
Mewtwo      vps     online
Eevee       phone   offline

# 远程执行命令
ll cmd node:Charizard "df -h"

# 传输文件
ll file put node:Charizard:/video.mp4

# 备份文件
ll backup /important/data node:Mewtwo

# 恢复文件
ll restore node:Mewtwo:/important/data

# 查看存储状态
ll storage status
USED    AVAILABLE   NODES
120GB   880GB       3

# VPN 管理
ll vpn status
ll vpn peers
```

---

## 十四、核心价值

```
传统 VPN：
  你 → 服务器 → 目标
  服务器是瓶颈
  服务器是单点故障
  服务器知道所有流量

我们的网状网络：
  你 ═══ 目标（直连）
  你 ── 中间节点 ── 目标（中继）
  你 ── A ── B ── 目标（多跳）

  没有中心
  没有单点故障
  没有人知道所有流量
  每个节点都是平等的
```

---

## 十五、一句话总结

**用宝可梦名字做地址，不用 IP，不用 TUN，让 LL 的所有命令都能跨网络用。**
