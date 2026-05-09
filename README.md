# wg-relay

> 一键 WireGuard 中转/落地部署脚本 — 系统调优 + BBR + RPS + 多落地端口映射

为 **GA / Anycast → AWS 中转 → WireGuard → 多落地服务器** 这种链路设计，承载 [SUDOKU](https://github.com/SUDOKU-ASCII/sudoku) / VLESS / Trojan / Hysteria 等任意 TCP/UDP 代理协议。

中转机和落地机用**同一个脚本**，启动时按角色区分。

---

## 特性

- **系统调优**：BBR + fq + 大缓冲 + TCP Fast Open + MTU Probing
- **conntrack 调优**：连接跟踪表 1M、hashsize 256K，超时收紧
- **RPS 多核分散**：把网卡软中断分摊到所有 CPU（用 systemd 持久化，不依赖 `/etc/rc.local`）
- **WireGuard**：自动装、自动生成密钥、MTU 1420（实测最优值）
- **Hub 模式**：单中转机挂任意多落地，靠不同对外端口区分
- **Node 模式**：自动写好回连 + `PersistentKeepalive=25`
- **add-node 子命令**：动态加落地 peer + DNAT，无需重启 WG（用 `wg syncconf` 热加载）
- **iptables 规则持久化**（netfilter-persistent / iptables-services）
- **幂等**：重复运行同一命令不会破坏已有配置

---

## 架构

```
        客户端
          │
          ▼
   ┌──────────────┐
   │     GA       │  Global Accelerator / Anycast
   └──────┬───────┘
          │
          ▼
   ┌──────────────┐         WireGuard
   │  Hub (中转)  │ ◀───────────────────────▶  Node 1 (Lax)    :443
   │  AWS ap3     │     10.66.0.0/24            10.66.0.2
   │  10.66.0.1   │ ◀───────────────────────▶  Node 2 (Japan)  :443
   └──────┬───────┘                             10.66.0.3
          │ DNAT
          │   :443  → 10.66.0.2:443  (Lax)
          │   :444  → 10.66.0.3:443  (Japan)
          │   :8443 → 10.66.0.4:443  (HK)
          ▼
       (各落地的 SUDOKU 服务真正处理流量并出网)
```

**为什么 Hub 要 SNAT/MASQUERADE 到 wg0？**
DNAT 改的是目的地址，源地址仍是原始客户端。如果不做 SNAT，落地收到包后用自己的公网 IP 回包（默认路由），就是非对称路由 → 连接死掉。`POSTROUTING -o wg0 -j MASQUERADE` 把源换成 Hub 的 WG IP，落地按 WG 路径回，Hub 再反向 NAT 回客户端。

---

## 快速开始

### 1) Hub（中转机，例如 AWS EC2 ap3）

```bash
curl -fsSL https://raw.githubusercontent.com/Neukchill/cc/main/install.sh -o install.sh
sudo bash install.sh install
# 选 1 (hub)，按提示用默认值即可
```

完成后会打印：
- Hub 的**公钥**（落地配置时要用）
- Hub 公网 IP / 端口

### 2) Node（每台落地机，比如 Lax / Japan）

```bash
curl -fsSL https://raw.githubusercontent.com/Neukchill/cc/main/install.sh -o install.sh
sudo bash install.sh install
# 选 2 (node)
# 输入：Hub 公网IP / Hub 端口 / Hub 公钥 / 本机序号 (Lax=2, Japan=3, HK=4...)
```

完成后会打印：
- 本落地的**公钥** + **WG 地址** (例 `10.66.0.3`)

### 3) 回到 Hub，把落地挂上去

```bash
sudo bash install.sh add-node
# 输入：
#   落地名称       japan
#   落地公钥       <步骤2输出>
#   落地WG地址     10.66.0.3
#   对外端口       444         ← 客户端连这个端口
#   落地服务端口   443         ← SUDOKU 在落地上监听的端口
#   协议           tcp / udp / both
```

脚本会自动：
- 把 `[Peer]` 追加到 Hub 的 `wg0.conf`，热加载（无需断流）
- 加 `PREROUTING -p tcp --dport 444 -j DNAT --to 10.66.0.3:443`
- 加 `FORWARD` 放行
- `netfilter-persistent save` 持久化

### 4) 客户端配置

把 SUDOKU 客户端的 `server_address` 指向 **Hub 公网 IP : 444**，连接就会走 GA → Hub → WG → Japan 落地。

---

## 多落地（你最初的问题）

> "如果我要通过 GA + EC2 对接多个服务器，是不是要去加 GA 端口（假设 444）中转日本服务器？"

**对，思路完全正确。** 单 Hub 挂 N 个落地，靠不同的对外端口区分：

| 客户端连 Hub 的端口 | DNAT 到 | 落地 |
|:--:|:--:|:--:|
| 443 | 10.66.0.2:443 | Lax |
| 444 | 10.66.0.3:443 | Japan |
| 8443 | 10.66.0.4:443 | HK |

每加一个落地：
1. 落地机跑 `install.sh install`（选 node，序号递增）
2. Hub 跑 `install.sh add-node`，对外端口选一个新的

GA 端：在 GA Listener 里把对应的端口（443/444/8443）都加上转发到 EC2 实例即可，不需要每次改 GA 配置。

---

## 子命令

```
sudo bash install.sh install     交互式安装（hub 或 node）
sudo bash install.sh add-node    Hub 上：动态新增落地 peer + DNAT
sudo bash install.sh status      查看 WG 状态与端口映射表
sudo bash install.sh tune        仅应用 sysctl + RPS（已有 WG 也可重跑）
sudo bash install.sh uninstall   卸载 WG 与映射规则（保留 sysctl）
```

非交互模式：
```bash
ROLE=hub  sudo -E bash install.sh install   # 仍会问端口、子网等参数
```

---

## 状态查看

```bash
sudo bash install.sh status
```

Hub 上输出示例：
```
== wg-relay 状态 ==
  角色: hub
  公网 IP: 13.x.x.x
  BBR: bbr
  ip_forward: 1

== WireGuard ==
[✓] wg-quick@wg0 运行中
interface: wg0
  public key: ...
  listening port: 51820
peer: <lax pubkey>
  endpoint: ...
  allowed ips: 10.66.0.2/32
peer: <japan pubkey>
  allowed ips: 10.66.0.3/32

== DNAT 端口映射 ==
  lax        :443/tcp  ->  10.66.0.2:443
  japan      :444/tcp  ->  10.66.0.3:443
```

---

## 应用的关键参数（FYI）

```ini
# 拥塞 / 缓冲
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_notsent_lowat = 131072
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_reordering = 8
net.ipv4.tcp_tw_reuse = 1

# 转发
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# conntrack（中转必备）
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
# + nf_conntrack hashsize=262144  (开机加载)

# WireGuard
MTU = 1420                 # 1500 - 60 (WG头) - 20 (安全余量)
PersistentKeepalive = 25   # 落地→中转，穿NAT用
```

---

## 故障排查

### 落地 ping 不通 Hub
1. 落地上 `wg show` 看握手是否成功（`latest handshake` 有时间戳就 OK）
2. Hub 是否已 `add-node` 把这台落地的 peer 加进来
3. 防火墙：Hub 的 `51820/udp` 是否对落地公网 IP 开放（云厂商安全组）

### 客户端连得上但慢 / 不稳定
1. `ethtool -S <网卡>` 看 `rx_dropped` 是否暴涨 → 加大 `netdev_max_backlog`
2. 看 `cat /proc/softirqs` 是否还压在 CPU0 → 重跑 `install.sh tune`
3. MTU：在路径上 `ping -M do -s 1392 <落地>` 测试，不通就把两端 MTU 调到 1400 或更低

### bufferbloat 高
本脚本默认开了 `fq + bbr`，bufferbloat 应该已经压到很低。如果还是高，检查云商提供的虚拟网卡是否启用了硬件 offload：
```bash
ethtool -K <网卡> tso off gso off gro off
```

### add-node 后端口不通
```bash
# Hub 上
sudo bash install.sh status        # 看 DNAT 是否进去了
sudo iptables -t nat -nL PREROUTING --line-numbers
sudo conntrack -L | grep <对外端口>
```

如果 conntrack 里看到 `[UNREPLIED]`，说明落地没回包 → 多半是 SNAT 缺失或落地的 SUDOKU 服务没起。

---

## 卸载

```bash
sudo bash install.sh uninstall
```

只清 WG + 端口映射，保留 sysctl 调优。要彻底清理：
```bash
sudo rm /etc/sysctl.d/99-wg-relay.conf /etc/modprobe.d/nf_conntrack.conf
sudo sysctl --system
```

---

## License

MIT
