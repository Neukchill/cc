#!/bin/bash
# =============================================================================
#  wg-relay — 一键 WireGuard 中转/落地部署脚本
# -----------------------------------------------------------------------------
#  适用场景：GA/Anycast → 中转机 (Hub) → WireGuard → 落地机 (Node) → 出口
#  承载协议：SUDOKU / VLESS / Trojan / Hysteria 等任意 TCP/UDP 代理
#
#  特性：
#    - 系统调优 (sysctl) + BBR + fq + 大缓冲 + conntrack
#    - 开启 IP 转发 + RPS 多核分散（systemd 持久化）
#    - WireGuard 安装 + 自动密钥生成 + MTU 1420
#    - Hub 模式：监听端，支持后续动态添加多个落地 (add-node)
#    - Node 模式：落地端，自动写好回连配置
#    - DNAT 端口映射：一个中转机可同时挂多个落地，靠端口区分
#
#  用法：
#    sudo bash install.sh install      # 交互式安装（角色: hub | node）
#    sudo bash install.sh add-node     # Hub 上：新增一个落地 peer + DNAT
#    sudo bash install.sh status       # 查看 WG 状态与端口映射
#    sudo bash install.sh tune         # 仅应用系统调优（不装 WG）
#    sudo bash install.sh uninstall    # 卸载 WG 与映射规则（保留 sysctl）
#
#  License: MIT
# =============================================================================

set -euo pipefail

# ----- 常量 ------------------------------------------------------------------
readonly WG_DIR="/etc/wireguard"
readonly WG_IF="wg0"
readonly WG_CONF="${WG_DIR}/${WG_IF}.conf"
readonly WG_PORT_DEFAULT=51820
readonly WG_MTU_DEFAULT=1420
readonly WG_SUBNET_DEFAULT="10.66.0"        # 10.66.0.0/24，避开常见冲突
readonly SYSCTL_FILE="/etc/sysctl.d/99-wg-relay.conf"
readonly RPS_SERVICE="/etc/systemd/system/wg-rps.service"
readonly RPS_SCRIPT="/usr/local/sbin/wg-rps-apply.sh"
readonly STATE_FILE="${WG_DIR}/.wg-relay.state"   # 记录角色 + 端口映射
readonly SCRIPT_VERSION="1.0.0"

# ----- 颜色输出 --------------------------------------------------------------
if [[ -t 1 ]]; then
    C_RED=$'\033[0;31m'; C_GRN=$'\033[0;32m'; C_YEL=$'\033[1;33m'
    C_BLU=$'\033[0;34m'; C_CYN=$'\033[0;36m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
    C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''; C_BLD=''; C_RST=''
fi
log()    { echo -e "${C_BLU}[*]${C_RST} $*"; }
ok()     { echo -e "${C_GRN}[✓]${C_RST} $*"; }
warn()   { echo -e "${C_YEL}[!]${C_RST} $*"; }
err()    { echo -e "${C_RED}[✗]${C_RST} $*" >&2; }
title()  { echo -e "\n${C_BLD}${C_CYN}== $* ==${C_RST}"; }

# ----- 前置检查 --------------------------------------------------------------
require_root() {
    if [[ $EUID -ne 0 ]]; then
        err "请使用 root 运行（sudo bash $0 ...）"
        exit 1
    fi
}

detect_os() {
    if [[ ! -f /etc/os-release ]]; then
        err "无法识别系统（缺 /etc/os-release）"
        exit 1
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu) PKG_MGR="apt" ;;
        centos|rhel|rocky|almalinux|fedora) PKG_MGR="dnf" ;;
        *) err "目前仅支持 Debian/Ubuntu/RHEL 系，当前: ${ID:-unknown}"; exit 1 ;;
    esac
    ok "系统: ${PRETTY_NAME:-$ID} (包管理器: $PKG_MGR)"
}

get_egress_iface() {
    ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

get_public_ip() {
    local ip
    ip=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null) \
        || ip=$(curl -fsS4 --max-time 5 https://ifconfig.me 2>/dev/null) \
        || ip=""
    echo "$ip"
}

# ----- 1. 系统调优 -----------------------------------------------------------
apply_sysctl() {
    title "应用系统内核调优"

    cat > "$SYSCTL_FILE" <<'EOF'
# wg-relay tuning — managed file, do not edit by hand
# ---- TCP / 拥塞 / 缓冲 ----
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

# ---- 转发 ----
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ---- conntrack（中转机尤其需要）----
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
EOF

    # nf_conntrack 模块 + hashsize（开机加载）
    modprobe nf_conntrack 2>/dev/null || true
    if [[ -w /sys/module/nf_conntrack/parameters/hashsize ]]; then
        echo 262144 > /sys/module/nf_conntrack/parameters/hashsize || true
    fi
    echo "options nf_conntrack hashsize=262144" > /etc/modprobe.d/nf_conntrack.conf
    grep -q '^nf_conntrack' /etc/modules-load.d/wg-relay.conf 2>/dev/null \
        || echo nf_conntrack > /etc/modules-load.d/wg-relay.conf

    sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null
    ok "sysctl 已写入 $SYSCTL_FILE 并生效"

    # 验证关键项
    local cc qd fwd
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo ?)
    qd=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo ?)
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo ?)
    echo "    BBR=${cc}  qdisc=${qd}  ip_forward=${fwd}"
    [[ "$cc" == "bbr" ]] || warn "BBR 未生效，可能内核 < 4.9 或模块缺失"
}

# ----- 2. RPS 多核分散 -------------------------------------------------------
setup_rps() {
    title "配置 RPS（多核处理网络中断）"

    cat > "$RPS_SCRIPT" <<'RPSEOF'
#!/bin/bash
# wg-relay RPS apply — 把网卡 RX 队列分散到所有 CPU
set -e
cores=$(nproc)
mask=$(printf '%x' $((2**cores - 1)))
applied=0
for nic in $(ls /sys/class/net/); do
    case "$nic" in lo|docker*|br-*|veth*|virbr*) continue ;; esac
    [[ -d /sys/class/net/$nic/queues ]] || continue
    for q in /sys/class/net/$nic/queues/rx-*/rps_cpus; do
        [[ -w "$q" ]] && echo "$mask" > "$q" 2>/dev/null && applied=1 || true
    done
done
exit 0
RPSEOF
    chmod +x "$RPS_SCRIPT"

    cat > "$RPS_SERVICE" <<EOF
[Unit]
Description=wg-relay RPS multicore distribution
After=network-online.target wg-quick@${WG_IF}.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${RPS_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now wg-rps.service >/dev/null 2>&1 || true

    # 立即应用一次
    bash "$RPS_SCRIPT" || true

    local cores mask
    cores=$(nproc)
    mask=$(printf '%x' $((2**cores - 1)))
    ok "RPS 已应用到 ${cores} 核 (mask=0x${mask})，并设为开机自启"
}

# ----- 3. 安装 WireGuard 与依赖 ----------------------------------------------
install_packages() {
    title "安装 WireGuard 及依赖"
    if [[ "$PKG_MGR" == "apt" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq wireguard wireguard-tools iptables \
            iptables-persistent netfilter-persistent curl jq qrencode \
            >/dev/null
    else
        $PKG_MGR install -y -q epel-release 2>/dev/null || true
        $PKG_MGR install -y -q wireguard-tools iptables iptables-services \
            curl jq qrencode >/dev/null
        systemctl enable --now iptables 2>/dev/null || true
    fi
    ok "$(wg --version | head -n1)"
}

# ----- 4. 密钥与配置 ---------------------------------------------------------
ensure_keys() {
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    if [[ ! -s "$WG_DIR/private.key" ]]; then
        umask 077
        wg genkey | tee "$WG_DIR/private.key" | wg pubkey > "$WG_DIR/public.key"
        chmod 600 "$WG_DIR/private.key" "$WG_DIR/public.key"
        ok "已生成新的 WG 密钥对"
    else
        log "已存在密钥，跳过生成"
    fi
}

backup_conf() {
    if [[ -f "$WG_CONF" ]]; then
        local bk
        bk="${WG_CONF}.bak.$(date +%s)"
        cp -a "$WG_CONF" "$bk"
        warn "已备份原配置到 $bk"
    fi
}

write_state() {
    # key=value 格式，保存角色等
    local k="$1" v="$2"
    touch "$STATE_FILE"
    chmod 600 "$STATE_FILE"
    if grep -q "^${k}=" "$STATE_FILE" 2>/dev/null; then
        sed -i "s|^${k}=.*|${k}=${v}|" "$STATE_FILE"
    else
        echo "${k}=${v}" >> "$STATE_FILE"
    fi
}

read_state() {
    local k="$1"
    [[ -f "$STATE_FILE" ]] || return 1
    grep "^${k}=" "$STATE_FILE" 2>/dev/null | head -n1 | cut -d= -f2-
}

# ----- 5a. Hub（中转机）配置 -------------------------------------------------
configure_hub() {
    title "配置中转机 (Hub)"

    local egress wg_port wg_mtu wg_subnet hub_ip pub_ip
    egress=$(get_egress_iface)
    [[ -z "$egress" ]] && { err "无法识别出网网卡"; exit 1; }
    log "出网网卡: $egress"

    read -rp "WireGuard 监听端口 [${WG_PORT_DEFAULT}]: " wg_port
    wg_port=${wg_port:-$WG_PORT_DEFAULT}
    read -rp "WG 隧道 MTU [${WG_MTU_DEFAULT}]: " wg_mtu
    wg_mtu=${wg_mtu:-$WG_MTU_DEFAULT}
    read -rp "WG 隧道 /24 子网前缀 [${WG_SUBNET_DEFAULT}]: " wg_subnet
    wg_subnet=${wg_subnet:-$WG_SUBNET_DEFAULT}
    hub_ip="${wg_subnet}.1"

    backup_conf
    ensure_keys
    local priv pub
    priv=$(cat "$WG_DIR/private.key")
    pub=$(cat "$WG_DIR/public.key")

    cat > "$WG_CONF" <<EOF
[Interface]
# Role: HUB  Subnet: ${wg_subnet}.0/24  Egress: ${egress}
PrivateKey = ${priv}
Address    = ${hub_ip}/24
ListenPort = ${wg_port}
MTU        = ${wg_mtu}

# 转发 + 对落地 SNAT（让落地回包走回 wg0，避免非对称路由）
PostUp   = iptables -A FORWARD -i %i -j ACCEPT
PostUp   = iptables -A FORWARD -o %i -j ACCEPT
PostUp   = iptables -t nat -A POSTROUTING -o %i -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -D FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o %i -j MASQUERADE

# ----- Peers 由 add-node 自动追加，请勿手动编辑下方 -----
EOF
    chmod 600 "$WG_CONF"

    write_state "ROLE" "hub"
    write_state "WG_PORT" "$wg_port"
    write_state "WG_MTU" "$wg_mtu"
    write_state "WG_SUBNET" "$wg_subnet"
    write_state "EGRESS" "$egress"

    systemctl enable wg-quick@${WG_IF} >/dev/null 2>&1
    systemctl restart wg-quick@${WG_IF}
    ok "WireGuard 已启动 (${WG_IF})"

    pub_ip=$(get_public_ip)

    cat <<EOF

${C_BLD}${C_GRN}========== Hub 部署完成 ==========${C_RST}
  角色:        中转机 (Hub)
  公网 IP:     ${pub_ip:-<未检测到>}
  WG 端口:     ${wg_port}
  WG 子网:     ${wg_subnet}.0/24   (Hub = ${hub_ip})
  MTU:         ${wg_mtu}
  本机公钥:    ${C_YEL}${pub}${C_RST}
${C_BLD}===================================${C_RST}

${C_CYN}下一步：${C_RST}
  1) 在每台落地机执行：
       sudo bash install.sh install   # 选 node，填入上面的 公网IP / 端口 / 公钥
  2) 落地机部署完成后，回到本机执行：
       sudo bash install.sh add-node
     录入落地的【公钥】+【对外端口】+【落地服务端口】，自动加 Peer 与 DNAT。
EOF
}

# ----- 5b. Node（落地机）配置 ------------------------------------------------
configure_node() {
    title "配置落地机 (Node)"

    local hub_ip hub_port hub_pub wg_subnet node_idx wg_mtu
    read -rp "中转机 (Hub) 公网 IP/域名: " hub_ip
    [[ -z "$hub_ip" ]] && { err "Hub 地址不能为空"; exit 1; }
    read -rp "Hub WireGuard 端口 [${WG_PORT_DEFAULT}]: " hub_port
    hub_port=${hub_port:-$WG_PORT_DEFAULT}
    read -rp "Hub 公钥: " hub_pub
    [[ -z "$hub_pub" ]] && { err "Hub 公钥不能为空"; exit 1; }
    read -rp "WG 子网前缀（与 Hub 一致）[${WG_SUBNET_DEFAULT}]: " wg_subnet
    wg_subnet=${wg_subnet:-$WG_SUBNET_DEFAULT}
    read -rp "本机在 WG 子网中的序号（2-254，每台落地需唯一）[2]: " node_idx
    node_idx=${node_idx:-2}
    if ! [[ "$node_idx" =~ ^[0-9]+$ ]] || (( node_idx < 2 || node_idx > 254 )); then
        err "序号必须是 2-254 的整数"; exit 1
    fi
    read -rp "WG 隧道 MTU [${WG_MTU_DEFAULT}]: " wg_mtu
    wg_mtu=${wg_mtu:-$WG_MTU_DEFAULT}

    backup_conf
    ensure_keys
    local priv pub node_addr
    priv=$(cat "$WG_DIR/private.key")
    pub=$(cat "$WG_DIR/public.key")
    node_addr="${wg_subnet}.${node_idx}"

    cat > "$WG_CONF" <<EOF
[Interface]
# Role: NODE  Address: ${node_addr}
PrivateKey = ${priv}
Address    = ${node_addr}/24
MTU        = ${wg_mtu}

[Peer]
# Hub
PublicKey           = ${hub_pub}
Endpoint            = ${hub_ip}:${hub_port}
AllowedIPs          = ${wg_subnet}.0/24
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONF"

    write_state "ROLE" "node"
    write_state "WG_MTU" "$wg_mtu"
    write_state "WG_SUBNET" "$wg_subnet"
    write_state "NODE_ADDR" "$node_addr"
    write_state "HUB_IP" "$hub_ip"
    write_state "HUB_PORT" "$hub_port"

    systemctl enable wg-quick@${WG_IF} >/dev/null 2>&1
    systemctl restart wg-quick@${WG_IF}
    ok "WireGuard 已启动"

    log "等待 3 秒测试与 Hub 的连通性..."
    sleep 3
    if ping -c 2 -W 2 "${wg_subnet}.1" >/dev/null 2>&1; then
        ok "已 ping 通 Hub (${wg_subnet}.1)"
    else
        warn "Hub ping 不通 — 检查 Hub 是否已添加本机 Peer"
    fi

    cat <<EOF

${C_BLD}${C_GRN}========== Node 部署完成 ==========${C_RST}
  角色:        落地机 (Node)
  WG 地址:     ${node_addr}/24
  Hub:         ${hub_ip}:${hub_port}
  MTU:         ${wg_mtu}
  本机公钥:    ${C_YEL}${pub}${C_RST}
${C_BLD}====================================${C_RST}

${C_CYN}下一步（在 Hub 上执行）：${C_RST}
  sudo bash install.sh add-node
  填入：
    Node 公钥        = ${pub}
    Node WG 地址     = ${node_addr}
    对外监听端口     = 你想从 Hub 暴露给客户端的端口 (例: 444)
    Node 服务实际端口= 本机 SUDOKU/代理监听的端口   (例: 443)
EOF
}

# ----- 6. add-node：在 Hub 上动态加落地 --------------------------------------
add_node() {
    [[ -f "$WG_CONF" ]] || { err "未找到 $WG_CONF，先 install"; exit 1; }
    local role
    role=$(read_state ROLE || echo "")
    if [[ "$role" != "hub" ]]; then
        err "本机不是 Hub（角色=$role），add-node 只能在 Hub 上执行"
        exit 1
    fi

    title "在 Hub 上添加新落地 Peer"

    local node_pub node_addr ext_port int_port proto egress wg_subnet name
    egress=$(read_state EGRESS || get_egress_iface)
    wg_subnet=$(read_state WG_SUBNET || echo "$WG_SUBNET_DEFAULT")

    read -rp "落地名称（用于备注，例: japan / lax / hk）: " name
    [[ -z "$name" ]] && name="node"
    read -rp "落地 公钥: " node_pub
    [[ -z "$node_pub" ]] && { err "公钥不能为空"; exit 1; }
    read -rp "落地 WG 地址 (例: ${wg_subnet}.3): " node_addr
    [[ -z "$node_addr" ]] && { err "WG 地址不能为空"; exit 1; }
    read -rp "Hub 对外监听端口（客户端连接的端口，例: 444）: " ext_port
    [[ -z "$ext_port" ]] && { err "对外端口不能为空"; exit 1; }
    read -rp "落地实际服务端口（落地上 SUDOKU 等监听的端口，例: 443）: " int_port
    [[ -z "$int_port" ]] && { err "落地端口不能为空"; exit 1; }
    read -rp "协议 [tcp/udp/both]，默认 tcp: " proto
    proto=${proto:-tcp}

    # 防重复：公钥已存在就拒绝
    if grep -qF "PublicKey = ${node_pub}" "$WG_CONF" 2>/dev/null; then
        err "该公钥已在配置中，跳过 Peer 追加（仍可重复运行以补加 DNAT）"
    else
        cat >> "$WG_CONF" <<EOF

[Peer]
# ${name}
PublicKey  = ${node_pub}
AllowedIPs = ${node_addr}/32
EOF
        ok "Peer 已写入 $WG_CONF"
    fi

    # 应用 Peer（不重启，热加载）
    if ! wg syncconf "${WG_IF}" <(wg-quick strip "${WG_IF}"); then
        warn "wg syncconf 失败，回退到 systemctl restart"
        systemctl restart wg-quick@${WG_IF}
    fi

    # ---- DNAT ----
    local dnat_protos=()
    case "$proto" in
        tcp) dnat_protos=(tcp) ;;
        udp) dnat_protos=(udp) ;;
        both) dnat_protos=(tcp udp) ;;
        *) err "未知协议 $proto"; exit 1 ;;
    esac

    for p in "${dnat_protos[@]}"; do
        # 幂等：先尝试删后加
        iptables -t nat -C PREROUTING -i "$egress" -p "$p" --dport "$ext_port" \
            -j DNAT --to-destination "${node_addr}:${int_port}" 2>/dev/null \
            && iptables -t nat -D PREROUTING -i "$egress" -p "$p" --dport "$ext_port" \
                 -j DNAT --to-destination "${node_addr}:${int_port}" || true
        iptables -t nat -A PREROUTING -i "$egress" -p "$p" --dport "$ext_port" \
            -j DNAT --to-destination "${node_addr}:${int_port}"

        iptables -C FORWARD -i "$egress" -o "${WG_IF}" -p "$p" \
            -d "$node_addr" --dport "$int_port" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$egress" -o "${WG_IF}" -p "$p" \
            -d "$node_addr" --dport "$int_port" -j ACCEPT
    done

    # 持久化 iptables
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save >/dev/null
    elif command -v iptables-save >/dev/null && [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4
    fi

    # 状态记录
    write_state "MAP_${ext_port}_${proto}" "${name}|${node_addr}|${int_port}|${node_pub}"

    cat <<EOF

${C_BLD}${C_GRN}========== add-node 完成 ==========${C_RST}
  落地名称:    ${name}
  落地 WG IP:  ${node_addr}
  入口端口:    ${egress}:${ext_port}/${proto}
  落地服务:    ${node_addr}:${int_port}
${C_BLD}====================================${C_RST}

  现在客户端把  ${C_YEL}server_address${C_RST}  指向：
    Hub公网IP  端口 ${ext_port}
  即可走  Hub → WG → ${name}  到达  SUDOKU/代理服务。
EOF
}

# ----- 7. 状态展示 -----------------------------------------------------------
show_status() {
    title "wg-relay 状态"

    if [[ ! -f "$WG_CONF" ]]; then
        warn "未安装 / $WG_CONF 不存在"
        return
    fi

    local role
    role=$(read_state ROLE || echo "?")
    echo "  角色: ${role}"
    echo "  公网 IP: $(get_public_ip || echo unknown)"
    echo "  内核: $(uname -r)"
    echo "  BBR: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo "  ip_forward: $(sysctl -n net.ipv4.ip_forward 2>/dev/null)"
    echo

    title "WireGuard"
    if systemctl is-active --quiet "wg-quick@${WG_IF}"; then
        ok "wg-quick@${WG_IF} 运行中"
    else
        err "wg-quick@${WG_IF} 未运行"
    fi
    wg show "${WG_IF}" 2>/dev/null || warn "wg show 无输出"

    if [[ "$role" == "hub" ]]; then
        title "DNAT 端口映射"
        if [[ -f "$STATE_FILE" ]]; then
            grep '^MAP_' "$STATE_FILE" 2>/dev/null | while IFS='=' read -r k v; do
                # MAP_444_tcp=name|10.66.0.3|443|pubkey
                local port_proto="${k#MAP_}"
                local ext_port="${port_proto%_*}"
                local proto="${port_proto##*_}"
                IFS='|' read -r name node_addr int_port _pub <<< "$v"
                printf "  %-10s  :%s/%s  ->  %s:%s\n" "$name" "$ext_port" "$proto" "$node_addr" "$int_port"
            done
        fi
        echo
        title "iptables NAT (PREROUTING)"
        iptables -t nat -nL PREROUTING --line-numbers | sed 's/^/  /'
    fi
}

# ----- 8. 卸载（保留 sysctl 调优）-------------------------------------------
do_uninstall() {
    title "卸载 wg-relay"
    read -rp "确定要卸载 WG 与端口映射吗？(yes/no): " ans
    [[ "$ans" == "yes" ]] || { log "已取消"; return; }

    systemctl disable --now "wg-quick@${WG_IF}" 2>/dev/null || true
    systemctl disable --now wg-rps.service 2>/dev/null || true

    # 清掉本脚本加的 NAT/FORWARD 规则
    if [[ -f "$STATE_FILE" ]]; then
        local egress; egress=$(read_state EGRESS || get_egress_iface)
        grep '^MAP_' "$STATE_FILE" | while IFS='=' read -r k v; do
            local port_proto="${k#MAP_}"
            local ext_port="${port_proto%_*}"
            local proto="${port_proto##*_}"
            IFS='|' read -r _n node_addr int_port _p <<< "$v"
            iptables -t nat -D PREROUTING -i "$egress" -p "$proto" --dport "$ext_port" \
                -j DNAT --to-destination "${node_addr}:${int_port}" 2>/dev/null || true
            iptables -D FORWARD -i "$egress" -o "${WG_IF}" -p "$proto" \
                -d "$node_addr" --dport "$int_port" -j ACCEPT 2>/dev/null || true
        done
    fi
    command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null || true

    rm -f "$WG_CONF" "$STATE_FILE" "$RPS_SERVICE" "$RPS_SCRIPT"
    systemctl daemon-reload
    ok "已卸载（系统调优 ${SYSCTL_FILE} 保留，如需也清掉请手动 rm）"
}

# ----- 主入口 ---------------------------------------------------------------
do_install() {
    require_root
    detect_os
    apply_sysctl
    install_packages
    setup_rps

    local role
    if [[ -n "${ROLE:-}" ]]; then
        role="$ROLE"
    else
        echo
        echo "${C_BLD}选择本机角色：${C_RST}"
        echo "  1) hub   — 中转机（监听端，对接 GA / 多落地）"
        echo "  2) node  — 落地机（落地端，跑 SUDOKU/代理服务）"
        read -rp "输入 1 或 2: " choice
        case "$choice" in
            1) role="hub" ;;
            2) role="node" ;;
            *) err "无效选择"; exit 1 ;;
        esac
    fi

    case "$role" in
        hub)  configure_hub ;;
        node) configure_node ;;
        *) err "未知角色: $role"; exit 1 ;;
    esac
}

print_help() {
    cat <<EOF
${C_BLD}wg-relay v${SCRIPT_VERSION}${C_RST} — 一键 WireGuard 中转/落地

用法:
  sudo bash $0 install     交互式安装（hub 或 node）
  sudo bash $0 add-node    Hub 上：动态新增一个落地 peer + DNAT
  sudo bash $0 status      查看当前状态与端口映射
  sudo bash $0 tune        仅应用 sysctl + RPS（不装 WG）
  sudo bash $0 uninstall   卸载 WG 与映射规则

环境变量:
  ROLE=hub|node            非交互模式下指定角色

示例:
  # Hub 上加日本落地，对外端口 444 -> 落地的 :443
  sudo bash $0 add-node
EOF
}

main() {
    case "${1:-}" in
        install)        do_install ;;
        add-node|peer)  require_root; add_node ;;
        status)         show_status ;;
        tune)           require_root; detect_os; apply_sysctl; setup_rps ;;
        uninstall)      require_root; do_uninstall ;;
        -h|--help|help|"") print_help ;;
        *) err "未知命令: $1"; print_help; exit 1 ;;
    esac
}

main "$@"
