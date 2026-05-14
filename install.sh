#!/usr/bin/env bash
set -Eeo pipefail

# 错误处理
trap 'echo -e "\033[0;31m[错误] 脚本在第 $LINENO 行出错 (退出码=$?)\033[0m"' ERR

# ============================================
# WireGuard 中继管理脚本 - 完整版 v3
# 功能：
#   1. 系统调优：BBR + fq + TCP Fast Open + MTU Probing + 大缓冲
#   2. conntrack 调优：连接跟踪表 1M、hashsize 256K
#   3. RPS 多核分散：systemd 持久化
#   4. WireGuard：自动安装、密钥、MTU 1420
#   5. Hub：单中转机挂任意多落地
#   6. Node：自动回连 + PersistentKeepalive=25
#   7. add-node：动态加 peer + DNAT，wg syncconf 热加载
#   8. iptables 持久化
#   9. 幂等：重复运行不破坏配置
# ============================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

WG_CONFIG_DIR="/etc/wireguard"
WG_CONFIG_FILE="${WG_CONFIG_DIR}/wg0.conf"
WG_ROLE_FILE="${WG_CONFIG_DIR}/.role"
WG_PEERS_FILE="${WG_CONFIG_DIR}/.peers"
SYSCTL_CONF="/etc/sysctl.d/99-wg-relay.conf"
RPS_SERVICE="/etc/systemd/system/rps-affinity.service"

DEFAULT_WG_PORT="48940"; DEFAULT_WG_MTU="1420"
DEFAULT_TUNNEL_IP_HUB="10.8.0.1/24"
DEFAULT_TUNNEL_IP_NODE="10.8.0.2/24"

ACTION=""; WG_ROLE=""; WG_LISTEN_PORT="$DEFAULT_WG_PORT"
WG_ENDPOINT=""; WG_PEER_PUBKEY=""; WG_PEER_PSK=""
WG_TUNNEL_IP=""; NODE_NAME=""; EXTERNAL_PORT=""

log_info()  { echo -e "${GREEN}[信息]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[警告]${NC} $1"; }
log_error() { echo -e "${RED}[错误]${NC} $1"; }
log_step()  { echo -e "${CYAN}[步骤]${NC} ${BOLD}$1${NC}"; }
log_ok()    { echo -e "${GREEN}  ✓ $1${NC}"; }

pause() { echo; read -r -p "按 Enter 继续..."; }
clear_screen() { clear 2>/dev/null || true; }

check_root() { [ "$(id -u)" -ne 0 ] && log_error "需要 root 权限" && exit 1; }

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release 2>/dev/null || true
        echo "${ID:-unknown}"
    else
        echo "unknown"
    fi
}

# ============================================
# 系统调优
# ============================================
optimize_system() {
    log_step "系统调优..."
    local os=$(detect_os)
    
    case "$os" in
        ubuntu|debian)
            DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iptables-persistent netfilter-persistent curl wget 2>/dev/null || true
            ;;
        centos|rhel|rocky|almalinux|fedora)
            (command -v dnf >/dev/null 2>&1 && dnf install -y -q wireguard-tools iptables-services) || yum install -y -q wireguard-tools iptables-services
            ;;
    esac
    
    if [ ! -f "$SYSCTL_CONF" ]; then
        log_info "配置系统参数..."
        cat > "$SYSCTL_CONF" <<'EOF'
net.ipv4.tcp_congestion_control=bbr
net.core.default_qdisc=fq
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_base_mss=1024
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.core.netdev_max_backlog=65536
net.ipv4.tcp_notsent_lowat=16384
net.ipv4.ip_local_port_range=1024 65535
net.netfilter.nf_conntrack_max=1048576
net.netfilter.nf_conntrack_tcp_timeout_established=600
net.netfilter.nf_conntrack_tcp_timeout_close_wait=60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait=60
net.netfilter.nf_conntrack_tcp_timeout_time_wait=60
net.netfilter.nf_conntrack_udp_timeout=60
net.netfilter.nf_conntrack_udp_timeout_stream=120
EOF
        sysctl --system >/dev/null 2>&1 || true
        log_ok "系统参数已配置"
    else
        log_info "系统参数已配置，跳过"
    fi
    
    # conntrack
    if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
        echo 1048576 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
    fi
    if [ -f /sys/module/nf_conntrack/parameters/hashsize ]; then
        echo 262144 > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true
    fi
    log_ok "conntrack 已优化"
    
    # RPS
    setup_rps
    
    log_ok "系统调优完成"
}

setup_rps() {
    log_step "配置 RPS..."
    local ifaces=$(ls /sys/class/net/ 2>/dev/null | grep -v '^lo$' || true)
    [ -z "$ifaces" ] && { log_warn "无网卡"; return; }
    
    local cpu=$(nproc 2>/dev/null || echo 1)
    local mask
    [ "$cpu" -le 32 ] && mask=$(printf '%x' $(( (1 << cpu) - 1 ))) || mask="ffffffff"
    
    if [ ! -f "$RPS_SERVICE" ]; then
        cat > "$RPS_SERVICE" <<EOF
[Unit]
Description=RPS
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for i in $ifaces; do for f in /sys/class/net/\$i/queues/rx-*/rps_cpus; do echo $mask > \$f 2>/dev/null || true; done; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable rps-affinity.service >/dev/null 2>&1 || true
        systemctl start rps-affinity.service >/dev/null 2>&1 || true
    fi
    
    for i in $ifaces; do
        for f in /sys/class/net/$i/queues/rx-*/rps_cpus; do
            [ -f "$f" ] && echo "$mask" > "$f" 2>/dev/null || true
        done
    done
    log_ok "RPS 已配置"
}

# ============================================
# WG 核心
# ============================================
generate_wg_keypair() {
    local priv=$(wg genkey)
    echo "${priv}:$(echo "$priv" | wg pubkey)"
}

detect_wg_role() {
    if [ -f "$WG_ROLE_FILE" ]; then cat "$WG_ROLE_FILE" 2>/dev/null | tr -d '[:space:]'; return; fi
    if [ -f "$WG_CONFIG_FILE" ]; then
        local peers=$(grep -c '^\[Peer\]' "$WG_CONFIG_FILE" 2>/dev/null || echo 0)
        [ "$peers" -gt 1 ] && echo "hub" && return
        [ "$peers" -eq 1 ] && grep -q '^ListenPort' "$WG_CONFIG_FILE" 2>/dev/null && echo "hub" || echo "node"
    fi
}

backup_wg_config() {
    [ -f "$WG_CONFIG_FILE" ] && cp "$WG_CONFIG_FILE" "${WG_CONFIG_FILE}.backup.$(date +%Y%m%d-%H%M%S)"
    log_info "配置已备份"
}

wg_reload() {
    if ! command -v wg-quick >/dev/null 2>&1; then log_warn "wg-quick 不可用"; return 1; fi
    
    if wg show wg0 >/dev/null 2>&1; then
        wg syncconf wg0 <(wg-quick strip wg0 2>/dev/null || cat "$WG_CONFIG_FILE") 2>/dev/null && log_ok "配置已热加载" && return 0
    fi
    
    wg-quick down wg0 2>/dev/null || true
    wg-quick up wg0 2>/dev/null && log_ok "WireGuard 已启动" && return 0
    log_warn "启动失败"
    return 1
}

save_iptables_rules() {
    log_step "保存 iptables..."
    local os=$(detect_os)
    case "$os" in
        ubuntu|debian)
            mkdir -p /etc/iptables
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            systemctl enable netfilter-persistent 2>/dev/null || true
            ;;
        centos|rhel|rocky|almalinux|fedora)
            service iptables save 2>/dev/null || true
            ;;
    esac
    log_ok "iptables 已保存"
}

# ============================================
# Hub
# ============================================
init_hub() {
    log_step "初始化 Hub"
    
    local current=$(detect_wg_role)
    if [ -n "$current" ] && [ "$current" != "hub" ]; then
        log_warn "当前是 $current，切换将覆盖！"
        read -r -p "输入 YES 确认: " confirm
        [ "$confirm" != "YES" ] && { log_warn "已取消"; return 1; }
    fi
    
    backup_wg_config
    
    local keys=$(generate_wg_keypair)
    local priv=$(echo "$keys" | cut -d: -f1)
    local pub=$(echo "$keys" | cut -d: -f2)
    
    mkdir -p "$WG_CONFIG_DIR" && chmod 700 "$WG_CONFIG_DIR"
    
    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
PrivateKey = $priv
Address = ${WG_TUNNEL_IP:-$DEFAULT_TUNNEL_IP_HUB}
ListenPort = ${WG_LISTEN_PORT:-$DEFAULT_WG_PORT}
MTU = $DEFAULT_WG_MTU
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
    
    chmod 600 "$WG_CONFIG_FILE"
    echo "hub" > "$WG_ROLE_FILE"
    echo "$pub" > "${WG_CONFIG_DIR}/.pubkey"
    
    log_ok "Hub 已初始化"
    echo
    log_info "公钥: $pub"
    echo "  bash $0 init-node --endpoint <IP>:${WG_LISTEN_PORT:-$DEFAULT_WG_PORT} --pubkey $pub"
    
    wg_reload
    save_iptables_rules
}

# ============================================
# Node
# ============================================
init_node() {
    log_step "初始化 Node"
    
    [ -z "$WG_ENDPOINT" ] && { log_error "缺少 --endpoint"; return 1; }
    [ -z "$WG_PEER_PUBKEY" ] && { log_error "缺少 --pubkey"; return 1; }
    
    local current=$(detect_wg_role)
    if [ -n "$current" ] && [ "$current" != "node" ]; then
        log_warn "当前是 $current，切换将覆盖！"
        read -r -p "输入 YES 确认: " confirm
        [ "$confirm" != "YES" ] && { log_warn "已取消"; return 1; }
    fi
    
    backup_wg_config
    
    local keys=$(generate_wg_keypair)
    local priv=$(echo "$keys" | cut -d: -f1)
    local pub=$(echo "$keys" | cut -d: -f2)
    
    mkdir -p "$WG_CONFIG_DIR" && chmod 700 "$WG_CONFIG_DIR"
    
    local psk=""
    [ -n "$WG_PEER_PSK" ] && psk="PresharedKey = $WG_PEER_PSK"
    
    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
PrivateKey = $priv
Address = ${WG_TUNNEL_IP:-$DEFAULT_TUNNEL_IP_NODE}
MTU = $DEFAULT_WG_MTU

[Peer]
PublicKey = $WG_PEER_PUBKEY
$psk
Endpoint = $WG_ENDPOINT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    
    chmod 600 "$WG_CONFIG_FILE"
    echo "node" > "$WG_ROLE_FILE"
    echo "$pub" > "${WG_CONFIG_DIR}/.pubkey"
    
    log_ok "Node 已初始化"
    echo
    log_info "公钥: $pub"
    echo "  bash $0 add-node --pubkey $pub --ip ${WG_TUNNEL_IP:-$DEFAULT_TUNNEL_IP_NODE}"
    
    wg_reload
}

# ============================================
# add-node
# ============================================
add_node() {
    log_step "添加 Node"
    
    [ -z "$WG_PEER_PUBKEY" ] && { log_error "缺少 --pubkey"; return 1; }
    [ -z "$WG_TUNNEL_IP" ] && { log_error "缺少 --ip"; return 1; }
    [ "$(detect_wg_role)" != "hub" ] && { log_error "当前不是 Hub"; return 1; }
    
    local node_ip=$(echo "$WG_TUNNEL_IP" | cut -d/ -f1)
    
    # 幂等检查
    if grep -q "PublicKey = $WG_PEER_PUBKEY" "$WG_CONFIG_FILE" 2>/dev/null; then
        log_warn "该 Node 已存在，跳过"
        return 0
    fi
    
    backup_wg_config
    
    local name="${NODE_NAME:-node-$(date +%s)}"
    local ext_port
    [ -n "$EXTERNAL_PORT" ] && ext_port="$EXTERNAL_PORT" || ext_port=$((50000 + $(grep -c '^\[Peer\]' "$WG_CONFIG_FILE" 2>/dev/null || echo 0)))
    
    local psk=""
    [ -n "$WG_PEER_PSK" ] && psk="PresharedKey = $WG_PEER_PSK"
    
    cat >> "$WG_CONFIG_FILE" <<EOF

# $name
[Peer]
PublicKey = $WG_PEER_PUBKEY
$psk
AllowedIPs = ${node_ip}/32
EOF
    
    log_ok "已添加 $name (${node_ip})"
    
    # DNAT 规则
    if ! iptables -t nat -C PREROUTING -p udp --dport "$ext_port" -j DNAT --to-destination "${node_ip}:$DEFAULT_WG_PORT" 2>/dev/null; then
        iptables -t nat -A PREROUTING -p udp --dport "$ext_port" -j DNAT --to-destination "${node_ip}:$DEFAULT_WG_PORT" 2>/dev/null || true
        iptables -t nat -A POSTROUTING -d "$node_ip" -p udp --dport "$DEFAULT_WG_PORT" -j MASQUERADE 2>/dev/null || true
        log_ok "DNAT 已添加: 外部 $ext_port -> ${node_ip}"
    fi
    
    echo "${name}:${WG_PEER_PUBKEY}:${node_ip}:${ext_port}" >> "$WG_PEERS_FILE"
    
    wg_reload
    save_iptables_rules
    
    log_ok "Node 添加完成！外部端口: $ext_port"
}

# ============================================
# 状态
# ============================================
show_status() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║   WireGuard 中继管理工具 v3       ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BOLD}━━━ 系统调优 ━━━${NC}"
    [ -f "$SYSCTL_CONF" ] && log_ok "系统参数已配置" || echo "  系统参数: ${DIM}未配置${NC}"
    [ -f "$RPS_SERVICE" ] && log_ok "RPS 已配置" || echo "  RPS: ${DIM}未配置${NC}"
    echo
    
    echo -e "${BOLD}━━━ WireGuard ━━━${NC}"
    local role=$(detect_wg_role)
    if [ -n "$role" ]; then
        [ "$role" = "hub" ] && echo -e "  角色: ${CYAN}Hub (中转)${NC}" || echo -e "  角色: ${CYAN}Node (落地)${NC}"
        
        if [ -f "$WG_CONFIG_FILE" ]; then
            local port=$(grep '^ListenPort' "$WG_CONFIG_FILE" 2>/dev/null | awk '{print $3}')
            local ip=$(grep '^Address' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}')
            local peers=$(grep -c '^\[Peer\]' "$WG_CONFIG_FILE" 2>/dev/null || echo 0)
            
            echo -e "  端口: ${port:-无}  IP: ${ip:-无}  Peers: ${peers}"
            
            # 公钥
            local priv=$(grep '^PrivateKey' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}')
            [ -n "$priv" ] && command -v wg >/dev/null 2>&1 && echo -e "  公钥: ${BOLD}$(echo "$priv" | wg pubkey 2>/dev/null)${NC}"
            
            # 运行状态
            if command -v wg >/dev/null 2>&1 && wg show wg0 >/dev/null 2>&1; then
                echo -e "  状态: ${GREEN}运行中${NC}"
                local hs=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -1)
                if [ -n "$hs" ] && [ "$hs" -gt 0 ] 2>/dev/null; then
                    local ago=$(( $(date +%s) - hs ))
                    [ "$ago" -lt 180 ] && echo -e "  握手: ${GREEN}${ago}秒前${NC}" || echo -e "  握手: ${RED}${ago}秒前${NC}"
                fi
            else
                echo -e "  状态: ${RED}未运行${NC}"
            fi
        fi
    else
        echo -e "  角色: ${DIM}未配置${NC}"
    fi
    echo
    
    # peers 列表
    if [ "$role" = "hub" ] && [ -f "$WG_PEERS_FILE" ]; then
        echo -e "${BOLD}━━━ Nodes ━━━${NC}"
        while IFS=: read -r n p i e; do
            [ -n "$n" ] && echo -e "  • $n: $i (端口: $e)"
        done < "$WG_PEERS_FILE" 2>/dev/null || true
        echo
    fi
}

# ============================================
# 菜单
# ============================================
show_menu() {
    while true; do
        show_status
        
        echo -e "${BOLD}操作:${NC}"
        echo "  ${CYAN}── 初始化 ──${NC}"
        echo "  ${GREEN}1.${NC} 初始化 Hub"
        echo "  ${GREEN}2.${NC} 初始化 Node"
        echo "  ${CYAN}── 管理 ──${NC}"
        echo "  ${GREEN}3.${NC} 添加 Node"
        echo "  ${GREEN}4.${NC} 启动 WG"
        echo "  ${GREEN}5.${NC} 停止 WG"
        echo "  ${GREEN}6.${NC} 重启 WG"
        echo "  ${GREEN}7.${NC} wg show"
        echo "  ${CYAN}── 系统 ──${NC}"
        echo "  ${GREEN}8.${NC} 系统调优"
        echo "  ${GREEN}9.${NC} 保存 iptables"
        echo "  ${DIM}0.${NC} 退出"
        echo
        read -r -p "选项 [0-9]: " choice
        
        case "$choice" in
            1)
                echo
                read -r -p "端口 [${DEFAULT_WG_PORT}]: " p
                WG_LISTEN_PORT="${p:-$DEFAULT_WG_PORT}"
                read -r -p "隧道IP [${DEFAULT_TUNNEL_IP_HUB}]: " i
                WG_TUNNEL_IP="${i:-$DEFAULT_TUNNEL_IP_HUB}"
                init_hub; pause ;;
            2)
                echo
                read -r -p "Hub地址 (IP:端口): " e
                [ -z "$e" ] && { log_error "不能为空"; pause; continue; }
                WG_ENDPOINT="$e"
                read -r -p "Hub公钥: " p
                [ -z "$p" ] && { log_error "不能为空"; pause; continue; }
                WG_PEER_PUBKEY="$p"
                read -r -p "本机隧道IP [${DEFAULT_TUNNEL_IP_NODE}]: " i
                WG_TUNNEL_IP="${i:-$DEFAULT_TUNNEL_IP_NODE}"
                init_node; pause ;;
            3)
                echo
                read -r -p "Node公钥: " p
                [ -z "$p" ] && { log_error "不能为空"; pause; continue; }
                WG_PEER_PUBKEY="$p"
                read -r -p "Node IP: " i
                [ -z "$i" ] && { log_error "不能为空"; pause; continue; }
                WG_TUNNEL_IP="$i"
                read -r -p "名称: " n
                NODE_NAME="$n"
                add_node; pause ;;
            4) wg_reload; pause ;;
            5) (wg-quick down wg0 2>/dev/null && log_ok "已停止") || log_warn "停止失败"; pause ;;
            6) wg_reload; pause ;;
            7) echo; wg show wg0 2>/dev/null || log_warn "获取失败"; echo; pause ;;
            8) optimize_system; pause ;;
            9) save_iptables_rules; pause ;;
            0|q) log_info "再见!"; exit 0 ;;
            *) log_warn "无效: $choice"; pause ;;
        esac
    done
}

# ============================================
# 参数
# ============================================
usage() {
    cat <<'EOF'
用法: bash install.sh [命令]

命令:
  (无参数)     交互式菜单
  init-hub     初始化 Hub
  init-node    初始化 Node
  add-node     添加 Node
  start/stop/restart  WG 控制
  status       查看状态
  optimize     系统调优
  help         帮助

选项:
  --port PORT      端口
  --endpoint ADDR 对端地址
  --pubkey KEY    公钥
  --ip IP         隧道 IP
  --name NAME     节点名称
  --ext-port PORT 外部端口
  --psk KEY       预共享密钥

示例:
  sudo bash install.sh init-hub --port 48940
  sudo bash install.sh init-node --endpoint 1.2.3.4:48940 --pubkey xxx
  sudo bash install.sh add-node --pubkey xxx --ip 10.8.0.3
  sudo bash install.sh optimize
EOF
}

parse_args() {
    local pos=()
    while [ $# -gt 0 ]; do
        case "$1" in
            init-hub|init-node|add-node|start|stop|restart|status|optimize|save-iptables|help)
                ACTION="$1"; shift ;;
            --port) WG_LISTEN_PORT="$2"; shift 2 ;;
            --endpoint) WG_ENDPOINT="$2"; shift 2 ;;
            --pubkey) WG_PEER_PUBKEY="$2"; shift 2 ;;
            --ip) WG_TUNNEL_IP="$2"; shift 2 ;;
            --name) NODE_NAME="$2"; shift 2 ;;
            --ext-port) EXTERNAL_PORT="$2"; shift 2 ;;
            --psk) WG_PEER_PSK="$2"; shift 2 ;;
            --help|-h) ACTION="help"; shift ;;
            *) pos+=("$1"); shift ;;
        esac
    done
    [ -z "$ACTION" ] && ACTION="interactive"
}

main() {
    parse_args "$@"
    
    case "$ACTION" in
        help) usage; exit 0 ;;
        status) check_root; show_status; exit 0 ;;
    esac
    
    check_root
    
    case "$ACTION" in
        interactive) show_menu ;;
        init-hub) init_hub; exit 0 ;;
        init-node) init_node; exit 0 ;;
        add-node) add_node; exit 0 ;;
        start) wg_reload; exit 0 ;;
        stop) wg-quick down wg0 2>/dev/null && log_ok "已停止" || log_warn "停止失败或未运行"; exit 0 ;;
        restart) wg_reload; exit 0 ;;
        optimize) optimize_system; exit 0 ;;
        save-iptables) save_iptables_rules; exit 0 ;;
        *) log_error "未知: $ACTION"; usage; exit 1 ;;
    esac
}

main "$@"
