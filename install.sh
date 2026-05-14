#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================
# Xboard-Node 安装脚本 - 改进版 v2
# 特性:
#   1. 交互式中文菜单 + 命令行参数双模式
#   2. WG 配置检测，避免覆盖已有隧道
#   3. Hub/Node 角色保护，防止误切换
#   4. 固定监听端口，避免随机端口
#   5. maintain 维护模式，仅更新 peer 不重新生成密钥
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

APP_NAME="xboard-node"
INSTALL_ROOT="/etc/xboard-node"
BACKUP_DIR="${INSTALL_ROOT}/backups"
INSTALL_META="${INSTALL_ROOT}/install-meta.json"
CONFIG_FILE="${INSTALL_ROOT}/config.yml"
CREDENTIALS_FILE="${INSTALL_ROOT}/credentials.env"
BINARY_PATH="/usr/local/bin/xboard-node"
SERVICE_NAME="xboard-node.service"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
CLI_PATH="/usr/local/bin/xbctl"
INSTALLER_COPY_PATH="${INSTALL_ROOT}/install.sh"
DEFAULT_DOWNLOAD_BASE="https://github.com/cedar2025/xboard-node/releases"

# WG 相关
WG_CONFIG_DIR="/etc/wireguard"
WG_CONFIG_FILE="${WG_CONFIG_DIR}/wg0.conf"
WG_ROLE_FILE="${INSTALL_ROOT}/wg-role"
WG_PEERS_FILE="${INSTALL_ROOT}/wg-peers"

# 全局变量
ACTION=""
MODE=""
PANEL_URL=""
TOKEN=""
NODE_ID=""
NODE_TYPE=""
MACHINE_ID=""
KERNEL_TYPE="singbox"
RELEASE_VERSION="latest"
HEALTH_PORT=65530
HEALTH_ENABLED=1
RUNTIME_GOMEMLIMIT=""
RUNTIME_GOGC=""
BINARY_SOURCE=""
CLI_BINARY_SOURCE=""
FORCE_RECONFIGURE=0
PURGE=0
YES=0
ARCH=""
OS=""
DOWNLOAD_URL=""
CURRENT_STATE="fresh"
TMP_DIR=""
BACKUP_PATH=""
SERVICE_EXISTED=0
CLEANUP_DONE=0

# WG 变量
WG_ROLE=""
WG_LISTEN_PORT="48940"
WG_ENDPOINT=""
WG_PEER_PUBKEY=""
WG_PEER_PSK=""
WG_TUNNEL_IP=""

# ============================================
# 工具函数
# ============================================
log_info()  { echo -e "${GREEN}[信息]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[警告]${NC} $1"; }
log_error() { echo -e "${RED}[错误]${NC} $1"; }
log_step()  { echo -e "${CYAN}[步骤]${NC} ${BOLD}$1${NC}"; }
log_ok()    { echo -e "${GREEN}  ✓ $1${NC}"; }
log_fail()  { echo -e "${RED}  ✗ $1${NC}"; }

cleanup_tmp() {
    [ "$CLEANUP_DONE" -eq 1 ] && return
    CLEANUP_DONE=1
    [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
}

on_error() {
    local exit_code=$? line_no=${1:-unknown}
    if [ "$exit_code" -ne 0 ]; then
        log_error "脚本在第 ${line_no} 行出错 (退出码=${exit_code})"
        [ -n "$BACKUP_PATH" ] && rollback_install 2>/dev/null || true
    fi
    cleanup_tmp; exit "$exit_code"
}
trap 'on_error $LINENO' ERR
trap cleanup_tmp EXIT

pause() {
    echo
    read -r -p "按 Enter 键继续..."
}

clear_screen() {
    clear 2>/dev/null || true
}

# ============================================
# WG 检测与管理函数
# ============================================
detect_wg_role() {
    if [ -f "$WG_ROLE_FILE" ]; then
        cat "$WG_ROLE_FILE" 2>/dev/null | tr -d '[:space:]'
        return
    fi
    # 从配置文件推断
    if [ -f "$WG_CONFIG_FILE" ]; then
        local peer_count
        peer_count=$(grep -c '^\[Peer\]' "$WG_CONFIG_FILE" 2>/dev/null || echo "0")
        if [ "$peer_count" -gt 1 ]; then
            echo "hub"
        elif [ "$peer_count" -eq 1 ]; then
            if grep -q '^ListenPort' "$WG_CONFIG_FILE" 2>/dev/null; then
                echo "hub"
            else
                echo "node"
            fi
        fi
    fi
}

detect_existing_wg_config() {
    if [ ! -f "$WG_CONFIG_FILE" ]; then
        echo "0"
        return
    fi
    echo "1"
}

show_wg_config_info() {
    echo
    echo -e "${BOLD}━━━ 当前 WireGuard 配置 ━━━${NC}"
    local role
    role=$(detect_wg_role)
    if [ -n "$role" ]; then
        case "$role" in
            hub)  echo -e "  角色:     ${CYAN}Hub (中转服务器)${NC}" ;;
            node) echo -e "  角色:     ${CYAN}Node (落地服务器)${NC}" ;;
        esac
    else
        echo -e "  角色:     ${DIM}未检测到${NC}"
    fi

    if [ -f "$WG_CONFIG_FILE" ]; then
        local port ip peers pubkey
        port=$(grep '^ListenPort' "$WG_CONFIG_FILE" 2>/dev/null | awk '{print $3}') || port=""
        ip=$(grep '^Address' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || ip=""
        peers=$(grep -c '^\[Peer\]' "$WG_CONFIG_FILE" 2>/dev/null) || peers="0"
        echo -e "  监听端口: ${port:-${DIM}无${NC}}"
        echo -e "  隧道IP:   ${ip:-${DIM}无${NC}}"
        echo -e "  Peer数量: ${peers}"

        # 显示本机公钥
        local privkey
        privkey=$(grep '^PrivateKey' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || privkey=""
        if [ -n "$privkey" ] && command -v wg >/dev/null 2>&1; then
            pubkey=$(echo "$privkey" | wg pubkey 2>/dev/null) || pubkey=""
            if [ -n "$pubkey" ]; then
                echo -e "  本机公钥: ${BOLD}${pubkey}${NC}"
            fi
        fi

        # 显示对端信息
        local endpoint
        endpoint=$(grep '^Endpoint' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || endpoint=""
        if [ -n "$endpoint" ]; then
            echo -e "  对端地址: ${endpoint}"
        fi

        if command -v wg >/dev/null 2>&1; then
            if wg show wg0 >/dev/null 2>&1; then
                echo -e "  运行状态: ${GREEN}运行中${NC}"
                # 显示最新握手时间
                local latest_handshake
                latest_handshake=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | sort -rn | head -1) || latest_handshake=""
                if [ -n "$latest_handshake" ] && [ "$latest_handshake" -gt 0 ] 2>/dev/null; then
                    local ago=$(( $(date +%s) - latest_handshake ))
                    if [ "$ago" -lt 180 ]; then
                        echo -e "  最新握手: ${GREEN}${ago}秒前${NC}"
                    else
                        echo -e "  最新握手: ${RED}${ago}秒前${NC}"
                    fi
                fi
            else
                echo -e "  运行状态: ${RED}未运行${NC}"
            fi
        fi
    else
        echo -e "  配置文件: ${DIM}不存在${NC}"
    fi
    echo
}

backup_wg_config() {
    if [ -f "$WG_CONFIG_FILE" ]; then
        local backup_file="${BACKUP_DIR}/wg0-$(date +%Y%m%d-%H%M%S).conf"
        mkdir -p "$BACKUP_DIR"
        cp "$WG_CONFIG_FILE" "$backup_file"
        log_info "已备份 WG 配置: $backup_file"
    fi
}

confirm_role_change() {
    local new_role="$1"
    local new_label="$2"
    local current_role
    current_role=$(detect_wg_role)

    if [ -n "$current_role" ] && [ "$current_role" != "$new_role" ]; then
        echo
        echo -e "${RED}${BOLD}╔══════════════════════════════════════════╗${NC}"
        echo -e "${RED}${BOLD}║          ⚠️  角色变更警告 ⚠️            ║${NC}"
        echo -e "${RED}${BOLD}╠══════════════════════════════════════════╣${NC}"
        echo -e "${RED}${BOLD}║${NC}  当前角色: ${BOLD}$current_role${NC}"
        echo -e "${RED}${BOLD}║${NC}  目标角色: ${BOLD}$new_label${NC}"
        echo -e "${RED}${BOLD}║${NC}  ${RED}这将覆盖现有配置，所有隧道连接将中断！${NC}"
        echo -e "${RED}${BOLD}╚══════════════════════════════════════════╝${NC}"
        echo
        read -r -p "确认切换角色？请输入 YES 继续: " answer
        if [ "$answer" != "YES" ]; then
            log_warn "操作已取消"
            return 1
        fi
    fi
    return 0
}

generate_wg_keypair() {
    local priv
    priv=$(wg genkey)
    local pub
    pub=$(echo "$priv" | wg pubkey)
    echo "${priv}:${pub}"
}

render_wg_hub_config() {
    local private_key="$1"
    local listen_port="${2:-48940}"
    local tunnel_ip="${3:-10.8.0.1/24}"

    mkdir -p "$WG_CONFIG_DIR" && chmod 700 "$WG_CONFIG_DIR"

    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
PrivateKey = $private_key
Address = $tunnel_ip
ListenPort = $listen_port
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
    chmod 600 "$WG_CONFIG_FILE"
    echo "hub" > "$WG_ROLE_FILE"
}

render_wg_node_config() {
    local private_key="$1"
    local peer_pubkey="$2"
    local endpoint="$3"
    local psk="${4:-}"
    local tunnel_ip="${5:-10.8.0.2/24}"

    mkdir -p "$WG_CONFIG_DIR" && chmod 700 "$WG_CONFIG_DIR"

    local psk_line=""
    [ -n "$psk" ] && psk_line="PresharedKey = $psk"

    cat > "$WG_CONFIG_FILE" <<EOF
[Interface]
PrivateKey = $private_key
Address = $tunnel_ip

[Peer]
PublicKey = $peer_pubkey
${psk_line}
Endpoint = $endpoint
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    chmod 600 "$WG_CONFIG_FILE"
    echo "node" > "$WG_ROLE_FILE"
}

add_wg_peer() {
    local node_pubkey="$1"
    local node_ip="$2"
    local psk="${3:-}"
    local node_name="${4:-node}"

    if [ ! -f "$WG_CONFIG_FILE" ]; then
        log_error "WG 配置文件不存在，请先初始化 Hub"
        return 1
    fi

    if grep -q "PublicKey = $node_pubkey" "$WG_CONFIG_FILE" 2>/dev/null; then
        log_warn "Peer $node_name 已存在，跳过"
        return 0
    fi

    local psk_line=""
    [ -n "$psk" ] && psk_line="PresharedKey = $psk"

    cat >> "$WG_CONFIG_FILE" <<EOF

# $node_name
[Peer]
PublicKey = $node_pubkey
${psk_line}
AllowedIPs = $node_ip/32
EOF
    log_ok "已添加 peer: $node_name ($node_ip)"
    echo "${node_name}:${node_pubkey}:${node_ip}" >> "$WG_PEERS_FILE"

    if command -v wg >/dev/null 2>&1; then
        wg syncconf wg0 <(wg-quick strip wg0 2>/dev/null || cat "$WG_CONFIG_FILE") 2>/dev/null || true
    fi
}

wg_reload() {
    if command -v wg-quick >/dev/null 2>&1; then
        wg-quick down wg0 2>/dev/null || true
        if wg-quick up wg0 2>/dev/null; then
            log_ok "WireGuard 已启动"
        else
            log_warn "WireGuard 启动失败，请手动检查"
        fi
    fi
}

# ============================================
# 原有安装函数（精简）
# ============================================
load_health_port_from_config() {
    local cfg_path="$1"
    [ ! -f "$cfg_path" ] && return
    local parsed
    if [ -x "$CLI_PATH" ]; then
        parsed=$("$CLI_PATH" config health-port --config "$cfg_path" 2>/dev/null)
    else
        parsed=$(grep -m1 'health_port:' "$cfg_path" 2>/dev/null | sed 's/.*health_port:[[:space:]]*//' | tr -cd '0-9')
    fi
    if [ -n "$parsed" ] && [ "$parsed" -ge 0 ] 2>/dev/null; then
        HEALTH_PORT="$parsed"
        [ "$HEALTH_PORT" -eq 0 ] && HEALTH_ENABLED=0 || HEALTH_ENABLED=1
    fi
}

rollback_install() {
    log_warn "正在回滚安装..."
    if [ -n "$BACKUP_PATH" ] && [ -d "$BACKUP_PATH" ]; then
        [ -f "$BACKUP_PATH/xboard-node" ] && install -m 755 "$BACKUP_PATH/xboard-node" "$BINARY_PATH" || rm -f "$BINARY_PATH"
        [ -f "$BACKUP_PATH/config.yml" ] && install -m 600 "$BACKUP_PATH/config.yml" "$CONFIG_FILE" || rm -f "$CONFIG_FILE"
        [ -f "$BACKUP_PATH/credentials.env" ] && install -m 600 "$BACKUP_PATH/credentials.env" "$CREDENTIALS_FILE" || rm -f "$CREDENTIALS_FILE"
        [ -f "$BACKUP_PATH/install-meta.json" ] && install -m 644 "$BACKUP_PATH/install-meta.json" "$INSTALL_META" || rm -f "$INSTALL_META"
        [ -f "$BACKUP_PATH/xbctl" ] && install -m 755 "$BACKUP_PATH/xbctl" "$CLI_PATH" || rm -f "$CLI_PATH"
        [ -f "$BACKUP_PATH/${SERVICE_NAME}" ] && install -m 644 "$BACKUP_PATH/${SERVICE_NAME}" "$SERVICE_PATH" || rm -f "$SERVICE_PATH"
    fi
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart "$SERVICE_NAME" 2>/dev/null || true
    log_warn "回滚完成"
}

detect_current_state() {
    local has_binary=0 has_config=0 has_service=0
    [ -x "$BINARY_PATH" ] && has_binary=1
    [ -f "$CONFIG_FILE" ] && has_config=1
    [ -f "$SERVICE_PATH" ] && has_service=1
    if [ "$has_binary" -eq 1 ] && [ "$has_config" -eq 1 ] && [ "$has_service" -eq 1 ]; then
        CURRENT_STATE="installed"
    elif [ "$has_binary" -eq 0 ] && [ "$has_config" -eq 0 ] && [ "$has_service" -eq 0 ]; then
        CURRENT_STATE="fresh"
    else
        CURRENT_STATE="partial"
    fi
}

check_root() {
    # 检查是否是 Windows 环境
    local uname_s
    uname_s=$(uname -s 2>/dev/null || echo "Linux")
    case "$uname_s" in
        MINGW*|MSYS*|CYGWIN*)
            echo -e "${RED}[错误]${NC} 此脚本需要在 Linux 服务器上运行，不能在 Windows 直接执行"
            echo -e "${DIM}请通过 SSH 连接到你的 Linux 服务器，然后运行此脚本${NC}"
            exit 1
            ;;
    esac
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        echo -e "${RED}[错误]${NC} 请使用 root 或 sudo 运行"
        exit 1
    fi
}

detect_platform() {
    local os_name
    os_name=$(uname -s 2>/dev/null || echo "unknown")
    case "$os_name" in
        Linux) return 0 ;;
        *) 
            log_error "不支持的平台: $os_name (仅支持 Linux)"
            exit 1
            ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) log_error "不支持的架构: $(uname -m)"; exit 1 ;;
    esac
}
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release && OS="$ID" || OS="linux"
    else
        OS="linux"
    fi
}
ensure_systemd() {
    command -v systemctl >/dev/null 2>&1 || { log_error "需要 systemd"; exit 1; }
    [ -d /run/systemd/system ] || { log_error "systemd 未运行"; exit 1; }
}
install_dependencies() {
    log_step "安装依赖..."
    
    # 检查系统工具是否存在
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl wget ca-certificates wireguard-tools iptables 2>/dev/null || true
        log_ok "依赖安装完成"
        return 0
    fi
    
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y -q curl wget ca-certificates wireguard-tools iptables 2>/dev/null || true
        log_ok "依赖安装完成"
        return 0
    fi
    
    if command -v yum >/dev/null 2>&1; then
        yum install -y -q curl wget ca-certificates wireguard-tools iptables 2>/dev/null || true
        log_ok "依赖安装完成"
        return 0
    fi
    
    log_warn "未找到包管理器，部分功能可能不可用"
}
ensure_dirs() { mkdir -p "$INSTALL_ROOT" "$BACKUP_DIR" && chmod 700 "$INSTALL_ROOT"; }

# ============================================
# 交互式菜单
# ============================================
show_banner() {
    clear_screen
    echo -e "${CYAN}${BOLD}"
    echo "  ╔═══════════════════════════════════════════════╗"
    echo "  ║       Xboard-Node 安装管理工具 v2           ║"
    echo "  ║       WireGuard 隧道管理                    ║"
    echo "  ╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

show_main_menu() {
    show_banner
    show_wg_config_info
    echo -e "${BOLD}请选择操作:${NC}"
    echo
    echo -e "  ${CYAN}── WireGuard 隧道管理 ──${NC}"
    echo -e "  ${GREEN}1.${NC} 初始化 Hub（中转服务器）"
    echo -e "  ${GREEN}2.${NC} 初始化 Node（落地服务器）"
    echo -e "  ${GREEN}3.${NC} 向 Hub 添加 Node"
    echo -e "  ${GREEN}4.${NC} 维护模式（更新配置，不重新生成密钥）"
    echo -e "  ${GREEN}5.${NC} 查看 WG 状态"
    echo -e "  ${GREEN}6.${NC} 修改 WG 配置（编辑配置文件）"
    echo -e "  ${GREEN}7.${NC} WG 启动 / 停止 / 重启"
    echo
    echo -e "  ${CYAN}── Xboard-Node 管理 ──${NC}"
    echo -e "  ${GREEN}8.${NC} 安装/配置 Xboard-Node"
    echo -e "  ${GREEN}9.${NC} 升级 Xboard-Node"
    echo -e "  ${GREEN}a.${NC} 卸载 Xboard-Node"
    echo -e "  ${GREEN}b.${NC} 查看整体状态"
    echo
    echo -e "  ${DIM}0. 退出${NC}"
    echo
}

read_input() {
    local prompt="$1"
    local default="${2:-}"
    if [ -n "$default" ]; then
        read -r -p "$prompt [$default]: " answer
        echo "${answer:-$default}"
    else
        read -r -p "$prompt: " answer
        echo "$answer"
    fi
}

# ============================================
# 交互式 WG 操作
# ============================================
interactive_wg_init_hub() {
    show_banner
    echo -e "${BOLD}━━━ 初始化 WireGuard Hub（中转服务器）━━━${NC}"
    echo

    # 检测现有配置
    if [ "$(detect_existing_wg_config)" = "1" ]; then
        local current_role
        current_role=$(detect_wg_role)
        if [ -n "$current_role" ] && [ "$current_role" != "hub" ]; then
            echo -e "${RED}${BOLD}⚠️  当前角色是 $current_role，切换到 Hub 将覆盖配置！${NC}"
            read -r -p "确认切换？输入 YES: " confirm
            [ "$confirm" != "YES" ] && { log_warn "已取消"; pause; return; }
        elif [ "$current_role" = "hub" ]; then
            log_warn "当前已是 Hub 角色，重新初始化将生成新密钥"
            read -r -p "继续？输入 YES: " confirm
            [ "$confirm" != "YES" ] && { log_warn "已取消"; pause; return; }
        fi
        backup_wg_config
    fi

    echo
    WG_LISTEN_PORT=$(read_input "监听端口" "48940")
    WG_TUNNEL_IP=$(read_input "隧道网段 (如 10.8.0.1/24)" "10.8.0.1/24")

    echo
    log_step "生成密钥对..."
    local keypair
    keypair=$(generate_wg_keypair)
    local priv
    priv=$(echo "$keypair" | cut -d: -f1)
    local pub
    pub=$(echo "$keypair" | cut -d: -f2)

    render_wg_hub_config "$priv" "$WG_LISTEN_PORT" "$WG_TUNNEL_IP"

    echo
    echo -e "${GREEN}${BOLD}━━━ Hub 初始化完成 ━━━${NC}"
    echo
    echo -e "  监听端口: ${BOLD}$WG_LISTEN_PORT${NC}"
    echo -e "  隧道网段: ${BOLD}$WG_TUNNEL_IP${NC}"
    echo
    echo -e "${YELLOW}请将以下公钥提供给 Node 端使用:${NC}"
    echo -e "${BOLD}  $pub${NC}"
    echo
    echo -e "${DIM}Node 端执行: bash install.sh wg-init-node --wg-peer-pubkey $pub --wg-endpoint <本机IP>:$WG_LISTEN_PORT${NC}"
    echo

    wg_reload
    pause
}

interactive_wg_init_node() {
    show_banner
    echo -e "${BOLD}━━━ 初始化 WireGuard Node（落地服务器）━━━${NC}"
    echo

    # 检测现有配置
    if [ "$(detect_existing_wg_config)" = "1" ]; then
        local current_role
        current_role=$(detect_wg_role)
        if [ -n "$current_role" ] && [ "$current_role" != "node" ]; then
            echo -e "${RED}${BOLD}⚠️  当前角色是 $current_role，切换到 Node 将覆盖配置！${NC}"
            read -r -p "确认切换？输入 YES: " confirm
            [ "$confirm" != "YES" ] && { log_warn "已取消"; pause; return; }
        elif [ "$current_role" = "node" ]; then
            log_warn "当前已是 Node 角色，重新初始化将生成新密钥"
            read -r -p "继续？输入 YES: " confirm
            [ "$confirm" != "YES" ] && { log_warn "已取消"; pause; return; }
        fi
        backup_wg_config
    fi

    echo
    WG_ENDPOINT=$(read_input "Hub 地址 (IP:端口)" "")
    [ -z "$WG_ENDPOINT" ] && { log_error "Hub 地址不能为空"; pause; return; }
    WG_PEER_PUBKEY=$(read_input "Hub 公钥" "")
    [ -z "$WG_PEER_PUBKEY" ] && { log_error "Hub 公钥不能为空"; pause; return; }
    local use_psk
    use_psk=$(read_input "是否使用预共享密钥？(y/N)" "n")
    if [[ "$use_psk" =~ ^[Yy]$ ]]; then
        WG_PEER_PSK=$(read_input "预共享密钥" "")
    fi
    WG_TUNNEL_IP=$(read_input "本机隧道IP (如 10.8.0.2/24)" "10.8.0.2/24")

    echo
    log_step "生成密钥对..."
    local keypair
    keypair=$(generate_wg_keypair)
    local priv
    priv=$(echo "$keypair" | cut -d: -f1)
    local pub
    pub=$(echo "$keypair" | cut -d: -f2)

    render_wg_node_config "$priv" "$WG_PEER_PUBKEY" "$WG_ENDPOINT" "$WG_PEER_PSK" "$WG_TUNNEL_IP"

    echo
    echo -e "${GREEN}${BOLD}━━━ Node 初始化完成 ━━━${NC}"
    echo
    echo -e "  Hub 地址:  ${BOLD}$WG_ENDPOINT${NC}"
    echo -e "  隧道IP:   ${BOLD}$WG_TUNNEL_IP${NC}"
    echo
    echo -e "${YELLOW}请将以下公钥提供给 Hub 端添加:${NC}"
    echo -e "${BOLD}  $pub${NC}"
    echo
    echo -e "${DIM}Hub 端执行: bash install.sh wg-add-node --wg-peer-pubkey $pub --wg-tunnel-ip ${WG_TUNNEL_IP%/*}${NC}"
    echo

    wg_reload
    pause
}

interactive_wg_add_node() {
    show_banner
    echo -e "${BOLD}━━━ 向 Hub 添加 Node ━━━${NC}"
    echo

    local role
    role=$(detect_wg_role)
    if [ "$role" = "node" ]; then
        log_error "当前是 Node 角色，不能添加 peer"
        log_info "请在 Hub 服务器上执行此操作"
        pause; return
    fi

    if [ ! -f "$WG_CONFIG_FILE" ]; then
        log_warn "Hub 尚未初始化，请先初始化 Hub"
        pause; return
    fi

    echo
    WG_PEER_PUBKEY=$(read_input "Node 公钥" "")
    [ -z "$WG_PEER_PUBKEY" ] && { log_error "公钥不能为空"; pause; return; }
    WG_TUNNEL_IP=$(read_input "Node 隧道IP (不带掩码，如 10.8.0.3)" "")
    [ -z "$WG_TUNNEL_IP" ] && { log_error "隧道IP不能为空"; pause; return; }
    local node_name
    node_name=$(read_input "节点名称" "node-$(date +%s)")
    local use_psk
    use_psk=$(read_input "是否使用预共享密钥？(y/N)" "n")
    if [[ "$use_psk" =~ ^[Yy]$ ]]; then
        WG_PEER_PSK=$(read_input "预共享密钥" "")
    fi

    echo
    add_wg_peer "$WG_PEER_PUBKEY" "$WG_TUNNEL_IP" "$WG_PEER_PSK" "$node_name"

    echo
    log_ok "Node $node_name 添加完成"
    show_wg_config_info
    pause
}

interactive_maintain() {
    show_banner
    echo -e "${BOLD}━━━ 维护模式 ━━━${NC}"
    echo

    if [ ! -f "$WG_CONFIG_FILE" ]; then
        log_error "未检测到 WG 配置"
        log_info "请先初始化 Hub 或 Node"
        pause; return
    fi

    local role
    role=$(detect_wg_role)
    log_info "当前角色: $role"
    echo

    if [ "$role" = "hub" ]; then
        echo -e "${BOLD}Hub 维护选项:${NC}"
        echo -e "  ${GREEN}1.${NC} 添加新 Node"
        echo -e "  ${GREEN}2.${NC} 查看当前配置"
        echo -e "  ${DIM}0.${NC} 返回"
        echo
        read -r -p "选择: " choice
        case "$choice" in
            1) interactive_wg_add_node ;;
            2) show_wg_config_info; pause ;;
            *) ;;
        esac
    elif [ "$role" = "node" ]; then
        echo -e "${BOLD}Node 维护选项:${NC}"
        echo -e "  ${GREEN}1.${NC} 更新 Hub endpoint"
        echo -e "  ${GREEN}2.${NC} 查看当前配置"
        echo -e "  ${DIM}0.${NC} 返回"
        echo
        read -r -p "选择: " choice
        case "$choice" in
            1)
                echo
                local current_endpoint
                current_endpoint=$(grep '^Endpoint' "$WG_CONFIG_FILE" 2>/dev/null | awk '{print $3}')
                echo -e "  当前 endpoint: ${DIM}${current_endpoint:-无}${NC}"
                local new_endpoint
                new_endpoint=$(read_input "新 endpoint (IP:端口)" "")
                [ -z "$new_endpoint" ] && { log_warn "未修改"; pause; return; }
                sed -i "s|Endpoint = .*|Endpoint = $new_endpoint|" "$WG_CONFIG_FILE"
                log_ok "endpoint 已更新为: $new_endpoint"
                wg_reload
                pause
                ;;
            2) show_wg_config_info; pause ;;
            *) ;;
        esac
    else
        log_error "无法确定角色"
        pause
    fi
}

interactive_status() {
    show_banner
    echo -e "${BOLD}━━━ 系统状态 ━━━${NC}"
    echo

    # xboard-node 状态
    detect_current_state
    echo -e "${CYAN}── Xboard-Node ──${NC}"
    echo -e "  安装状态: ${CURRENT_STATE}"
    if [ -f "$SERVICE_PATH" ]; then
        if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
            echo -e "  服务状态: ${GREEN}运行中${NC}"
        else
            echo -e "  服务状态: ${RED}未运行${NC}"
        fi
    fi
    if [ -f "$INSTALL_META" ]; then
        echo -e "  元数据:   $INSTALL_META"
    fi
    echo

    # WG 状态
    show_wg_config_info

    pause
}

# ============================================
# 交互式编辑配置
# ============================================
interactive_edit_config() {
    show_banner
    echo -e "${BOLD}━━━ 修改 WireGuard 配置 ━━━${NC}"
    echo

    if [ ! -f "$WG_CONFIG_FILE" ]; then
        log_error "WG 配置文件不存在: $WG_CONFIG_FILE"
        pause; return
    fi

    echo -e "  配置路径: ${DIM}$WG_CONFIG_FILE${NC}"
    echo
    echo -e "${BOLD}请选择修改方式:${NC}"
    echo -e "  ${GREEN}1.${NC} 直接编辑配置文件 (vi)"
    echo -e "  ${GREEN}2.${NC} 修改本机隧道 IP"
    echo -e "  ${GREEN}3.${NC} 修改对端 Endpoint"
    echo -e "  ${GREEN}4.${NC} 修改对端公钥"
    echo -e "  ${GREEN}5.${NC} 修改监听端口 (仅 Hub)"
    echo -e "  ${GREEN}6.${NC} 查看完整配置文件"
    echo -e "  ${DIM}0.${NC} 返回"
    echo
    read -r -p "选择: " choice

    case "$choice" in
        1)
            # 备份后编辑
            backup_wg_config
            if command -v vi >/dev/null 2>&1; then
                vi "$WG_CONFIG_FILE"
            elif command -v nano >/dev/null 2>&1; then
                nano "$WG_CONFIG_FILE"
            else
                log_error "未找到 vi 或 nano 编辑器"
                pause; return
            fi
            echo
            log_ok "配置已修改"
            read -r -p "是否重启 WireGuard 使配置生效？(y/N): " reload
            if [[ "$reload" =~ ^[Yy]$ ]]; then
                wg_reload
            fi
            ;;
        2)
            echo
            local current_ip
            current_ip=$(grep '^Address' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || current_ip="无"
            echo -e "  当前隧道IP: ${DIM}${current_ip}${NC}"
            local new_ip
            new_ip=$(read_input "新隧道IP" "")
            [ -z "$new_ip" ] && { log_warn "未修改"; pause; return; }
            backup_wg_config
            sed -i "0,/^Address = .*/s||Address = $new_ip|" "$WG_CONFIG_FILE"
            log_ok "隧道IP 已更新为: $new_ip"
            wg_reload
            pause
            ;;
        3)
            echo
            local current_ep
            current_ep=$(grep '^Endpoint' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || current_ep="无"
            echo -e "  当前对端: ${DIM}${current_ep}${NC}"
            local new_ep
            new_ep=$(read_input "新对端地址 (IP:端口)" "")
            [ -z "$new_ep" ] && { log_warn "未修改"; pause; return; }
            backup_wg_config
            sed -i "s|Endpoint = .*|Endpoint = $new_ep|" "$WG_CONFIG_FILE"
            log_ok "对端地址已更新为: $new_ep"
            wg_reload
            pause
            ;;
        4)
            echo
            local current_pk
            current_pk=$(grep '^PublicKey' "$WG_CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $3}') || current_pk="无"
            echo -e "  当前对端公钥: ${DIM}${current_pk:0:20}...${NC}"
            local new_pk
            new_pk=$(read_input "新对端公钥" "")
            [ -z "$new_pk" ] && { log_warn "未修改"; pause; return; }
            backup_wg_config
            sed -i "0,/^PublicKey = .*/s||PublicKey = $new_pk|" "$WG_CONFIG_FILE"
            log_ok "对端公钥已更新"
            wg_reload
            pause
            ;;
        5)
            local role
            role=$(detect_wg_role)
            if [ "$role" != "hub" ]; then
                log_warn "监听端口仅 Hub 可修改"
                pause; return
            fi
            echo
            local current_port
            current_port=$(grep '^ListenPort' "$WG_CONFIG_FILE" 2>/dev/null | awk '{print $3}') || current_port="无"
            echo -e "  当前端口: ${DIM}${current_port}${NC}"
            local new_port
            new_port=$(read_input "新端口" "")
            [ -z "$new_port" ] && { log_warn "未修改"; pause; return; }
            backup_wg_config
            sed -i "s/^ListenPort = .*/ListenPort = $new_port/" "$WG_CONFIG_FILE"
            log_ok "监听端口已更新为: $new_port"
            wg_reload
            pause
            ;;
        6)
            echo
            echo -e "${DIM}──── $WG_CONFIG_FILE ────${NC}"
            cat "$WG_CONFIG_FILE" 2>/dev/null || log_error "无法读取"
            echo -e "${DIM}────────────────────${NC}"
            echo
            pause
            ;;
        *) ;;
    esac
}

# ============================================
# 交互式 WG 启停控制
# ============================================
interactive_wg_control() {
    show_banner
    echo -e "${BOLD}━━━ WireGuard 启动 / 停止 / 重启 ━━━${NC}"
    echo

    if [ ! -f "$WG_CONFIG_FILE" ]; then
        log_error "WG 配置文件不存在，请先初始化"
        pause; return
    fi

    # 显示当前状态
    local running=0
    if command -v wg >/dev/null 2>&1 && wg show wg0 >/dev/null 2>&1; then
        running=1
    fi

    if [ "$running" -eq 1 ]; then
        echo -e "  当前状态: ${GREEN}● 运行中${NC}"
    else
        echo -e "  当前状态: ${RED}○ 已停止${NC}"
    fi
    echo

    if [ "$running" -eq 1 ]; then
        echo -e "${BOLD}请选择操作:${NC}"
        echo -e "  ${GREEN}1.${NC} 重启 WireGuard"
        echo -e "  ${GREEN}2.${NC} 停止 WireGuard"
        echo -e "  ${GREEN}3.${NC} 查看详细状态 (wg show)"
        echo -e "  ${GREEN}4.${NC} 查看配置文件"
        echo -e "  ${DIM}0.${NC} 返回"
    else
        echo -e "${BOLD}请选择操作:${NC}"
        echo -e "  ${GREEN}1.${NC} 启动 WireGuard"
        echo -e "  ${GREEN}2.${NC} 查看配置文件"
        echo -e "  ${GREEN}3.${NC} 检查配置语法"
        echo -e "  ${DIM}0.${NC} 返回"
    fi
    echo
    read -r -p "选择: " choice

    if [ "$running" -eq 1 ]; then
        case "$choice" in
            1)
                log_step "重启 WireGuard..."
                wg_reload
                pause
                ;;
            2)
                log_step "停止 WireGuard..."
                if command -v wg-quick >/dev/null 2>&1; then
                    wg-quick down wg0 2>/dev/null && log_ok "WireGuard 已停止" || log_warn "停止失败"
                fi
                pause
                ;;
            3)
                echo
                if command -v wg >/dev/null 2>&1; then
                    wg show wg0 2>/dev/null || log_warn "无法获取状态"
                else
                    log_error "wg 命令不可用"
                fi
                echo
                pause
                ;;
            4)
                echo
                echo -e "${DIM}──── $WG_CONFIG_FILE ────${NC}"
                cat "$WG_CONFIG_FILE" 2>/dev/null
                echo -e "${DIM}────────────────────${NC}"
                echo
                pause
                ;;
            *) ;;
        esac
    else
        case "$choice" in
            1)
                log_step "启动 WireGuard..."
                wg_reload
                pause
                ;;
            2)
                echo
                echo -e "${DIM}──── $WG_CONFIG_FILE ────${NC}"
                cat "$WG_CONFIG_FILE" 2>/dev/null
                echo -e "${DIM}────────────────────${NC}"
                echo
                pause
                ;;
            3)
                echo
                log_step "检查配置语法..."
                if command -v wg-quick >/dev/null 2>&1; then
                    # strip 不实际启动，只解析配置
                    if wg-quick strip wg0 >/dev/null 2>&1; then
                        log_ok "配置语法正确"
                    else
                        log_error "配置语法有误"
                    fi
                else
                    log_error "wg-quick 命令不可用"
                fi
                echo
                pause
                ;;
            *) ;;
        esac
    fi
}

# ============================================
# 命令行参数模式（WG 操作）
# ============================================
cmd_wg_init_hub() {
    log_step "初始化 WG Hub"
    if [ "$(detect_existing_wg_config)" = "1" ]; then
        confirm_role_change "hub" "Hub (中转)" || return
        backup_wg_config
    fi
    local tunnel_ip="${WG_TUNNEL_IP:-10.8.0.1/24}"
    local keypair
    keypair=$(generate_wg_keypair)
    local priv
    priv=$(echo "$keypair" | cut -d: -f1)
    local pub
    pub=$(echo "$keypair" | cut -d: -f2)
    render_wg_hub_config "$priv" "$WG_LISTEN_PORT" "$tunnel_ip"
    echo
    log_info "Hub 公钥: $pub"
    log_info "Node 端: bash $0 wg-init-node --wg-peer-pubkey $pub --wg-endpoint <IP>:$WG_LISTEN_PORT"
    wg_reload
}

cmd_wg_init_node() {
    log_step "初始化 WG Node"
    [ -z "$WG_ENDPOINT" ] && log_error "缺少 --wg-endpoint" && exit 1
    [ -z "$WG_PEER_PUBKEY" ] && log_error "缺少 --wg-peer-pubkey" && exit 1
    if [ "$(detect_existing_wg_config)" = "1" ]; then
        confirm_role_change "node" "Node (落地)" || return
        backup_wg_config
    fi
    local tunnel_ip="${WG_TUNNEL_IP:-10.8.0.2/24}"
    local keypair
    keypair=$(generate_wg_keypair)
    local priv
    priv=$(echo "$keypair" | cut -d: -f1)
    local pub
    pub=$(echo "$keypair" | cut -d: -f2)
    render_wg_node_config "$priv" "$WG_PEER_PUBKEY" "$WG_ENDPOINT" "$WG_PEER_PSK" "$tunnel_ip"
    echo
    log_info "Node 公钥: $pub"
    log_info "Hub 端: bash $0 wg-add-node --wg-peer-pubkey $pub --wg-tunnel-ip ${tunnel_ip%/*}"
    wg_reload
}

cmd_wg_add_node() {
    log_step "向 Hub 添加 Node"
    [ -z "$WG_PEER_PUBKEY" ] && log_error "缺少 --wg-peer-pubkey" && exit 1
    [ -z "$WG_TUNNEL_IP" ] && log_error "缺少 --wg-tunnel-ip" && exit 1
    local role
    role=$(detect_wg_role)
    [ "$role" = "node" ] && log_error "Node 角色不能添加 peer" && exit 1
    [ ! -f "$WG_CONFIG_FILE" ] && log_error "Hub 未初始化" && exit 1
    add_wg_peer "$WG_PEER_PUBKEY" "${WG_TUNNEL_IP%/*}" "$WG_PEER_PSK" "node-$(date +%s)"
    show_wg_config_info
}

cmd_maintain() {
    log_step "维护模式"
    [ ! -f "$WG_CONFIG_FILE" ] && log_error "无 WG 配置" && exit 1
    local role
    role=$(detect_wg_role)
    log_info "当前角色: $role"
    case "$role" in
        hub)
            if [ -n "$WG_PEER_PUBKEY" ] && [ -n "$WG_TUNNEL_IP" ]; then
                cmd_wg_add_node
            else
                show_wg_config_info
                log_info "添加: $0 maintain --wg-peer-pubkey <key> --wg-tunnel-ip <IP>"
            fi
            ;;
        node)
            if [ -n "$WG_ENDPOINT" ]; then
                log_info "更新 endpoint: $WG_ENDPOINT"
                sed -i "s|Endpoint = .*|Endpoint = $WG_ENDPOINT|" "$WG_CONFIG_FILE"
                wg_reload
            else
                show_wg_config_info
                log_info "更新: $0 maintain --wg-endpoint <IP:Port>"
            fi
            ;;
        *) log_error "未知角色"; exit 1 ;;
    esac
}

cmd_status() {
    interactive_status
}

cmd_wg_status() {
    show_wg_config_info
}

# ============================================
# 参数解析
# ============================================
usage() {
    cat <<'HELP'

用法: bash install.sh [命令] [选项]

命令:
  (无参数)        进入交互式菜单
  wg-init-hub      初始化 Hub（中转服务器）
  wg-init-node     初始化 Node（落地服务器）
  wg-add-node      向 Hub 添加 Node
  wg-start         启动 WireGuard
  wg-stop          停止 WireGuard
  wg-restart       重启 WireGuard
  maintain         维护模式（更新配置，不重新生成密钥）
  status           查看整体状态
  wg-status        查看 WG 状态
  upgrade          升级 Xboard-Node
  uninstall        卸载 Xboard-Node
  help             显示帮助

WG 选项:
  --wg-port PORT          监听端口 (默认: 48940)
  --wg-endpoint ADDR      对端地址 (IP:Port)
  --wg-peer-pubkey KEY    对端公钥
  --wg-psk KEY            预共享密钥
  --wg-tunnel-ip IP       隧道 IP

示例:
  # 交互式菜单
  sudo bash install.sh

  # 命令行 - 初始化 Hub
  sudo bash install.sh wg-init-hub --wg-port 48940

  # 命令行 - 初始化 Node
  sudo bash install.sh wg-init-node --wg-endpoint 1.2.3.4:48940 --wg-peer-pubkey xxx

  # 命令行 - 添加 Node
  sudo bash install.sh wg-add-node --wg-peer-pubkey xxx --wg-tunnel-ip 10.8.0.3

  # 命令行 - 维护（更新 endpoint）
  sudo bash install.sh maintain --wg-endpoint 5.6.7.8:48940

HELP
}

parse_args() {
    local positional=()
    while [ $# -gt 0 ]; do
        case "$1" in
            install|wg-init-hub|wg-init-node|wg-add-node|wg-update|wg-status|wg-start|wg-stop|wg-restart|maintain|status|upgrade|uninstall|help)
                ACTION="$1"; shift ;;
            --wg-port) WG_LISTEN_PORT="$2"; shift 2 ;;
            --wg-endpoint) WG_ENDPOINT="$2"; shift 2 ;;
            --wg-peer-pubkey) WG_PEER_PUBKEY="$2"; shift 2 ;;
            --wg-psk) WG_PEER_PSK="$2"; shift 2 ;;
            --wg-tunnel-ip) WG_TUNNEL_IP="$2"; shift 2 ;;
            --yes|-y) YES=1; shift ;;
            --purge) PURGE=1; shift ;;
            --help|-h) ACTION="help"; shift ;;
            *) positional+=("$1"); shift ;;
        esac
    done
    # 如果没有识别到命令，且没有位置参数，进入交互模式
    if [ -z "$ACTION" ] && [ ${#positional[@]} -eq 0 ]; then
        ACTION="interactive"
    fi
}

# ============================================
# 主函数
# ============================================
main() {
    parse_args "$@"

    case "$ACTION" in
        help)
            usage; exit 0 ;;
        wg-status)
            check_root; cmd_wg_status; exit 0 ;;
        status)
            ensure_systemd; cmd_status; exit 0 ;;
    esac

    check_root
    detect_arch
    detect_os
    install_dependencies
    ensure_dirs

    case "$ACTION" in
        interactive)
            # 交互式主循环
            while true; do
                show_main_menu
                read -r -p "请输入选项 [0-9]: " choice
                case "$choice" in
                    1) interactive_wg_init_hub ;;
                    2) interactive_wg_init_node ;;
                    3) interactive_wg_add_node ;;
                    4) interactive_maintain ;;
                    5) show_wg_config_info; pause ;;
                    6) interactive_edit_config ;;
                    7) interactive_wg_control ;;
                    8) log_info "Xboard-Node 安装功能请使用命令行参数"; pause ;;
                    9) log_info "Xboard-Node 升级功能请使用命令行参数"; pause ;;
                    a|A) log_info "Xboard-Node 卸载功能请使用命令行参数"; pause ;;
                    b|B) interactive_status ;;
                    0|q|Q|exit) log_info "再见！"; exit 0 ;;
                    *) log_warn "无效选项: $choice"; pause ;;
                esac
            done
            ;;
        wg-init-hub) cmd_wg_init_hub; exit 0 ;;
        wg-init-node) cmd_wg_init_node; exit 0 ;;
        wg-add-node) cmd_wg_add_node; exit 0 ;;
        wg-start)
            log_step "启动 WireGuard..."
            wg_reload; exit 0 ;;
        wg-stop)
            log_step "停止 WireGuard..."
            wg-quick down wg0 2>/dev/null && log_ok "已停止" || log_warn "停止失败"
            exit 0 ;;
        wg-restart)
            log_step "重启 WireGuard..."
            wg_reload; exit 0 ;;
        maintain) cmd_maintain; exit 0 ;;
        install) 
            log_info "此脚本主要用于 WireGuard 隧道管理"
            log_info "直接运行进入交互菜单: sudo bash install.sh"
            log_info "Xboard-Node 安装请使用原版 install.sh"
            exit 0
            ;;
        upgrade) log_info "升级功能请参考原版 install.sh"; exit 0 ;;
        uninstall) log_info "卸载功能请参考原版 install.sh"; exit 0 ;;
        *)
            log_error "未知命令: $ACTION"
            usage
            exit 1
            ;;
    esac
}

main "$@"
