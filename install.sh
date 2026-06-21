#!/usr/bin/env bash
# FlashAccess installer — Ubuntu 24.04
# Usage:  curl -fsSL https://raw.githubusercontent.com/KnAWLeDGE/flashaccess/main/install.sh | bash
# Or:     bash install.sh [--version v1.0.0] [--addr 127.0.0.1:7432] [--mode strict|unrestricted] [--fresh]
set -euo pipefail

REPO="KnAWLeDGE/flashaccess"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/flashaccess"
SERVICE_USER="flashaccess"
SERVICE_FILE="/etc/systemd/system/flashaccess.service"
NGINX_CONF="/etc/nginx/sites-available/flashaccess"

# ── Defaults ───────────────────────────────────────────────────
VERSION="${FA_VERSION:-latest}"
ADDR="${FA_ADDR:-127.0.0.1:7432}"
MODE="${FA_MODE:-}"          # set via --mode flag or wizard

# ── Colour helpers ─────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[0;34m'; N='\033[0m'
info()  { echo -e "${G}[flashaccess]${N} $*"; }
warn()  { echo -e "${Y}[warning]${N} $*"; }
error() { echo -e "${R}[error]${N} $*" >&2; exit 1; }
step()  { echo -e "\n${B}▶ $*${N}"; }

# ── Root check ─────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "Run as root (sudo bash install.sh)"

# ── Arg parsing ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --addr)    ADDR="$2";    shift 2 ;;
        --mode)    MODE="$2";    shift 2 ;;
        --fresh)   FRESH="yes";  shift ;;
        *) warn "Unknown argument: $1"; shift ;;
    esac
done

# ── Resolve latest version via GitHub API ──────────────────────
if [[ "$VERSION" == "latest" ]]; then
    info "Fetching latest release tag…"
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\(.*\)".*/\1/')
    [[ -n "$VERSION" ]] || error "Could not resolve latest version"
fi
info "Installing FlashAccess ${VERSION}"

# ── Download binary ────────────────────────────────────────────
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
    amd64)   GOARCH="amd64" ;;
    arm64)   GOARCH="arm64" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
esac

BIN_URL="https://github.com/${REPO}/releases/download/${VERSION}/flashaccess_${VERSION}_linux_${GOARCH}"
TMP=$(mktemp)
info "Downloading binary from ${BIN_URL}"
curl -fsSL -o "$TMP" "$BIN_URL"
chmod +x "$TMP"

# Quick sanity check
"$TMP" version || error "Downloaded binary failed version check"

install -m 0755 "$TMP" "${INSTALL_DIR}/flashaccess"
rm -f "$TMP"
info "Binary installed to ${INSTALL_DIR}/flashaccess"

# ── System user ────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    info "Created system user: ${SERVICE_USER}"
fi

# ── sudoers rule for ufw ───────────────────────────────────────
SUDOERS_FILE="/etc/sudoers.d/flashaccess-ufw"
UFW_BIN=$(readlink -f "$(which ufw 2>/dev/null)" 2>/dev/null || echo "/usr/sbin/ufw")
echo "${SERVICE_USER} ALL=(root) NOPASSWD: ${UFW_BIN}" > "$SUDOERS_FILE"
chmod 440 "$SUDOERS_FILE"
info "sudoers rule written: ${SUDOERS_FILE} (${UFW_BIN})"

# ── Fresh install option ───────────────────────────────────────
FRESH="${FA_FRESH:-}"   # set to "yes" to skip the prompt and always wipe

if [[ -d "$DATA_DIR" ]] && [[ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]]; then
    if [[ "$FRESH" != "yes" ]]; then
        if [[ -t 0 ]]; then
            echo
            warn "Existing FlashAccess data found at ${DATA_DIR}"
            echo "  A fresh install will DELETE all existing configuration,"
            echo "  session history, and the master encryption key."
            echo "  You will need to re-run 'flashaccess connect' afterwards."
            echo
            read -rp "Start fresh (wipe ${DATA_DIR})? [y/N]: " FRESH_ANS
            case "${FRESH_ANS,,}" in
                y|yes) FRESH="yes" ;;
                *)     FRESH="no" ;;
            esac
        else
            FRESH="no"
            info "Non-interactive install — preserving existing data at ${DATA_DIR}"
        fi
    fi

    if [[ "$FRESH" == "yes" ]]; then
        # Stop the service first if running
        if systemctl is-active --quiet flashaccess 2>/dev/null; then
            info "Stopping flashaccess service before wiping data…"
            systemctl stop flashaccess
        fi
        rm -rf "$DATA_DIR"
        info "Wiped ${DATA_DIR} for fresh install"
    fi
fi

# ── Data directory ─────────────────────────────────────────────
mkdir -p "$DATA_DIR"
chown "${SERVICE_USER}:${SERVICE_USER}" "$DATA_DIR"
chmod 0700 "$DATA_DIR"
info "Data directory: ${DATA_DIR}"

# ── systemd unit ───────────────────────────────────────────────
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=FlashAccess — temporary IP-locked MySQL dashboard
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${INSTALL_DIR}/flashaccess serve
Restart=on-failure
RestartSec=5s
Environment=FLASHACCESS_ADDR=${ADDR}
StateDirectory=flashaccess
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
info "systemd unit installed: ${SERVICE_FILE}"

# ── nginx (optional) ───────────────────────────────────────────
if command -v nginx &>/dev/null; then
    if [[ ! -f "$NGINX_CONF" ]]; then
        SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
        if [[ -f "${SCRIPT_DIR}/deploy/nginx.conf" ]]; then
            cp "${SCRIPT_DIR}/deploy/nginx.conf" "$NGINX_CONF"
            info "nginx config written to ${NGINX_CONF}"
            warn "Edit ${NGINX_CONF} to set your domain, then:"
            warn "  ln -s ${NGINX_CONF} /etc/nginx/sites-enabled/flashaccess"
            warn "  nginx -t && systemctl reload nginx"
        fi
    else
        info "nginx config already exists at ${NGINX_CONF} — skipping"
    fi
fi

# ── Restart service if already running (update path) ──────────
if systemctl is-active --quiet flashaccess; then
    info "Existing service detected — restarting to apply update…"
    systemctl restart flashaccess
    info "Service restarted. Run 'flashaccess version' to confirm."
    echo
    exit 0
fi

# ── Mode wizard (fresh install only) ──────────────────────────
step "Installation Mode"
echo
echo "  unrestricted (default) — Full CRUD access:"
echo "    • Manage MySQL users (create, drop, set privileges)"
echo "    • Create and drop databases"
echo "    • Browse, query, and modify all data"
echo "    • Ideal for experienced operators and dev servers"
echo
echo "  strict — Safe operations only:"
echo "    • Browse tables and run queries"
echo "    • No user management, no database drops"
echo "    • Ideal for production environments or shared servers"
echo
echo "  You can change this later with: flashaccess mode <strict|unrestricted>"
echo

if [[ -z "$MODE" ]]; then
    # Only ask interactively if stdin is a terminal
    if [[ -t 0 ]]; then
        read -rp "Enable strict mode? [y/N]: " MODE_ANS
        case "${MODE_ANS,,}" in
            y|yes) MODE="strict" ;;
            *)     MODE="unrestricted" ;;
        esac
    else
        MODE="unrestricted"
        info "Non-interactive install — defaulting to unrestricted mode"
    fi
fi

case "$MODE" in
    strict|unrestricted) ;;
    *) error "Invalid mode '${MODE}' — use 'strict' or 'unrestricted'" ;;
esac

info "Mode: ${MODE}"

# ── Done (fresh install) ────────────────────────────────────────
echo
info "Installation complete."
echo -e "${G}Next steps:${N}"
echo "  1. Run the configuration wizard (sets MySQL credentials + admin password):"
echo "       flashaccess connect"
echo
echo "     When prompted for mode, choose: ${MODE}"
echo "     Or pass the FA_MODE environment variable to skip the prompt:"
echo "       FA_MODE=${MODE} flashaccess connect"
echo
echo "  2. Fix file ownership (connect runs as root; service runs as ${SERVICE_USER}):"
echo "       chown -R ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR}"
echo "  3. Start and enable the service:"
echo "       systemctl enable --now flashaccess"
echo "  4. Configure nginx (see deploy/nginx.conf) and point your domain here."
echo
