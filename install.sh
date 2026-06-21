#!/usr/bin/env bash
# FlashAccess installer — Ubuntu 24.04
# Usage:  curl -fsSL https://raw.githubusercontent.com/KnAWLeDGE/flashaccess/main/install.sh | bash
# Or:     bash install.sh [--version v1.0.0] [--addr 127.0.0.1:7432]
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

# ── Colour helpers ─────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; N='\033[0m'
info()  { echo -e "${G}[flashaccess]${N} $*"; }
warn()  { echo -e "${Y}[warning]${N} $*"; }
error() { echo -e "${R}[error]${N} $*" >&2; exit 1; }

# ── Root check ─────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "Run as root (sudo bash install.sh)"

# ── Arg parsing ────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --addr)    ADDR="$2";    shift 2 ;;
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

# Install
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
if [[ ! -f "$SUDOERS_FILE" ]]; then
    echo "flashaccess ALL=(root) NOPASSWD: /usr/sbin/ufw" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    info "sudoers rule written: ${SUDOERS_FILE}"
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

# ── Done (fresh install) ────────────────────────────────────────
echo
info "Installation complete."
echo -e "${G}Next steps:${N}"
echo "  1. Run the configuration wizard:"
echo "       flashaccess connect"
echo "  2. Fix file ownership (connect runs as root; service runs as ${SERVICE_USER}):"
echo "       chown -R ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR}"
echo "  3. Start and enable the service:"
echo "       systemctl enable --now flashaccess"
echo "  4. Configure nginx (see deploy/nginx.conf) and point your domain here."
echo
