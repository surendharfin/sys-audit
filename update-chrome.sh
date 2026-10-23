#!/usr/bin/env bash
# =====================================================================
#  Chrome Enterprise Updater - Linux (Debian/Ubuntu + RHEL/Fedora)
#  Target: latest Google Chrome Stable from Google's official repos
#  Run as root (sudo) or push via Ansible / Satellite / SCCM-Linux
# =====================================================================

set -euo pipefail

LOGDIR="/var/log/chrome-update"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/chrome-update.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "===== Chrome update started on $(hostname) ====="

if [[ $EUID -ne 0 ]]; then
    log "ERROR: must run as root"
    exit 1
fi

# --- Capture OLD version (before update) ---
if command -v google-chrome >/dev/null 2>&1; then
    OLD_VER="$(google-chrome --version 2>/dev/null | awk '{print $NF}')"
else
    OLD_VER="not installed"
fi
log "[BEFORE] Current Chrome version: $OLD_VER"

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" ]]; then
    log "ERROR: unsupported architecture $ARCH (Google Chrome ships amd64 only)"
    exit 2
fi

# --- Detect package manager ---
if   command -v apt-get >/dev/null 2>&1; then PM="apt"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
elif command -v yum     >/dev/null 2>&1; then PM="yum"
elif command -v zypper  >/dev/null 2>&1; then PM="zypper"
else
    log "ERROR: no supported package manager found"
    exit 3
fi
log "Package manager: $PM"

install_repo_debian() {
    local key="/usr/share/keyrings/google-chrome.gpg"
    local list="/etc/apt/sources.list.d/google-chrome.list"
    if [[ ! -f "$key" ]]; then
        log "Adding Google signing key"
        curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
            | gpg --dearmor -o "$key"
    fi
    if [[ ! -f "$list" ]]; then
        log "Adding Chrome apt repo"
        echo "deb [arch=amd64 signed-by=$key] https://dl.google.com/linux/chrome/deb/ stable main" \
            > "$list"
    fi
}

install_repo_rpm() {
    local repo="/etc/yum.repos.d/google-chrome.repo"
    if [[ ! -f "$repo" ]]; then
        log "Adding Chrome yum/dnf repo"
        cat > "$repo" <<'EOF'
[google-chrome]
name=google-chrome
baseurl=https://dl.google.com/linux/chrome/rpm/stable/x86_64
enabled=1
gpgcheck=1
gpgkey=https://dl.google.com/linux/linux_signing_key.pub
EOF
    fi
}

case "$PM" in
    apt)
        install_repo_debian
        log "Running apt-get update"
        apt-get update -y >>"$LOG" 2>&1
        log "Installing/upgrading google-chrome-stable"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade google-chrome-stable >>"$LOG" 2>&1 \
            || DEBIAN_FRONTEND=noninteractive apt-get install -y google-chrome-stable >>"$LOG" 2>&1
        ;;
    dnf)
        install_repo_rpm
        log "Installing/upgrading google-chrome-stable via dnf"
        dnf install -y google-chrome-stable >>"$LOG" 2>&1
        ;;
    yum)
        install_repo_rpm
        log "Installing/upgrading google-chrome-stable via yum"
        yum install -y google-chrome-stable >>"$LOG" 2>&1
        ;;
    zypper)
        rpm --import https://dl.google.com/linux/linux_signing_key.pub >>"$LOG" 2>&1 || true
        zypper --non-interactive addrepo -f \
            https://dl.google.com/linux/chrome/rpm/stable/x86_64 google-chrome 2>/dev/null || true
        log "Installing/upgrading google-chrome-stable via zypper"
        zypper --non-interactive install --no-confirm google-chrome-stable >>"$LOG" 2>&1
        ;;
esac

# --- Report NEW installed version ---
if command -v google-chrome >/dev/null 2>&1; then
    NEW_VER="$(google-chrome --version 2>/dev/null | awk '{print $NF}')"
else
    log "ERROR: google-chrome binary not found after install"
    exit 4
fi

echo "" | tee -a "$LOG"
echo "----------------------------------------------" | tee -a "$LOG"
echo " Old version : $OLD_VER"                        | tee -a "$LOG"
echo " New version : $NEW_VER"                        | tee -a "$LOG"
if [[ "$OLD_VER" == "$NEW_VER" ]]; then
    echo " Status      : No change (already latest)"  | tee -a "$LOG"
else
    echo " Status      : UPDATED  $OLD_VER  ->  $NEW_VER" | tee -a "$LOG"
fi
echo "----------------------------------------------" | tee -a "$LOG"

log "===== Chrome update finished OK ====="
exit 0
