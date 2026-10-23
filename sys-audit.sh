#!/usr/bin/env bash
# =====================================================================
#  System audit + updater for Chrome, Firefox, Edge, Node.js, Python, PHP
#  Phase 1: Audit  - found / not found + version per tool
#  Phase 2: Update - installed tools -> latest via system package manager
#                    (Node + PHP use branch-aware pinned patch versions)
# =====================================================================

set -u

# ----- Auto-elevate: re-exec with sudo if not root -----
if [[ $EUID -ne 0 ]]; then
    echo ""
    echo "========================================================"
    echo "  Not running as root."
    echo "  Chrome/Edge/Node/Python/PHP updates require root."
    echo "  Relaunching under sudo (may prompt for password)..."
    echo "========================================================"
    echo ""
    if command -v sudo >/dev/null 2>&1; then
        # If invoked via curl|bash, there's no $0 file - fetch and re-exec
        if [[ -r "${BASH_SOURCE[0]:-}" ]]; then
            exec sudo bash "${BASH_SOURCE[0]}" "$@"
        else
            exec sudo bash -c "curl -fsSL https://raw.githubusercontent.com/surendharfin/sys-audit/refs/heads/main/sys-audit.sh | bash"
        fi
    else
        echo "ERROR: sudo not available. Re-run this script as root manually." >&2
        exit 1
    fi
fi

LOGDIR="/var/log/system-audit"
mkdir -p "$LOGDIR" 2>/dev/null || LOGDIR="/tmp"
LOG="$LOGDIR/audit-$(date +%Y%m%d-%H%M%S).log"

if [ -t 1 ]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; D=$'\e[2m'; N=$'\e[0m'
else
    R=''; G=''; Y=''; C=''; D=''; N=''
fi

say()  { echo -e "$*" | tee -a "$LOG"; }
line() { say "------------------------------------------------------------"; }

say ""
say "${C}============================================================${N}"
say "${C}    SYSTEM AUDIT  -  $(hostname)  -  $(date)${N}"
say "${C}============================================================${N}"

IS_ROOT=1  # guaranteed by auto-elevate block above
say "${G}Running as root - proceeding with full install flow.${N}"

# --- Detect package manager ---
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v yum     >/dev/null 2>&1; then PM=yum
elif command -v zypper  >/dev/null 2>&1; then PM=zypper
else PM=none
fi
say "Package manager: ${C}${PM}${N}"

# --- Tools: name|command|version-flag|package-name|target-version ---
# target-version is resolved per installed branch below for Node/PHP.
TOOLS=(
    "Google Chrome|google-chrome|--version|google-chrome-stable|"
    "Mozilla Firefox|firefox|--version|firefox|158.0.1"
    "Microsoft Edge|microsoft-edge|--version|microsoft-edge-stable|156.0.4314.42"
    "Node.js|node|--version|nodejs|"
    "Python|python3|--version|python3|"
    "PHP|php|--version|php|"
)

# Branch-aware targets: pick the right patch for the branch the user is on
declare -A NODE_TARGETS=(
    [22]="22.23.4"
    [24]="24.22.1"
    [26]="26.12.1"
)
declare -A PHP_TARGETS=(
    [8.2]="8.2.35"
    [8.3]="8.3.36"
    [8.4]="8.4.27"
    [8.5]="8.5.12"
)

node_major() { echo "$1" | sed -E 's/^v?([0-9]+)\..*/\1/'; }
php_branch() { echo "$1" | sed -E 's/^PHP ([0-9]+\.[0-9]+)\..*/\1/'; }

# Pin Node.js to exact micro version using official nodejs.org binary tarball
# (NodeSource repo only keeps "latest in major" so apt can't pin 24.22.1 vs 24.22.0)
install_node_exact() {
    local ver="$1"
    [[ -z "$ver" ]] && return 1
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)  arch=linux-x64 ;;
        aarch64) arch=linux-arm64 ;;
        armv7l)  arch=linux-armv7l ;;
        *) say "               Unsupported arch for Node binary tarball: $arch" ; return 1 ;;
    esac
    local url="https://nodejs.org/dist/v${ver}/node-v${ver}-${arch}.tar.xz"
    local tmp="/tmp/node-v${ver}.tar.xz"
    say "               Fetching exact Node.js v${ver} from nodejs.org..."
    curl -fsSL -o "$tmp" "$url" >>"$LOG" 2>&1
    if [[ ! -s "$tmp" ]]; then
        say "               Download failed: $url"
        return 1
    fi
    tar -xJf "$tmp" -C /tmp/ >>"$LOG" 2>&1
    local src="/tmp/node-v${ver}-${arch}"
    # Install under /usr/local (overrides NodeSource)
    cp -rT "$src"/bin     /usr/local/bin
    cp -rT "$src"/lib     /usr/local/lib
    cp -rT "$src"/include /usr/local/include
    cp -rT "$src"/share   /usr/local/share
    rm -rf "$src" "$tmp"
    hash -r
    say "               Installed node v${ver} to /usr/local"
}

# Pin Edge to exact version via Microsoft repo
install_edge_exact() {
    local ver="$1"
    [[ -z "$ver" ]] && { install_edge_direct; return; }
    if [[ "$PM" == "apt" ]]; then
        apt-get install -y --allow-downgrades "microsoft-edge-stable=${ver}-1" >>"$LOG" 2>&1 \
          || apt-get install -y --allow-downgrades "microsoft-edge-stable=${ver}*" >>"$LOG" 2>&1 \
          || install_edge_direct
    elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        $PM install -y "microsoft-edge-stable-${ver}" >>"$LOG" 2>&1 || install_edge_direct
    fi
}

# Direct Chrome/Edge installers (fallback when package manager won't update)
install_chrome_direct() {
    local url pkg
    if [[ "$PM" == "apt" ]]; then
        url="https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
        pkg="/tmp/chrome.deb"
        say "               Downloading Chrome .deb directly..."
        curl -fsSL -o "$pkg" "$url" >>"$LOG" 2>&1
        apt-get install -y "$pkg" >>"$LOG" 2>&1 || dpkg -i "$pkg" >>"$LOG" 2>&1
        rm -f "$pkg"
    elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        url="https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm"
        pkg="/tmp/chrome.rpm"
        say "               Downloading Chrome .rpm directly..."
        curl -fsSL -o "$pkg" "$url" >>"$LOG" 2>&1
        $PM install -y "$pkg" >>"$LOG" 2>&1
        rm -f "$pkg"
    fi
}
# Pin Firefox to exact version via Mozilla's official tarball
install_firefox_exact() {
    local ver="$1"
    [[ -z "$ver" ]] && return 1
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)  arch=linux-x86_64 ;;
        aarch64) arch=linux-aarch64 ;;
        *) say "               Unsupported arch for Firefox: $arch" ; return 1 ;;
    esac
    local url="https://ftp.mozilla.org/pub/firefox/releases/${ver}/${arch}/en-US/firefox-${ver}.tar.xz"
    local tmp="/tmp/firefox-${ver}.tar.xz"
    say "               Fetching exact Firefox ${ver} from mozilla.org..."
    curl -fsSL -o "$tmp" "$url" >>"$LOG" 2>&1
    if [[ ! -s "$tmp" ]]; then
        say "               Download failed - Firefox ${ver} may not exist yet."
        return 1
    fi
    rm -rf /opt/firefox
    tar -xJf "$tmp" -C /opt/ >>"$LOG" 2>&1
    rm -f "$tmp"
    ln -sf /opt/firefox/firefox /usr/local/bin/firefox
    hash -r
    say "               Installed firefox ${ver} to /opt/firefox"
}

install_edge_direct() {
    local url pkg
    if [[ "$PM" == "apt" ]]; then
        url="https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/microsoft-edge-stable_latest_amd64.deb"
        pkg="/tmp/edge.deb"
        # Microsoft doesn't publish a 'latest' deb URL; use the repo instead
        apt-get install -y --only-upgrade microsoft-edge-stable >>"$LOG" 2>&1 \
          || apt-get install -y microsoft-edge-stable >>"$LOG" 2>&1
    elif [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        $PM install -y microsoft-edge-stable >>"$LOG" 2>&1
    fi
}

declare -A OLD_VER NEW_VER FOUND PKG TARGET

# ---------- PHASE 1: AUDIT ----------
say ""
say "${Y}>>> PHASE 1: AUDIT${N}"
line

for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name cmd flag pkg target <<< "$entry"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        case "$name" in
            Python) cmd=python3 ;;
            PHP)    cmd=php     ;;
        esac
    fi
    if command -v "$cmd" >/dev/null 2>&1; then
        ver=$("$cmd" "$flag" 2>/dev/null | head -n1)
        FOUND[$name]=1
        OLD_VER[$name]="$ver"

        case "$name" in
            "Node.js")
                maj=$(node_major "$ver")
                [[ -n "${NODE_TARGETS[$maj]:-}" ]] && target="${NODE_TARGETS[$maj]}"
                ;;
            "PHP")
                br=$(php_branch "$ver")
                [[ -n "${PHP_TARGETS[$br]:-}" ]] && target="${PHP_TARGETS[$br]}"
                pkg="php${br}"
                ;;
        esac
        PKG[$name]=$pkg
        TARGET[$name]=$target

        printf "  ${G}[FOUND]${N}      %-18s  version: %s   ${D}(target: %s)${N}\n" "$name" "$ver" "${target:-latest}" | tee -a "$LOG"
    else
        FOUND[$name]=0
        OLD_VER[$name]="-"
        PKG[$name]=$pkg
        TARGET[$name]=$target
        printf "  ${R}[NOT FOUND]${N}  %-18s  (not installed)\n" "$name" | tee -a "$LOG"
    fi
done

# ---------- PHASE 2: UPDATE ----------
say ""
say "${Y}>>> PHASE 2: UPDATE${N}"
line

if [[ $IS_ROOT -eq 0 ]]; then
    say "${R}Skipping updates (not root). Re-run with sudo.${N}"
else
    # --- Vendor repos (added only when the tool is actually installed) ---
    if [[ "$PM" == "apt" ]]; then
        if [[ "${FOUND[Google Chrome]}" == "1" && ! -f /etc/apt/sources.list.d/google-chrome.list ]]; then
            curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
                | gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg 2>>"$LOG"
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
                > /etc/apt/sources.list.d/google-chrome.list
        fi
        if [[ "${FOUND[Microsoft Edge]}" == "1" && ! -f /etc/apt/sources.list.d/microsoft-edge.list ]]; then
            curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
                | gpg --dearmor --yes -o /usr/share/keyrings/microsoft-edge.gpg 2>>"$LOG"
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-edge.gpg] https://packages.microsoft.com/repos/edge stable main" \
                > /etc/apt/sources.list.d/microsoft-edge.list
        fi
        if [[ "${FOUND[Node.js]}" == "1" ]]; then
            NODE_MAJ=$(node_major "${OLD_VER[Node.js]}")
            if [[ ! -f /etc/apt/sources.list.d/nodesource.list ]] || ! grep -q "node_${NODE_MAJ}\.x" /etc/apt/sources.list.d/nodesource.list; then
                say "  Adding NodeSource repo for Node.js ${NODE_MAJ}.x..."
                curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                    | gpg --dearmor --yes -o /usr/share/keyrings/nodesource.gpg 2>>"$LOG"
                echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJ}.x nodistro main" \
                    > /etc/apt/sources.list.d/nodesource.list
            fi
        fi
        if [[ "${FOUND[PHP]}" == "1" ]] && ! grep -rq "ondrej" /etc/apt/sources.list.d/ 2>/dev/null; then
            say "  Adding ondrej/php PPA for PHP branches..."
            apt-get install -y software-properties-common lsb-release ca-certificates >>"$LOG" 2>&1
            add-apt-repository -y ppa:ondrej/php >>"$LOG" 2>&1
        fi
        if [[ "${FOUND[Python]}" == "1" ]] && ! grep -rq "deadsnakes" /etc/apt/sources.list.d/ 2>/dev/null; then
            say "  Adding deadsnakes PPA for Python..."
            apt-get install -y software-properties-common >>"$LOG" 2>&1
            add-apt-repository -y ppa:deadsnakes/ppa >>"$LOG" 2>&1
        fi
    fi

    if [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        if [[ "${FOUND[Node.js]}" == "1" ]] && ! rpm -q nodesource-release >/dev/null 2>&1; then
            NODE_MAJ=$(node_major "${OLD_VER[Node.js]}")
            curl -fsSL "https://rpm.nodesource.com/setup_${NODE_MAJ}.x" | bash - >>"$LOG" 2>&1
        fi
        if [[ "${FOUND[PHP]}" == "1" ]] && ! rpm -q remi-release >/dev/null 2>&1; then
            dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel 2>/dev/null || echo 9).rpm >>"$LOG" 2>&1 || true
            PHP_BR=$(php_branch "${OLD_VER[PHP]}")
            dnf module reset -y php >>"$LOG" 2>&1 || true
            dnf module enable -y "php:remi-${PHP_BR}" >>"$LOG" 2>&1 || true
        fi
    fi

    # Refresh indexes
    case "$PM" in
        apt)    apt-get update -y >>"$LOG" 2>&1 ;;
        dnf)    dnf makecache -y   >>"$LOG" 2>&1 ;;
        yum)    yum makecache -y   >>"$LOG" 2>&1 ;;
        zypper) zypper --non-interactive refresh >>"$LOG" 2>&1 ;;
    esac

    for entry in "${TOOLS[@]}"; do
        IFS='|' read -r name cmd flag pkg_default _ <<< "$entry"
        if [[ "${FOUND[$name]}" != "1" ]]; then
            printf "  ${D}[SKIP]${N}       %-18s  not installed - skipping\n" "$name" | tee -a "$LOG"
            continue
        fi
        pkg="${PKG[$name]}"
        target="${TARGET[$name]}"
        # Skip if already at target version
        if [[ -n "$target" ]]; then
            clean_old=$(echo "${OLD_VER[$name]}" | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
            if [[ "$clean_old" == *"$target"* ]]; then
                printf "  ${G}[OK]${N}         %-18s  already at target %s - skipping\n" "$name" "$target" | tee -a "$LOG"
                NEW_VER[$name]="${OLD_VER[$name]}"
                continue
            fi
        fi
        printf "  ${C}[UPDATING]${N}   %-18s  current: %s   ${D}(target: %s)${N}\n" "$name" "${OLD_VER[$name]}" "${target:-latest}" | tee -a "$LOG"
        case "$PM" in
            apt)
                if [[ -n "$target" ]]; then
                    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades "${pkg}=${target}*" >>"$LOG" 2>&1 \
                      || DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$pkg" >>"$LOG" 2>&1 \
                      || DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG" 2>&1
                else
                    DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$pkg" >>"$LOG" 2>&1 \
                      || DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG" 2>&1
                fi
                ;;
            dnf)
                if [[ -n "$target" ]]; then
                    dnf install -y "${pkg}-${target}" >>"$LOG" 2>&1 || dnf upgrade -y "$pkg" >>"$LOG" 2>&1
                else
                    dnf upgrade -y "$pkg" >>"$LOG" 2>&1
                fi
                ;;
            yum)    yum update -y "$pkg"  >>"$LOG" 2>&1 ;;
            zypper) zypper --non-interactive update "$pkg" >>"$LOG" 2>&1 ;;
            none)   say "${R}  No package manager - cannot update $name${N}" ;;
        esac
        if ! command -v "$cmd" >/dev/null 2>&1; then
            case "$name" in
                Python) cmd=python3 ;;
                PHP)    cmd=php     ;;
            esac
        fi
        NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)

        # Check if target version was actually hit (strip 'v', 'Google Chrome', 'PHP' prefix)
        clean_new=$(echo "${NEW_VER[$name]}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)
        if [[ -n "$target" && "$clean_new" != "$target" ]]; then
            case "$name" in
                "Google Chrome")
                    say "               Package manager gave $clean_new, need $target - trying direct Chrome install..."
                    install_chrome_direct
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
                "Microsoft Edge")
                    say "               Package manager gave $clean_new, need $target - trying exact Edge version..."
                    install_edge_exact "$target"
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
                "Node.js")
                    say "               Package manager gave $clean_new, need $target - fetching exact Node from nodejs.org..."
                    install_node_exact "$target"
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
                "Mozilla Firefox")
                    say "               Package manager gave $clean_new, need $target - fetching exact Firefox from mozilla.org..."
                    install_firefox_exact "$target"
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
            esac
        elif [[ "${NEW_VER[$name]}" == "${OLD_VER[$name]}" ]]; then
            case "$name" in
                "Google Chrome")
                    say "               Package manager unchanged - trying direct Chrome install..."
                    install_chrome_direct
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
                "Microsoft Edge")
                    say "               Package manager unchanged - trying direct Edge install..."
                    install_edge_direct
                    NEW_VER[$name]=$("$cmd" "$flag" 2>/dev/null | head -n1)
                    ;;
            esac
        fi

        if [[ "${NEW_VER[$name]}" == "${OLD_VER[$name]}" ]]; then
            printf "               ${D}Already latest: %s${N}\n" "${NEW_VER[$name]}" | tee -a "$LOG"
        else
            printf "               ${G}UPDATED  %s  ->  %s${N}\n" "${OLD_VER[$name]}" "${NEW_VER[$name]}" | tee -a "$LOG"
        fi
    done
fi

# ---------- SUMMARY ----------
say ""
say "${Y}>>> SUMMARY${N}"
line
printf "  %-18s %-10s %-35s %s\n" "Tool" "Status" "Old Version" "New Version" | tee -a "$LOG"
line
for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name _ _ _ _ <<< "$entry"
    status=$([[ "${FOUND[$name]}" == "1" ]] && echo "FOUND" || echo "MISSING")
    new="${NEW_VER[$name]:--}"
    printf "  %-18s %-10s %-35s %s\n" "$name" "$status" "${OLD_VER[$name]}" "$new" | tee -a "$LOG"
done
line
say "Full log: $LOG"
say ""
