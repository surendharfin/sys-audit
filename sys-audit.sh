#!/usr/bin/env bash
# =====================================================================
#  System audit + updater for Chrome, Firefox, Edge, Node.js, Python, PHP
#  Phase 1: Audit  - found / not found + version per tool
#  Phase 2: Update - installed tools -> latest via system package manager
#                    (Node + PHP use branch-aware pinned patch versions)
# =====================================================================

set -u

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

# --- Must be root for updates ---
if [[ $EUID -ne 0 ]]; then
    say "${Y}WARNING: not running as root. Audit will run, updates will be skipped.${N}"
    IS_ROOT=0
else
    IS_ROOT=1
fi

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
    "Mozilla Firefox|firefox|--version|firefox|"
    "Microsoft Edge|microsoft-edge|--version|microsoft-edge-stable|"
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
