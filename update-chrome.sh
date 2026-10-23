#!/usr/bin/env bash
# =====================================================================
#  System audit + updater for Chrome, Node.js, Python, PHP on Linux
#  Phase 1: Audit (found / not found + version)
#  Phase 2: Update installed tools to latest via system package manager
# =====================================================================

set -u

LOGDIR="/var/log/system-audit"
mkdir -p "$LOGDIR" 2>/dev/null || LOGDIR="/tmp"
LOG="$LOGDIR/audit-$(date +%Y%m%d-%H%M%S).log"

# Colors
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

# --- Tools to audit: name|command|version-flag|package-name|target-version ---
TOOLS=(
    "Google Chrome|google-chrome|--version|google-chrome-stable|"
    "Mozilla Firefox|firefox|--version|firefox|"
    "Microsoft Edge|microsoft-edge|--version|microsoft-edge-stable|"
    "Node.js|node|--version|nodejs|26.12.1"
    "Python|python3.14|--version|python3.14|3.14.9"
    "PHP|php|--version|php8.5|8.5.12"
)
# PHP fallback (8.4 branch) if 8.5.12 is unavailable
PHP_FALLBACK_PKG="php8.4"
PHP_FALLBACK_VER="8.4.27"

declare -A OLD_VER NEW_VER FOUND PKG TARGET

# ---------- PHASE 1: AUDIT ----------
say ""
say "${Y}>>> PHASE 1: AUDIT${N}"
line

for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name cmd flag pkg target <<< "$entry"
    PKG[$name]=$pkg
    TARGET[$name]=$target
    # Also look up generic command for CLI tools (python3 / php) when pinned command isn't found
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
        printf "  ${G}[FOUND]${N}      %-15s  version: %s   ${D}(target: %s)${N}\n" "$name" "$ver" "${target:-latest}" | tee -a "$LOG"
    else
        FOUND[$name]=0
        OLD_VER[$name]="-"
        printf "  ${R}[NOT FOUND]${N}  %-15s  (not installed)   ${D}(target: %s)${N}\n" "$name" "${target:-latest}" | tee -a "$LOG"
    fi
done

# ---------- PHASE 2: UPDATE ----------
say ""
say "${Y}>>> PHASE 2: UPDATE${N}"
line

if [[ $IS_ROOT -eq 0 ]]; then
    say "${R}Skipping updates (not root). Re-run with sudo.${N}"
else
    # ---- Add vendor repos needed for pinned versions ----
    if [[ "$PM" == "apt" ]]; then
        # Google Chrome
        if [[ "${FOUND[Google Chrome]}" == "1" && ! -f /etc/apt/sources.list.d/google-chrome.list ]]; then
            curl -fsSL https://dl.google.com/linux/linux_signing_key.pub \
                | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg 2>>"$LOG"
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" \
                > /etc/apt/sources.list.d/google-chrome.list
        fi

        # Microsoft Edge
        if [[ "${FOUND[Microsoft Edge]}" == "1" && ! -f /etc/apt/sources.list.d/microsoft-edge.list ]]; then
            curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
                | gpg --dearmor -o /usr/share/keyrings/microsoft-edge.gpg 2>>"$LOG"
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-edge.gpg] https://packages.microsoft.com/repos/edge stable main" \
                > /etc/apt/sources.list.d/microsoft-edge.list
        fi

        # NodeSource for Node.js 26.x
        if [[ ! -f /etc/apt/sources.list.d/nodesource.list ]]; then
            say "  Adding NodeSource repo for Node.js 26.x..."
            curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg 2>>"$LOG"
            echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_26.x nodistro main" \
                > /etc/apt/sources.list.d/nodesource.list
        fi

        # deadsnakes PPA for Python 3.15
        if ! grep -rq "deadsnakes" /etc/apt/sources.list.d/ 2>/dev/null; then
            say "  Adding deadsnakes PPA for Python 3.15..."
            apt-get install -y software-properties-common >>"$LOG" 2>&1
            add-apt-repository -y ppa:deadsnakes/ppa >>"$LOG" 2>&1
        fi

        # Ondřej Surý's PPA for PHP 8.5
        if ! grep -rq "ondrej" /etc/apt/sources.list.d/ 2>/dev/null; then
            say "  Adding ondrej/php PPA for PHP 8.5..."
            apt-get install -y software-properties-common lsb-release ca-certificates >>"$LOG" 2>&1
            add-apt-repository -y ppa:ondrej/php >>"$LOG" 2>&1
        fi
    fi

    if [[ "$PM" == "dnf" || "$PM" == "yum" ]]; then
        # NodeSource for RHEL/Fedora
        if ! rpm -q nodesource-release >/dev/null 2>&1; then
            curl -fsSL https://rpm.nodesource.com/setup_26.x | bash - >>"$LOG" 2>&1
        fi
        # Remi for PHP 8.5 (Fedora/RHEL)
        if ! rpm -q remi-release >/dev/null 2>&1; then
            dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel 2>/dev/null || echo 9).rpm >>"$LOG" 2>&1 || true
            dnf module reset -y php >>"$LOG" 2>&1 || true
            dnf module enable -y php:remi-8.5 >>"$LOG" 2>&1 || true
        fi
    fi

    # Refresh package indexes once
    case "$PM" in
        apt)    apt-get update -y >>"$LOG" 2>&1 ;;
        dnf)    dnf makecache -y   >>"$LOG" 2>&1 ;;
        yum)    yum makecache -y   >>"$LOG" 2>&1 ;;
        zypper) zypper --non-interactive refresh >>"$LOG" 2>&1 ;;
    esac

    for entry in "${TOOLS[@]}"; do
        IFS='|' read -r name cmd flag pkg <<< "$entry"
        if [[ "${FOUND[$name]}" != "1" ]]; then
            printf "  ${D}[SKIP]${N}       %-15s  not installed - skipping\n" "$name" | tee -a "$LOG"
            continue
        fi
        target="${TARGET[$name]}"
        printf "  ${C}[UPDATING]${N}   %-15s  current: %s   ${D}(target: %s)${N}\n" "$name" "${OLD_VER[$name]}" "${target:-latest}" | tee -a "$LOG"
        case "$PM" in
            apt)
                # Try pinned version first (apt uses pkg=version syntax)
                if [[ -n "$target" ]]; then
                    DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
                        "$pkg=${target}*" >>"$LOG" 2>&1
                    rc=$?
                    # PHP 8.5 fallback -> 8.4 branch
                    if [[ $rc -ne 0 && "$name" == "PHP" ]]; then
                        say "               PHP $target unavailable - trying ${PHP_FALLBACK_PKG}=${PHP_FALLBACK_VER}"
                        DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades \
                            "${PHP_FALLBACK_PKG}=${PHP_FALLBACK_VER}*" >>"$LOG" 2>&1
                        rc=$?
                    fi
                    if [[ $rc -ne 0 ]]; then
                        DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "$pkg" >>"$LOG" 2>&1 \
                          || DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >>"$LOG" 2>&1
                    fi
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
        # Re-detect version (python3.15 may now be the right binary)
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
printf "  %-15s %-10s %-35s %s\n" "Tool" "Status" "Old Version" "New Version" | tee -a "$LOG"
line
for entry in "${TOOLS[@]}"; do
    IFS='|' read -r name _ _ _ <<< "$entry"
    status=$([[ "${FOUND[$name]}" == "1" ]] && echo "FOUND" || echo "MISSING")
    new="${NEW_VER[$name]:--}"
    printf "  %-15s %-10s %-35s %s\n" "$name" "$status" "${OLD_VER[$name]}" "$new" | tee -a "$LOG"
done
line
say "Full log: $LOG"
say ""
