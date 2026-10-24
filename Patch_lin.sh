#!/usr/bin/env bash
# =============================================================================
# vulnpatch-linux.sh - DETECT and PATCH, in one file (Linux counterpart of vulnpatch-windows.ps1).
#
# DETECT: finds EVERY copy of PHP, Node.js, Python, Chrome, Chromium, Edge, Brave and
# Firefox anywhere on the machine (all disks, every user's home, app and temp folders),
# however it got there:
#   package managers ... apt/dpkg, dnf/yum/rpm (distro packages, PPAs, vendor repos)
#   app stores ......... snap, flatpak (system-wide and per-user)
#   version managers ... nvm, n, fnm, volta, asdf, pyenv, conda/miniforge, uv
#   anything else ...... curl/wget downloads, tarballs, zips, source builds, Puppeteer/
#                        Playwright browser caches, runtimes inside other apps, virtualenvs
# plus the OS CA trust store, and rates every copy against the fixed versions:
#   PHP2Shell CVE-2026-109618/109619 | Node.js 21-Oct release (CVE-2026-111497 + 9)
#   eMudhra CA compromise (Python pip/certifi, Firefox, OS trust store)
#   Chromium 156 security fixes (Chrome, Chromium, Edge, Brave)
#   Java CVE-2026-91403 (eMudhra intermediates trusted by JSSE) + October 2026 Java CPU
# Products that are not on the machine at all are listed as NOT FOUND.
# Every run writes an Excel-ready CSV report to the Desktop of whoever ran it (one file per machine,
# updated on each run): host, IP, MAC, each copy found, version before / fixed in / after, the result
# and the error for anything that could not be patched. Docker/Podman/LXD containers and VMs on the
# machine are listed as NOT SCANNED: they are separate systems - run the script inside each of them.
#
# PATCH: every finding gets an automatic action - there are no manual decisions:
#   apt / dnf / snap / flatpak .. upgrades ONLY packages already installed (adds nothing new)
#   downloaded / manager copies . the fixed release swapped into the SAME folder
#   PHP / Python source builds .. rebuilt with the SAME ./configure options into the same place
#                                 (as the user who owns it)
#   runtimes inside apps ........ the owning package is upgraded first; if still vulnerable, the
#                                 runtime itself is refreshed in place (Node.js binary / certifi)
#   Chromium inside apps ........ Chrome for Testing swapped in (Google checksum verified)
#   Python (any kind) ........... certificate bundle (certifi) refreshed; venvs included
#   Java (any vendor, any copy) . package update where it has one, then the 16 eMudhra fingerprints
#                                 added to its lib/security/blocked.certs (Oracle's own fix)
#   OS trust store .............. ca-certificates update; where the distro has none (Ubuntu 20.04
#                                 without Pro): emSign ECC Root CA - G3 distrusted directly
#   distro Firefox package ...... package update; where the distro has none: Mozilla's build swapped in
#   end-of-life lines ........... moved to the nearest supported line (Node.js, PHP)
# Each change is backed up while it is made (/var/backups/vulnpatch); once the re-scan confirms an
# item PATCHED its backup is deleted, so no old versions are left behind (--keep-backups keeps
# them; backups stay only for items that are not confirmed). After patching the whole machine
# is scanned again and every copy is reported PATCHED / STILL VULNERABLE (with the reason).
#
#   sudo bash vulnpatch-linux.sh --scan     # detection report only (+ JSON)
#   sudo bash vulnpatch-linux.sh            # detection + patch plan (changes nothing)
#   sudo bash vulnpatch-linux.sh --apply    # detect, ASK which copies to patch, patch, verify
# Options:
#   --pick SPEC     (--apply) choose without the prompt: all | 1,3,5-7 | php,node | none
#   --only LIST     php,node,python,java,chrome,chromium,edge,brave,firefox,ca (limits the plan)
#   --keep-backups  keep the backups of verified fixes too (default: deleted once the fix is verified)
#   --report PATH   folder (or .csv file) for the report, e.g. a mounted share
#                   (default: your Desktop, else Downloads - file vulnpatch-report-<host>.csv)
#   --no-rebuild    skip PHP/Python source rebuilds (fast run; Python still gets certifi)
#   --quick         scan common install folders only, not every disk
#   --json FILE     where to write the JSON report
#   --no-exec       (--scan only) never run binaries found on disk
#   -y              no prompts (patches every plan item unless --pick says otherwise)
#
# Safety: a binary found on disk is only run (for --version) as the user who owns it, or as
# 'nobody' when it sits in a temp folder or is world-writable, with a clean environment and
# a timeout - never with more privilege than its owner.
# Exit code: 0 = nothing vulnerable (left), 1 = vulnerable copies found/left, 2 = usage error
# =============================================================================
set -uo pipefail

# ---- fixed versions (researched 2026-10-23) ---------------------------------
declare -A PHP_FIX=(  [8.2]=8.2.35  [8.3]=8.3.36  [8.4]=8.4.27  [8.5]=8.5.12 )
declare -A NODE_FIX=( [22]=22.23.4  [24]=24.22.1  [26]=26.12.1 )
declare -A PY_FIX=(   [3.13]=3.13.17 [3.14]=3.14.9 [3.15]=3.15.1 )
CHROME_FIX=156.0.8078.47      # Chrome and Chromium
EDGE_FIX=156.0.4314.42
BRAVE_FIX=1.98.60
FIREFOX_FIX=158.0.1           # ESR: 153.5.1 / 115.43.1
CERTIFI_FIX=2026.10.19        # first certifi without the compromised eMudhra CAs
declare -A JAVA_FIX=( [8]=8.0.511 [11]=11.0.33 [17]=17.0.21 [21]=21.0.13 [25]=25.0.5 [27]=27.0.1 )   # Oct-2026 CPU (8 = 8u511)
# CVE-2026-91403: the 16 eMudhra intermediates OpenJDK/Oracle added to lib/security/blocked.certs
# (JDK-8395142; checked against openjdk/jdk blocked.certs.pem)
EMUDHRA_FPS=(
  0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
  432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
  4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1 579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
  5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699 62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
  7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489 84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
  98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B 9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
  A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8 CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
  E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838 FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
)
# ---- libraries and supply chain (researched 2026-10-24) ----
PILLOW_FIX=13.0.0                       # CVE-2026-112900 (Ghostscript RCE) + 5 more; needs Python 3.11+
BROTLI_FIX=1.2.1                        # CVE-2026-111497 (Node2Shell) in the Brotli library itself
BROTLICFFI_FIX=1.2.1.0
LITELLM_BAD=(1.107.0 1.82.7 1.82.8)     # malicious releases (credential stealer + remote-control backdoor)
LITELLM_FIX=1.83.14                     # first release with the April-2026 CVE fixes (CVSS 10.0 RCE)
LITELLM_SPEC='litellm>=1.106.2,!=1.107.0'
declare -A NEXT_FIX=( [15]=15.5.28 [16]=16.4.1 )   # 14-Oct-2026: use-cache RCE, image RCE, Server Actions DoS
SHARP_FIX=0.35.5                        # librsvg RCE through image processing (CVE-2026-96889)
BUN_FIX=1.4.4                           # CVE-2026-111497 (Node2Shell) in Bun
KEV_DAYS=30                             # CISA KEV additions of the last N days are matched against installed apps
KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# litellm 1.107.0 indicators (Socket / Aikido): SHA-256 of cook.pth, cook.py, sitecustomize.py (two builds each)
LITELLM_IOC_SHA=(7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb 84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d
                 9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25 03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea
                 34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465)
LITELLM_IOC_MARK='remote_code_loader|letters9813|litellm\.dev/healthcheck|XWiA8gZNa7NcX2XRoAEb'
PRODUCTS=(PHP Node.js Bun Python Java Chrome Edge Firefox Brave LiteLLM Pillow Brotli Next.js sharp)   # listed as NOT FOUND when absent
SCRIPT_VERSION=2026.10.24

# ---- options ----------------------------------------------------------------
MODE=plan; ASSUME_YES=0; NO_REBUILD=0; KEEP_BACKUPS=0; ONLY_PRODUCTS=""; PICK_SPEC=""; REPORT_PATH=""; ARGS_TXT="$*"
QUICK=0; NO_EXEC=0; JSON_OUT=""; CUSTOM_PATHS=""; ROOTS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scan)       MODE=scan; shift ;;
    --apply)      MODE=apply; shift ;;
    -y|--yes)     ASSUME_YES=1; shift ;;
    --no-rebuild) NO_REBUILD=1; shift ;;
    --pick)       PICK_SPEC=$2; shift 2 ;;
    --only)       ONLY_PRODUCTS=${2,,}; shift 2 ;;
    --quick)      QUICK=1; shift ;;
    --no-exec)    NO_EXEC=1; shift ;;
    --json)       JSON_OUT=$2; shift 2 ;;
    --paths)      CUSTOM_PATHS=$2; shift 2 ;;
    --report)     REPORT_PATH=$2; shift 2 ;;
    --keep-backups) KEEP_BACKUPS=1; shift ;;
    -h|--help)    if [[ -f $0 ]]; then awk 'NR==1{next} /^set -uo/{exit} {print}' "$0"; else echo "options: --scan | --apply [--pick SPEC] [--only LIST] [--no-rebuild] [--quick] [--json FILE] [-y]"; fi; exit 0 ;;
    *)            echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
if (( NO_EXEC )) && [[ $MODE != scan ]]; then echo "--no-exec only works with --scan" >&2; exit 2; fi
if [[ $MODE == apply && $EUID -ne 0 ]]; then echo "--apply needs root (sudo)" >&2; exit 2; fi

STAMP=$(date +%Y%m%d-%H%M%S)
LOGDIR=/var/log/vulnpatch
BACKUP_DIR=/var/backups/vulnpatch
BACKUP_INDEX=$BACKUP_DIR/index-$STAMP.tsv   # item <TAB> backup, to delete each one once its fix is verified
CUR_KEY=""; BACKUPS_DROPPED=0
LOG=/dev/null
# questions are read from the keyboard even when the script itself arrives on stdin (curl ... | sudo bash)
TTY_IN=/dev/stdin
if [[ ! -t 0 && -r /dev/tty ]]; then TTY_IN=/dev/tty; fi
if command -v apt-get >/dev/null 2>&1; then PKGMGR=apt
elif command -v dnf >/dev/null 2>&1; then PKGMGR=dnf
elif command -v yum >/dev/null 2>&1; then PKGMGR=yum
else PKGMGR=none; fi

if [[ -t 1 ]]; then
  RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; DIM=$'\e[2m'; RST=$'\e[0m'
else
  RED=''; GRN=''; YEL=''; CYN=''; DIM=''; RST=''
fi

# ---- helpers ----------------------------------------------------------------
say()       { printf '%s\n' "$*"; }
step()      { printf '\n%s==> %s%s\n' "$CYN" "$*" "$RST"; }
warn()      { printf '    %s[!!]%s %s\n' "$YEL" "$RST" "$*"; }
have()      { command -v "$1" >/dev/null 2>&1; }
ver_lt()    { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1) == "$1" ]]; }
first_ver() { grep -oE '[0-9]+(\.[0-9]+)+' | head -n1; }
json_esc()  { local s=${1//\\/\\\\}; printf '%s' "${s//\"/\\\"}"; }

# 2:8.3.36-1+ubuntu22.04.1+deb.sury.org+1 -> 8.3.36 ; 12.22.9~dfsg-1ubuntu3 -> 12.22.9
upstream_of() { local v=${1#*:}; v=${v%%-*}; printf '%s\n' "${v%%[~+]*}"; }

# Distro builds (Ubuntu/Debian/RHEL/SUSE) backport fixes without changing the upstream
# number, so "8.1.2" from Ubuntu can be patched. Vendor repos (sury, NodeSource, remi) can't.
is_backport() {
  [[ $1 =~ (ubuntu|deb[0-9]+u|~[0-9]{2}\.[0-9]{2}|\.el[0-9]|\.fc[0-9]|amzn|suse|dfsg) && ! $1 =~ (sury|nodesource|remi) ]]
}

# Runs a discovered binary with no more privilege than its owner has.
run_bin() {
  local bin=$1; shift
  local owner run_as=""
  owner=$(stat -c %U "$bin" 2>/dev/null) || return 0
  if [[ $EUID -eq 0 ]]; then
    case $bin in /tmp/*|/var/tmp/*|/dev/shm/*) run_as=nobody ;; esac      # anyone could have planted it
    [[ $(stat -c %A "$bin") == ????????w? ]] && run_as=nobody               # world-writable
    [[ $owner == UNKNOWN ]] && run_as=nobody                                # uid without an account
    [[ -z $run_as && $owner != root ]] && run_as=$owner
    if [[ -n $run_as ]]; then
      have runuser || return 0
      timeout 15 runuser -u "$run_as" -- env -i PATH=/usr/bin:/bin HOME=/tmp "$bin" "$@" 2>"${RUN_BIN_ERR:-/dev/null}"
      return 0
    fi
  fi
  timeout 15 env -i PATH=/usr/bin:/bin HOME=/tmp "$bin" "$@" 2>"${RUN_BIN_ERR:-/dev/null}"
  return 0
}

java_norm() {  # 1.8.0_402-b06 -> 8.0.402 | 21.0.5+11 -> 21.0.5 | 25 -> 25.0.0 | 25.0.5.0.2 -> 25.0.5.0.2
  local v=${1%%[+-]*}
  if [[ $v =~ ^1\.([0-9]+)\.0_([0-9]+) ]]; then echo "${BASH_REMATCH[1]}.0.${BASH_REMATCH[2]}"
  elif [[ $v =~ ^1\.([0-9]+)(\.0)?$ ]]; then echo "${BASH_REMATCH[1]}.0.0"
  elif [[ $v =~ ^[0-9]+$ ]]; then echo "$v.0.0"
  else first_ver <<<"$v"; fi
}

java_blockfile() {  # install root -> the block list file that JVM reads (JDK 8: jre/lib/security, blacklisted.certs)
  local sec=$1/lib/security f
  if [[ -d $1/jre/lib/security ]]; then sec=$1/jre/lib/security; fi
  for f in "$sec/blocked.certs" "$sec/blacklisted.certs"; do if [[ -e $f ]]; then echo "$f"; return 0; fi; done
  echo "$sec/blocked.certs"
}

java_fp_count() {  # block list file -> how many of the 16 eMudhra fingerprints it holds
  local f=$1 n=0 fp
  [[ -r $f ]] || { echo 0; return 0; }
  for fp in "${EMUDHRA_FPS[@]}"; do if grep -qi "^$fp" "$f"; then n=$((n + 1)); fi; done
  echo "$n"
}

node_target() {  # version -> fixed version of the same line, or of the nearest supported line (end-of-life)
  local br=${1%%.*} m
  if [[ -n ${NODE_FIX[$br]:-} ]]; then echo "${NODE_FIX[$br]}"; return 0; fi
  for m in $(printf '%s\n' "${!NODE_FIX[@]}" | sort -n); do
    if (( m > br )); then echo "${NODE_FIX[$m]}"; return 0; fi
  done
  return 0
}

# =============================================================================
# DETECTION
# =============================================================================
# one row per installation; binaries of the same install (php, php-fpm, php-cgi) are merged
declare -A R_PROD R_VER R_FIX R_STATUS R_METHOD R_ROOT R_OWNER R_PKGS R_PATHS R_NOTE R_ACTION R_BACKPORT R_CERTIFI R_DEFAULT R_EMBED R_VENDOR \
           R_LIB R_PY R_PYMODE R_PYVER R_MAJOR R_KEV
KEYS=()
SKIPPED=0
VENV_ROOTS=(); VENV_OLD=(); KEV_STATE=""

reset_results() {  # clears all rows so the machine can be scanned again (after patching)
  unset R_PROD R_VER R_FIX R_STATUS R_METHOD R_ROOT R_OWNER R_PKGS R_PATHS R_NOTE R_ACTION R_BACKPORT R_CERTIFI R_DEFAULT R_EMBED R_VENDOR \
        R_LIB R_PY R_PYMODE R_PYVER R_MAJOR R_KEV
  declare -gA R_PROD=() R_VER=() R_FIX=() R_STATUS=() R_METHOD=() R_ROOT=() R_OWNER=() R_PKGS=() R_PATHS=() \
              R_NOTE=() R_ACTION=() R_BACKPORT=() R_CERTIFI=() R_DEFAULT=() R_EMBED=() R_VENDOR=() \
              R_LIB=() R_PY=() R_PYMODE=() R_PYVER=() R_MAJOR=() R_KEV=()
  KEYS=(); SKIPPED=0; VENV_ROOTS=(); VENV_OLD=()
}

add_row() {  # key product version method root owner package binary
  local k=$1
  if [[ -z ${R_PROD[$k]+x} ]]; then
    KEYS+=("$k")
    R_PROD[$k]=$2; R_VER[$k]=$3; R_METHOD[$k]=$4; R_ROOT[$k]=$5; R_OWNER[$k]=$6
    R_PKGS[$k]=""; R_PATHS[$k]=""; R_NOTE[$k]=""
  fi
  if [[ -n $7 && " ${R_PKGS[$k]} " != *" $7 "* ]]; then R_PKGS[$k]="${R_PKGS[$k]:+${R_PKGS[$k]} }$7"; fi
  if [[ -n $8 ]]; then R_PATHS[$k]="${R_PATHS[$k]:+${R_PATHS[$k]};}$8"; fi
}

owner_of() {  # user name, or uid:N when the uid has no account (e.g. kept from a tarball)
  local u; u=$(stat -c %U "$1" 2>/dev/null) || { echo '?'; return 0; }
  if [[ $u == UNKNOWN ]]; then echo "uid:$(stat -c %u "$1")"; else echo "$u"; fi
}

pkg_is_product() {  # product package -> true when the package IS that product
  case $1 in
    PHP)      [[ $2 == php* ]] ;;
    Node.js)  [[ $2 == nodejs* || $2 == node ]] ;;
    Python)   [[ $2 == python3* || $2 == libpython3* ]] ;;
    Chrome)   [[ $2 == google-chrome* ]] ;;
    Chromium) [[ $2 == chromium* ]] ;;
    Edge)     [[ $2 == microsoft-edge* ]] ;;
    Brave)    [[ $2 == brave-browser* || $2 == brave-origin* ]] ;;
    Firefox)  [[ $2 == firefox* ]] ;;
    Java)     [[ $2 =~ ^(openjdk|java|jdk|jre|temurin|zulu|.*corretto|oracle-java|msopenjdk|bellsoft|sapmachine|semeru) ]] ;;
    *)        return 1 ;;
  esac
}

product_of() {  # real path -> product, empty if not one of ours
  local p=$1 b=${1##*/}
  case $b in
    php|php[0-9]*|php-fpm*|php-cgi*) echo PHP ;;
    node|nodejs)                     echo Node.js ;;
    python3*)                        [[ $b =~ ^python3(\.[0-9]+t?)?$ ]] && echo Python ;;
    chrome)                          case $p in */google/chrome*) echo Chrome ;; *) echo Chromium ;; esac ;;
    chromium|chromium-browser)       echo Chromium ;;
    msedge)                          echo Edge ;;
    brave)                           echo Brave ;;
    firefox)                         [[ -f ${p%/*}/application.ini ]] && echo Firefox ;;   # skips wrapper scripts
    java)                            echo Java ;;
    bun)                             echo Bun ;;
  esac
  return 0
}

method_of_path() {
  case $1 in
    */.nvm/*)                       echo nvm ;;
    */.pyenv/*)                     echo pyenv ;;
    */.volta/*)                     echo volta ;;
    */fnm/node-versions/*)          echo fnm ;;
    */.asdf/installs/*)             echo asdf ;;
    */n/versions/node/*)            echo n ;;
    */.local/share/uv/python/*)     echo uv ;;
    */.sdkman/candidates/*)         echo sdkman ;;
    */.jdks/*|*/.jabba/*)           echo jdk-manager ;;
    */miniconda*/*|*/anaconda*/*|*/miniforge*/*|*/mambaforge*/*|*/conda/*) echo conda ;;
    */.cache/puppeteer/*)           echo puppeteer ;;
    */ms-playwright*/*)             echo playwright ;;
    */node_modules/*)               echo npm-package ;;
    /tmp/*|/var/tmp/*|/dev/shm/*)   echo download-in-temp ;;
    *)                              echo manual ;;
  esac
}

version_of() {  # product binary install-root
  local prod=$1 bin=$2 root=$3 v="" mm h
  if [[ $prod == Firefox ]]; then
    v=$(sed -n 's/^Version=//p' "${bin%/*}/application.ini" 2>/dev/null | head -n1)
  fi
  if [[ $prod == Java ]]; then   # every JDK/JRE image has a 'release' file - nothing needs to run
    v=$(sed -n 's/^JAVA_VERSION="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$root/release" 2>/dev/null | head -n1)
    if [[ -z $v ]] && (( ! NO_EXEC )); then v=$(RUN_BIN_ERR=/dev/stdout run_bin "$bin" -version | sed -n 's/.*version "\([^"]*\)".*/\1/p' | head -n1); fi
    [[ -n $v ]] && java_norm "$v"
    return 0
  fi
  if [[ -z $v ]] && (( ! NO_EXEC )); then
    case $prod in
      PHP)   v=$(run_bin "$bin" -v | first_ver) ;;
      Brave) v=$(run_bin "$bin" --version | first_ver)
             # brave --version can report <chromium major>.<brave version>, e.g. 155.1.97.59
             if [[ $v =~ ^[0-9]{3,}\.([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then v=${BASH_REMATCH[1]}; fi ;;
      *)     v=$(run_bin "$bin" --version | first_ver) ;;
    esac
  fi
  if [[ -z $v ]]; then   # static fallbacks (the only source with --no-exec)
    case $prod in
      PHP)     h=$root/include/php/main/php_version.h
               [[ -f $h ]] && v=$(sed -nE 's/^#define PHP_VERSION "([^"]+)".*/\1/p' "$h") ;;
      Node.js) h=$root/include/node/node_version.h
               [[ -f $h ]] && v=$(awk '/^#define NODE_(MAJOR|MINOR|PATCH)_VERSION /{printf "%s%s", s, $3; s="."}' "$h") ;;
      Python)  mm=$(grep -oE '[0-9]+\.[0-9]+' <<<"${bin##*/}")
               h=$root/include/python$mm/patchlevel.h
               [[ -n $mm && -f $h ]] && v=$(sed -nE 's/^#define PY_VERSION[[:space:]]+"([^"]+)".*/\1/p' "$h") ;;
    esac
  fi
  first_ver <<<"$v"
}

scan_file() {
  local f=$1 real prod root owner method pkg="" pkgver="" ver o backport=0 embedded=0 key
  real=$(readlink -f "$f") || return 0
  prod=$(product_of "$real"); [[ -n $prod ]] || return 0
  # real programs only: skips wrapper/shim scripts (snap launchers, pyenv/asdf shims)
  if [[ $(head -c4 "$real" 2>/dev/null) != $'\177ELF' ]]; then SKIPPED=$((SKIPPED + 1)); return 0; fi
  root=${real%/*}
  case $prod in PHP|Node.js|Python|Java|Bun) [[ ${root##*/} == bin || ${root##*/} == sbin ]] && root=${root%/*} ;; esac
  # JDK 8: jdk/jre/bin/java belongs to the JDK around it
  if [[ $prod == Java && ${root##*/} == jre && -e ${root%/*}/bin/java ]]; then root=${root%/*}; fi
  root=${root:-/}

  if have dpkg && o=$(dpkg -S "$real" 2>/dev/null | head -n1); then
    pkg=${o%%: *}; pkg=${pkg%%,*}; pkg=${pkg%%:*}; method=apt
    pkgver=$(dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null | head -n1)
  elif have rpm && o=$(rpm -qf --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' "$real" 2>/dev/null | head -n1) && [[ $o == *'|'* ]]; then
    pkg=${o%%|*}; pkgver=${o#*|}; method=rpm
  else
    method=$(method_of_path "$real")
  fi

  # a runtime shipped inside some other package (Electron apps, IDEs): that package's
  # version says nothing about the runtime, and updating that package comes first
  if [[ -n $pkg ]] && ! pkg_is_product "$prod" "$pkg"; then embedded=1; pkgver=""; fi

  if [[ -n $pkgver && $prod != Java ]]; then   # Java: the release file is exact (8u422 package numbers are not)
    ver=$(upstream_of "$pkgver")
    case $prod in PHP|Node.js|Python) is_backport "$pkgver" && backport=1 ;; esac
  else
    ver=$(version_of "$prod" "$real" "$root")
  fi
  if [[ ! $ver =~ ^[0-9]+(\.[0-9]+)+$ ]]; then SKIPPED=$((SKIPPED + 1)); return 0; fi

  owner=$(owner_of "$root")
  key="$prod|$root|$ver"
  add_row "$key" "$prod" "$ver" "$method" "$root" "$owner" "$pkg" "$real"
  (( backport )) && R_BACKPORT[$key]=1
  (( embedded )) && R_EMBED[$key]=1
  if [[ $prod == Java ]]; then R_VENDOR[$key]=$(sed -n 's/^IMPLEMENTOR="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$root/release" 2>/dev/null | head -n1); fi
  [[ -n ${ACTIVE[$real]:-} ]] && R_DEFAULT[$key]=${ACTIVE[$real]}
  return 0
}

scan_snaps() {
  have snap || return 0
  local name ver prod
  while read -r name ver _; do
    case $name in
      firefox)  prod=Firefox ;;  chromium) prod=Chromium ;;
      brave)    prod=Brave ;;    node)     prod=Node.js ;;
      *)        continue ;;
    esac
    ver=${ver%%-*}
    [[ $ver =~ ^[0-9]+(\.[0-9]+)+$ ]] || continue
    add_row "$prod|/snap/$name|$ver" "$prod" "$ver" snap "/snap/$name" root "$name" ""
  done < <(snap list 2>/dev/null | tail -n +2)
}

scan_flatpaks() {
  have flatpak || return 0
  local user d
  _flatpak_rows() {  # scope user
    local list id ver prod
    if [[ $1 == user ]]; then list=$(runuser -u "$2" -- flatpak list --user --app --columns=application,version 2>/dev/null)
    else list=$(flatpak list --system --app --columns=application,version 2>/dev/null); fi
    while read -r id ver; do
      case $id in
        org.mozilla.firefox) prod=Firefox ;;  com.google.Chrome) prod=Chrome ;;
        com.microsoft.Edge)  prod=Edge ;;     com.brave.Browser) prod=Brave ;;
        org.chromium.Chromium) prod=Chromium ;;
        *) continue ;;
      esac
      ver=$(first_ver <<<"$ver")
      [[ -n $ver ]] || continue
      add_row "$prod|flatpak:$1:$2:$id|$ver" "$prod" "$ver" "flatpak-$1" "flatpak:$id" "$2" "$id" ""
    done <<<"$list"
  }
  _flatpak_rows system root
  if [[ $EUID -eq 0 ]] && have runuser; then
    for d in /home/*/.local/share/flatpak /root/.local/share/flatpak; do
      [[ -d $d/app ]] || continue
      user=$(stat -c %U "$d")
      _flatpak_rows user "$user"
    done
  fi
}

# OS trust store: Mozilla NSS removed "emSign ECC Root CA - G3" on 20-Oct-2026.
scan_trust_store() {
  local b bundle="" pkgver="" method=""
  for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
           /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/ca-bundle.pem; do
    if [[ -f $b ]]; then bundle=$b; break; fi
  done
  [[ -n $bundle ]] && have openssl || return 0
  if have dpkg-query; then pkgver=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null); method=apt
  elif have rpm; then pkgver=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2>/dev/null); method=rpm; fi
  local k="CA store|$bundle|${pkgver:-?}"
  add_row "$k" "CA store" "${pkgver:-?}" "$method" "$bundle" root ca-certificates ""
  if openssl crl2pkcs7 -nocrl -certfile "$bundle" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null \
       | grep -qiE 'CN ?= ?emSign ECC Root CA - G3'; then
    R_STATUS[$k]=VULNERABLE; R_NOTE[$k]="emSign ECC Root CA - G3 is still trusted (eMudhra compromise)"
  else
    R_STATUS[$k]=PATCHED; R_NOTE[$k]="emSign ECC Root CA - G3 not in the trust store"
  fi
  R_FIX[$k]="G3 removed"
}

site_packages_of() {  # python install root -> its site-packages folders
  local sp
  for sp in "$1"/lib/python3*/site-packages "$1"/lib/python3*/dist-packages; do
    if [[ -d $sp ]]; then printf '%s\n' "$sp"; fi
  done
  return 0
}

certifi_old_dirs() {  # site-packages... -> outdated certifi folders (standalone + pip's vendored one) as "dir|version"
  local sp d v
  for sp in "$@"; do
    for d in "$sp/certifi" "$sp/pip/_vendor/certifi"; do
      [[ -f $d/__init__.py ]] || continue
      v=$(sed -nE 's/^__version__ = "([^"]+)".*/\1/p' "$d/__init__.py" | head -n1)
      if [[ -n $v ]] && ver_lt "$v" "$CERTIFI_FIX"; then printf '%s|%s\n' "$d" "$v"; fi
    done
  done
  return 0
}

scan_venvs() {  # one row for all Python virtual environments (their certifi lives inside each one)
  (( ${#VENV_ROOTS[@]} )) || return 0
  local v sp n k="Python|venvs|"
  local -a old=()
  mapfile -t VENV_ROOTS < <(printf '%s\n' "${VENV_ROOTS[@]}" | sort -u)
  n=${#VENV_ROOTS[@]}
  for v in "${VENV_ROOTS[@]}"; do
    while IFS= read -r sp; do
      while IFS= read -r e; do old+=("$e"); done < <(certifi_old_dirs "$sp")
    done < <(site_packages_of "$v")
  done
  add_row "$k" Python "venvs ($n)" venv "$n virtual environments" root "" ""
  VENV_OLD=("${old[@]}")
  R_FIX[$k]=$CERTIFI_FIX
  if (( ${#old[@]} )); then
    R_STATUS[$k]=VULNERABLE; R_NOTE[$k]="${#old[@]} certifi copies in virtualenvs still trust the compromised eMudhra CAs"
  else
    R_STATUS[$k]=PATCHED; R_NOTE[$k]="no outdated certifi in any virtualenv"
  fi
}

# ---- libraries inside Python environments and Node.js projects ------------
pyenv_of() {  # site-packages dir -> PE_PY (interpreter) / PE_MODE (env | user | system | pkg) / PE_VER (3.X)
  local sp=$1 pre mm c
  PE_PY=""; PE_MODE=env
  mm=$(grep -oE 'python3\.[0-9]+' <<<"$sp" | tail -n1); PE_VER=${mm#python}
  if [[ $sp == /usr/lib/python3/dist-packages || ( $sp == /usr/lib/* && $sp == */site-packages ) ]]; then
    PE_MODE=pkg; PE_PY=/usr/bin/python3                                  # the distro's own Python
  elif [[ $sp == /usr/local/lib/python3*/dist-packages ]]; then
    PE_MODE=system; PE_PY=/usr/bin/$mm                                   # pip as root into the system Python
  elif [[ $sp == */.local/lib/python3*/site-packages ]]; then
    PE_MODE=user; PE_PY=/usr/bin/$mm; [[ -x $PE_PY ]] || PE_PY=/usr/bin/python3
  else                                                                   # venv, conda, pyenv, uv, tarball, app bundle
    pre=${sp%/lib/python3*}
    for c in "$pre/bin/$mm" "$pre/bin/python3" "$pre/bin/python"; do if [[ -x $c ]]; then PE_PY=$c; break; fi; done
    if [[ -f $pre/pyvenv.cfg ]]; then
      c=$(sed -nE 's/^version(_info)? *= *([0-9]+\.[0-9]+).*/\2/p' "$pre/pyvenv.cfg" | head -n1); [[ -n $c ]] && PE_VER=$c
    fi
  fi
  if [[ -z $PE_VER && -n $PE_PY && -x $PE_PY ]]; then PE_VER=$(run_bin "$PE_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])'); fi
  return 0
}

scan_pydist() {  # <site-packages>/<name>-<version>.dist-info -> Pillow / Brotli / LiteLLM row
  local d=$1 sp=${1%/*} base=${1##*/} name prod ver key o pkg="" pkgver=""
  case $sp in */.cache/uv/*|*/.cache/pip/*|*/archive-v[0-9]*/*) return 0 ;; esac   # download caches, not Python environments
  name=${base%%-*}; name=${name,,}
  case $name in pillow) prod=Pillow ;; brotli|brotlicffi) prod=Brotli ;; litellm) prod=LiteLLM ;; *) return 0 ;; esac
  ver=$(sed -n 's/^Version: *//p' "$d/METADATA" 2>/dev/null | head -n1 | tr -d '\r')
  if [[ -z $ver ]]; then ver=${base#*-}; ver=${ver%.dist-info}; fi
  pyenv_of "$sp"
  key="$prod|$sp|$name"
  add_row "$key" "$prod" "$ver" pip "$sp" "$(owner_of "$sp")" "$name" "$d"
  R_LIB[$key]=$name; R_PY[$key]=$PE_PY; R_PYMODE[$key]=$PE_MODE; R_PYVER[$key]=$PE_VER
  if [[ $PE_MODE == pkg ]]; then   # python3-pil & co. come from the distro: updated through its package
    if have dpkg && o=$(dpkg -S "$d" 2>/dev/null | head -n1); then
      pkg=${o%%: *}; pkg=${pkg%%:*}; pkgver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)
    elif have rpm && o=$(rpm -qf --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' "$d" 2>/dev/null | head -n1) && [[ $o == *'|'* ]]; then
      pkg=${o%%|*}; pkgver=${o#*|}
    fi
    if [[ -n $pkg ]]; then R_METHOD[$key]=apt; [[ $o == *'|'* ]] && R_METHOD[$key]=rpm; R_PKGS[$key]=$pkg; is_backport "$pkgver" && R_BACKPORT[$key]=1
    else R_PYMODE[$key]=system; fi                                       # pip-installed into the distro Python
  fi
  return 0
}

scan_npm() {  # <project>/node_modules/.../{next,sharp}/package.json -> one row per project (lowest copy)
  local f=$1 dir=${1%/package.json} name prod ver proj key
  name=${dir##*/}
  case $name in next) prod=Next.js ;; sharp) prod=sharp ;; *) return 0 ;; esac
  ver=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n1)
  [[ $ver =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0                    # canary / pre-releases: not rated
  proj=${f%%/node_modules/*}
  [[ -f $proj/package.json ]] || return 0                                # global / cache copy without a project
  key="$prod|$proj|"
  if [[ -n ${R_PROD[$key]+x} ]]; then
    if ver_lt "$ver" "${R_VER[$key]}"; then R_VER[$key]=$ver; fi
    R_PATHS[$key]+=";$f"; return 0
  fi
  add_row "$key" "$prod" "$ver" npm "$proj" "$(owner_of "$proj")" "$name" "$f"
  R_LIB[$key]=$name
}

is_litellm_ioc() {  # file -> true when it is one of the known malicious litellm 1.107.0 files
  local h
  h=$(sha256sum "$1" 2>/dev/null | cut -d' ' -f1)
  [[ -n $h && " ${LITELLM_IOC_SHA[*]} " == *" $h "* ]] && return 0
  [[ ${1##*/} == cook.pth ]] && grep -qx 'import cook' "$1" 2>/dev/null && return 0
  grep -qE "$LITELLM_IOC_MARK" "$1" 2>/dev/null
}

scan_ioc() {  # <site-packages>/cook.pth of the litellm 1.107.0 malware (it stays after an uninstall)
  local f=$1 sp=${1%/*} key
  is_litellm_ioc "$f" || return 0
  key="LiteLLM malware|$sp|"
  add_row "$key" "LiteLLM malware" "1.107.0 hooks" ioc "$sp" "$(owner_of "$sp")" "" "$f"
}

lib_verdict() {  # libraries, Bun and the malware rows
  local k=$1 v=${R_VER[$1]} p=${R_PROD[$1]} fix="" st="" note="" b
  case $p in
    Pillow)  fix=$PILLOW_FIX; note="CVE-2026-112900 (Ghostscript RCE) and 5 more" ;;
    Brotli)  if [[ ${R_LIB[$k]} == brotlicffi ]]; then fix=$BROTLICFFI_FIX; else fix=$BROTLI_FIX; fi
             note="CVE-2026-111497 (Node2Shell) in the Brotli decoder"
             if ver_lt "$v" 1.0.3; then st=PATCHED; note="older than the affected range (1.0.3+)"; fi ;;
    LiteLLM) if [[ " ${LITELLM_BAD[*]} " == *" $v "* ]]; then
               st=COMPROMISED; fix=1.106.2; note="MALICIOUS RELEASE (credential stealer + backdoor) - rotate every credential used on this machine"
             else fix=$LITELLM_FIX; note="April-2026 CVEs (CVSS 10.0 RCE)"; fi ;;
    Next.js) b=${v%%.*}; fix=${NEXT_FIX[$b]:-}; note="use-cache RCE, image-optimisation RCE, Server Actions DoS (14 Oct 2026)"
             if [[ -z $fix ]]; then
               if (( b > 16 )); then st=PATCHED; fix=-; note="newer line"
               else st=VULNERABLE; fix=${NEXT_FIX[15]}; R_MAJOR[$k]=1
                    note="Next.js $b has no fixed release - the project has to move to Next.js ${NEXT_FIX[15]} / ${NEXT_FIX[16]} (major upgrade)"; fi
             fi ;;
    sharp)   fix=$SHARP_FIX; note="librsvg RCE in image processing (CVE-2026-96889)" ;;
    Bun)     fix=$BUN_FIX; note="CVE-2026-111497 (Node2Shell) in Bun's Brotli decoder" ;;
    "LiteLLM malware") st=COMPROMISED; fix=removed
             note="litellm 1.107.0 startup hooks (cook.pth / sitecustomize.py) - rotate every credential used on this machine"
             if [[ -e /tmp/.pc_once_72129118c59f5636c0bb ]]; then note+="; the stealer has already run here"; fi ;;
  esac
  if [[ -z $st ]]; then if ver_lt "$v" "$fix"; then st=VULNERABLE; else st=PATCHED; note=""; fi; fi
  if [[ -n ${R_BACKPORT[$k]:-} && $st == VULNERABLE ]]; then
    st=REVIEW; note="distro package: fixes are backported - updated through the distro's own packages"
  fi
  R_STATUS[$k]=$st; R_FIX[$k]=$fix; R_NOTE[$k]=$note
}

# ---- CISA Known Exploited Vulnerabilities: recent additions vs. installed packages
scan_kev() {
  have python3 || return 0
  local since json src pkg ver name cve date act key cand newer
  since=$(date -d "-$KEV_DAYS days" +%F 2>/dev/null) || return 0
  json=$(mktemp /var/tmp/vulnpatch-kev.XXXXXX 2>/dev/null || mktemp)
  if ! curl -fsSL --max-time 60 -o "$json" "$KEV_URL" 2>/dev/null; then rm -f "$json"; KEV_STATE="CISA KEV list could not be downloaded"; return 0; fi
  KEV_STATE=""
  while IFS=$'\t' read -r src pkg ver name cve date act; do
    key="KEV: $name|$src:$pkg|"
    if [[ -n ${R_PROD[$key]+x} ]]; then R_KEV[$key]+=", $cve"; continue; fi
    add_row "$key" "KEV: $name" "$ver" "$src" "$src:$pkg" root "$pkg" ""
    R_KEV[$key]="$cve"
    newer=""
    case $src in
      apt)  cand=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}')
            if [[ -n $cand && $cand != "(none)" ]] && dpkg --compare-versions "$cand" gt "$ver" 2>/dev/null; then newer=$cand; fi ;;
      rpm)  cand=$(timeout 60 "$PKGMGR" -q list --upgrades "$pkg" 2>/dev/null | awk -v p="$pkg" '$1 ~ "^"p"\\." {print $2}' | head -n1); newer=$cand ;;
      snap) if snap refresh --list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$pkg"; then newer=newer; fi ;;
    esac
    R_FIX[$key]=${newer:-latest}
    if [[ -n $newer ]]; then R_STATUS[$key]=VULNERABLE; R_NOTE[$key]="CISA KEV (actively exploited, added $date): CVES - update available ($newer)"
    else R_STATUS[$key]=PATCHED; R_NOTE[$key]="CISA KEV (actively exploited, added $date): CVES - newest available version is installed; confirm with the vendor advisory: $act"; fi
  done < <( { if have dpkg-query; then dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print "apt\t" $2 "\t" $3}'; fi
              if [[ $PKGMGR != apt ]] && have rpm; then rpm -qa --qf 'rpm\t%{NAME}\t%{VERSION}-%{RELEASE}\n' 2>/dev/null; fi
              if have snap; then snap list 2>/dev/null | awk 'NR > 1 {print "snap\t" $1 "\t" $2}'; fi; } | python3 -I -c '
import json, re, sys
def n(s): return re.sub(r"[^a-z0-9]", "", s.lower())
kev = json.load(open(sys.argv[1], encoding="utf-8"))["vulnerabilities"]
# already handled by this script, part of the OS (kernel updates), or too generic to match
skip = re.compile(r"chrom|firefox|edge|java|node\.?js|php|python|kernel|windows|multiple products|android|ios|macos", re.I)
inst = [l.rstrip("\n").split("\t") for l in sys.stdin if l.count("\t") == 2]
for v in kev:
    if v["dateAdded"] < sys.argv[2] or skip.search(v["vendorProject"] + " " + v["product"]): continue
    vend, prod = n(v["vendorProject"]), n(v["product"])
    cands = {vend + prod} | ({prod} if len(prod) >= 5 else set())
    for src, pkg, ver in inst:
        whole, base = n(pkg), n(pkg.split("-")[0])
        if whole in cands or base in cands or (len(re.sub(r"\d+$", "", base)) >= 5 and re.sub(r"\d+$", "", base) in cands):
            name = v["product"] if v["product"].lower().startswith(v["vendorProject"].split()[0].lower()) else v["vendorProject"] + " " + v["product"]
            print("\t".join([src, pkg, ver, name, v["cveID"], v["dateAdded"], " ".join(v["requiredAction"].split())[:200]]))
' "$json" "$since" 2>/dev/null)
  rm -f "$json"
  if (( ${#KEYS[@]} )); then
    for key in "${KEYS[@]}"; do   # the CVE list goes into the note once all are collected
      if [[ -n ${R_KEV[$key]:-} ]]; then R_NOTE[$key]=${R_NOTE[$key]/CVES/${R_KEV[$key]}}; fi
    done
  fi
  return 0
}

add_missing() {  # products with no copy at all are listed as NOT FOUND
  local p k found
  for p in "${PRODUCTS[@]}"; do
    found=0
    if (( ${#KEYS[@]} )); then
      for k in "${KEYS[@]}"; do if [[ ${R_PROD[$k]} == "$p" ]]; then found=1; break; fi; done
    fi
    if (( ! found )); then
      k="$p|missing|"
      add_row "$k" "$p" "-" "-" "-" "-" "" ""
      R_STATUS[$k]="NOT FOUND"; R_FIX[$k]="-"; R_NOTE[$k]="not installed on this machine"; R_ACTION[$k]="-"
    fi
  done
}

# ---- rating -----------------------------------------------------------------
verdict() {  # product version backport -> V_STATUS V_FIXED V_NOTE
  local prod=$1 v=$2 backport=$3 br fix
  V_STATUS=""; V_FIXED=""; V_NOTE=""
  case $prod in
    PHP)
      br=$(cut -d. -f1-2 <<<"$v"); fix=${PHP_FIX[$br]:-}
      if [[ -n $fix ]]; then V_FIXED=$fix
      elif ver_lt "$br" 8.2; then V_STATUS=EOL; V_FIXED=${PHP_FIX[8.2]}; V_NOTE="PHP $br is end-of-life - moved to PHP 8.2 (branch change)"
      else V_STATUS=PATCHED; V_NOTE="newer branch"; fi ;;
    Node.js)
      br=${v%%.*}; V_FIXED=$(node_target "$v")
      if [[ -z ${NODE_FIX[$br]:-} ]]; then
        if [[ -n $V_FIXED ]]; then V_STATUS=EOL; V_NOTE="Node.js $br is end-of-life - moved to Node.js ${V_FIXED%%.*} (major version change)"
        else V_STATUS=PATCHED; V_NOTE="newer release line"; fi
      fi ;;
    Python)
      br=$(cut -d. -f1-2 <<<"$v"); fix=${PY_FIX[$br]:-}
      if [[ -n $fix ]]; then V_FIXED=$fix
      elif ver_lt "$br" 3.10; then V_STATUS=EOL; V_NOTE="Python $br is end-of-life"
      else V_STATUS=PATCHED; V_NOTE="no newer CPython $br release exists - only certifi matters"; fi ;;
    Chrome|Chromium) V_FIXED=$CHROME_FIX ;;
    Edge)            V_FIXED=$EDGE_FIX ;;
    Brave)           V_FIXED=$BRAVE_FIX ;;
    Firefox)
      case ${v%%.*} in
        153) V_FIXED=153.5.1;  V_NOTE="ESR" ;;
        115) V_FIXED=115.43.1; V_NOTE="ESR" ;;
        *)   V_FIXED=$FIREFOX_FIX ;;
      esac ;;
  esac
  if [[ -z $V_STATUS ]]; then
    if ver_lt "$v" "$V_FIXED"; then V_STATUS=VULNERABLE; else V_STATUS=PATCHED; fi
  fi
  if (( backport )) && [[ $V_STATUS == VULNERABLE || $V_STATUS == EOL ]]; then
    V_STATUS=REVIEW
    V_NOTE="distro build: the upstream number hides backported fixes - patched through the distro's own packages"
  fi
}

certifi_check() {  # flags Python installs whose bundled certifi still trusts the eMudhra CAs
  local k=$1 low="" e v
  local -a sps=()
  mapfile -t sps < <(site_packages_of "${R_ROOT[$k]}")
  (( ${#sps[@]} )) || return 0
  while IFS= read -r e; do
    v=${e#*|}
    if [[ -z $low ]] || ver_lt "$v" "$low"; then low=$v; fi
  done < <(certifi_old_dirs "${sps[@]}")
  if [[ -n $low ]]; then
    R_NOTE[$k]="${R_NOTE[$k]:+${R_NOTE[$k]}; }bundled certifi $low still trusts the compromised eMudhra CAs"
    if [[ ${R_STATUS[$k]} == PATCHED || ${R_STATUS[$k]} == REVIEW ]]; then R_STATUS[$k]=VULNERABLE; fi
    R_CERTIFI[$k]=1
  fi
}

java_verdict() {  # rated on the eMudhra block list (CVE-2026-91403); the October CPU version is reported with it
  local k=$1 v=${R_VER[$1]} major fix n f note
  major=${v%%.*}; fix=${JAVA_FIX[$major]:-}
  f=$(java_blockfile "${R_ROOT[$k]}"); n=$(java_fp_count "$f")
  R_FIX[$k]=${fix:--}
  if (( n == ${#EMUDHRA_FPS[@]} )); then R_STATUS[$k]=PATCHED; note="eMudhra certificates blocked (CVE-2026-91403)"
  else R_STATUS[$k]=VULNERABLE; note="CVE-2026-91403: $n of ${#EMUDHRA_FPS[@]} eMudhra certificates blocked in ${f##*/}"; fi
  if [[ -z $fix ]]; then note+="; Java $major is end-of-life (no more updates) - plan a move to Java 21 or 25"
  elif ver_lt "$v" "$fix"; then note+="; older than the October 2026 update ($fix)"; fi
  if [[ -n ${R_VENDOR[$k]:-} ]]; then note+="; ${R_VENDOR[$k]}"; fi
  if [[ -n ${R_EMBED[$k]:-} ]]; then note+="; built into package '${R_PKGS[$k]}'"; fi
  R_NOTE[$k]=$note
}

finalize() {
  local k
  (( ${#KEYS[@]} )) || return 0
  for k in "${KEYS[@]}"; do
    [[ ${R_PROD[$k]} == "CA store" || ${R_PROD[$k]} == KEV:* || ${R_METHOD[$k]} == venv ]] && continue     # rated while scanning
    if [[ ${R_PROD[$k]} == Java ]]; then java_verdict "$k"; continue; fi
    case ${R_PROD[$k]} in Pillow|Brotli|LiteLLM|Next.js|sharp|Bun|"LiteLLM malware") lib_verdict "$k"; continue ;; esac
    verdict "${R_PROD[$k]}" "${R_VER[$k]}" "${R_BACKPORT[$k]:-0}"
    R_STATUS[$k]=$V_STATUS; R_FIX[$k]=$V_FIXED; R_NOTE[$k]=$V_NOTE
    if [[ ${R_PROD[$k]} == Python && -n ${R_BACKPORT[$k]:-} ]]; then
      # distro Python (Debian/Ubuntu/RHEL patch pip/certifi to use the OS store): eMudhra = CA store row
      R_STATUS[$k]=PATCHED; R_NOTE[$k]="distro Python - TLS trust comes from the OS store (see CA store row)"
    elif [[ ${R_PROD[$k]} == Python && ( -n ${R_EMBED[$k]:-} || ( ${R_METHOD[$k]} != apt && ${R_METHOD[$k]} != rpm ) ) ]]; then
      certifi_check "$k"
    fi
    if [[ -n ${R_EMBED[$k]:-} ]]; then R_NOTE[$k]="${R_NOTE[$k]:+${R_NOTE[$k]}; }built into package '${R_PKGS[$k]}'"; fi
    if [[ ${R_METHOD[$k]} == download-in-temp ]]; then R_NOTE[$k]="${R_NOTE[$k]:+${R_NOTE[$k]}; }found in a temp folder"; fi
  done
}

scan_roots() {
  local d
  if [[ -n $CUSTOM_PATHS ]]; then
    read -ra ROOTS <<<"$CUSTOM_PATHS"
  elif (( QUICK )); then
    ROOTS=()
    for d in /opt /usr /home /root /srv /var/www /tmp /var/tmp; do [[ -d $d ]] && ROOTS+=("$d"); done
  else
    # every real (disk-backed) filesystem, minus container storage and snap mounts
    mapfile -t ROOTS < <(findmnt -rn -o TARGET,FSTYPE 2>/dev/null \
      | awk '$2 ~ /^(ext[234]|xfs|btrfs|zfs|f2fs|jfs|reiserfs)$/ && $1 !~ /^\/(var\/lib\/(docker|containerd|containers)|var\/snap|snap)\// {print $1}')
    (( ${#ROOTS[@]} )) || ROOTS=(/)
  fi
}

scan_machine() {   # finds every copy on the machine and rates it (fills KEYS / R_*)
  local t a r f k
  declare -gA ACTIVE=()
  for t in php node python3; do
    a=$(command -v "$t" 2>/dev/null) && ACTIVE[$(readlink -f "$a")]=$t
  done
  (( ${#ROOTS[@]} )) || scan_roots
  for r in "${ROOTS[@]}"; do
    while IFS= read -r -d '' f; do
      case $f in
        */pyvenv.cfg)   VENV_ROOTS+=("${f%/pyvenv.cfg}") ;;
        *.dist-info)    scan_pydist "$f" ;;
        */package.json) scan_npm "$f" ;;
        */cook.pth)     scan_ioc "$f" ;;
        *)              scan_file "$f" ;;
      esac
    done < <(
      find "$r" -xdev -regextype posix-extended \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/lib/snapd \
           -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers \
           -o -path /var/lib/flatpak -o -path '*/.local/share/flatpak' -o -path '*/.local/share/containers' \
           -o -path '*/.vulnpatch.*' -o -path '/var/tmp/vulnpatch-*' -o -path "$BACKUP_DIR" \) -prune \
        -o -type d \( -iname 'pillow-*.dist-info' -o -iname 'brotli-*.dist-info' -o -iname 'brotlicffi-*.dist-info' \
           -o -iname 'litellm-*.dist-info' \) -print0 -prune \
        -o -type f \( -perm /111 \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
           -o -name node -o -name nodejs -o -regex '.*/python3(\.[0-9]+t?)?' \
           -o -name chrome -o -name chromium -o -name chromium-browser -o -name msedge -o -name brave -o -name firefox -o -name java \
           -o -name bun \) \
           -o -name pyvenv.cfg -o -name cook.pth -o -path '*/node_modules/next/package.json' -o -path '*/node_modules/sharp/package.json' \) \
        -print0 2>/dev/null)
  done
  scan_snaps
  scan_flatpaks
  scan_trust_store
  scan_venvs
  scan_kev
  finalize
  add_missing
  if (( ${#KEYS[@]} )); then
    for k in "${KEYS[@]}"; do
      if [[ ${R_STATUS[$k]} == PATCHED || ${R_STATUS[$k]} == "NOT FOUND" ]]; then R_ACTION[$k]="-"; else set_kind "$k"; R_ACTION[$k]=${PLAN_DESC[$k]}; fi
    done
  fi
}

# ---- detection report -------------------------------------------------------
report() {  # full table + why + automatic fix (scan mode)
  local k line rank col n_vuln=0 n_eol=0 n_rev=0 n_ok=0 n_miss=0 i=0
  local -a order=() missing=()
  if (( ${#KEYS[@]} == 0 )); then echo "  nothing found"; return 0; fi
  for k in "${KEYS[@]}"; do
    case ${R_STATUS[$k]} in
      VULNERABLE|COMPROMISED) rank=0; n_vuln=$((n_vuln + 1)) ;;
      EOL)         rank=1; n_eol=$((n_eol + 1)) ;;
      REVIEW)      rank=2; n_rev=$((n_rev + 1)) ;;
      "NOT FOUND") rank=4; n_miss=$((n_miss + 1)); missing+=("${R_PROD[$k]}") ;;
      *)           rank=3; n_ok=$((n_ok + 1)) ;;
    esac
    order+=("$rank|${R_PROD[$k]}|$k")
  done
  mapfile -t order < <(printf '%s\n' "${order[@]}" | sort -t'|' -k1,1n -k2,2 -k4,4)

  printf '\n  %-11s %-9s %-16s %-15s %s\n' STATUS PRODUCT VERSION FIXED_IN LOCATION
  printf '  %s\n' "$LINE"
  for line in "${order[@]}"; do
    k=${line#*|}; k=${k#*|}
    case ${R_STATUS[$k]} in VULNERABLE|EOL|COMPROMISED) col=$RED ;; REVIEW) col=$YEL ;; PATCHED) col=$GRN ;; *) col=$DIM ;; esac
    printf '  %s%-11s%s %-9s %-16s %-15s %s\n' "$col" "${R_STATUS[$k]}" "$RST" "$(disp_prod "${R_PROD[$k]}")" \
      "${R_VER[$k]}" "${R_FIX[$k]:--}" "$(short_loc "${R_ROOT[$k]}")"
  done

  if (( n_vuln + n_eol + n_rev )); then
    printf '\n  %sWhy, and what --apply will do%s\n' "$CYN" "$RST"
    for line in "${order[@]}"; do
      k=${line#*|}; k=${k#*|}
      [[ ${R_STATUS[$k]} == PATCHED || ${R_STATUS[$k]} == "NOT FOUND" ]] && continue
      i=$((i + 1))
      printf '  %2d) %s %s  [%s]  %s%s\n' "$i" "${R_PROD[$k]}" "${R_VER[$k]}" "${R_STATUS[$k]}" "${R_ROOT[$k]}" \
        "${R_DEFAULT[$k]:+  <- default '${R_DEFAULT[$k]}' on PATH}"
      [[ -n ${R_NOTE[$k]} ]] && printf '      %swhy:%s %s\n' "$DIM" "$RST" "${R_NOTE[$k]}"
      printf '      %sfix:%s %s\n' "$DIM" "$RST" "${R_ACTION[$k]:--}"
    done
  fi
  printf '\n  Summary: %s%d vulnerable%s, %s%d end-of-life%s, %s%d review%s, %s%d patched%s, %d not installed' \
    "$RED" "$n_vuln" "$RST" "$RED" "$n_eol" "$RST" "$YEL" "$n_rev" "$RST" "$GRN" "$n_ok" "$RST" "$n_miss"
  (( SKIPPED )) && printf '  (%d unidentifiable candidate files ignored)' "$SKIPPED"
  printf '\n'
  (( n_miss )) && printf '  %sNOT FOUND (not installed): %s%s\n' "$DIM" "${missing[*]}" "$RST"
  RESULT_BAD=$((n_vuln + n_eol))
}

not_found_list() {  # names of the products that are not installed
  local k out=()
  if (( ${#KEYS[@]} )); then
    for k in "${KEYS[@]}"; do [[ ${R_STATUS[$k]} == "NOT FOUND" ]] && out+=("${R_PROD[$k]}"); done
  fi
  printf '%s' "${out[*]:-}"
}

write_json() {  # file
  local k sep="" p psep nf
  {
    printf '{"host":"%s","scanned_at":"%s","as_root":%s,"findings":[' \
      "$(json_esc "$(hostname -f 2>/dev/null || hostname)")" "$(date -Is)" "$([[ $EUID -eq 0 ]] && echo true || echo false)"
    if (( ${#KEYS[@]} )); then
      for k in "${KEYS[@]}"; do
        [[ ${R_STATUS[$k]} == "NOT FOUND" ]] && continue
        printf '%s{"product":"%s","version":"%s","fixed_in":"%s","status":"%s","method":"%s","packages":"%s",' "$sep" \
          "$(json_esc "${R_PROD[$k]}")" "$(json_esc "${R_VER[$k]}")" "$(json_esc "${R_FIX[$k]:-}")" "${R_STATUS[$k]}" \
          "$(json_esc "${R_METHOD[$k]}")" "$(json_esc "${R_PKGS[$k]}")"
        printf '"install_root":"%s","owner":"%s","default_on_path":"%s","note":"%s","fix":"%s","binaries":[' \
          "$(json_esc "${R_ROOT[$k]}")" "$(json_esc "${R_OWNER[$k]}")" "$(json_esc "${R_DEFAULT[$k]:-}")" \
          "$(json_esc "${R_NOTE[$k]}")" "$(json_esc "${R_ACTION[$k]:-}")"
        psep=""
        IFS=';' read -ra _bins <<<"${R_PATHS[$k]}"
        for p in "${_bins[@]}"; do printf '%s"%s"' "$psep" "$(json_esc "$p")"; psep=","; done
        printf ']}'
        sep=","
      done
    fi
    printf '],"not_found":['
    psep=""
    for nf in $(not_found_list); do printf '%s"%s"' "$psep" "$nf"; psep=","; done
    printf ']}\n'
  } >"$1"
}

# =============================================================================
# PLAN - every finding gets an automatic action
# =============================================================================
prod_token() { case $1 in Node.js) echo node ;; Next.js) echo next ;; "CA store") echo ca ;; "LiteLLM malware") echo litellm ;; KEV:*) echo kev ;; *) echo "${1,,}" ;; esac; }
disp_prod() { case $1 in KEV:*) echo KEV ;; "LiteLLM malware") echo MALWARE ;; *) echo "$1" ;; esac; }   # fits the 8-wide column
selected()   { [[ -z $ONLY_PRODUCTS || ",$ONLY_PRODUCTS," == *",$(prod_token "$1"),"* ]]; }

# key that survives a patch (the version changes, the product/location/branch does not)
match_key() {
  local k=$1 v=${R_VER[$1]} br=""
  case ${R_PROD[$k]} in
    PHP|Python) br=$(cut -d. -f1-2 <<<"$v") ;;
    Node.js)    br=${v%%.*} ;;
  esac
  [[ ${R_METHOD[$k]} == venv ]] && br=""
  [[ -n ${R_LIB[$k]:-} ]] && br=${R_LIB[$k]}   # libraries: brotli and brotlicffi can share a site-packages
  printf '%s|%s|%s' "${R_PROD[$k]}" "${R_ROOT[$k]}" "$br"
}

declare -A IN_PLAN PLAN_KIND PLAN_DESC PLAN_PKGS PICKED OUTCOME B_MK B_VER B_PROD B_ROOT B_METHOD B_FIX B_DESC B_NOTE NOTE_PKG DEPS_DONE
PLAN_ORDER=(); DISPLAY_ORDER=(); PICK_ORDER=(); EXTERNAL_ORDER=(); PKGS=(); SNAPS=(); FLATPAKS=()

add_unique() {  # array-name value...
  local -n arr=$1; shift
  local v
  for v in "$@"; do [[ -n $v && " ${arr[*]} " != *" $v "* ]] && arr+=("$v"); done
  return 0
}

pkg_list_for() {  # key -> installed packages to upgrade for that copy
  local k=$1 br
  if [[ ${R_PROD[$k]} == PHP && ${R_METHOD[$k]} == apt && -z ${R_EMBED[$k]:-} ]]; then
    # the whole PHP branch moves together (cli, fpm, common, modules, mod_php)
    br=$(cut -d. -f1-2 <<<"${R_VER[$k]}")
    dpkg-query -W -f='${Status} ${Package}\n' "php$br" "php$br-*" "libapache2-mod-php$br" 2>/dev/null \
      | awk '/ installed /{printf "%s ", $NF}'
  elif [[ ${R_PROD[$k]} == PHP && ${R_METHOD[$k]} == rpm ]]; then
    rpm -qa --qf '%{NAME} ' 'php*' 2>/dev/null
  else
    printf '%s' "${R_PKGS[$k]}"
  fi
}

runas_for() {  # key -> the account a rebuild runs as (system locations: root)
  local o=${R_OWNER[$1]}
  if [[ $o == root || $o == uid:* || $o == '?' || $o == '-' ]]; then echo root; else echo "$o"; fi
}

lib_spec() {  # key -> pip requirement of the fixed release
  case ${R_LIB[$1]} in
    pillow) echo "pillow>=$PILLOW_FIX" ;; brotli) echo "brotli>=$BROTLI_FIX" ;;
    brotlicffi) echo "brotlicffi>=$BROTLICFFI_FIX" ;; litellm) echo "$LITELLM_SPEC" ;;
  esac
}
npm_spec() {  # key -> npm package@range of the fixed release (same major line)
  if [[ ${R_LIB[$1]} == sharp ]]; then echo "sharp@^$SHARP_FIX"; else echo "next@^${NEXT_FIX[${R_VER[$1]%%.*}]}"; fi
}

set_kind() {  # picks the automatic action for one finding (PLAN_KIND / PLAN_DESC / PLAN_PKGS)
  local k=$1 p=${R_PROD[$1]} m=${R_METHOD[$1]} st=${R_STATUS[$1]} list pre=""
  PLAN_PKGS[$k]=""
  if [[ -n ${R_EMBED[$k]:-} ]]; then
    PLAN_PKGS[$k]=${R_PKGS[$k]}; pre="upgrade package '${R_PKGS[$k]}', then "
  fi
  if [[ $p == "LiteLLM malware" ]]; then
    PLAN_KIND[$k]=ioc; PLAN_DESC[$k]="quarantine the malicious startup files, stop the backdoor, block its server - then ROTATE credentials"
  elif [[ $m == pip ]]; then
    if [[ $st == COMPROMISED ]]; then
      PLAN_KIND[$k]=litellm; PLAN_DESC[$k]="remove malicious litellm ${R_VER[$k]} and its startup files, install clean litellm - then ROTATE credentials"
    else PLAN_KIND[$k]=pip; PLAN_DESC[$k]="pip install -U '$(lib_spec "$k")' in this Python (as $(runas_for "$k"))"; fi
  elif [[ $m == npm ]]; then
    if [[ -n ${R_MAJOR[$k]:-} ]]; then PLAN_KIND[$k]=external; PLAN_DESC[$k]=${R_NOTE[$k]}
    else PLAN_KIND[$k]=npm; PLAN_DESC[$k]="update to $(npm_spec "$k") in this project (package.json + lock file backed up)"; fi
  elif [[ $p == Bun ]]; then
    PLAN_KIND[$k]=bun; PLAN_DESC[$k]="Bun $BUN_FIX swapped in (SHA-256 checked)"
  elif [[ $p == "CA store" ]]; then
    PLAN_KIND[$k]=ca; PLAN_PKGS[$k]=ca-certificates
    PLAN_DESC[$k]="upgrade ca-certificates; if this release has no fixed package: distrust emSign ECC Root CA - G3"
  elif [[ $m == venv ]]; then
    PLAN_KIND[$k]=venvs; PLAN_DESC[$k]="refresh certifi in ${#VENV_ROOTS[@]} virtualenvs"
  elif [[ $p == Java ]]; then
    PLAN_KIND[$k]=java
    if [[ $m == apt || $m == rpm ]]; then PLAN_PKGS[$k]=${R_PKGS[$k]}; fi
    PLAN_DESC[$k]="${PLAN_PKGS[$k]:+upgrade package(s) ${PLAN_PKGS[$k]}, then }add the eMudhra fingerprints to $(basename "$(java_blockfile "${R_ROOT[$k]}")")"
  elif [[ -z ${R_EMBED[$k]:-} && ( $m == apt || $m == rpm ) ]]; then
    list=$(pkg_list_for "$k"); PLAN_PKGS[$k]=${list% }
    PLAN_KIND[$k]=pkg; PLAN_DESC[$k]="upgrade installed package(s): ${list% }"
    if [[ $p == Firefox ]]; then   # e.g. Ubuntu 20.04 without Pro: the archive has no fixed Firefox
      PLAN_KIND[$k]=firefox-pkg; PLAN_DESC[$k]+="; if the distro has no fixed build: Mozilla's Firefox ${R_FIX[$k]} swapped in"
    fi
  elif [[ $m == snap ]]; then
    PLAN_KIND[$k]=snap; PLAN_PKGS[$k]=${R_PKGS[$k]}; PLAN_DESC[$k]="snap refresh ${R_PKGS[$k]}"
  elif [[ $m == flatpak-system ]]; then
    PLAN_KIND[$k]=flatpak; PLAN_PKGS[$k]=${R_PKGS[$k]}; PLAN_DESC[$k]="flatpak update ${R_PKGS[$k]}"
  elif [[ $m == flatpak-user ]]; then
    PLAN_KIND[$k]=flatpak-user; PLAN_DESC[$k]="as ${R_OWNER[$k]}: flatpak update --user ${R_PKGS[$k]}"
  else
    case $p in
      Node.js)
        if [[ -z ${R_EMBED[$k]:-} && -d ${R_ROOT[$k]}/lib/node_modules/npm ]]; then
          PLAN_KIND[$k]=node; PLAN_DESC[$k]="Node.js ${R_FIX[$k]} swapped into the same folder (old copy archived)"
        else
          PLAN_KIND[$k]=node-bin; PLAN_DESC[$k]="${pre}swap the node binary for ${R_FIX[$k]}"
        fi ;;
      Firefox)
        PLAN_KIND[$k]=firefox; PLAN_DESC[$k]="${pre}Firefox ${R_FIX[$k]} swapped into the same folder (policies kept)" ;;
      Chrome|Chromium)
        PLAN_KIND[$k]=chromium; PLAN_DESC[$k]="${pre}Chrome for Testing $CHROME_FIX swapped into the same folder" ;;
      PHP)
        if (( NO_REBUILD )); then PLAN_KIND[$k]=external; PLAN_DESC[$k]="rebuild skipped (--no-rebuild)"
        else PLAN_KIND[$k]=rebuild; PLAN_DESC[$k]="rebuild PHP ${R_FIX[$k]} with the original ./configure options (as $(runas_for "$k"))"; fi ;;
      Python)
        # uv / rye / pdm Pythons are prebuilt python-build-standalone builds: the same project's build of the fix
        if [[ -n ${R_FIX[$k]} && $st != EOL ]] && ver_lt "${R_VER[$k]}" "${R_FIX[$k]}" && pbs_target "${R_ROOT[$k]}" >/dev/null; then
          PLAN_KIND[$k]=pbs; PLAN_DESC[$k]="python-build-standalone ${R_FIX[$k]} (the build uv installs) swapped into the same folder, site-packages kept"
        # any other Python with no package of its own (inside apps, tarball, pyenv, conda, temp): rebuilt in place
        elif [[ -n ${R_FIX[$k]} && $st != EOL ]] && ver_lt "${R_VER[$k]}" "${R_FIX[$k]}" && (( ! NO_REBUILD )); then
          PLAN_KIND[$k]=rebuild; PLAN_DESC[$k]="${pre}rebuild Python ${R_FIX[$k]} with the original ./configure options (as $(runas_for "$k"))"
        else
          PLAN_KIND[$k]=certifi; PLAN_DESC[$k]="${pre}refresh certifi in place"
        fi ;;
      *)
        PLAN_KIND[$k]=external; PLAN_DESC[$k]="portable $p - no vendor build to swap in" ;;
    esac
  fi
}

build_plan() {
  local k
  (( ${#KEYS[@]} )) || return 0
  for k in "${KEYS[@]}"; do
    [[ ${R_STATUS[$k]} == PATCHED || ${R_STATUS[$k]} == "NOT FOUND" ]] && continue
    selected "${R_PROD[$k]}" || continue
    PLAN_ORDER+=("$k"); IN_PLAN[$k]=1
    set_kind "$k"
  done
}

prod_rank() {
  case $1 in "LiteLLM malware") echo 0 ;; PHP) echo 1 ;; Node.js) echo 2 ;; Bun) echo 3 ;; Python) echo 4 ;; Java) echo 5 ;;
             Chrome) echo 6 ;; Chromium) echo 7 ;; Edge) echo 8 ;; Brave) echo 9 ;; Firefox) echo 10 ;; LiteLLM) echo 11 ;;
             Pillow) echo 12 ;; Brotli) echo 13 ;; Next.js) echo 14 ;; sharp) echo 15 ;; KEV:*) echo 16 ;; *) echo 17 ;; esac
}

# DISPLAY_ORDER = plan grouped by product, then version, then location
# PICK_ORDER    = the copies the script patches (what the numbers refer to)
# EXTERNAL_ORDER = copies that only get updated outside this script
sort_plan() {
  local k line
  DISPLAY_ORDER=(); PICK_ORDER=(); EXTERNAL_ORDER=()
  (( ${#PLAN_ORDER[@]} )) || return 0
  while IFS= read -r line; do
    k=${line#*|}; k=${k#*|}; k=${k#*|}
    DISPLAY_ORDER+=("$k")
    if [[ ${PLAN_KIND[$k]} == external ]]; then EXTERNAL_ORDER+=("$k"); else PICK_ORDER+=("$k"); fi
  done < <(for k in "${PLAN_ORDER[@]}"; do
             printf '%s|%s|%s|%s\n' "$(prod_rank "${R_PROD[$k]}")" "${R_VER[$k]}" "${R_ROOT[$k]}" "$k"
           done | sort -t'|' -k1,1n -k2,2V -k3,3)
}

short_loc() {  # keeps long paths readable: /usr/share/curso...resources/helpers
  local p=$1 max=40
  if (( ${#p} <= max )); then printf '%s' "$p"; else printf '%s...%s' "${p:0:15}" "${p: -$((max - 18))}"; fi
}

action_label() {
  case ${PLAN_KIND[$1]} in
    rebuild)                    echo "rebuild" ;;
    node|node-bin|firefox|chromium|pbs) echo "replace" ;;
    certifi|venvs)              echo "certifi" ;;
    java)                       echo "blocklist" ;;
    ca)                         echo "distrust" ;;
    pip)                        echo "pip update" ;;
    npm)                        echo "npm update" ;;
    litellm|ioc)                echo "clean" ;;
    bun)                        echo "replace" ;;
    external)                   echo "-" ;;
    *)                          echo "update" ;;      # apt / dnf / snap / flatpak package update
  esac
}

est_min() {  # key -> rough minutes for that item (source builds dominate)
  case ${PLAN_KIND[$1]} in
    rebuild)  if [[ ${R_PROD[$1]} == PHP ]]; then echo 5; else echo 4; fi ;;
    chromium|npm) echo 2 ;;
    *)        echo 1 ;;
  esac
}

LINE=$(printf '%.0s-' {1..108})

print_plan() {
  local k i=0 total=0 m nf
  printf '\n  %3s  %-8s %-16s    %-14s %-11s %4s  %s\n' '#' PRODUCT INSTALLED 'FIXED IN' ACTION TIME LOCATION
  printf '  %s\n' "$LINE"
  for k in "${PICK_ORDER[@]}"; do
    i=$((i + 1)); m=$(est_min "$k"); total=$((total + m))
    printf '  %3d  %-8s %-16s -> %-14s %-11s %3sm  %s\n' "$i" "$(disp_prod "${R_PROD[$k]}")" "${R_VER[$k]}" "${R_FIX[$k]:--}" \
      "$(action_label "$k")" "$m" "$(short_loc "${R_ROOT[$k]}")"
  done
  (( i )) || printf '       %s(nothing to patch)%s\n' "$DIM" "$RST"
  printf '  %s\n' "$LINE"
  printf '  %d can be patched - all of them: ~%d min\n' "$i" "$total"
  printf '  %srebuild%s = compile the fixed version into the same folder (PHP/Python built from source)\n' "$DIM" "$RST"
  printf '  %sreplace%s = the fixed release swapped into the same folder (runtimes inside apps: package first)\n' "$DIM" "$RST"
  printf '  %supdate%s  = normal package update (only packages that are already installed)\n' "$DIM" "$RST"
  printf '  %scertifi%s = refresh the certificate bundle inside that Python (removes the compromised eMudhra CAs)\n' "$DIM" "$RST"
  printf '  %sblocklist%s = add the 16 eMudhra certificates to that Java'"'"'s blocked.certs   |   %sdistrust%s = take emSign G3 out of the OS trust store\n' "$DIM" "$RST" "$DIM" "$RST"
  printf '  %spip / npm update%s = the fixed version installed in that Python environment / project (package.json + lock file backed up)\n' "$DIM" "$RST"
  printf '  %sclean%s = malicious files quarantined, backdoor stopped, clean version installed - credentials must be ROTATED\n' "$DIM" "$RST"
  printf '  %sKEV%s = on the CISA list of actively exploited vulnerabilities - updated to the newest version available\n' "$DIM" "$RST"
  printf '  %sOld versions are backed up during the run and deleted once the fix is verified (--keep-backups keeps them)%s\n' "$DIM" "$RST"
  if (( ${#EXTERNAL_ORDER[@]} )); then
    printf '\n  %sUpdated outside this script (%d):%s\n' "$DIM" "${#EXTERNAL_ORDER[@]}" "$RST"
    for k in "${EXTERNAL_ORDER[@]}"; do printf '    %s- %s %s  %s: %s%s\n' "$DIM" "${R_PROD[$k]}" "${R_VER[$k]}" "$(short_loc "${R_ROOT[$k]}")" "${PLAN_DESC[$k]}" "$RST"; done
  fi
  nf=$(not_found_list)
  [[ -n $nf ]] && printf '\n  %sNOT FOUND (not installed, nothing to patch): %s%s\n' "$DIM" "$nf" "$RST"
  return 0
}

report_brief() {  # plan/apply mode: counts + what is already fine (full table: --scan)
  local k n_v=0 n_e=0 n_r=0 n_p=0 n_f=0 nf
  (( ${#KEYS[@]} )) || { echo "  nothing found"; return 0; }
  for k in "${KEYS[@]}"; do
    case ${R_STATUS[$k]} in
      VULNERABLE|COMPROMISED) n_v=$((n_v + 1)) ;; EOL) n_e=$((n_e + 1)) ;; REVIEW) n_r=$((n_r + 1)) ;; "NOT FOUND") ;; *) n_p=$((n_p + 1)) ;;
    esac
  done
  n_f=$((n_v + n_e + n_r + n_p))
  printf '  Found %d copies: %s%d vulnerable%s, %s%d end-of-life%s, %s%d review%s, %s%d already patched%s   (full table: --scan)\n' \
    "$n_f" "$RED" "$n_v" "$RST" "$RED" "$n_e" "$RST" "$YEL" "$n_r" "$RST" "$GRN" "$n_p" "$RST"
  nf=$(not_found_list)
  [[ -n $nf ]] && printf '  %sNOT FOUND (not installed): %s%s\n' "$DIM" "$nf" "$RST"
  return 0
}

parse_pick() {  # all | none | 1,3,5-7 | php,node (mixable) -> marks PICKED[]
  local spec=${1,,} tok a b i n=${#PICK_ORDER[@]} k hit
  local -a toks=()
  spec=${spec// /}
  if [[ -z $spec || $spec == all ]]; then for k in "${PICK_ORDER[@]}"; do PICKED[$k]=1; done; return 0; fi
  [[ $spec == none ]] && return 0
  IFS=',' read -ra toks <<<"$spec"
  for tok in "${toks[@]}"; do
    [[ -n $tok ]] || continue
    if [[ $tok =~ ^[0-9]+$ ]]; then a=$tok; b=$tok
    elif [[ $tok =~ ^([0-9]+)-([0-9]+)$ ]]; then a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
    else
      hit=0
      for k in "${PICK_ORDER[@]}"; do
        if [[ $(prod_token "${R_PROD[$k]}") == "$tok" ]]; then PICKED[$k]=1; hit=1; fi
      done
      (( hit )) || { warn "nothing in the list matches '$tok'"; return 1; }
      continue
    fi
    if (( a < 1 || b > n || a > b )); then warn "'$tok' is not a number between 1 and $n"; return 1; fi
    for (( i = a; i <= b; i++ )); do PICKED[${PICK_ORDER[i-1]}]=1; done
  done
}

choose_items() {  # asks (or takes --pick) which plan items to patch; returns 1 to cancel
  local k i=0 total=0 answer n=0
  if [[ -n $PICK_SPEC ]]; then
    parse_pick "$PICK_SPEC" || return 1
  elif (( ASSUME_YES )); then
    parse_pick all
  else
    while true; do
      printf '\n  Which copies should be patched?\n'
      printf '    all          every numbered item\n'
      printf '    1,3,5-7      only those numbers from the list above\n'
      printf '    php,node     everything of those products (php node bun python java chrome chromium edge brave firefox ca litellm pillow brotli next sharp kev)\n'
      printf '    none         cancel\n'
      read -r -p "  Your choice [all]: " answer <"$TTY_IN"
      PICKED=()
      parse_pick "${answer:-all}" && break
    done
  fi
  for k in "${PICK_ORDER[@]}"; do
    if [[ -n ${PICKED[$k]:-} ]]; then i=$((i + 1)); total=$((total + $(est_min "$k"))); fi
  done
  if (( i == 0 )); then echo "  Nothing selected - nothing changed."; return 1; fi
  printf '\n  Selected %d of %d item(s) from the plan above - estimated ~%d min\n' "$i" "${#PICK_ORDER[@]}" "$total"
  if (( ! ASSUME_YES )); then
    read -r -p "  Type YES to start: " answer <"$TTY_IN"
    [[ ${answer,,} == yes ]] || { echo "  Aborted - nothing changed."; return 1; }
  fi
}

collect_selected() {  # builds the package / snap / flatpak batches from the chosen items only
  local k
  PKGS=(); SNAPS=(); FLATPAKS=()
  for k in "${PICK_ORDER[@]}"; do
    [[ -n ${PICKED[$k]:-} ]] || continue
    case ${PLAN_KIND[$k]} in
      snap)    add_unique SNAPS "${PLAN_PKGS[$k]}" ;;
      flatpak) add_unique FLATPAKS "${PLAN_PKGS[$k]}" ;;
      *)       if [[ -n ${PLAN_PKGS[$k]:-} ]]; then read -ra _p <<<"${PLAN_PKGS[$k]}"; add_unique PKGS "${_p[@]}"; fi ;;
    esac
  done
}

# =============================================================================
# PATCH ACTIONS
# =============================================================================
fetch_verified() {  # url dest sha256
  curl -fL --retry 3 --retry-delay 5 -sS -o "$2" "$1" >>"$LOG" 2>&1 || return 1
  echo "$3  $2" | sha256sum -c --status
}

declare -A ITEM_NO; ITEM_TOTAL=0
item_line() {  # key colour word reason -> the one line an item gets while patching
  local k=$1 r=$4
  if (( ${#r} > 100 )); then r="${r:0:97}..."; fi
  printf '  [%*s/%d] %s%-6s%s %-8s %-16s -> %-14s %s%s\n' "${#ITEM_TOTAL}" "${ITEM_NO[$k]:-?}" "$ITEM_TOTAL" "$2" "$3" "$RST" \
    "$(disp_prod "${R_PROD[$k]}")" "${R_VER[$k]}" "${R_FIX[$k]:--}" "$(short_loc "${R_ROOT[$k]}")" "${r:+  - $r}"
}
ok_item()   { OUTCOME[$1]="done: $2"; printf '[ok] %s %s: %s\n' "${R_PROD[$1]}" "${R_ROOT[$1]}" "$2" >>"$LOG"; item_line "$1" "$GRN" ok ""; }
fail_item() { OUTCOME[$1]="failed: $2"; printf '[failed] %s %s: %s\n' "${R_PROD[$1]}" "${R_ROOT[$1]}" "$2" >>"$LOG"; item_line "$1" "$RED" FAILED "$2"; }

archive_tree() {  # folder or file -> path of a tar.gz backup (old binaries stay restorable but not runnable)
  local d=$1 a
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
  a="$BACKUP_DIR/$(tr '/' '_' <<<"${d#/}")-$STAMP.tar.gz"
  tar -czf "$a" -C "$(dirname "$d")" "$(basename "$d")" 2>>"$LOG" && note_backup "$a" && printf '%s' "$a"
}

note_backup() { printf '%s\t%s\n' "$CUR_KEY" "$1" >> "$BACKUP_INDEX"; }   # a file: survives $(...) subshells

drop_backups() {  # key -> deletes that item's backups once its fix is verified (no old versions are left behind)
  local k=$1 key f
  [[ -f $BACKUP_INDEX ]] || return 0
  while IFS=$'\t' read -r key f; do
    if [[ $key == "$k" && -n $f && -e $f ]]; then rm -rf -- "$f" && BACKUPS_DROPPED=$((BACKUPS_DROPPED + 1)); fi
  done < "$BACKUP_INDEX"
  OUTCOME[$k]=$(sed -E 's/ \((package\.json )?backup: [^)]*\)//g' <<<"${OUTCOME[$k]:-}")
}

# moves a freshly extracted tree into the exact path of the old one, so every symlink,
# service unit and PATH entry that points there keeps working
swap_in() {  # key live-dir new-dir
  local k=$1 live=$2 new=$3 owner home archive
  owner=$(stat -c %U "$live" 2>/dev/null)
  archive=$(archive_tree "$live") || { fail_item "$k" "could not back up $live - nothing changed"; return 1; }
  if ! mv "$live" "$live.vulnpatch-old"; then fail_item "$k" "could not move $live"; return 1; fi
  if ! mv "$new" "$live"; then mv "$live.vulnpatch-old" "$live"; fail_item "$k" "swap failed - old copy restored"; return 1; fi
  rm -rf "$live.vulnpatch-old"
  home=$(getent passwd "$owner" 2>/dev/null | cut -d: -f6)
  if [[ -n $owner && $owner != root && -n $home && $live == "$home"/* ]]; then
    chown -R "$owner": "$live"          # a user's own copy stays theirs
  else
    chown -R root:root "$live"          # system locations belong to root (not to a tarball's uid)
  fi
  ok_item "$k" "replaced in place (backup: $archive)"
}

node_arch() { case $(uname -m) in x86_64) echo x64 ;; aarch64|arm64) echo arm64 ;; *) return 1 ;; esac; }

node_tarball() {  # version dir -> downloads and verifies node-v<version>-linux-<arch>.tar.xz into dir; prints its path
  local t=$1 dir=$2 arch name sha
  arch=$(node_arch) || return 1
  name=node-v$t-linux-$arch.tar.xz
  sha=$(curl -fsSL "https://nodejs.org/dist/v$t/SHASUMS256.txt" 2>>"$LOG" | awk -v f="$name" '$2==f {print $1}')
  [[ -n $sha ]] || return 1
  fetch_verified "https://nodejs.org/dist/v$t/$name" "$dir/$name" "$sha" || return 1
  printf '%s' "$dir/$name"
}

patch_node_manual() {
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} tmp tb
  tmp=$(mktemp -d "$(dirname "$root")/.vulnpatch.XXXXXX") || { fail_item "$k" "no temp dir"; return; }
  if tb=$(node_tarball "$t" "$tmp") && mkdir "$tmp/new" && tar -xJf "$tb" -C "$tmp/new" --strip-components=1 --no-same-owner; then
    swap_in "$k" "$root" "$tmp/new"
  else
    fail_item "$k" "download/verify/extract of Node.js $t failed"
  fi
  rm -rf "$tmp"
}

patch_node_binary() {  # a node binary inside an app (no folder of its own): swapped for the fixed build
  local k=$1 bin=${R_PATHS[$1]%%;*} t=${R_FIX[$1]} tmp tb cur bak arch
  cur=$(run_bin "$bin" --version | first_ver)
  if [[ -n $cur ]] && ! ver_lt "$cur" "$t"; then ok_item "$k" "now $cur after the package update"; return; fi
  arch=$(node_arch) || { fail_item "$k" "unsupported CPU $(uname -m)"; return; }
  tmp=$(mktemp -d /var/tmp/vulnpatch-node.XXXXXX) || { fail_item "$k" "no temp dir"; return; }
  if tb=$(node_tarball "$t" "$tmp") && tar -xJf "$tb" -C "$tmp" --strip-components=2 "node-v$t-linux-$arch/bin/node"; then
    if bak=$(archive_tree "$bin") && cp "$tmp/node" "$bin.vulnpatch-new" && chown --reference="$bin" "$bin.vulnpatch-new" \
       && chmod --reference="$bin" "$bin.vulnpatch-new" && mv -f "$bin.vulnpatch-new" "$bin"; then
      ok_item "$k" "node binary ${cur:-${R_VER[$k]}} -> $t (backup: $bak)"
    else
      rm -f "$bin.vulnpatch-new"; fail_item "$k" "could not replace $bin"
    fi
  else
    fail_item "$k" "download/verify/extract of Node.js $t failed"
  fi
  rm -rf "$tmp"
}

patch_firefox_manual() {
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} rel arch name sha tmp e b
  rel=$t; [[ ${R_NOTE[$k]} == ESR* ]] && rel="${t}esr"
  case $(uname -m) in x86_64) arch=linux-x86_64 ;; aarch64|arm64) arch=linux-aarch64 ;; *) fail_item "$k" "unsupported CPU"; return ;; esac
  name=firefox-$rel.tar.xz
  sha=$(curl -fsSL "https://archive.mozilla.org/pub/firefox/releases/$rel/SHA256SUMS" 2>>"$LOG" | awk -v f="$arch/en-US/$name" '$2==f {print $1}')
  [[ -n $sha ]] || { fail_item "$k" "could not get the SHA-256 for $name"; return; }
  tmp=$(mktemp -d "$(dirname "$root")/.vulnpatch.XXXXXX") || { fail_item "$k" "no temp dir"; return; }
  pkill -f "^$root/firefox" 2>/dev/null || true
  if fetch_verified "https://archive.mozilla.org/pub/firefox/releases/$rel/$arch/en-US/$name" "$tmp/$name" "$sha" \
     && mkdir "$tmp/new" && tar -xJf "$tmp/$name" -C "$tmp/new" --strip-components=1 --no-same-owner; then
    # keep what Mozilla's release does not ship: enterprise policies (distribution/), the distro's
    # launcher (/usr/bin/firefox -> /usr/lib/firefox/firefox.sh on Ubuntu 20.04) and similar files
    for e in "$root"/* "$root"/.[!.]*; do
      [[ -e $e || -L $e ]] || continue
      b=${e##*/}
      case $b in *.so|*.so.*|*.chk) continue ;; esac
      [[ -e $tmp/new/$b || -L $tmp/new/$b ]] || cp -a "$e" "$tmp/new/"
    done
    swap_in "$k" "$root" "$tmp/new"
  else
    fail_item "$k" "download/verify/extract of $name failed"
  fi
  rm -rf "$tmp"
}

# unzips keeping the executable bits (python's zipfile alone drops them)
unzip_keep_modes() {  # zip dest
  python3 -I -c '
import os, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
for i in z.infolist():
    p = z.extract(i, sys.argv[2]); m = (i.external_attr >> 16) & 0o777
    if m and not i.is_dir(): os.chmod(p, m)' "$1" "$2"
}

patch_chromium() {  # Chromium inside an app or a browser cache: Chrome for Testing (Google storage checksum)
  local k=$1 root=${R_ROOT[$1]} bin=${R_PATHS[$1]%%;*} cur meta ver url b64 md5 tmp
  cur=$(run_bin "$bin" --version | first_ver)
  if [[ -n $cur ]] && ! ver_lt "$cur" "$CHROME_FIX"; then ok_item "$k" "now $cur after the package update"; return; fi
  have python3 || { fail_item "$k" "python3 is needed to read Google's release list"; return; }
  meta=$(curl -fsSL https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json 2>>"$LOG" \
         | python3 -I -c 'import json,sys; s=json.load(sys.stdin)["channels"]["Stable"]; print(s["version"], [d["url"] for d in s["downloads"]["chrome"] if d["platform"]=="linux64"][0])' 2>>"$LOG") \
    || { fail_item "$k" "could not read the Chrome for Testing release list"; return; }
  read -r ver url <<<"$meta"
  b64=$(curl -fsSI "$url" 2>>"$LOG" | tr -d '\r' | sed -n 's/^x-goog-hash:.*md5=\([A-Za-z0-9+/=]*\).*/\1/Ip' | head -n1)
  [[ -n $b64 ]] || { fail_item "$k" "Google storage returned no checksum - refusing the download"; return; }
  md5=$(printf '%s' "$b64" | base64 -d | od -An -tx1 | tr -d ' \n')
  tmp=$(mktemp -d "$(dirname "$root")/.vulnpatch.XXXXXX") || { fail_item "$k" "no temp dir"; return; }
  if curl -fL --retry 3 -sS -o "$tmp/c.zip" "$url" >>"$LOG" 2>&1 && [[ $(md5sum "$tmp/c.zip" | cut -d' ' -f1) == "$md5" ]] \
     && unzip_keep_modes "$tmp/c.zip" "$tmp" 2>>"$LOG"; then
    # keep the file name the app launches
    if [[ ${bin##*/} != chrome ]]; then cp -a "$tmp/chrome-linux64/chrome" "$tmp/chrome-linux64/${bin##*/}"; fi
    swap_in "$k" "$root" "$tmp/chrome-linux64" && OUTCOME[$k]="done: Chrome for Testing $ver - ${OUTCOME[$k]#done: }"
  else
    fail_item "$k" "download/checksum/unzip of Chrome for Testing $ver failed"
  fi
  rm -rf "$tmp"
}

get_certifi_pem() {  # cacert.pem + version from the current certifi wheel on PyPI (SHA-256 checked)
  [[ -n ${CERTIFI_PEM:-} && -f ${CERTIFI_PEM:-/nonexistent} ]] && return 0
  have python3 || { warn "python3 is needed to read PyPI's answer"; return 1; }
  local meta ver url sha dir
  meta=$(curl -fsSL https://pypi.org/pypi/certifi/json 2>>"$LOG" \
         | python3 -I -c 'import json,sys; d=json.load(sys.stdin); w=[u for u in d["urls"] if u["packagetype"]=="bdist_wheel"][0]; print(d["info"]["version"], w["url"], w["digests"]["sha256"])' 2>>"$LOG") || return 1
  read -r ver url sha <<<"$meta"
  dir=$(mktemp -d /var/tmp/vulnpatch-certifi.XXXXXX) || return 1
  fetch_verified "$url" "$dir/certifi.whl" "$sha" || return 1
  python3 -I -c 'import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract("certifi/cacert.pem", sys.argv[2])' "$dir/certifi.whl" "$dir" 2>>"$LOG" || return 1
  CERTIFI_PEM=$dir/certifi/cacert.pem; CERTIFI_VER=$ver; CERTIFI_TMP=$dir
}

refresh_certifi_dirs() {  # "dir|version"... -> replaces the CA bundle and version stamp; the code of each copy is untouched
  local e d o n=0
  get_certifi_pem || return 1
  for e in "$@"; do
    d=${e%%|*}
    archive_tree "$d" >/dev/null || return 1
    o=$(stat -c %u:%g "$d/__init__.py")
    cp -f "$CERTIFI_PEM" "$d/cacert.pem" || return 1
    sed -i -E "s/^__version__ = \"[^\"]*\"/__version__ = \"$CERTIFI_VER\"/" "$d/__init__.py" && chown "$o" "$d/__init__.py" || return 1
    n=$((n + 1))
  done
  CERTIFI_MSG="certifi $CERTIFI_VER bundle in $n place(s)"
}

patch_certifi() {  # any Python: its certifi copies get the fixed CA bundle
  local k=$1 cur
  local -a sps=() dirs=()
  if [[ -n ${R_EMBED[$k]:-} ]]; then
    cur=$(run_bin "${R_PATHS[$k]%%;*}" --version | first_ver)
    [[ -n $cur && $cur != "${R_VER[$k]}" ]] && say "    the package update moved it to Python $cur"
  fi
  mapfile -t sps < <(site_packages_of "${R_ROOT[$k]}")
  if (( ${#sps[@]} )); then mapfile -t dirs < <(certifi_old_dirs "${sps[@]}"); fi
  if (( ${#dirs[@]} == 0 )); then ok_item "$k" "certifi already current"; return; fi
  if refresh_certifi_dirs "${dirs[@]}"; then ok_item "$k" "$CERTIFI_MSG"; else fail_item "$k" "certifi refresh failed (no PyPI access?)"; fi
}

patch_venvs() {
  local k=$1
  if refresh_certifi_dirs "${VENV_OLD[@]}"; then ok_item "$k" "$CERTIFI_MSG across ${#VENV_ROOTS[@]} virtualenvs"; else fail_item "$k" "certifi refresh failed (no PyPI access?)"; fi
}

ensure_build_deps() {  # php | python
  [[ -n ${DEPS_DONE[$1]:-} ]] && return 0
  local pk=()
  if [[ $PKGMGR == apt ]]; then
    case $1 in
      php)    pk=(build-essential pkg-config autoconf xz-utils libxml2-dev libsqlite3-dev libssl-dev zlib1g-dev libcurl4-openssl-dev libonig-dev libzip-dev libreadline-dev) ;;
      python) pk=(build-essential pkg-config xz-utils libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncurses-dev uuid-dev) ;;
    esac
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "${pk[@]}" >>"$LOG" 2>&1 \
      || warn "some $1 build dependencies could not be installed (see $LOG)"
  else
    case $1 in
      php)    pk=(gcc gcc-c++ make autoconf pkgconf-pkg-config xz tar libxml2-devel sqlite-devel openssl-devel zlib-devel libcurl-devel) ;;
      python) pk=(gcc make pkgconf-pkg-config xz tar openssl-devel zlib-devel bzip2-devel readline-devel sqlite-devel libffi-devel xz-devel ncurses-devel libuuid-devel) ;;
    esac
    "$PKGMGR" install -y -q "${pk[@]}" >>"$LOG" 2>&1 || warn "some $1 build dependencies could not be installed (see $LOG)"
  fi
  DEPS_DONE[$1]=1
}

php_src_sha() {  # version -> sha256 of php-<v>.tar.xz, as published by php.net
  curl -fsSL "https://www.php.net/releases/index.php?json&version=$1" 2>>"$LOG" | tr '{}' '\n\n' \
    | grep -F "\"php-$1.tar.xz\"" | grep -oE '"sha256": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -n1
}

py_src_sha() {  # version -> sha256 of Python-<v>.tar.xz, as published by python.org
  local id
  id=$(curl -fsSL "https://www.python.org/api/v2/downloads/release/?name=Python%20$1" 2>>"$LOG" \
       | grep -oE '/downloads/release/[0-9]+/' | grep -oE '[0-9]+' | head -n1)
  [[ -n $id ]] || return 0
  curl -fsSL "https://www.python.org/api/v2/downloads/release_file/?release=$id" 2>>"$LOG" | tr '{}' '\n\n' \
    | grep -F "Python-$1.tar.xz\"" | grep -oE '"sha256_sum": *"[0-9a-f]{64}"' | grep -oE '[0-9a-f]{64}' | head -n1
}

# rewrites the original prefix to the live location, so a copied tree is rebuilt where it is
retarget_args() {  # oldprefix newroot args... -> one arg per line
  local old=$1 new=$2 a found=0; shift 2
  for a in "$@"; do
    [[ $a == --prefix=* ]] && found=1
    printf '%s\n' "${a//"$old"/"$new"}"
  done
  (( found )) || printf '%s\n' "--prefix=$new"
}

build_into() {  # key name url sha target-root make-target run-as configure-args...
  local k=$1 name=$2 url=$3 sha=$4 root=$5 target=$6 runas=$7; shift 7
  local tmp archive rc
  local -a as=()
  tmp=$(mktemp -d /var/tmp/vulnpatch-build.XXXXXX) || { fail_item "$k" "no build dir"; return 1; }
  if ! fetch_verified "$url" "$tmp/src.tar.xz" "$sha"; then fail_item "$k" "download/verify of $url failed"; rm -rf "$tmp"; return 1; fi
  mkdir "$tmp/src" && tar -xJf "$tmp/src.tar.xz" -C "$tmp/src" --strip-components=1 --no-same-owner
  archive=$(archive_tree "$root") || { fail_item "$k" "could not back up $root - nothing changed"; rm -rf "$tmp"; return 1; }
  if [[ $runas != root ]]; then chown -R "$runas": "$tmp"; as=(runuser -u "$runas" --); fi   # a user's build stays theirs
  say "    building $name in $root as $runas (log: $LOGDIR/$name-$STAMP.log) ..."
  { "${as[@]}" env -C "$tmp/src" ./configure "$@" && "${as[@]}" make -C "$tmp/src" -j"$(nproc)" \
      && "${as[@]}" make -C "$tmp/src" "$target"; } >"$LOGDIR/$name-$STAMP.log" 2>&1
  rc=$?
  rm -rf "$tmp"
  if (( rc )); then fail_item "$k" "build failed - see $LOGDIR/$name-$STAMP.log (backup: $archive)"; return 1; fi
  ok_item "$k" "rebuilt from source with the original options (backup: $archive)"
}

patch_php_rebuild() {
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} bin="" b sha old=/usr/local a
  local -a raw=() args=()
  for b in "$root/bin/php" "$root/bin/php-cgi" "$root/sbin/php-fpm"; do [[ -x $b ]] && { bin=$b; break; }; done
  [[ -n $bin ]] || { fail_item "$k" "no php binary in $root"; return; }
  mapfile -t raw < <(run_bin "$bin" -n -i | sed -n 's/^Configure Command => *//p' | grep -oE "'[^']*'" | sed "s/^'//; s/'\$//")
  (( ${#raw[@]} > 1 )) || { fail_item "$k" "could not read the original ./configure options"; return; }
  for a in "${raw[@]:1}"; do [[ $a == --prefix=* ]] && old=${a#--prefix=}; done
  mapfile -t args < <(retarget_args "$old" "$root" "${raw[@]:1}")
  sha=$(php_src_sha "$t"); [[ -n $sha ]] || { fail_item "$k" "could not get the php.net SHA-256 for $t"; return; }
  ensure_build_deps php
  build_into "$k" "php-$t" "https://www.php.net/distributions/php-$t.tar.xz" "$sha" "$root" install "$(runas_for "$k")" "${args[@]}"
}

certifi_fix_in() {  # key -> refreshes every outdated certifi in that Python; CFX_MSG says what was done
  local k=$1
  local -a sps=() dirs=()
  CFX_MSG=""
  mapfile -t sps < <(site_packages_of "${R_ROOT[$k]}")
  if (( ${#sps[@]} )); then mapfile -t dirs < <(certifi_old_dirs "${sps[@]}"); fi
  if (( ${#dirs[@]} )) && refresh_certifi_dirs "${dirs[@]}" >>"$LOG" 2>&1; then CFX_MSG=$CERTIFI_MSG; fi
  return 0
}

pbs_target() {  # python-build-standalone folder (uv: cpython-3.13.11-linux-x86_64-gnu) -> its target triple
  local n=${1##*/} arch libc
  [[ $n == cpython-* && $n != *freethreaded* && $n != *debug* ]] || return 1
  [[ -d $1/lib && -x $1/bin/python3 ]] || return 1
  case $n in *x86_64*) arch=x86_64 ;; *aarch64*) arch=aarch64 ;; *) return 1 ;; esac
  case $n in *musl*) libc=musl ;; *) libc=gnu ;; esac
  echo "$arch-unknown-linux-$libc"
}

patch_python_pbs() {  # the same project's prebuilt build of the fixed version, swapped into the same folder
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} target meta url sums name sha tmp mm sp
  target=$(pbs_target "$root") || { fail_item "$k" "not a python-build-standalone folder"; return; }
  have python3 || { fail_item "$k" "python3 is needed to read the release list"; return; }
  if [[ ! -s ${PBS_JSON:-} ]]; then   # one GitHub API call per run, shared by every such Python
    PBS_JSON=$(mktemp /var/tmp/vulnpatch-pbs.XXXXXX)
    curl -fsSL "https://api.github.com/repos/astral-sh/python-build-standalone/releases?per_page=8" -o "$PBS_JSON" 2>>"$LOG"
  fi
  meta=$(python3 -I -c 'import json, sys
want, tail = "cpython-%s+" % sys.argv[2], "-%s-install_only_stripped.tar.gz" % sys.argv[3]
for r in json.load(open(sys.argv[1])):
    a = {x["name"]: x["browser_download_url"] for x in r["assets"]}
    for n, u in a.items():
        if n.startswith(want) and n.endswith(tail) and "SHA256SUMS" in a: print(u, a["SHA256SUMS"], n); sys.exit(0)
sys.exit(1)' "$PBS_JSON" "$t" "$target" 2>>"$LOG") || { fail_item "$k" "no python-build-standalone $t build for $target published yet"; return; }
  read -r url sums name <<<"$meta"
  sha=$(curl -fsSL "$sums" 2>>"$LOG" | awk -v n="$name" '$2 == n {print $1}')
  tmp=$(mktemp -d "$(dirname "$root")/.vulnpatch.XXXXXX") || { fail_item "$k" "no temp dir"; return; }
  if [[ -n $sha ]] && fetch_verified "$url" "$tmp/$name" "$sha" && tar -xzf "$tmp/$name" -C "$tmp" --no-same-owner && [[ -x $tmp/python/bin/python3 ]]; then
    mm=$(cut -d. -f1-2 <<<"$t"); sp=lib/python$mm/site-packages
    if [[ -d $root/$sp ]]; then rm -rf "$tmp/python/$sp" && cp -a "$root/$sp" "$tmp/python/$sp"; fi   # the user's packages stay
    if swap_in "$k" "$root" "$tmp/python"; then
      certifi_fix_in "$k"; if [[ -n $CFX_MSG ]]; then OUTCOME[$k]+="; $CFX_MSG"; fi
      OUTCOME[$k]="done: python-build-standalone $t swapped in, site-packages kept; ${OUTCOME[$k]#done: }"
    fi
  else
    fail_item "$k" "download/verify/unpack of $name failed"
  fi
  rm -rf "$tmp"
}

patch_python_rebuild() {
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} mm py sha old=/usr/local a runas
  local -a raw=() args=() as=() sps=() dirs=()
  mm=$(cut -d. -f1-2 <<<"${R_VER[$k]}"); py=$root/bin/python$mm; runas=$(runas_for "$k")
  [[ -x $py ]] || { fail_item "$k" "no $py - not a standard prefix layout, only its vendor can ship Python $t"; patch_certifi "$k"; OUTCOME[$k]="failed: not a standard prefix layout; ${OUTCOME[$k]}"; return; }
  if [[ -n ${R_EMBED[$k]:-} ]]; then   # the owning package was upgraded first - maybe that already fixed it
    a=$(run_bin "$py" --version | first_ver)
    if [[ -n $a ]] && ! ver_lt "$a" "$t"; then patch_certifi "$k"; OUTCOME[$k]="done: now $a after the package update; ${OUTCOME[$k]#done: }"; return; fi
  fi
  mapfile -d '' -t raw < <(run_bin "$py" -c \
    'import sysconfig,shlex,sys; sys.stdout.write("\0".join(shlex.split(sysconfig.get_config_var("CONFIG_ARGS") or "")))')
  for a in "${raw[@]}"; do [[ $a == --prefix=* ]] && old=${a#--prefix=}; done
  mapfile -t args < <(retarget_args "$old" "$root" "${raw[@]}")
  sha=$(py_src_sha "$t"); [[ -n $sha ]] || { fail_item "$k" "could not get the python.org SHA-256 for $t"; return; }
  ensure_build_deps python
  if ! build_into "$k" "Python-$t" "https://www.python.org/ftp/python/$t/Python-$t.tar.xz" "$sha" "$root" altinstall "$runas" "${args[@]}"; then
    certifi_fix_in "$k"; if [[ -n $CFX_MSG ]]; then OUTCOME[$k]+="; $CFX_MSG (the runtime itself is still the old version)"; fi
    return
  fi
  # the new build ships pip/certifi without the eMudhra CAs, but altinstall keeps an existing older pip
  [[ $runas != root ]] && as=(runuser -u "$runas" --)
  "${as[@]}" "$py" -m ensurepip --upgrade --altinstall >>"$LOG" 2>&1 || warn "ensurepip --upgrade failed for $py"
  mapfile -t sps < <(site_packages_of "$root")
  if (( ${#sps[@]} )); then mapfile -t dirs < <(certifi_old_dirs "${sps[@]}"); fi
  if (( ${#dirs[@]} )) && refresh_certifi_dirs "${dirs[@]}"; then OUTCOME[$k]="${OUTCOME[$k]}; $CERTIFI_MSG"; fi
}

# ---- libraries, Bun and the litellm malware ----------------------------------
run_as() {  # account dir extra-PATH command... -> runs it as that account in dir (clean env, proxies kept); output in RUN_OUT
  local u=$1 dir=$2 pre=$3 home v; shift 3
  local -a envs=() as=()
  home=$(getent passwd "$u" | cut -d: -f6)
  envs=("PATH=${pre:+$pre:}/usr/local/bin:/usr/bin:/bin" "HOME=${home:-/tmp}" "USER=$u" "LANG=C.UTF-8"
        "COREPACK_ENABLE_DOWNLOAD_PROMPT=0" "COREPACK_ENABLE_STRICT=0" "CI=1")
  for v in http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY PIP_INDEX_URL npm_config_registry; do
    if [[ -n ${!v:-} ]]; then envs+=("$v=${!v}"); fi
  done
  if [[ $EUID -eq 0 && $u != root ]]; then as=(runuser -u "$u" --); fi
  RUN_OUT=$(timeout 900 "${as[@]}" env -i "${envs[@]}" env -C "$dir" "$@" 2>&1)
}

pip_cmd() {  # key pip-arguments... -> pip of that Python environment, as its owner
  local k=$1; shift
  local -a extra=()
  if [[ $1 == install && ${R_PYMODE[$k]} == user ]]; then extra+=(--user); fi
  if [[ ( $1 == install || $1 == uninstall ) && ${R_PYMODE[$k]} == system ]] && compgen -G '/usr/lib/python3*/EXTERNALLY-MANAGED' >/dev/null; then
    extra+=(--break-system-packages)
  fi
  run_as "$(runas_for "$k")" / "" "${R_PY[$k]}" -m pip "$@" "${extra[@]}" --no-input --disable-pip-version-check
}

patch_pip() {  # Pillow / Brotli / LiteLLM: the fixed release, inside that exact Python environment
  local k=$1 spec need=""
  spec=$(lib_spec "$k")
  case ${R_LIB[$k]} in pillow) need=3.11 ;; litellm) need=3.10 ;; esac
  if [[ -n $need && -n ${R_PYVER[$k]:-} ]] && ver_lt "${R_PYVER[$k]}" "$need"; then
    fail_item "$k" "${R_PROD[$k]} ${R_FIX[$k]} needs Python $need or newer - this environment runs Python ${R_PYVER[$k]} (move it to a newer Python)"; return
  fi
  if [[ -z ${R_PY[$k]} || ! -x ${R_PY[$k]} ]]; then fail_item "$k" "no Python interpreter found for ${R_ROOT[$k]}"; return; fi
  if ! pip_cmd "$k" --version; then run_as "$(runas_for "$k")" / "" "${R_PY[$k]}" -m ensurepip --upgrade; fi   # e.g. uv venvs ship without pip
  if pip_cmd "$k" install --upgrade "$spec"; then ok_item "$k" "pip install -U '$spec' (was ${R_VER[$k]})"
  else fail_item "$k" "pip failed: $(tail -n 2 <<<"$RUN_OUT" | tr '\n' ' ')"; fi
}

quarantine_ioc() {  # site-packages -> its malicious litellm startup files go into a root-only archive; sets IOC_MSG
  local sp=$1 f q
  local -a found=()
  if [[ -f $sp/cook.pth ]] && is_litellm_ioc "$sp/cook.pth"; then
    found+=("$sp/cook.pth"); [[ -f $sp/cook.py ]] && found+=("$sp/cook.py")
    for f in "$sp"/__pycache__/cook.*.pyc; do [[ -f $f ]] && found+=("$f"); done
  fi
  if [[ -f $sp/sitecustomize.py ]] && is_litellm_ioc "$sp/sitecustomize.py"; then
    found+=("$sp/sitecustomize.py")
    for f in "$sp"/__pycache__/sitecustomize.*.pyc; do [[ -f $f ]] && found+=("$f"); done
  fi
  IOC_MSG="no malicious startup files left in site-packages"
  (( ${#found[@]} )) || return 0
  mkdir -p "$BACKUP_DIR/quarantine" && chmod 700 "$BACKUP_DIR" "$BACKUP_DIR/quarantine"
  q=$BACKUP_DIR/quarantine/litellm-malware-$(tr '/' '_' <<<"${sp#/}")-$STAMP.tar.gz
  if tar -czPf "$q" "${found[@]}" 2>>"$LOG" && chmod 600 "$q" && rm -f "${found[@]}"; then
    IOC_MSG="${#found[@]} malicious startup file(s) quarantined in $q"
  else IOC_MSG="could not quarantine ${found[*]}"; return 1; fi
}

stop_litellm_backdoor() {  # kills whatever holds the backdoor's lock file and blocks its server; sets STOP_MSG
  local p fd pids=""
  for p in /proc/[0-9]*; do
    for fd in "$p"/fd/*; do
      if [[ $(readlink "$fd" 2>/dev/null) == /tmp/remote_code_loader.lock ]]; then kill -9 "${p#/proc/}" 2>/dev/null && pids+=" ${p#/proc/}"; break; fi
    done
  done
  rm -f /tmp/remote_code_loader.lock
  if ! grep -qE '^[^#]*[[:space:]]www\.litellm\.dev([[:space:]]|$)' /etc/hosts 2>/dev/null; then
    cp -a /etc/hosts "$BACKUP_DIR/hosts-$STAMP" 2>/dev/null && note_backup "$BACKUP_DIR/hosts-$STAMP"
    printf '0.0.0.0 www.litellm.dev litellm.dev   # vulnpatch: litellm 1.107.0 malware server\n' >>/etc/hosts
  fi
  STOP_MSG="backdoor stopped${pids:+ (PID$pids)}, www.litellm.dev blocked in /etc/hosts"
}

patch_ioc() {  # startup files left by litellm 1.107.0 (even after the package itself is gone)
  local k=$1
  if quarantine_ioc "${R_ROOT[$k]}"; then
    stop_litellm_backdoor
    ok_item "$k" "$IOC_MSG; $STOP_MSG - ROTATE every credential used on this machine (cloud, SSH, API keys, tokens)"
  else fail_item "$k" "$IOC_MSG"; fi
}

patch_litellm() {  # the malicious release: startup files out, package and cached wheel out, clean release in
  local k=$1 sp=${R_ROOT[$1]} now
  quarantine_ioc "$sp" || { fail_item "$k" "$IOC_MSG"; return; }
  stop_litellm_backdoor
  pip_cmd "$k" uninstall -y litellm
  rm -rf "$sp/litellm" "$sp"/litellm-*.dist-info 2>/dev/null          # whatever the uninstall left behind
  pip_cmd "$k" cache remove litellm
  if pip_cmd "$k" install --upgrade "$LITELLM_SPEC"; then
    now=$(sed -n 's/^Version: *//p' "$sp"/litellm-*.dist-info/METADATA 2>/dev/null | head -n1)
    ok_item "$k" "malicious litellm ${R_VER[$k]} removed, clean ${now:-litellm} installed; $IOC_MSG; $STOP_MSG - ROTATE every credential used on this machine"
  else
    fail_item "$k" "malicious litellm removed, clean reinstall failed: $(tail -n 2 <<<"$RUN_OUT" | tr '\n' ' ') - $IOC_MSG; ROTATE credentials"
  fi
}

find_npm() {  # account -> the npm of the NEWEST Node.js that account can run (a current Node avoids engine errors)
  local u=$1 home c v best="" bv="" k
  local -a cands=(/usr/bin/npm /usr/local/bin/npm)
  home=$(getent passwd "$u" | cut -d: -f6)
  mapfile -t -O "${#cands[@]}" cands < <(ls -d "$home"/.nvm/versions/node/*/bin/npm "$home"/.volta/bin/npm \
                                           "$home"/.local/share/fnm/node-versions/*/installation/bin/npm 2>/dev/null)
  for k in "${KEYS[@]}"; do
    if [[ ${R_PROD[$k]} == Node.js && -z ${R_EMBED[$k]:-} && -x ${R_ROOT[$k]}/bin/npm ]]; then cands+=("${R_ROOT[$k]}/bin/npm"); fi
  done
  for c in "${cands[@]}"; do
    [[ -x $c && -x ${c%/*}/node ]] || continue
    v=$(run_bin "${c%/*}/node" --version | first_ver)
    if [[ -n $v ]] && { [[ -z $bv ]] || ver_lt "$bv" "$v"; }; then best=$c; bv=$v; fi
  done
  [[ -n $best ]] || return 1
  echo "$best"
}

pm_of() {  # project -> PM (npm | pnpm | yarn | bun) and PM_SPEC (name@version from "packageManager", if any)
  local p=$1
  PM_SPEC=$(sed -n 's/.*"packageManager"[[:space:]]*:[[:space:]]*"\([a-z]*@[^"+]*\).*/\1/p' "$p/package.json" 2>/dev/null | head -n1)
  if [[ -n $PM_SPEC ]]; then PM=${PM_SPEC%%@*}
  elif [[ -f $p/bun.lock || -f $p/bun.lockb ]]; then PM=bun
  elif [[ -f $p/pnpm-lock.yaml ]]; then PM=pnpm
  elif [[ -f $p/yarn.lock ]]; then PM=yarn
  else PM=npm; fi
  case $PM in npm|pnpm|yarn|bun) ;; *) PM=npm ;; esac
}

pm_tool() {  # account npm -> PM_CMD: the project's package manager, installed or fetched for this run
  local u=$1 npm=$2 dir=${2%/*} home c k
  home=$(getent passwd "$u" | cut -d: -f6)
  PM_CMD=()
  case $PM in
    npm)  PM_CMD=("$npm") ;;
    bun)  for c in "$home/.bun/bin/bun" /usr/local/bin/bun /usr/bin/bun; do if [[ -x $c ]]; then PM_CMD=("$c"); break; fi; done
          if (( ! ${#PM_CMD[@]} )); then
            for k in "${KEYS[@]}"; do if [[ ${R_PROD[$k]} == Bun && -x ${R_PATHS[$k]%%;*} ]]; then PM_CMD=("${R_PATHS[$k]%%;*}"); break; fi; done
          fi
          if (( ! ${#PM_CMD[@]} )); then PM_CMD=("$dir/npx" --yes bun); fi ;;
    pnpm|yarn)
          if [[ -x $dir/$PM ]]; then PM_CMD=("$dir/$PM")
          elif c=$(command -v "$PM" 2>/dev/null); then PM_CMD=("$c")
          elif [[ -n $PM_SPEC && -x $dir/corepack ]]; then PM_CMD=("$dir/corepack" "$PM")     # the exact version the project asks for
          elif [[ -n $PM_SPEC ]]; then PM_CMD=("$dir/npx" --yes "$PM_SPEC")
          elif [[ $PM == yarn ]] && grep -q '^__metadata:' "$PROJ_DIR/yarn.lock" 2>/dev/null; then
            if [[ -x $dir/corepack ]]; then PM_CMD=("$dir/corepack" yarn); fi                 # Yarn 2+ only comes through corepack
          elif [[ $PM == yarn ]]; then PM_CMD=("$dir/npx" --yes yarn@1)
          else PM_CMD=("$dir/npx" --yes pnpm@latest); fi ;;
  esac
  (( ${#PM_CMD[@]} ))
}

set_override() {  # project section name range -> writes the override into package.json with node (any workspace format)
  local js
  js=$(mktemp /var/tmp/vulnpatch-override.XXXXXX.js)
  cat >"$js" <<'EOF'
const fs = require("fs"), [file, section, name, range] = process.argv.slice(2);
const j = JSON.parse(fs.readFileSync(file, "utf8"));
let o = j; for (const part of section.split(".")) { o[part] = o[part] || {}; o = o[part]; }
o[name] = range;
fs.writeFileSync(file, JSON.stringify(j, null, 2) + "\n");
EOF
  chmod 644 "$js"
  run_as "$1" "$2" "$5" node "$js" "$2/package.json" "$3" "$4" "$6"
  local rc=$?; rm -f "$js"; return $rc
}

dep_field() {  # package.json name -> the section that lists it directly (empty: only a sub-dependency)
  if have python3; then
    python3 -I -c 'import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for f in ("dependencies", "devDependencies", "optionalDependencies"):
    if sys.argv[2] in (d.get(f) or {}): print(f); break' "$1" "$2" 2>/dev/null
  elif grep -qE "\"$2\"[[:space:]]*:" "$1"; then echo dependencies; fi
}

patch_npm() {  # next / sharp: the fixed release inside the project, with the project's own package manager
  local k=$1 proj=${R_ROOT[$1]} name=${R_LIB[$1]} spec range u npm dir bak field now rc
  local -a files=() cmd=()
  spec=$(npm_spec "$k"); range=${spec#*@}; u=$(runas_for "$k")
  npm=$(find_npm "$u") || { fail_item "$k" "no Node.js/npm found for $u - run in the project: npm install $spec"; return; }
  dir=${npm%/*}; PROJ_DIR=$proj
  pm_of "$proj"
  pm_tool "$u" "$npm" || { fail_item "$k" "this project uses $PM ${PM_SPEC:+($PM_SPEC) }and it could not be started - run in the project: $PM add $spec"; return; }
  mapfile -t files < <(cd "$proj" && ls package.json package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock bun.lockb 2>/dev/null)
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
  bak=$BACKUP_DIR/$(tr '/' '_' <<<"${proj#/}")-npm-$STAMP.tar.gz
  tar -czf "$bak" -C "$proj" "${files[@]}" 2>>"$LOG" || { fail_item "$k" "could not back up package.json - nothing changed"; return; }
  note_backup "$bak"
  field=$(dep_field "$proj/package.json" "$name")
  if [[ -n $field ]]; then              # a direct dependency: update it where it is listed
    if [[ $PM == npm ]]; then cmd=("${PM_CMD[@]}" install "$spec" --no-audit --no-fund); else cmd=("${PM_CMD[@]}" add "$spec"); fi
    if [[ $field == devDependencies ]]; then case $PM in yarn) cmd+=(--dev) ;; bun) cmd+=(--dev) ;; *) cmd+=(--save-dev) ;; esac; fi
    run_as "$u" "$proj" "$dir" "${cmd[@]}"; rc=$?
  else                                  # pulled in by another package (sharp via next): pin it with an override
    case $PM in npm|bun) field=overrides ;; yarn) field=resolutions ;; pnpm) field=pnpm.overrides ;; esac
    set_override "$u" "$proj" "$field" "$name" "$dir" "$range"; rc=$?
    if (( rc == 0 )); then
      if [[ $PM == npm ]]; then run_as "$u" "$proj" "$dir" "${PM_CMD[@]}" install --no-audit --no-fund; else run_as "$u" "$proj" "$dir" "${PM_CMD[@]}" install; fi
      rc=$?
    fi
  fi
  now=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$proj/node_modules/$name/package.json" 2>/dev/null | head -n1)
  if (( rc == 0 )) && [[ -n $now ]] && ! ver_lt "$now" "${R_FIX[$k]}"; then
    ok_item "$k" "$PM: $name ${R_VER[$k]} -> $now (package.json backup: $bak)"
  else
    fail_item "$k" "$PM could not update $name (now ${now:-?}): $(grep -v '^[[:space:]]*$' <<<"$RUN_OUT" | tail -n 2 | tr '\n' ' ') - backup: $bak"
  fi
}

patch_bun() {  # Bun's own release for this CPU and libc, SHA-256 checked, swapped for the binary in place
  local k=$1 bin=${R_PATHS[$1]%%;*} a name zip tmp sha bak base="https://github.com/oven-sh/bun/releases/download/bun-v$BUN_FIX"
  case $(uname -m) in x86_64) a=x64 ;; aarch64|arm64) a=aarch64 ;; *) fail_item "$k" "unsupported CPU $(uname -m)"; return ;; esac
  name=bun-linux-$a
  if ldd --version 2>&1 | grep -qi musl; then name+=-musl; fi
  if [[ $a == x64 ]] && ! grep -qw avx2 /proc/cpuinfo; then name+=-baseline; fi   # older CPUs
  zip=$name.zip
  have python3 || { fail_item "$k" "python3 is needed to unpack the Bun release"; return; }
  tmp=$(mktemp -d /var/tmp/vulnpatch-bun.XXXXXX) || { fail_item "$k" "no temp dir"; return; }
  sha=$(curl -fsSL "$base/SHASUMS256.txt" 2>>"$LOG" | awk -v f="$zip" '$2 == f {print $1}')
  if [[ -n $sha ]] && fetch_verified "$base/$zip" "$tmp/$zip" "$sha" && unzip_keep_modes "$tmp/$zip" "$tmp" 2>>"$LOG" && [[ -x $tmp/$name/bun ]]; then
    if bak=$(archive_tree "$bin") && cp "$tmp/$name/bun" "$bin.vulnpatch-new" && chown --reference="$bin" "$bin.vulnpatch-new" \
       && chmod --reference="$bin" "$bin.vulnpatch-new" && mv -f "$bin.vulnpatch-new" "$bin"; then
      ok_item "$k" "bun ${R_VER[$k]} -> $BUN_FIX (backup: $bak)"
    else rm -f "$bin.vulnpatch-new"; fail_item "$k" "could not replace $bin"; fi
  else fail_item "$k" "download/verify of $zip failed"; fi
  rm -rf "$tmp"
}

patch_firefox_pkg() {  # after the package update: if the distro had no fixed build, Mozilla's release goes in its place
  local k=$1 cur
  cur=$(sed -n 's/^Version=//p' "${R_ROOT[$k]}/application.ini" 2>/dev/null | head -n1)
  if [[ -n $cur ]] && ! ver_lt "$cur" "${R_FIX[$k]}"; then ok_item "$k" "firefox package updated to $cur"; return; fi
  say "    the package manager has no Firefox ${R_FIX[$k]} for ${PRETTY_NAME:-this release} (still ${cur:-?}) - Mozilla's build goes in its place"
  patch_firefox_manual "$k"
}

patch_java() {  # adds the missing eMudhra fingerprints to the block list that JVM reads (after any package update)
  local k=$1 root=${R_ROOT[$1]} f n fp bak="" made=0
  local -a missing=()
  f=$(java_blockfile "$root"); n=$(java_fp_count "$f")
  if (( n == ${#EMUDHRA_FPS[@]} )); then ok_item "$k" "eMudhra certificates already blocked (package update)"; return; fi
  for fp in "${EMUDHRA_FPS[@]}"; do grep -qi "^$fp" "$f" 2>/dev/null || missing+=("$fp"); done
  if [[ -e $f ]]; then
    bak=$(archive_tree "$(readlink -f "$f")") || { fail_item "$k" "could not back up $f - nothing changed"; return; }
  else
    { mkdir -p "${f%/*}" && printf 'Algorithm=SHA-256\n' >"$f"; } || { fail_item "$k" "cannot create $f"; return; }
    chown --reference="${f%/*}" "$f" 2>/dev/null; made=1
  fi
  if [[ -s $f && -n $(tail -c1 "$f") ]]; then printf '\n' >>"$f"; fi   # the list must not run into the last line
  printf '%s\n' "${missing[@]}" >>"$f" || { fail_item "$k" "cannot write $f"; return; }
  # no block list at all: write it under both names (JDK 8-15 read blacklisted.certs, newer ones blocked.certs)
  if (( made )) && [[ ! -e ${f%/*}/blacklisted.certs ]]; then cp -p "$f" "${f%/*}/blacklisted.certs"; fi
  n=$(java_fp_count "$f")
  if (( n == ${#EMUDHRA_FPS[@]} )); then ok_item "$k" "${#missing[@]} eMudhra certificates added to $f${bak:+ (backup: $bak)} - running Java apps need a restart"
  else fail_item "$k" "block list still incomplete ($n/${#EMUDHRA_FPS[@]}) in $f"; fi
}

ca_g3_trusted() {  # bundle -> true while emSign ECC Root CA - G3 is in it
  openssl crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -qiE 'CN ?= ?emSign ECC Root CA - G3'
}

patch_ca() {  # after the ca-certificates update: if this release has no fixed package, the root is distrusted directly
  local k=$1 bundle=${R_ROOT[$1]} conf=/etc/ca-certificates.conf name="" tmp c dir
  if ! ca_g3_trusted "$bundle"; then ok_item "$k" "emSign ECC Root CA - G3 removed by the ca-certificates update"; return; fi
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
  if [[ -f $conf ]] && have update-ca-certificates; then         # Debian / Ubuntu: deselect it in ca-certificates.conf
    name=$(cd /usr/share/ca-certificates 2>/dev/null && ls mozilla/*emSign_ECC_Root_CA_-_G3* 2>/dev/null | head -n1)
    if [[ -z $name ]]; then fail_item "$k" "emSign ECC Root CA - G3 is trusted but not from /usr/share/ca-certificates (look in /usr/local/share/ca-certificates)"; return; fi
    cp -a "$conf" "$BACKUP_DIR/ca-certificates.conf-$STAMP" && note_backup "$BACKUP_DIR/ca-certificates.conf-$STAMP"
    if grep -qxF "$name" "$conf"; then sed -i "s|^$name\$|!$name|" "$conf"
    elif ! grep -qxF "!$name" "$conf"; then printf '!%s\n' "$name" >>"$conf"; fi
    update-ca-certificates --fresh >>"$LOG" 2>&1 || warn "update-ca-certificates reported errors (see $LOG)"
  elif have update-ca-trust; then                                 # RHEL / Fedora: copy it into the block list
    dir=/etc/pki/ca-trust/source/blocklist; [[ -d $dir ]] || dir=/etc/pki/ca-trust/source/blacklist
    mkdir -p "$dir"; tmp=$(mktemp -d /var/tmp/vulnpatch-ca.XXXXXX)
    awk -v d="$tmp" '/BEGIN CERTIFICATE/{n++} n{print > (d "/c" n ".pem")}' "$bundle"
    for c in "$tmp"/c*.pem; do
      if openssl x509 -noout -subject -in "$c" 2>/dev/null | grep -qiE 'CN ?= ?emSign ECC Root CA - G3'; then cp "$c" "$dir/emSign_ECC_Root_CA_-_G3.pem"; fi
    done
    rm -rf "$tmp"
    update-ca-trust extract >>"$LOG" 2>&1 || warn "update-ca-trust reported errors (see $LOG)"
  else
    fail_item "$k" "neither update-ca-certificates nor update-ca-trust exists here"; return
  fi
  if ca_g3_trusted "$bundle"; then fail_item "$k" "emSign ECC Root CA - G3 is still in $bundle after distrusting it"
  else ok_item "$k" "no fixed ca-certificates for ${PRETTY_NAME:-this release} - emSign ECC Root CA - G3 distrusted (backup: $BACKUP_DIR)"; fi
}

run_packages() {
  (( ${#PKGS[@]} )) || return 0
  local p cand todo=() holds=()
  printf '  [pkg] %s: updating %d installed package(s): %s\n' "$PKGMGR" "${#PKGS[@]}" "${PKGS[*]}"
  if [[ $PKGMGR == apt ]]; then
    apt-get update -qq >>"$LOG" 2>&1 || warn "apt-get update reported errors (see $LOG) - continuing"
    mapfile -t holds < <(apt-mark showhold 2>/dev/null)
    for p in "${PKGS[@]}"; do
      if printf '%s\n' "${holds[@]}" | grep -qx "$p"; then NOTE_PKG[$p]="held with apt-mark hold - not changed"; continue; fi
      cand=$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/ {print $2}')
      if [[ -z $cand || $cand == "(none)" ]]; then
        NOTE_PKG[$p]="blocked: apt pinning (Pin-Priority -1) or no repository offers it"; continue
      fi
      todo+=("$p")
    done
    if (( ${#todo[@]} )); then
      DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold "${todo[@]}" >>"$LOG" 2>&1 \
        || warn "apt-get install --only-upgrade reported an error (see $LOG)"
    fi
  else
    "$PKGMGR" upgrade -y "${PKGS[@]}" >>"$LOG" 2>&1 || warn "$PKGMGR upgrade reported an error (see $LOG)"
  fi
  for p in "${!NOTE_PKG[@]}"; do printf '  [pkg] %s: %s\n' "$p" "${NOTE_PKG[$p]}"; done
}

execute_plan() {
  local k n=0
  collect_selected
  ITEM_TOTAL=0
  for k in "${PICK_ORDER[@]}"; do   # items handled one by one get a number; package updates run as one batch
    [[ -n ${PICKED[$k]:-} ]] || continue
    case ${PLAN_KIND[$k]} in pkg|snap|flatpak) ;; *) ITEM_TOTAL=$((ITEM_TOTAL + 1)); ITEM_NO[$k]=$ITEM_TOTAL ;; esac
  done
  printf '\n'
  run_packages
  if (( ${#SNAPS[@]} )); then printf '  [pkg] snap refresh %s\n' "${SNAPS[*]}"; snap refresh "${SNAPS[@]}" >>"$LOG" 2>&1 || warn "snap refresh failed (see $LOG)"; fi
  if (( ${#FLATPAKS[@]} )); then printf '  [pkg] flatpak update %s\n' "${FLATPAKS[*]}"; flatpak update -y --noninteractive "${FLATPAKS[@]}" >>"$LOG" 2>&1 || warn "flatpak update failed"; fi
  for k in "${PICK_ORDER[@]}"; do
    [[ -n ${PICKED[$k]:-} ]] || continue
    CUR_KEY=$k                          # backups made from here on belong to this item
    case ${PLAN_KIND[$k]} in
      flatpak-user) runuser -u "${R_OWNER[$k]}" -- flatpak update --user -y --noninteractive "${R_PKGS[$k]}" >>"$LOG" 2>&1 \
                      && ok_item "$k" "flatpak updated" || fail_item "$k" "flatpak update failed" ;;
      node)     patch_node_manual "$k" ;;
      node-bin) patch_node_binary "$k" ;;
      firefox)  patch_firefox_manual "$k" ;;
      chromium) patch_chromium "$k" ;;
      rebuild)  if [[ ${R_PROD[$k]} == PHP ]]; then patch_php_rebuild "$k"; else patch_python_rebuild "$k"; fi ;;
      pbs)      patch_python_pbs "$k" ;;
      certifi)  patch_certifi "$k" ;;
      venvs)    patch_venvs "$k" ;;
      java)     patch_java "$k" ;;
      ioc)      patch_ioc "$k" ;;
      litellm)  patch_litellm "$k" ;;
      pip)      patch_pip "$k" ;;
      npm)      patch_npm "$k" ;;
      bun)      patch_bun "$k" ;;
      ca)       patch_ca "$k" ;;
      firefox-pkg) patch_firefox_pkg "$k" ;;
    esac
  done
  [[ -n ${CERTIFI_TMP:-} ]] && rm -rf "$CERTIFI_TMP"
  return 0
}

why_not_patched() {  # key -> the reason a picked copy is still vulnerable (for the screen and the report)
  local k=$1 why=${OUTCOME[$1]:-} p
  for p in ${PLAN_PKGS[$k]:-}; do if [[ -n ${NOTE_PKG[$p]:-} ]]; then why+="${why:+; }$p: ${NOTE_PKG[$p]}"; fi; done
  if [[ -z $why && -n ${PLAN_PKGS[$k]:-} ]]; then
    why="the package manager offers no fixed version of ${PLAN_PKGS[$k]}"
    if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 20.04 ]]; then why+=" (Ubuntu 20.04 standard support has ended - fixes ship through Ubuntu Pro/ESM)"; fi
  fi
  printf '%s' "${why:-the fix ran but the copy still reports a vulnerable version}"
}

# ---- Excel-ready CSV report -------------------------------------------------
REPORT_ROWS=()

host_info() {  # name, IP and MAC of the interface that carries the default route
  local dev
  dev=$(ip route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
  if [[ -z $dev ]]; then dev=$(ls /sys/class/net 2>/dev/null | grep -vx lo | head -n1); fi
  HOST_NAME=$(hostname -f 2>/dev/null || hostname)
  HOST_MAC=$(cat "/sys/class/net/$dev/address" 2>/dev/null)
  HOST_IP=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)
  RUN_AT=$(date '+%Y-%m-%d %H:%M:%S')
}

csv() {  # fields -> one CSV line: every field quoted, quotes doubled
  local f out="" sep=""
  for f in "$@"; do f=${f//\"/\"\"}; out+="$sep\"$f\""; sep=,; done
  printf '%s' "$out"
}

add_report_row() {  # product before fixed after result action error location method note
  REPORT_ROWS+=("$(csv "$HOST_NAME" "${HOST_IP:-}" "${HOST_MAC:-}" "${PRETTY_NAME:-Linux}" \
    "vulnpatch-linux.sh $SCRIPT_VERSION${ARGS_TXT:+ $ARGS_TXT}" "$RUN_AT" "$MODE" "$@")")
}

add_current_rows() {  # [skip-plan] -> one row per copy as found now (scan / plan mode, or the copies outside the plan)
  local k res act after
  (( ${#KEYS[@]} )) || return 0
  for k in "${KEYS[@]}"; do
    if [[ ${1:-} == skip-plan && -n ${IN_PLAN[$k]:-} ]]; then continue; fi
    res=${R_STATUS[$k]}; act=${R_ACTION[$k]:--}; after=""
    if [[ ${1:-} == skip-plan ]]; then
      after=${R_VER[$k]}
      case $res in PATCHED) res="ALREADY PATCHED" ;; "NOT FOUND") after="-" ;; *) res="NOT SELECTED (--only)" ;; esac
    fi
    add_report_row "${R_PROD[$k]}" "${R_VER[$k]}" "${R_FIX[$k]:--}" "$after" "$res" "$act" "" "${R_ROOT[$k]}" "${R_METHOD[$k]}" "${R_NOTE[$k]}"
  done
}

report_owner() { if [[ -n ${SUDO_USER:-} ]]; then echo "$SUDO_USER"; else id -un; fi; }   # who ran it, also under sudo

report_dir() {  # that person's Desktop (else Downloads, else home); --report overrides
  local u home d x
  if [[ -n $REPORT_PATH && $REPORT_PATH != *.csv ]]; then echo "$REPORT_PATH"; return 0; fi
  u=$(report_owner); home=$(getent passwd "$u" | cut -d: -f6); home=${home:-${HOME:-/root}}
  if have xdg-user-dir; then   # the real (possibly translated) folder names, e.g. ~/Schreibtisch
    for x in DESKTOP DOWNLOAD; do
      if [[ $EUID -eq 0 && $u != root ]]; then d=$(runuser -u "$u" -- env HOME="$home" xdg-user-dir "$x" 2>/dev/null)
      else d=$(HOME=$home xdg-user-dir "$x" 2>/dev/null); fi
      if [[ -n $d && $d != "$home" && -d $d ]]; then echo "$d"; return 0; fi
    done
  fi
  for d in "$home/Desktop" "$home/Downloads" "$home"; do if [[ -d $d ]]; then echo "$d"; return 0; fi; done
  echo "$LOGDIR/reports"
}

# Containers and virtual machines are separate systems: their disks are images this scan cannot look
# into. They are listed so none is missed - run the script inside each of them.
INNER=()
scan_inner_systems() {
  local c home re='^"(.+)" \{' u
  u=$(report_owner); home=$(getent passwd "$u" | cut -d: -f6)
  INNER=()
  if have docker; then
    while IFS= read -r c; do if [[ -n $c ]]; then INNER+=("Docker container|$c|rebuild its image with patched packages (changes inside a container are lost)"); fi
    done < <(timeout 20 docker ps -a --format '{{.Names}} ({{.Image}}, {{.Status}})' 2>/dev/null)
  fi
  if have podman; then
    while IFS= read -r c; do if [[ -n $c ]]; then INNER+=("Podman container|$c|rebuild its image with patched packages (changes inside a container are lost)"); fi
    done < <(timeout 20 podman ps -a --format '{{.Names}} ({{.Image}}, {{.Status}})' 2>/dev/null)
  fi
  if have lxc && [[ -S /var/snap/lxd/common/lxd/unix.socket || -S /var/lib/lxd/unix.socket ]]; then
    while IFS= read -r c; do if [[ -n $c ]]; then INNER+=("LXD container/VM|$c|run this script inside it (lxc exec $c -- bash)"); fi
    done < <(timeout 20 lxc list -c n --format csv 2>/dev/null)
  fi
  if have virsh; then
    while IFS= read -r c; do if [[ -n $c ]]; then INNER+=("KVM/libvirt VM|$c|run this script inside the VM"); fi
    done < <(timeout 20 virsh -c qemu:///system list --all --name 2>/dev/null)
  fi
  if have VBoxManage; then   # VirtualBox VMs belong to a user
    while IFS= read -r c; do if [[ $c =~ $re ]]; then INNER+=("VirtualBox VM|${BASH_REMATCH[1]}|run this script inside the VM"); fi
    done < <(if [[ $EUID -eq 0 && $u != root ]]; then timeout 20 runuser -u "$u" -- VBoxManage list vms; else timeout 20 VBoxManage list vms; fi 2>/dev/null)
  fi
  if [[ -n $home && -f $home/.vmware/inventory.vmls ]]; then
    while IFS= read -r c; do if [[ -n $c ]]; then INNER+=("VMware VM|$c|run this script inside the VM"); fi
    done < <(sed -n 's/^vmlist[0-9]*\.config = "\(.*\.vmx\)"$/\1/p' "$home/.vmware/inventory.vmls")
  fi
}

show_inner() {
  (( ${#INNER[@]} )) || return 0
  local e ik iname ihow
  printf '\n  %sNOT SCANNED - separate systems inside this machine (%d):%s\n' "$YEL" "${#INNER[@]}" "$RST"
  for e in "${INNER[@]}"; do IFS='|' read -r ik iname ihow <<<"$e"; printf '    %s- %s: %s  ->  %s%s\n' "$YEL" "$ik" "$iname" "$ihow" "$RST"; done
}

write_report() {  # one report per machine (Desktop): a re-run updates it; rows of other hosts in a shared file are kept
  local f u state=created tmp e ik iname ihow
  if [[ $REPORT_PATH == *.csv ]]; then f=$REPORT_PATH; else f=$(report_dir)/vulnpatch-report-$(hostname -s).csv; fi
  mkdir -p "$(dirname "$f")" 2>/dev/null || { warn "cannot create $(dirname "$f") - report not written"; return 0; }
  if (( ${#INNER[@]} )); then
    for e in "${INNER[@]}"; do
      IFS='|' read -r ik iname ihow <<<"$e"
      add_report_row "$ik" - - - "NOT SCANNED" "$ihow" "separate system - its disk cannot be scanned from this machine" "$iname" - ""
    done
  fi
  [[ -f $f ]] && state=updated
  tmp=$f.vulnpatch-tmp
  if { printf '\xEF\xBB\xBF'
       printf '%s\r\n' "$(csv Host "IP address" "MAC address" OS Script "Run at" Mode Product "Version before" "Fixed in" \
         "Version after" Result Action "Error / reason" Location "Install method" Note)"
       if [[ -f $f ]]; then tail -n +2 "$f" | awk -v h="\"$HOST_NAME\"," 'index($0, h) != 1 && NF'; fi
       if (( ${#REPORT_ROWS[@]} )); then printf '%s\r\n' "${REPORT_ROWS[@]}"; fi
     } >"$tmp" 2>/dev/null && mv -f "$tmp" "$f"; then
    u=$(report_owner)
    if [[ $EUID -eq 0 && $u != root ]]; then chown "$u": "$f" 2>/dev/null; fi
    printf '\n  %sExcel report %s: %s%s\n' "$CYN" "$state" "$f" "$RST"
  else
    rm -f "$tmp"; warn "cannot write $f - report not written"
  fi
}

verify() {  # compares the re-scan with the copies found before patching (same numbers as the plan)
  local k mk after_ver after_st n_ok=0 n_bad=0 n_skip=0 n_rev=0 col res why i=0 nf
  local -a details=()
  declare -A A_STATUS=() A_VER=() A_NOTE=()
  if (( ${#KEYS[@]} )); then
    for k in "${KEYS[@]}"; do
      [[ ${R_STATUS[$k]} == "NOT FOUND" ]] && continue
      mk=$(match_key "$k"); A_STATUS[$mk]=${R_STATUS[$k]}; A_VER[$mk]=${R_VER[$k]}; A_NOTE[$mk]=${R_NOTE[$k]}
    done
  fi
  printf '\n  %3s  %-16s %-8s %-16s    %-16s %s\n' '#' RESULT PRODUCT BEFORE AFTER LOCATION
  printf '  %s\n' "$LINE"
  for k in "${PICK_ORDER[@]}"; do
    i=$((i + 1))
    mk=${B_MK[$k]}
    after_st=${A_STATUS[$mk]:-GONE}; after_ver=${A_VER[$mk]:--}
    if [[ $after_st == PATCHED || $after_st == GONE ]]; then
      res=PATCHED; col=$GRN; n_ok=$((n_ok + 1)); [[ $after_st == GONE ]] && res=REMOVED
    elif [[ -z ${PICKED[$k]:-} ]]; then
      res="NOT SELECTED"; col=$YEL; n_skip=$((n_skip + 1))
    elif [[ $after_st == REVIEW ]]; then
      res="REVIEW"; col=$YEL; n_rev=$((n_rev + 1)); why="${OUTCOME[$k]:-} | ${A_NOTE[$mk]:-}"
      details+=("$i  ${B_PROD[$k]} ${B_VER[$k]} (${B_ROOT[$k]}): $why")
    else
      res="STILL VULNERABLE"; col=$RED; n_bad=$((n_bad + 1)); why=$(why_not_patched "$k")
      details+=("$i  ${B_PROD[$k]} ${B_VER[$k]} (${B_ROOT[$k]}): $why${A_NOTE[$mk]:+ | now: ${A_NOTE[$mk]}}")
      why+="${A_NOTE[$mk]:+ | now: ${A_NOTE[$mk]}}"
    fi
    printf '  %3s  %s%-16s%s %-8s %-16s -> %-16s %s\n' "$i" "$col" "$res" "$RST" "$(disp_prod "${B_PROD[$k]}")" \
      "${B_VER[$k]}" "$after_ver" "$(short_loc "${B_ROOT[$k]}")"
    case $res in PATCHED|REMOVED) why=""; (( KEEP_BACKUPS )) || drop_backups "$k" ;; "NOT SELECTED") why="not selected in this run" ;; esac
    add_report_row "${B_PROD[$k]}" "${B_VER[$k]}" "${B_FIX[$k]}" "$after_ver" "$res" "${B_DESC[$k]}" "$why" \
      "${B_ROOT[$k]}" "${B_METHOD[$k]}" "${OUTCOME[$k]:-}"
  done
  for k in "${EXTERNAL_ORDER[@]}"; do
    add_report_row "${B_PROD[$k]}" "${B_VER[$k]}" "${B_FIX[$k]}" "${A_VER[${B_MK[$k]}]:-${B_VER[$k]}}" "NOT PATCHED" "-" \
      "${B_DESC[$k]}" "${B_ROOT[$k]}" "${B_METHOD[$k]}" "${B_NOTE[$k]}"
  done
  printf '  %s\n' "$LINE"
  printf '  Result: %s%d patched%s, %s%d still vulnerable%s, %s%d not selected%s, %d review (distro packages)\n' \
    "$GRN" "$n_ok" "$RST" "$RED" "$n_bad" "$RST" "$YEL" "$n_skip" "$RST" "$n_rev"
  if (( ${#details[@]} )); then
    printf '\n  Why these are not fully patched:\n'
    printf '    %s\n' "${details[@]}"
  fi
  nf=$(not_found_list)
  [[ -n $nf ]] && printf '  %sNOT FOUND (not installed): %s%s\n' "$DIM" "$nf" "$RST"
  local kept=0 f
  if [[ -f $BACKUP_INDEX ]]; then while IFS=$'\t' read -r _ f; do [[ -e $f ]] && kept=$((kept + 1)); done < "$BACKUP_INDEX"; fi
  if (( KEEP_BACKUPS )); then printf '  Backups kept (--keep-backups): %d in %s\n' "$kept" "$BACKUP_DIR"
  else
    printf '  Backups: %d deleted (fix verified - no old versions left)' "$BACKUPS_DROPPED"
    if (( kept )); then printf ', %d kept in %s for items that are not confirmed (to restore them)' "$kept" "$BACKUP_DIR"; fi
    printf '\n'
  fi
  STILL_BAD=$((n_bad + n_skip))
}

restart_check() {   # processes still running the old (replaced/deleted) binaries
  local p exe hits=()
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    [[ $exe == *" (deleted)" ]] || continue
    case ${exe##*/} in php*|node*|python3*|java|bun|chrome*|msedge*|brave*|firefox*) hits+=("${exe% (deleted)}") ;; esac
  done
  if (( ${#hits[@]} )); then   # one line per program, not one per process
    printf '\n  %sRestart needed - still running the old code:%s ' "$YEL" "$RST"
    printf '%s\n' "${hits[@]}" | sort | uniq -c | awk '{n = $1; $1 = ""; sub(/^ /, ""); printf "%s%s (%d)", sep, $0, n; sep = ", "} END {print ""}'
  fi
}

# =============================================================================
# MAIN - wrapped in { } so bash reads the whole block before running it: replacing this
# file while a patch run is in progress can then never change what that run does next.
# =============================================================================
{
START=$(date +%s)
. /etc/os-release 2>/dev/null || true
case $MODE in scan) MODE_TXT="DETECTION ONLY" ;; plan) MODE_TXT="DETECTION + PLAN (nothing will be changed)" ;; *) MODE_TXT="DETECT + PATCH + VERIFY" ;; esac
printf '\n%s== vulnpatch: %s | %s | %s | %s ==%s\n' "$CYN" "$(hostname)" "${PRETTY_NAME:-Linux}" "$(date '+%F %T')" "$MODE_TXT" "$RST"
scan_roots
printf '  scanning: %s%s\n' "${ROOTS[*]}" "$( (( NO_EXEC )) && echo '  (no-exec mode)')"
[[ $EUID -eq 0 ]] || warn "not root: other users' home directories cannot be read - run with sudo for full coverage"

step "Detection: every copy on the machine"
scan_machine
host_info
scan_inner_systems
RESULT_BAD=0
if [[ $MODE == scan ]]; then
  report
  show_inner
  JSON_OUT=${JSON_OUT:-/tmp/vulnscan-$(hostname -s)-$STAMP.json}
  write_json "$JSON_OUT"
  printf '  JSON report: %s   (%ss)\n' "$JSON_OUT" "$(( $(date +%s) - START ))"
  add_current_rows; write_report
  (( RESULT_BAD )) && exit 1
  exit 0
fi
report_brief
show_inner

build_plan
sort_plan
for k in "${DISPLAY_ORDER[@]}"; do      # remember each copy, to compare with the re-scan after patching
  B_MK[$k]=$(match_key "$k"); B_VER[$k]=${R_VER[$k]}; B_PROD[$k]=${R_PROD[$k]}
  B_ROOT[$k]=${R_ROOT[$k]}; B_METHOD[$k]=${R_METHOD[$k]}
  B_FIX[$k]=${R_FIX[$k]:--}; B_DESC[$k]=${PLAN_DESC[$k]}; B_NOTE[$k]=${R_NOTE[$k]}
done
if (( ${#PLAN_ORDER[@]} == 0 )); then
  step "Nothing to patch - every copy found is already patched"
  add_current_rows; write_report; exit 0
fi
step "Patch plan"
print_plan

if [[ $MODE == plan ]]; then
  printf '\n  Nothing was changed. To patch: run the same command again with --apply\n'
  printf '  It will ask which numbers to patch (e.g. all | 1,3,5-7 | php,node), or pass --pick to choose up front.\n'
  add_current_rows; write_report; printf '\n'
  exit 1
fi
(( ${#PICK_ORDER[@]} )) || exit 1
choose_items || exit 1

mkdir -p "$LOGDIR"
LOG=$LOGDIR/vulnpatch-$STAMP.log
exec > >(tee -a "$LOGDIR/vulnpatch-$STAMP.console.log") 2>&1
write_json "$LOGDIR/before-$STAMP.json"
add_current_rows skip-plan     # report rows for the copies that needed nothing (taken before the re-scan)

step "Patching"
execute_plan

step "Verification: scanning the whole machine again"
reset_results
scan_machine
write_json "$LOGDIR/after-$STAMP.json"
STILL_BAD=0
verify
restart_check
printf '\n  Logs: %s/vulnpatch-%s*.log   scans: before-%s.json / after-%s.json   (%s min)\n' \
  "$LOGDIR" "$STAMP" "$STAMP" "$STAMP" "$(( ($(date +%s) - START) / 60 ))"
write_report; printf '\n'
(( STILL_BAD )) && exit 1
exit 0
}
