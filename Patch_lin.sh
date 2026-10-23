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
# Products that are not on the machine at all are listed as NOT FOUND.
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
#   end-of-life lines ........... moved to the nearest supported line (Node.js, PHP)
# Every change is backed up first (/var/backups/vulnpatch). After patching the whole machine
# is scanned again and every copy is reported PATCHED / STILL VULNERABLE (with the reason).
#
#   sudo bash vulnpatch-linux.sh --scan     # detection report only (+ JSON)
#   sudo bash vulnpatch-linux.sh            # detection + patch plan (changes nothing)
#   sudo bash vulnpatch-linux.sh --apply    # detect, ASK which copies to patch, patch, verify
# Options:
#   --pick SPEC     (--apply) choose without the prompt: all | 1,3,5-7 | php,node | none
#   --only LIST     php,node,python,chrome,chromium,edge,brave,firefox,ca (limits the plan)
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
PRODUCTS=(PHP Node.js Python Chrome Edge Firefox Brave)   # listed as NOT FOUND when absent

# ---- options ----------------------------------------------------------------
MODE=plan; ASSUME_YES=0; NO_REBUILD=0; ONLY_PRODUCTS=""; PICK_SPEC=""
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
    -h|--help)    if [[ -f $0 ]]; then awk 'NR==1{next} /^set -uo/{exit} {print}' "$0"; else echo "options: --scan | --apply [--pick SPEC] [--only LIST] [--no-rebuild] [--quick] [--json FILE] [-y]"; fi; exit 0 ;;
    *)            echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
done
if (( NO_EXEC )) && [[ $MODE != scan ]]; then echo "--no-exec only works with --scan" >&2; exit 2; fi
if [[ $MODE == apply && $EUID -ne 0 ]]; then echo "--apply needs root (sudo)" >&2; exit 2; fi

STAMP=$(date +%Y%m%d-%H%M%S)
LOGDIR=/var/log/vulnpatch
BACKUP_DIR=/var/backups/vulnpatch
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
      timeout 15 runuser -u "$run_as" -- env -i PATH=/usr/bin:/bin HOME=/tmp "$bin" "$@" 2>/dev/null
      return 0
    fi
  fi
  timeout 15 env -i PATH=/usr/bin:/bin HOME=/tmp "$bin" "$@" 2>/dev/null
  return 0
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
declare -A R_PROD R_VER R_FIX R_STATUS R_METHOD R_ROOT R_OWNER R_PKGS R_PATHS R_NOTE R_ACTION R_BACKPORT R_CERTIFI R_DEFAULT R_EMBED
KEYS=()
SKIPPED=0
VENV_ROOTS=(); VENV_OLD=()

reset_results() {  # clears all rows so the machine can be scanned again (after patching)
  unset R_PROD R_VER R_FIX R_STATUS R_METHOD R_ROOT R_OWNER R_PKGS R_PATHS R_NOTE R_ACTION R_BACKPORT R_CERTIFI R_DEFAULT R_EMBED
  declare -gA R_PROD=() R_VER=() R_FIX=() R_STATUS=() R_METHOD=() R_ROOT=() R_OWNER=() R_PKGS=() R_PATHS=() \
              R_NOTE=() R_ACTION=() R_BACKPORT=() R_CERTIFI=() R_DEFAULT=() R_EMBED=()
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
  case $prod in PHP|Node.js|Python) [[ ${root##*/} == bin || ${root##*/} == sbin ]] && root=${root%/*} ;; esac
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

  if [[ -n $pkgver ]]; then
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

finalize() {
  local k
  (( ${#KEYS[@]} )) || return 0
  for k in "${KEYS[@]}"; do
    [[ ${R_PROD[$k]} == "CA store" || ${R_METHOD[$k]} == venv ]] && continue     # rated while scanning
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
      if [[ $f == */pyvenv.cfg ]]; then VENV_ROOTS+=("${f%/pyvenv.cfg}"); else scan_file "$f"; fi
    done < <(
      find "$r" -xdev -regextype posix-extended \
        \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path /var/lib/snapd \
           -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers \
           -o -path /var/lib/flatpak -o -path '*/.local/share/flatpak' -o -path '*/.local/share/containers' \
           -o -path '*/.vulnpatch.*' -o -path '/var/tmp/vulnpatch-*' -o -path "$BACKUP_DIR" \) -prune \
        -o -type f \( -perm /111 \( -name php -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \
           -o -name node -o -name nodejs -o -regex '.*/python3(\.[0-9]+t?)?' \
           -o -name chrome -o -name chromium -o -name chromium-browser -o -name msedge -o -name brave -o -name firefox \) \
           -o -name pyvenv.cfg \) \
        -print0 2>/dev/null)
  done
  scan_snaps
  scan_flatpaks
  scan_trust_store
  scan_venvs
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
      VULNERABLE)  rank=0; n_vuln=$((n_vuln + 1)) ;;
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
    case ${R_STATUS[$k]} in VULNERABLE|EOL) col=$RED ;; REVIEW) col=$YEL ;; PATCHED) col=$GRN ;; *) col=$DIM ;; esac
    printf '  %s%-11s%s %-9s %-16s %-15s %s\n' "$col" "${R_STATUS[$k]}" "$RST" "${R_PROD[$k]}" \
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
prod_token() { case $1 in Node.js) echo node ;; "CA store") echo ca ;; *) echo "${1,,}" ;; esac; }
selected()   { [[ -z $ONLY_PRODUCTS || ",$ONLY_PRODUCTS," == *",$(prod_token "$1"),"* ]]; }

# key that survives a patch (the version changes, the product/location/branch does not)
match_key() {
  local k=$1 v=${R_VER[$1]} br=""
  case ${R_PROD[$k]} in
    PHP|Python) br=$(cut -d. -f1-2 <<<"$v") ;;
    Node.js)    br=${v%%.*} ;;
  esac
  [[ ${R_METHOD[$k]} == venv ]] && br=""
  printf '%s|%s|%s' "${R_PROD[$k]}" "${R_ROOT[$k]}" "$br"
}

declare -A PLAN_KIND PLAN_DESC PLAN_PKGS PICKED OUTCOME B_MK B_VER B_PROD B_ROOT B_METHOD NOTE_PKG DEPS_DONE
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

set_kind() {  # picks the automatic action for one finding (PLAN_KIND / PLAN_DESC / PLAN_PKGS)
  local k=$1 p=${R_PROD[$1]} m=${R_METHOD[$1]} st=${R_STATUS[$1]} list pre=""
  PLAN_PKGS[$k]=""
  if [[ -n ${R_EMBED[$k]:-} ]]; then
    PLAN_PKGS[$k]=${R_PKGS[$k]}; pre="upgrade package '${R_PKGS[$k]}', then "
  fi
  if [[ $p == "CA store" ]]; then
    PLAN_KIND[$k]=pkg; PLAN_PKGS[$k]=ca-certificates; PLAN_DESC[$k]="upgrade ca-certificates (removes the emSign G3 root)"
  elif [[ $m == venv ]]; then
    PLAN_KIND[$k]=venvs; PLAN_DESC[$k]="refresh certifi in ${#VENV_ROOTS[@]} virtualenvs"
  elif [[ -z ${R_EMBED[$k]:-} && ( $m == apt || $m == rpm ) ]]; then
    list=$(pkg_list_for "$k"); PLAN_PKGS[$k]=${list% }
    PLAN_KIND[$k]=pkg; PLAN_DESC[$k]="upgrade installed package(s): ${list% }"
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
        # any Python with no package of its own (inside apps, tarball, pyenv, uv, conda, temp): rebuilt in place
        if [[ -n ${R_FIX[$k]} && $st != EOL ]] && ver_lt "${R_VER[$k]}" "${R_FIX[$k]}" && (( ! NO_REBUILD )); then
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
    PLAN_ORDER+=("$k")
    set_kind "$k"
  done
}

prod_rank() {
  case $1 in PHP) echo 1 ;; Node.js) echo 2 ;; Python) echo 3 ;; Chrome) echo 4 ;; Chromium) echo 5 ;;
             Edge) echo 6 ;; Brave) echo 7 ;; Firefox) echo 8 ;; *) echo 9 ;; esac
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
    node|node-bin|firefox|chromium) echo "replace" ;;
    certifi|venvs)              echo "certifi" ;;
    external)                   echo "-" ;;
    *)                          echo "update" ;;      # apt / dnf / snap / flatpak package update
  esac
}

est_min() {  # key -> rough minutes for that item (source builds dominate)
  case ${PLAN_KIND[$1]} in
    rebuild)  if [[ ${R_PROD[$1]} == PHP ]]; then echo 5; else echo 4; fi ;;
    chromium) echo 2 ;;
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
    printf '  %3d  %-8s %-16s -> %-14s %-11s %3sm  %s\n' "$i" "${R_PROD[$k]}" "${R_VER[$k]}" "${R_FIX[$k]:--}" \
      "$(action_label "$k")" "$m" "$(short_loc "${R_ROOT[$k]}")"
  done
  (( i )) || printf '       %s(nothing to patch)%s\n' "$DIM" "$RST"
  printf '  %s\n' "$LINE"
  printf '  %d can be patched - all of them: ~%d min\n' "$i" "$total"
  printf '  %srebuild%s = compile the fixed version into the same folder (PHP/Python built from source)\n' "$DIM" "$RST"
  printf '  %sreplace%s = the fixed release swapped into the same folder (runtimes inside apps: package first)\n' "$DIM" "$RST"
  printf '  %supdate%s  = normal package update (only packages that are already installed)\n' "$DIM" "$RST"
  printf '  %scertifi%s = refresh the certificate bundle inside that Python (removes the compromised eMudhra CAs)\n' "$DIM" "$RST"
  printf '  %sEvery change is backed up first to %s%s\n' "$DIM" "$BACKUP_DIR" "$RST"
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
      VULNERABLE) n_v=$((n_v + 1)) ;; EOL) n_e=$((n_e + 1)) ;; REVIEW) n_r=$((n_r + 1)) ;; "NOT FOUND") ;; *) n_p=$((n_p + 1)) ;;
    esac
  done
  n_f=$((n_v + n_e + n_r + n_p))
  printf '  Found %d copies: %s%d vulnerable%s, %s%d end-of-life%s, %s%d review%s, %s%d already patched%s   (full table: --scan)\n' \
    "$n_f" "$RED" "$n_v" "$RST" "$RED" "$n_e" "$RST" "$YEL" "$n_r" "$RST" "$GRN" "$n_p" "$RST"
  if (( n_p )); then
    printf '  Already patched - nothing to do:\n'
    for k in "${KEYS[@]}"; do
      if [[ ${R_STATUS[$k]} == PATCHED ]]; then
        printf '    %s-%s %-8s %-24s %s\n' "$GRN" "$RST" "${R_PROD[$k]}" "${R_VER[$k]}" "$(short_loc "${R_ROOT[$k]}")"
      fi
    done
  fi
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
      printf '    php,node     everything of those products (php node python chrome chromium edge brave firefox ca)\n'
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
  printf '\n  Selected %d item(s) - estimated ~%d min:\n' "$i" "$total"
  for k in "${PICK_ORDER[@]}"; do
    n=$((n + 1))
    if [[ -n ${PICKED[$k]:-} ]]; then
      printf '  %3d  %-8s %-16s -> %-14s %s\n' "$n" "${R_PROD[$k]}" "${R_VER[$k]}" "${R_FIX[$k]:--}" "${PLAN_DESC[$k]}"
    fi
  done
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

ok_item()   { OUTCOME[$1]="done: $2"; say "    [ok] ${R_PROD[$1]} ${R_ROOT[$1]}: $2"; }
fail_item() { OUTCOME[$1]="failed: $2"; warn "${R_PROD[$1]} ${R_ROOT[$1]}: $2"; }

archive_tree() {  # folder or file -> path of a tar.gz backup (old binaries stay restorable but not runnable)
  local d=$1 a
  mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
  a="$BACKUP_DIR/$(tr '/' '_' <<<"${d#/}")-$STAMP.tar.gz"
  tar -czf "$a" -C "$(dirname "$d")" "$(basename "$d")" 2>>"$LOG" && printf '%s' "$a"
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
  local k=$1 root=${R_ROOT[$1]} t=${R_FIX[$1]} rel arch name sha tmp
  rel=$t; [[ ${R_NOTE[$k]} == ESR* ]] && rel="${t}esr"
  case $(uname -m) in x86_64) arch=linux-x86_64 ;; aarch64|arm64) arch=linux-aarch64 ;; *) fail_item "$k" "unsupported CPU"; return ;; esac
  name=firefox-$rel.tar.xz
  sha=$(curl -fsSL "https://archive.mozilla.org/pub/firefox/releases/$rel/SHA256SUMS" 2>>"$LOG" | awk -v f="$arch/en-US/$name" '$2==f {print $1}')
  [[ -n $sha ]] || { fail_item "$k" "could not get the SHA-256 for $name"; return; }
  tmp=$(mktemp -d "$(dirname "$root")/.vulnpatch.XXXXXX") || { fail_item "$k" "no temp dir"; return; }
  pkill -f "^$root/firefox" 2>/dev/null || true
  if fetch_verified "https://archive.mozilla.org/pub/firefox/releases/$rel/$arch/en-US/$name" "$tmp/$name" "$sha" \
     && mkdir "$tmp/new" && tar -xJf "$tmp/$name" -C "$tmp/new" --strip-components=1 --no-same-owner; then
    if [[ -d $root/distribution ]]; then cp -a "$root/distribution" "$tmp/new/"; fi   # enterprise policies
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
  build_into "$k" "Python-$t" "https://www.python.org/ftp/python/$t/Python-$t.tar.xz" "$sha" "$root" altinstall "$runas" "${args[@]}" || return
  # the new build ships pip/certifi without the eMudhra CAs, but altinstall keeps an existing older pip
  [[ $runas != root ]] && as=(runuser -u "$runas" --)
  "${as[@]}" "$py" -m ensurepip --upgrade --altinstall >>"$LOG" 2>&1 || warn "ensurepip --upgrade failed for $py"
  mapfile -t sps < <(site_packages_of "$root")
  if (( ${#sps[@]} )); then mapfile -t dirs < <(certifi_old_dirs "${sps[@]}"); fi
  if (( ${#dirs[@]} )) && refresh_certifi_dirs "${dirs[@]}"; then OUTCOME[$k]="${OUTCOME[$k]}; $CERTIFI_MSG"; fi
}

run_packages() {
  (( ${#PKGS[@]} )) || return 0
  local p cand todo=() holds=()
  step "Package manager ($PKGMGR): ${PKGS[*]}"
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
  for p in "${!NOTE_PKG[@]}"; do warn "$p: ${NOTE_PKG[$p]}"; done
}

execute_plan() {
  local k
  collect_selected
  run_packages
  if (( ${#SNAPS[@]} )); then step "snap refresh ${SNAPS[*]}"; snap refresh "${SNAPS[@]}" >>"$LOG" 2>&1 || warn "snap refresh failed (see $LOG)"; fi
  if (( ${#FLATPAKS[@]} )); then step "flatpak update ${FLATPAKS[*]}"; flatpak update -y --noninteractive "${FLATPAKS[@]}" >>"$LOG" 2>&1 || warn "flatpak update failed"; fi
  for k in "${PICK_ORDER[@]}"; do
    [[ -n ${PICKED[$k]:-} ]] || continue
    case ${PLAN_KIND[$k]} in
      flatpak-user) step "flatpak (user ${R_OWNER[$k]})"
                    runuser -u "${R_OWNER[$k]}" -- flatpak update --user -y --noninteractive "${R_PKGS[$k]}" >>"$LOG" 2>&1 \
                      && ok_item "$k" "flatpak updated" || fail_item "$k" "flatpak update failed" ;;
      node)     step "Node.js ${R_VER[$k]} -> ${R_FIX[$k]}  ${R_ROOT[$k]}"; patch_node_manual "$k" ;;
      node-bin) step "Node.js ${R_VER[$k]} -> ${R_FIX[$k]}  ${R_ROOT[$k]}"; patch_node_binary "$k" ;;
      firefox)  step "Firefox ${R_VER[$k]} -> ${R_FIX[$k]}  ${R_ROOT[$k]}"; patch_firefox_manual "$k" ;;
      chromium) step "${R_PROD[$k]} ${R_VER[$k]} -> $CHROME_FIX  ${R_ROOT[$k]}"; patch_chromium "$k" ;;
      rebuild)  step "${R_PROD[$k]} ${R_VER[$k]} -> ${R_FIX[$k]}  ${R_ROOT[$k]}"
                if [[ ${R_PROD[$k]} == PHP ]]; then patch_php_rebuild "$k"; else patch_python_rebuild "$k"; fi ;;
      certifi)  step "Python ${R_VER[$k]} certifi  ${R_ROOT[$k]}"; patch_certifi "$k" ;;
      venvs)    step "Python virtualenvs (${#VENV_ROOTS[@]}) certifi"; patch_venvs "$k" ;;
    esac
  done
  [[ -n ${CERTIFI_TMP:-} ]] && rm -rf "$CERTIFI_TMP"
  return 0
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
      res="REVIEW"; col=$YEL; n_rev=$((n_rev + 1))
      details+=("$i  ${B_PROD[$k]} ${B_VER[$k]} (${B_ROOT[$k]}): ${OUTCOME[$k]:-} | ${A_NOTE[$mk]:-}")
    else
      res="STILL VULNERABLE"; col=$RED; n_bad=$((n_bad + 1)); why=${OUTCOME[$k]:-}
      if [[ -z $why && ${PLAN_KIND[$k]} == pkg ]]; then why="no fixed version in the configured repositories (or blocked/held)"; fi
      details+=("$i  ${B_PROD[$k]} ${B_VER[$k]} (${B_ROOT[$k]}): $why${A_NOTE[$mk]:+ | now: ${A_NOTE[$mk]}}")
    fi
    printf '  %3s  %s%-16s%s %-8s %-16s -> %-16s %s\n' "$i" "$col" "$res" "$RST" "${B_PROD[$k]}" \
      "${B_VER[$k]}" "$after_ver" "$(short_loc "${B_ROOT[$k]}")"
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
  STILL_BAD=$((n_bad + n_skip))
}

restart_check() {   # processes still running the old (replaced/deleted) binaries
  local p exe hits=()
  for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null) || continue
    [[ $exe == *" (deleted)" ]] || continue
    case ${exe##*/} in php*|node*|python3*|chrome*|msedge*|brave*|firefox*) hits+=("PID ${p#/proc/}  ${exe% (deleted)}") ;; esac
  done
  if (( ${#hits[@]} )); then
    printf '\n  %sRestart needed - these processes still run the old vulnerable code:%s\n' "$YEL" "$RST"
    printf '    %s\n' "${hits[@]}"
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
RESULT_BAD=0
if [[ $MODE == scan ]]; then
  report
  JSON_OUT=${JSON_OUT:-/tmp/vulnscan-$(hostname -s)-$STAMP.json}
  write_json "$JSON_OUT"
  printf '  JSON report: %s   (%ss)\n' "$JSON_OUT" "$(( $(date +%s) - START ))"
  if [[ -d /var/lib/docker || -d /var/lib/containerd || -d /var/lib/containers ]]; then
    printf '  %snote: container storage present - images are not scanned here; use trivy/grype or rebuild images%s\n' "$DIM" "$RST"
  fi
  (( RESULT_BAD )) && exit 1
  exit 0
fi
report_brief

build_plan
sort_plan
for k in "${DISPLAY_ORDER[@]}"; do      # remember each copy, to compare with the re-scan after patching
  B_MK[$k]=$(match_key "$k"); B_VER[$k]=${R_VER[$k]}; B_PROD[$k]=${R_PROD[$k]}
  B_ROOT[$k]=${R_ROOT[$k]}; B_METHOD[$k]=${R_METHOD[$k]}
done
if (( ${#PLAN_ORDER[@]} == 0 )); then step "Nothing to patch - every copy found is already patched"; exit 0; fi
step "Patch plan"
print_plan

if [[ $MODE == plan ]]; then
  printf '\n  Nothing was changed. To patch: run the same command again with --apply\n'
  printf '  It will ask which numbers to patch (e.g. all | 1,3,5-7 | php,node), or pass --pick to choose up front.\n\n'
  exit 1
fi
(( ${#PICK_ORDER[@]} )) || exit 1
choose_items || exit 1

mkdir -p "$LOGDIR"
LOG=$LOGDIR/vulnpatch-$STAMP.log
exec > >(tee -a "$LOGDIR/vulnpatch-$STAMP.console.log") 2>&1
write_json "$LOGDIR/before-$STAMP.json"

step "Patching"
execute_plan

step "Verification: scanning the whole machine again"
reset_results
scan_machine
write_json "$LOGDIR/after-$STAMP.json"
STILL_BAD=0
verify
restart_check
printf '\n  Logs: %s/vulnpatch-%s*.log   scans: before-%s.json / after-%s.json   (%s min)\n\n' \
  "$LOGDIR" "$STAMP" "$STAMP" "$STAMP" "$(( ($(date +%s) - START) / 60 ))"
(( STILL_BAD )) && exit 1
exit 0
}
