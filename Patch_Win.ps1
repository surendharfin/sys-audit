<#
.SYNOPSIS
    vulnpatch-windows.ps1 - DETECT and PATCH in one file: the Windows counterpart of vulnpatch-linux.sh.

.DESCRIPTION
    DETECT: finds EVERY copy of PHP, Node.js, Python, Chrome, Chromium, Edge, Firefox and Brave on this
    machine, however it got there, by searching every fixed drive for the real program files:
      installers ......... MSI / EXE, system-wide or per-user (winget installs land here too)
      package managers ... Chocolatey, Scoop, nvm-windows, Volta, fnm, pyenv-win, uv, conda,
                           the Python install manager, Microsoft Store Python
      web stacks ......... XAMPP, WAMP, Laragon
      anything else ...... zip downloads extracted anywhere, temp folders, Puppeteer/Playwright caches,
                           runtimes and browsers bundled inside other applications, Python virtualenvs
    Versions are read from each program file's own version resource - nothing found on disk is executed.
    Products that are not on the machine at all are listed as NOT FOUND.

    PATCH: every finding gets an automatic action - there are no manual decisions:
      installed copies ......... the vendor's official installer / MSI for the fixed version
      zip / manager copies ..... the fixed release swapped into the SAME folder (php.ini kept)
      runtimes inside apps ..... the owning app is updated with winget first; if still vulnerable, the
                                 runtime itself is refreshed in place (Node.js binary / Python certifi)
      Chromium inside apps ..... app update first, then Chrome for Testing (Google checksum verified)
      Python (any kind) ........ python.org installer / py install --update where they own the copy; any
                                 other copy (inside apps, zip, uv, pyenv, conda) gets python.org's signed
                                 build of the fixed version copied in, site-packages kept; certifi refreshed
      end-of-life lines ........ moved to the nearest supported line (Node.js, PHP)
      Java (any vendor/copy) ... the 16 eMudhra fingerprints added to its lib\security\blocked.certs
                                 (CVE-2026-91403 - Oracle's own fix); installed JDKs updated with winget first
      Windows CA store ......... the compromised emSign ECC Root CA - G3 is marked untrusted
    Every run writes an Excel-ready CSV report to the Desktop (one file per machine, updated on each run):
    host, IP, MAC, each copy found, version before / fixed in / after, the result, and the error for
    anything that could not be patched. WSL distros, Docker containers and VMs on the machine are listed
    as NOT SCANNED: they are separate systems - run the script inside each of them.
    Each change is backed up while it is made (C:\ProgramData\vulnpatch\backups); once the re-scan confirms
    an item PATCHED its backup is deleted, so no old versions are left behind (-KeepBackups keeps them;
    backups stay only for items that are not confirmed). After patching the whole machine
    is scanned again and every copy is reported PATCHED / STILL VULNERABLE (with the reason).

    Works in Constrained Language Mode (AppLocker / WDAC managed laptops).

.PARAMETER Scan    Detection report only (and JSON).
.PARAMETER Apply   Detect, ask which numbers to patch, patch, verify. Needs an elevated PowerShell.
.PARAMETER Pick    With -Apply: choose without the prompt - all | 1,3,5-7 | php,node | none
.PARAMETER Only    Limit the plan to some products: php,node,python,java,chrome,chromium,edge,brave,firefox,ca
.PARAMETER Report  Folder (or .csv file) for the report, e.g. \\server\share\vulnpatch. Default: your Desktop (else
                   Downloads), file vulnpatch-report-<COMPUTERNAME>.csv - a re-run updates that same file.
.PARAMETER Quick   Search the usual install folders only instead of every fixed drive.
.PARAMETER Json    Where to write the JSON report.
.PARAMETER KeepBackups  Keep the backups of verified fixes too (default: deleted once the fix is verified).
.PARAMETER Yes     No prompts (patches every plan item unless -Pick says otherwise).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Scan
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Apply
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Apply -Pick 1,3,5-7 -Yes
.EXAMPLE
    From memory, nothing saved (works in Constrained Language Mode, the window stays open):
    iex "& { $(irm https://raw.githubusercontent.com/surendharfin/sys-audit/main/Patch_Win.ps1) } -Apply"
#>
[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$Apply,
    [string]$Pick,
    [string[]]$Only,
    [switch]$Quick,
    [string]$Json,
    [string]$Report,
    [switch]$KeepBackups,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
# Constrained Language Mode (managed laptops) allows only core types: no Add-Type, no .NET calls,
# no property setting on .NET objects. Everything below sticks to cmdlets, strings and hashtables.
$FullLang = ($ExecutionContext.SessionState.LanguageMode -eq 'FullLanguage')
if ($FullLang) { try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { } }

# =============================================================================
# Fixed versions (researched 23-Oct-2026)
# =============================================================================
$PhpFix     = @{ '8.2' = '8.2.35'; '8.3' = '8.3.36'; '8.4' = '8.4.27'; '8.5' = '8.5.12' }
$NodeFix    = @{ '22' = '22.23.4'; '24' = '24.22.1'; '26' = '26.12.1' }
$PyFix      = @{ '3.13' = '3.13.17'; '3.14' = '3.14.9'; '3.15' = '3.15.1' }
$ChromeFix  = '156.0.8078.47'     # Chrome and Chromium
$EdgeFix    = '156.0.4314.42'
$BraveFix   = '1.98.60'
$FirefoxFix = '158.0.1'           # ESR: 153.5.1 / 115.43.1
$CertifiFix = '2026.10.19'        # first certifi without the compromised eMudhra CAs
$JavaFix    = @{ '8' = '8.0.511'; '11' = '11.0.33'; '17' = '17.0.21'; '21' = '21.0.13'; '25' = '25.0.5'; '27' = '27.0.1' }   # Oct-2026 CPU (8 = 8u511)
# CVE-2026-91403: the 16 eMudhra intermediates OpenJDK/Oracle added to lib\security\blocked.certs
# (JDK-8395142; checked against openjdk/jdk blocked.certs.pem)
$EmudhraFps = @(
    '0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19', '42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493',
    '432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3', '45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE',
    '4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1', '579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512',
    '5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699', '62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72',
    '7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489', '84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD',
    '98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B', '9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4',
    'A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8', 'CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F',
    'E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838', 'FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F'
)
# ---- libraries and supply chain (researched 24-Oct-2026) ----
$PillowFix     = '13.0.0'        # CVE-2026-112900 (Ghostscript RCE) + 5 more; needs Python 3.11+
$BrotliFix     = '1.2.1'         # CVE-2026-111497 (Node2Shell) in the Brotli library itself
$BrotliCffiFix = '1.2.1.0'
$LiteLLMBad    = '1.107.0', '1.82.7', '1.82.8'   # malicious releases (credential stealer + remote-control backdoor)
$LiteLLMFix    = '1.83.14'       # first release with the April-2026 CVE fixes (CVSS 10.0 RCE)
$LiteLLMSpec   = 'litellm>=1.106.2,!=1.107.0'
$NextFix       = @{ '15' = '15.5.28'; '16' = '16.4.1' }   # 14-Oct-2026: use-cache RCE, image RCE, Server Actions DoS
$SharpFix      = '0.35.5'        # librsvg RCE through image processing (CVE-2026-96889)
$BunFix        = '1.4.4'         # CVE-2026-111497 (Node2Shell) in Bun
$KevDays       = 30              # CISA KEV additions of the last N days are matched against installed apps
$KevUrl        = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
# litellm 1.107.0 indicators (Socket / Aikido): SHA-256 of cook.pth, cook.py, sitecustomize.py (two builds each)
$LiteLLMIocSha = '7f191632e7320705d154b85204f1ae546b543acbd7e8861229b76f5042b92bdb', '84dc8c82c0a4a4a62552ef826b49fcc86d1a5c4a5d0f2c06665723f93d129d7d',
                 '9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25', '03ac2a8b752605d1d7710979c17ff18b03dd978203ba23ba97fd8ce3d6f897ea',
                 '34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa', 'b6122440d0d9cb1eb1ade9933f49214da8c31288de7710c076c2680dfa528465'
$LiteLLMIocMark = 'remote_code_loader|letters9813|litellm\.dev/healthcheck|XWiA8gZNa7NcX2XRoAEb'
$Products   = 'PHP', 'Node.js', 'Bun', 'Python', 'Java', 'Chrome', 'Edge', 'Firefox', 'Brave', 'LiteLLM', 'Pillow', 'Brotli', 'Next.js', 'sharp'   # listed as NOT FOUND when absent
$ScriptVersion = '2026.10.24'

$Mode = 'plan'
if ($Scan)  { $Mode = 'scan' }
if ($Apply) { $Mode = 'apply' }
$OnlyList  = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLower() })
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$WorkDir   = Join-Path $env:ProgramData 'vulnpatch'
$LogDir    = Join-Path $WorkDir 'logs'
$BackupDir = Join-Path $WorkDir 'backups'
$DlDir     = Join-Path $WorkDir 'downloads'
$Line      = '-' * 108
$Me        = $env:USERNAME
# Windows' own tools by full path: Git for Windows (usr\bin) on PATH has GNU whoami/tar/curl with other options
$Sys32     = Join-Path $env:SystemRoot 'System32'
function Get-SysExe([string]$Name) { $p = Join-Path $Sys32 $Name; if (Test-Path -LiteralPath $p) { return $p }; return $Name }
$WhoAmI    = Get-SysExe 'whoami.exe'
$CertUtil  = Get-SysExe 'certutil.exe'
$Robocopy  = Get-SysExe 'robocopy.exe'
$CmdExe    = Get-SysExe 'cmd.exe'
$MsiExec   = Get-SysExe 'msiexec.exe'
$Tar       = Join-Path $Sys32 'tar.exe';  $HasTar  = Test-Path -LiteralPath $Tar    # Windows 10 1803+
$Curl      = Join-Path $Sys32 'curl.exe'; $HasCurl = Test-Path -LiteralPath $Curl
$IsAdmin   = [bool](& $WhoAmI /groups | Select-String -Pattern 'S-1-16-12288|S-1-16-16384')   # elevated admin, or SYSTEM (Intune/SCCM)
$HasWinget = [bool](Get-Command winget.exe -ErrorAction SilentlyContinue)

# =============================================================================
# Helpers (Constrained Language Mode safe)
# =============================================================================
function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Note([string]$m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }

function ConvertTo-Ver([string]$s) { if ($s -match '(\d+(?:\.\d+)+)') { return $Matches[1] } }

function Compare-Ver([string]$a, [string]$b) {
    $x = @($a -split '\.'); $y = @($b -split '\.')
    $n = $x.Count; if ($y.Count -gt $n) { $n = $y.Count }
    for ($i = 0; $i -lt $n; $i++) {
        $p = 0; $q = 0
        if ($i -lt $x.Count -and $x[$i] -match '^\d+$') { $p = [long]$x[$i] }
        if ($i -lt $y.Count -and $y[$i] -match '^\d+$') { $q = [long]$y[$i] }
        if ($p -lt $q) { return -1 }
        if ($p -gt $q) { return 1 }
    }
    return 0
}
function Test-VerLt([string]$a, [string]$b) { (Compare-Ver $a $b) -lt 0 }
function Get-Branch([string]$v, [int]$parts) { (@($v -split '\.')[0..($parts - 1)]) -join '.' }

function Get-SortVer([string]$v) {   # sortable [version] for anything, e.g. "3.12 (Store)" or "Windows"
    $n = ConvertTo-Ver $v
    if (-not $n) { return [version]'0.0' }
    $p = @($n -split '\.'); if ($p.Count -gt 4) { $p = $p[0..3] }
    try { return [version]($p -join '.') } catch { return [version]'0.0' }
}

function Get-FileVer([string]$Path) {   # version resource of the file - nothing is executed
    try { $vi = (Get-Item -LiteralPath $Path -Force).VersionInfo } catch { return $null }
    $v = ConvertTo-Ver $vi.ProductVersion
    if (-not $v) { $v = ConvertTo-Ver $vi.FileVersion }
    return $v
}

function Get-PeArch([string]$Path) {    # CPU type from the PE header: x64 | x86 | arm64
    try {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $b = Get-Content -LiteralPath $Path -AsByteStream -TotalCount 4096 }
        else { $b = Get-Content -LiteralPath $Path -Encoding Byte -TotalCount 4096 }
        $pe = [int]$b[0x3C] + 256 * [int]$b[0x3D] + 65536 * [int]$b[0x3E]
        $m = [int]$b[$pe + 4] + 256 * [int]$b[$pe + 5]
        if ($m -eq 0x8664) { return 'x64' }
        if ($m -eq 0x14c)  { return 'x86' }
        if ($m -eq 0xAA64) { return 'arm64' }
    } catch { }
    return 'x64'
}

function Get-ShortLoc([string]$p) {
    if ($p.Length -le 40) { return $p }
    return $p.Substring(0, 15) + '...' + $p.Substring($p.Length - 22)
}

function Get-OwnerOf([string]$Path) {   # the user whose profile holds this copy, or 'system'
    $users = (Join-Path $env:SystemDrive 'Users').ToLower()
    $p = $Path.ToLower()
    if ($p.StartsWith("$users\")) { return @($Path.Substring($users.Length + 1) -split '\\')[0] }
    return 'system'
}

function ConvertFrom-B64Hex([string]$b64) {   # base64 -> lowercase hex, without .NET (Constrained Language Mode)
    $alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    $bits = 0; $nbits = 0; $hex = ''
    foreach ($ch in $b64.TrimEnd('=').ToCharArray()) {
        $v = $alpha.IndexOf([string]$ch); if ($v -lt 0) { continue }
        $bits = ($bits -shl 6) -bor $v; $nbits += 6
        if ($nbits -ge 8) {
            $nbits -= 8
            $hex += '{0:x2}' -f (($bits -shr $nbits) -band 0xFF)
            $bits = $bits -band ((1 -shl $nbits) - 1)
        }
    }
    return $hex
}

# Windows' own programs instead of Get-FileHash / Expand-Archive / Compress-Archive: those are PowerShell
# script functions and can be blocked by Constrained Language Mode on locked-down laptops.
function Get-Hash([string]$Path, [string]$Algo) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $CertUtil -hashfile $Path $Algo 2>&1 } finally { $ErrorActionPreference = $old }
    $line = @($out | Where-Object { "$_" -match '^[0-9a-fA-F ]{32,}$' })[0]
    if (-not $line) { throw "could not compute the $Algo of $Path" }
    return ("$line" -replace ' ', '').ToUpper()
}

function Expand-Zip([string]$Zip, [string]$Dest) {
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    if ($HasTar) {
        & $Tar -xf $Zip -C $Dest
        if ($LASTEXITCODE -ne 0) { throw "could not extract $Zip" }
    } else { Expand-Archive -LiteralPath $Zip -DestinationPath $Dest -Force }
}

function New-Zip([string]$Path, [string]$Zip, [string]$Exclude) {   # a folder or a single file; Exclude: sub-path left out
    if ($HasTar) {
        $leaf = Split-Path $Path -Leaf
        if ($Exclude) { & $Tar -a -c -f $Zip --exclude "$leaf/$($Exclude -replace '\\', '/')" -C (Split-Path $Path -Parent) $leaf }
        else { & $Tar -a -c -f $Zip -C (Split-Path $Path -Parent) $leaf }
        if ($LASTEXITCODE -ne 0) { throw "could not back up $Path" }
    } else { Compress-Archive -LiteralPath $Path -DestinationPath $Zip -CompressionLevel Fastest -Force }
}

# Downloads into the cache and verifies it: SHA-256, SHA-512 (nuget.org), MD5 (Google storage checksum) or a signer.
function Get-Download([string]$Url, [string]$FileName, [string]$Sha256, [string]$Signer, [string]$Md5, [string]$Sha512) {
    New-Item -ItemType Directory -Force -Path $DlDir | Out-Null
    $dest = Join-Path $DlDir $FileName
    $part = "$dest.part"
    if (Test-Path -LiteralPath $part) { Remove-Item -LiteralPath $part -Force }
    if ($HasCurl) {
        & $Curl -L --fail --retry 3 --retry-delay 5 -sS -o $part $Url
        if ($LASTEXITCODE -ne 0) { throw "download failed: $Url" }
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $part -UseBasicParsing
    }
    if ($Sha256) {
        if ((Get-Hash $part SHA256) -ne $Sha256.ToUpper()) { Remove-Item -LiteralPath $part -Force; throw "SHA-256 mismatch for $FileName" }
    } elseif ($Sha512) {
        if ((Get-Hash $part SHA512) -ne $Sha512.ToUpper()) { Remove-Item -LiteralPath $part -Force; throw "SHA-512 mismatch for $FileName" }
    } elseif ($Md5) {
        if ((Get-Hash $part MD5) -ne $Md5.ToUpper()) { Remove-Item -LiteralPath $part -Force; throw "checksum mismatch for $FileName" }
    } elseif ($Signer) {
        $sig = Get-AuthenticodeSignature -LiteralPath $part
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch [regex]::Escape($Signer)) {
            Remove-Item -LiteralPath $part -Force; throw "$FileName is not validly signed by $Signer"
        }
    } else {
        Remove-Item -LiteralPath $part -Force; throw "nothing to verify $FileName with - refusing to use it"
    }
    Move-Item -LiteralPath $part -Destination $dest -Force
    return $dest
}

function Get-WebText([string]$Url) {   # small text file via curl (no .NET encoding calls)
    New-Item -ItemType Directory -Force -Path $DlDir | Out-Null
    $k = $Url -replace '[^A-Za-z0-9]', '_'; if ($k.Length -gt 80) { $k = $k.Substring($k.Length - 80) }
    $f = Join-Path $DlDir "txt-$k.txt"
    if ($HasCurl) {
        & $Curl -L --fail --retry 3 -sS -o $f $Url
        if ($LASTEXITCODE -ne 0) { throw "download failed: $Url" }
    } else { Invoke-WebRequest -Uri $Url -OutFile $f -UseBasicParsing }
    return (Get-Content -LiteralPath $f -Raw -Encoding UTF8)
}

# JSON APIs through curl.exe: Windows PowerShell 5.1 may not negotiate TLS 1.2 by itself, and in
# Constrained Language Mode the script cannot switch it on
function Get-Json([string]$Url) { return (Get-WebText $Url | ConvertFrom-Json) }

function Copy-Tree([string]$From, [string]$To, [string[]]$Extra) {   # robocopy merges into the existing folder (exit 0-7 = success)
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $Robocopy $From $To @Extra /R:1 /W:1 /NP /NFL /NDL /NJH /NJS 2>&1; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    if ($code -ge 8) { throw "copy into $To failed (robocopy exit $code): $((@($out) | Where-Object { "$_".Trim() } | Select-Object -Last 2) -join ' ')" }
}

# Waits on the installer itself (not its children - Omaha installers leave an updater running).
function Invoke-Installer([string]$FilePath, [string]$Arguments, [int]$TimeoutMin = 30) {
    $sp = @{ FilePath = $FilePath; PassThru = $true }
    if ($Arguments) { $sp.ArgumentList = $Arguments }
    $p = Start-Process @sp
    $null = $p.Handle
    $deadline = (Get-Date).AddMinutes($TimeoutMin)
    while (-not $p.HasExited) {
        if ((Get-Date) -gt $deadline) { throw "$(Split-Path $FilePath -Leaf) did not finish within $TimeoutMin min" }
        Start-Sleep -Seconds 2
    }
    return $p.ExitCode
}

# =============================================================================
# DETECTION
# =============================================================================
$WalkerSource = @'
using System; using System.IO; using System.Collections.Generic;
public static class VpWalk {
    public static List<string> Find(string root, string[] names, string[] skip) {
        List<string> hits = new List<string>();
        HashSet<string> want = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
        Stack<string> todo = new Stack<string>(); todo.Push(root);
        while (todo.Count > 0) {
            string dir = todo.Pop();
            try {
                string leaf = Path.GetFileName(dir);
                bool npmPkg = (leaf.Equals("next", StringComparison.OrdinalIgnoreCase) || leaf.Equals("sharp", StringComparison.OrdinalIgnoreCase))
                              && Path.GetFileName(Path.GetDirectoryName(dir) ?? "").Equals("node_modules", StringComparison.OrdinalIgnoreCase);
                bool pyDist = leaf.EndsWith(".dist-info", StringComparison.OrdinalIgnoreCase) && LibDist(leaf);
                foreach (string f in Directory.EnumerateFiles(dir)) {
                    string n = Path.GetFileName(f);
                    if (want.Contains(n)) hits.Add(f);
                    else if (npmPkg && n.Equals("package.json", StringComparison.OrdinalIgnoreCase)) hits.Add(f);
                    else if (pyDist && n.Equals("METADATA", StringComparison.OrdinalIgnoreCase)) hits.Add(f);
                }
                foreach (string d in Directory.EnumerateDirectories(dir)) {
                    try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
                    bool skipIt = false;
                    foreach (string s in skip) if (d.IndexOf(s, StringComparison.OrdinalIgnoreCase) >= 0) { skipIt = true; break; }
                    if (!skipIt) todo.Push(d);
                }
            } catch { }
        }
        return hits;
    }
    static bool LibDist(string leaf) {   // pillow-*, brotli-*, brotlicffi-*, litellm-* .dist-info
        string l = leaf.ToLowerInvariant();
        return l.StartsWith("pillow-") || l.StartsWith("brotli-") || l.StartsWith("brotlicffi-") || l.StartsWith("litellm-");
    }
}
'@
$ExeNames  = 'php.exe', 'node.exe', 'python.exe', 'java.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'bun.exe', 'cook.pth'
$SkipParts = '\windows\winsxs', '\windows\servicing', '\windows\softwaredistribution', '\windows\installer', '\windows\assembly',
             '\windows\system32\driverstore', '\$recycle.bin', '\system volume information', '\windowsapps',
             '\edgewebview', '\edgecore', '\edgeupdate', '\programdata\vulnpatch', '\.vulnpatch-',
             '\oracle\java\javapath'   # Oracle's java.exe launcher copies (they start the real JRE elsewhere)

function Get-SearchRoots {
    if ($Quick) {
        $c = $env:SystemDrive
        $cand = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData, "$c\Users", "$c\php", "$c\xampp", "$c\wamp64",
                  "$c\wamp", "$c\laragon", "$c\tools", "$c\inetpub", "$c\srv") + @(Get-ChildItem "$c\" -Directory -Filter 'Python*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        return @($cand | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
    }
    return @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { $_.DeviceID + '\' })
}

function Test-Skipped([string]$p) {
    $l = $p.ToLower()
    foreach ($s in $SkipParts) { if ($l.Contains($s)) { return $true } }
    return $false
}

function Test-UnderReparse([string]$p) {   # dir /s follows junctions; the walker does not - skip those extra copies
    $d = Split-Path $p -Parent
    while ($d -and $d.Length -gt 3) {
        try { if ("$((Get-Item -LiteralPath $d -Force).Attributes)" -match 'ReparsePoint') { return $true } } catch { }
        $d = Split-Path $d -Parent
    }
    return $false
}

function Find-ProgramFiles {
    $hits = @()
    $fast = $false
    if ($FullLang) {   # compiled walker: fastest, exact Unicode paths
        try { if (-not ('VpWalk' -as [type])) { Add-Type -TypeDefinition $WalkerSource -Language CSharp }; $fast = $true } catch { $fast = $false }
    }
    foreach ($r in $script:Roots) {
        if ($fast) {
            $hits += @([VpWalk]::Find($r, [string[]]$ExeNames, [string[]]$SkipParts))
        } else {       # Constrained Language Mode: Windows' own dir /s, one walk for all four kinds of file
            $out = & $CmdExe /c "dir /s /b /a-d `"$(Join-Path $r '*.exe')`" `"$(Join-Path $r 'package.json')`" `"$(Join-Path $r 'METADATA')`" `"$(Join-Path $r 'cook.pth')`" 2>nul"
            foreach ($p in @($out)) {
                if (-not $p) { continue }
                $leaf = (Split-Path $p -Leaf).ToLower()
                if ($leaf -eq 'package.json') { if ($p -notmatch '\\node_modules\\(next|sharp)\\package\.json$') { continue } }
                elseif ($leaf -eq 'metadata') { if ($p -notmatch '\\(pillow|brotli|brotlicffi|litellm)-[^\\]+\.dist-info\\METADATA$') { continue } }
                elseif ($ExeNames -notcontains $leaf) { continue }
                if (-not (Test-Skipped $p) -and -not (Test-UnderReparse $p)) { $hits += $p }
            }
        }
    }
    return $hits
}

function Get-UninstallEntries {
    $keys = @(
        @{ Hive = 'system'; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
        @{ Hive = 'system'; Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' }
        @{ Hive = 'user';   Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    )
    $list = @()
    foreach ($k in $keys) {
        foreach ($e in @(Get-ItemProperty $k.Path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })) {
            $loc = "$($e.InstallLocation)".Trim().Trim('"').TrimEnd('\')
            $icon = @("$($e.DisplayIcon)" -split ',')[0].Trim('"')
            $list += @{ Name = "$($e.DisplayName)"; Version = "$($e.DisplayVersion)"; Location = $loc; Icon = $icon; Scope = $k.Hive; Publisher = "$($e.Publisher)" }
        }
    }
    return $list
}

function Get-PythonRegistry {   # PEP 514 registrations -> install folder => system | user
    $map = @{}
    foreach ($k in @(@{ S = 'system'; P = 'HKLM:\SOFTWARE\Python\PythonCore' }, @{ S = 'system'; P = 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore' },
                     @{ S = 'user'; P = 'HKCU:\SOFTWARE\Python\PythonCore' })) {
        foreach ($t in @(Get-ChildItem $k.P -ErrorAction SilentlyContinue)) {
            $ip = (Get-ItemProperty (Join-Path $t.PSPath 'InstallPath') -ErrorAction SilentlyContinue).'(default)'
            if ($ip) { $map["$ip".TrimEnd('\').ToLower()] = $k.S }
        }
    }
    return $map
}

function Find-Uninstall([string]$Product, [string]$Root) {   # the product's own installer entry
    $pat = $null
    switch ($Product) {
        'Chrome' { $pat = '^Google Chrome' }  'Edge' { $pat = '^Microsoft Edge$' }  'Firefox' { $pat = '^Mozilla Firefox' }
        'Brave'  { $pat = '^Brave' }          'Node.js' { $pat = '^Node\.js$' }
        'Java'   { $pat = 'Java|JDK|JRE|OpenJDK|Temurin|Corretto|Zulu|Liberica|Semeru|SapMachine' }
    }
    if (-not $pat) { return $null }
    $r = $Root.TrimEnd('\').ToLower()
    foreach ($e in $script:Entries) {
        if ($e.Name -notmatch $pat) { continue }
        $l = $e.Location.ToLower()
        if ($l -and ($r -eq $l -or $r.StartsWith("$l\"))) { return $e }
        if ($e.Icon -and $e.Icon.ToLower().StartsWith("$r\")) { return $e }
        if ($Product -eq 'Node.js' -and $r -eq (Join-Path $env:ProgramFiles 'nodejs').ToLower()) { return $e }
    }
    return $null
}

function Find-OwningApp([string]$Root) {   # the installed application whose folder holds this copy
    $r = $Root.TrimEnd('\').ToLower(); $best = $null
    foreach ($e in $script:Entries) {
        $l = $e.Location.ToLower()
        if ($l.Length -lt 4) { continue }
        if ($r.StartsWith("$l\") -and (-not $best -or $l.Length -gt $best.Location.Length)) { $best = $e }
    }
    return $best
}

function Get-MethodOf([string]$Product, [string]$Root, $Entry, $PyReg) {
    $r = $Root.ToLower()
    if ($r -match '\\appdata\\local\\temp\\|\\windows\\temp\\') { return 'download-in-temp' }
    if ($r -match '\\nvm\\v\d') { return 'nvm' }
    if ($r -match '\\volta\\') { return 'volta' }
    if ($r -match '\\fnm\\|\\fnm_multishells\\') { return 'fnm' }
    if ($r -match '\\scoop\\apps\\') { return 'scoop' }
    if ($r -match '\\chocolatey\\lib\\|^[a-z]:\\tools\\') { return 'choco' }
    if ($r -match '\\\.pyenv\\pyenv-win\\') { return 'pyenv' }
    if ($r -match '\\appdata\\local\\python\\pythoncore-') { return 'pymanager' }
    if ($r -match '\\uv\\python\\') { return 'uv' }
    if ($r -match 'anaconda|miniconda|miniforge|mambaforge') { return 'conda' }
    if ($r -match '\\puppeteer\\') { return 'puppeteer' }
    if ($r -match '\\ms-playwright') { return 'playwright' }
    if ($r -match '\\node_modules\\') { return 'npm-package' }
    if ($r -match '\\xampp\\') { return 'xampp' }
    if ($r -match '\\wamp(64)?\\') { return 'wamp' }
    if ($r -match '\\laragon\\') { return 'laragon' }
    if ($Product -eq 'Firefox' -and $r -match 'tor browser') { return 'bundled-in-app' }
    if ($Entry) {
        if ($Product -eq 'Node.js') { return 'msi' }
        if ($Entry.Scope -eq 'user' -or $r.StartsWith(($env:SystemDrive + '\users\').ToLower())) { return 'installer-user' }
        return 'installer'
    }
    if ($Product -eq 'Python' -and $PyReg.ContainsKey($r)) { if ($PyReg[$r] -eq 'user') { return 'installer-user' }; return 'installer' }
    if ($Product -eq 'Node.js' -and -not (Test-Path -LiteralPath (Join-Path $Root 'node_modules\npm'))) { return 'bundled-in-app' }
    if ($Product -eq 'Java') {
        if ($r -match '\\\.jdks\\|\\\.sdkman\\|\\\.jabba\\') { return 'jdk-manager' }
        if ($r -match '\\(jre|jbr|runtime|jdk)[^\\]*$' -and (Find-OwningApp $Root)) { return 'bundled-in-app' }   # e.g. Burp, IntelliJ, DBeaver
    }
    if ($Product -in 'Python', 'Node.js') {
        if ($r -match '\\resources\\|\\dependencies\\|\\runtimes?\\') { return 'bundled-in-app' }
        if ($r -match '\\users\\[^\\]+\\\.[^\\]+\\') { return 'bundled-in-app' }
        if ($r -match '\\appdata\\local\\programs\\([^\\]+)' -and $Matches[1] -notmatch '^python') { return 'bundled-in-app' }
    }
    $pf = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
    if ($Product -eq 'Python') { foreach ($p in $pf) { if ($r.StartsWith("$p\")) { return 'bundled-in-app' } } }
    if ($Product -in 'Chrome', 'Chromium', 'Edge', 'Brave', 'Firefox') {
        $std = switch ($Product) { 'Chrome' { '\\google\\chrome' } 'Chromium' { '\\chromium\\' } 'Edge' { '\\microsoft\\edge' }
                                   'Brave' { '\\bravesoftware\\' } 'Firefox' { '\\mozilla firefox' } }
        if ($r -notmatch $std) { return 'bundled-in-app' }
    }
    return 'manual'
}

function New-Row([string]$Product, [string]$Version, [string]$Method, [string]$Root, [string]$Exe) {
    @{ Key = "$Product|$Root|$Version"; Product = $Product; Version = $Version; Fixed = ''; Status = ''; Method = $Method
       Root = $Root; Exe = $Exe; Owner = (Get-OwnerOf $Root); Note = ''; Embedded = $false; CertifiOld = @()
       Default = ''; Arch = ''; Flavor = ''; Package = ''; AppName = ''; Kind = ''; Desc = ''; Picked = $false
       Outcome = ''; MatchKey = ''; Target = ''; Venvs = @(); Vendor = ''; InPlan = $false
       Lib = ''; Py = ''; PyMode = ''; PyVer = ''; Major = $false; Kev = ''; KevDate = ''; KevAction = ''; Backups = @() }
}

function Add-Row($Row) {
    if (-not $script:RowIndex.ContainsKey($Row.Key)) { $script:RowIndex[$Row.Key] = $Row; $script:Rows += $Row }
}

function Get-CertifiOld([string]$SitePackages) {   # certifi copies (standalone + pip's vendored one) older than the fix
    $old = @()
    foreach ($d in (Join-Path $SitePackages 'certifi'), (Join-Path $SitePackages 'pip\_vendor\certifi')) {
        $f = Join-Path $d '__init__.py'
        if (-not (Test-Path -LiteralPath $f)) { continue }
        $m = Select-String -LiteralPath $f -Pattern '^__version__ = "([^"]+)"' | Select-Object -First 1
        if ($m -and (Test-VerLt $m.Matches[0].Groups[1].Value $CertifiFix)) { $old += @{ Dir = $d; Version = $m.Matches[0].Groups[1].Value } }
    }
    return $old
}

function Get-PyCertifiOld([string]$Root, [string]$Version) {   # Lib\site-packages, or ..\lib\python3.X\site-packages (MinGW/MSYS builds)
    $sps = @(Join-Path $Root 'Lib\site-packages')
    if ((Split-Path $Root -Leaf) -eq 'bin') { $sps += Join-Path (Split-Path $Root -Parent) "lib\python$(Get-Branch $Version 2)\site-packages" }
    $old = @()
    foreach ($sp in $sps) { if (Test-Path -LiteralPath $sp) { $old += @(Get-CertifiOld $sp) } }
    return $old
}

function ConvertTo-JavaVer([string]$v) {   # 1.8.0_402-b06 -> 8.0.402 | 21.0.5+11 -> 21.0.5 | 25 -> 25.0.0
    $v = @($v -split '[+-]')[0]
    if ($v -match '^1\.(\d+)\.0_(\d+)') { return "$($Matches[1]).0.$($Matches[2])" }
    if ($v -match '^1\.(\d+)(\.0)?$') { return "$($Matches[1]).0.0" }
    if ($v -match '^\d+$') { return "$v.0.0" }
    return ConvertTo-Ver $v
}

function Get-JavaRelease([string]$Root, [string]$Key) {   # a value from the JDK/JRE 'release' file (every image has one)
    $f = Join-Path $Root 'release'
    if (-not (Test-Path -LiteralPath $f)) { return '' }
    $m = Select-String -LiteralPath $f -Pattern "^$Key=`"?([^`"]*)`"?\s*$" | Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return ''
}

function Get-JavaBlockFile([string]$Root) {   # the block list that JVM reads (JDK 8: jre\lib\security, blacklisted.certs)
    $sec = Join-Path $Root 'lib\security'
    if (Test-Path -LiteralPath (Join-Path $Root 'jre\lib\security')) { $sec = Join-Path $Root 'jre\lib\security' }
    foreach ($n in 'blocked.certs', 'blacklisted.certs') { $f = Join-Path $sec $n; if (Test-Path -LiteralPath $f) { return $f } }
    return (Join-Path $sec 'blocked.certs')
}

function Get-JavaFpCount([string]$File) {   # how many of the 16 eMudhra fingerprints that block list holds
    if (-not (Test-Path -LiteralPath $File)) { return 0 }
    $have = @(Get-Content -LiteralPath $File | ForEach-Object { "$_".Trim().ToUpper() })
    return @($EmudhraFps | Where-Object { $have -contains $_ }).Count
}

function Add-Copy([string]$Exe, $PyReg, $Defaults) {
    $name = (Split-Path $Exe -Leaf).ToLower()
    $prod = switch ($name) {
        'php.exe' { 'PHP' } 'node.exe' { 'Node.js' } 'python.exe' { 'Python' } 'msedge.exe' { 'Edge' }
        'firefox.exe' { 'Firefox' } 'brave.exe' { 'Brave' } 'java.exe' { 'Java' } 'bun.exe' { 'Bun' }
        'chrome.exe' { if ($Exe -match '\\Google\\Chrome') { 'Chrome' } else { 'Chromium' } }
    }
    if (-not $prod) { return }
    $root = Split-Path $Exe -Parent
    if ($prod -eq 'Java') {
        if ((Split-Path $root -Leaf) -eq 'bin') { $root = Split-Path $root -Parent }
        # JDK 8: jdk\jre\bin\java.exe belongs to the JDK around it
        if ((Split-Path $root -Leaf) -eq 'jre' -and (Test-Path -LiteralPath (Join-Path (Split-Path $root -Parent) 'bin\java.exe'))) { return }
    }
    if ($prod -eq 'Python') {
        # venv launcher templates and packaged copies: Lib\venv\scripts\nt, lib\python3.9\venv\scripts\nt (MinGW/MSYS)
        if ($root -match '\\Lib\\(python[\d.]+\\)?(venv|site-packages)\\') { return }
        if ((Split-Path $root -Leaf) -in 'Scripts', 'bin' -and (Test-Path -LiteralPath (Join-Path (Split-Path $root -Parent) 'pyvenv.cfg'))) {
            $script:VenvRoots += (Split-Path $root -Parent); return
        }
    }
    if ($prod -in 'Chrome', 'Chromium', 'Edge', 'Brave') {
        # Edge keeps a copy of msedge.exe in Application\<version>\ next to the real one - not a separate install
        if ((Split-Path $root -Leaf) -match '^\d+(\.\d+){3}$' -and (Test-Path -LiteralPath (Join-Path (Split-Path $root -Parent) $name))) { return }
        # a real browser has its engine DLL beside the exe or in a version folder; stubs and launchers do not
        $dll = 'chrome.dll'; if ($prod -eq 'Edge') { $dll = 'msedge.dll' }
        $hasDll = (Test-Path -LiteralPath (Join-Path $root $dll)) -or [bool](Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                  Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName $dll) } | Select-Object -First 1)
        if (-not $hasDll) { $script:Skipped++; return }
    }
    if ($prod -eq 'Firefox' -and -not (Test-Path -LiteralPath (Join-Path $root 'xul.dll'))) { $script:Skipped++; return }
    $ver = Get-FileVer $Exe
    if ($prod -eq 'Java') {   # the 'release' file is exact; java.exe of JDK 8 says e.g. 8.0.4020.8 for 8u402
        $ver = ConvertTo-JavaVer (Get-JavaRelease $root 'JAVA_VERSION')
        if (-not $ver -and (Get-FileVer $Exe) -match '^(\d+)\.(\d+)\.(\d+)') {
            $u = [int]$Matches[3]; if ($Matches[1] -eq '8' -and $u -gt 999) { $u = ($u - ($u % 10)) / 10 }
            $ver = "$($Matches[1]).$($Matches[2]).$u"
        }
    }
    if ($prod -eq 'Brave' -and $ver -match '^\d{3,}\.(\d+\.\d+\.\d+)$') { $ver = $Matches[1] }   # 155.1.97.59 -> 1.97.59
    if (-not $ver) { $script:Skipped++; return }
    if ($prod -eq 'Python' -and $ver -notmatch '^[23]\.') { $script:Skipped++; return }   # e.g. the Python install manager's launcher
    $entry = Find-Uninstall $prod $root
    $row = New-Row $prod $ver (Get-MethodOf $prod $root $entry $PyReg) $root $Exe
    if ($entry) { $row.Package = $entry.Name }
    if ($prod -eq 'Java') { $row.Vendor = Get-JavaRelease $root 'IMPLEMENTOR' }
    if ($row.Method -eq 'bundled-in-app') {
        $row.Embedded = $true
        $app = Find-OwningApp $root; if ($app) { $row.AppName = $app.Name }
    }
    if ($prod -in 'PHP', 'Node.js', 'Python', 'Bun') { $row.Arch = Get-PeArch $Exe }
    if ($prod -eq 'PHP') { if (Test-Path -LiteralPath (Join-Path $root 'php8ts.dll')) { $row.Flavor = 'ts' } else { $row.Flavor = 'nts' } }
    if ($prod -eq 'Python') { $row.CertifiOld = @(Get-PyCertifiOld $root $ver) }
    if ($Defaults.ContainsKey($Exe.ToLower())) { $row.Default = $Defaults[$Exe.ToLower()] }
    Add-Row $row
}

function Get-DefaultExes {   # which copy runs when someone types php / node / python
    $d = @{}
    foreach ($c in 'php', 'node', 'python') {
        $cmd = Get-Command $c -CommandType Application -ErrorAction SilentlyContinue | Where-Object { $_.Source -notmatch '\\WindowsApps\\' } | Select-Object -First 1
        if ($cmd) { $d[$cmd.Source.ToLower()] = $c }
    }
    return $d
}

function Add-StorePython {
    $pk = @()
    try { $pk = @(Get-AppxPackage -AllUsers -Name 'PythonSoftwareFoundation.Python.*' -ErrorAction Stop) }
    catch { try { $pk = @(Get-AppxPackage -Name 'PythonSoftwareFoundation.Python.*' -ErrorAction Stop) } catch { } }
    foreach ($p in $pk) {
        $mm = ($p.Name -replace '^PythonSoftwareFoundation\.Python\.', '')
        $row = New-Row 'Python' "$mm (Store)" 'store' "Microsoft Store: $($p.Name)" ''
        $row.Key = "Python|store|$($p.Name)"; $row.Owner = 'store'
        Add-Row $row
    }
}

function Add-VenvRow {   # one row for all Python virtual environments (their certifi lives inside each one)
    if (-not $script:VenvRoots.Count) { return }
    $old = @()
    foreach ($v in ($script:VenvRoots | Select-Object -Unique)) {
        $sps = @(Join-Path $v 'Lib\site-packages') + @(Get-ChildItem -LiteralPath (Join-Path $v 'lib') -Directory -Filter 'python3*' -ErrorAction SilentlyContinue |
                                                      ForEach-Object { Join-Path $_.FullName 'site-packages' })
        foreach ($sp in ($sps | Select-Object -Unique)) { if (Test-Path -LiteralPath $sp) { $old += @(Get-CertifiOld $sp) } }
    }
    $n = @($script:VenvRoots | Select-Object -Unique).Count
    $row = New-Row 'Python' "venvs ($n)" 'venv' "$n virtual environments" ''
    $row.Key = 'Python|venvs'; $row.Owner = 'system'; $row.CertifiOld = $old; $row.Venvs = @($script:VenvRoots | Select-Object -Unique)
    Add-Row $row
}

# ---- libraries inside Python environments and Node.js projects ------------
function Get-Norm([string]$s) { return ("$s".ToLower() -replace '[^a-z0-9]', '') }

function Get-PyEnvOf([string]$Sp) {   # site-packages -> @{ Py; Mode (env | user); Ver (3.X) }
    $e = @{ Py = ''; Mode = 'env'; Ver = '' }
    if ($Sp -match '\\AppData\\Roaming\\Python\\Python(\d)(\d+)\\site-packages$') { $e.Mode = 'user'; $e.Ver = "$($Matches[1]).$($Matches[2])"; return $e }
    $pre = $Sp
    if ($Sp -match '^(.*)\\Lib\\site-packages$') { $pre = $Matches[1] }
    elseif ($Sp -match '^(.*)\\lib\\python(\d+\.\d+)\\site-packages$') { $pre = $Matches[1]; $e.Ver = $Matches[2] }   # MinGW / MSYS layout
    foreach ($c in (Join-Path $pre 'python.exe'), (Join-Path $pre 'Scripts\python.exe'), (Join-Path $pre 'bin\python.exe')) {
        if (Test-Path -LiteralPath $c) { $e.Py = $c; break }
    }
    $cfg = Join-Path $pre 'pyvenv.cfg'
    if (Test-Path -LiteralPath $cfg) {
        $m = Select-String -LiteralPath $cfg -Pattern '^version(_info)?\s*=\s*(\d+\.\d+)' | Select-Object -First 1
        if ($m) { $e.Ver = $m.Matches[0].Groups[2].Value }
    }
    if (-not $e.Ver -and $e.Py) { $v = Get-FileVer $e.Py; if ($v) { $e.Ver = Get-Branch $v 2 } }
    return $e
}

function Add-PyDist([string]$Meta) {   # <site-packages>\<name>-<version>.dist-info\METADATA -> Pillow / Brotli / LiteLLM row
    $dist = Split-Path $Meta -Parent; $sp = Split-Path $dist -Parent
    if ($sp -match '\\uv\\cache\\|\\pip\\cache\\|\\archive-v\d+\\') { return }   # download caches, not Python environments
    $name = ((Split-Path $dist -Leaf) -replace '-.*$', '').ToLower()
    $prod = switch ($name) { 'pillow' { 'Pillow' } 'brotli' { 'Brotli' } 'brotlicffi' { 'Brotli' } 'litellm' { 'LiteLLM' } }
    if (-not $prod) { return }
    $m = Select-String -LiteralPath $Meta -Pattern '^Version:\s*(\S+)' | Select-Object -First 1
    if (-not $m) { $script:Skipped++; return }
    $pe = Get-PyEnvOf $sp
    $row = New-Row $prod $m.Matches[0].Groups[1].Value 'pip' $sp $Meta
    $row.Key = "$prod|$sp|$name"; $row.Lib = $name; $row.Py = $pe.Py; $row.PyMode = $pe.Mode; $row.PyVer = $pe.Ver
    Add-Row $row
}

function Add-NpmCopy([string]$Pj) {   # <project>\node_modules\...\{next,sharp}\package.json -> one row per project (lowest copy)
    $name = (Split-Path (Split-Path $Pj -Parent) -Leaf).ToLower()
    $prod = switch ($name) { 'next' { 'Next.js' } 'sharp' { 'sharp' } }
    if (-not $prod) { return }
    $m = Select-String -LiteralPath $Pj -Pattern '^\s*"version"\s*:\s*"([^"]+)"' | Select-Object -First 1
    if (-not $m) { return }
    $ver = $m.Matches[0].Groups[1].Value
    if ($ver -notmatch '^\d+\.\d+\.\d+$') { return }                      # canary / pre-releases: not rated
    $proj = $Pj.Substring(0, $Pj.ToLower().IndexOf('\node_modules\'))
    if (-not (Test-Path -LiteralPath (Join-Path $proj 'package.json'))) { return }   # global / cache copy without a project
    $key = "$prod|$proj|"
    if ($script:RowIndex.ContainsKey($key)) { $o = $script:RowIndex[$key]; if (Test-VerLt $ver $o.Version) { $o.Version = $ver }; return }
    $row = New-Row $prod $ver 'npm' $proj $Pj
    $row.Key = $key; $row.Lib = $name
    Add-Row $row
}

function Test-LiteLLMIoc([string]$Path) {   # one of the known malicious litellm 1.107.0 files?
    $h = ''; try { $h = (Get-Hash $Path SHA256).ToLower() } catch { }
    if ($h -and $LiteLLMIocSha -contains $h) { return $true }
    $txt = "$(Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue)"
    if ((Split-Path $Path -Leaf) -eq 'cook.pth' -and $txt.Trim() -eq 'import cook') { return $true }
    return ($txt -match $LiteLLMIocMark)
}

function Add-Ioc([string]$F) {   # cook.pth of the litellm 1.107.0 malware (it stays after an uninstall)
    if (-not (Test-LiteLLMIoc $F)) { return }
    $sp = Split-Path $F -Parent
    $row = New-Row 'LiteLLM malware' '1.107.0 hooks' 'ioc' $sp $F
    $row.Key = "LiteLLM malware|$sp|"
    Add-Row $row
}

function Set-LibVerdict($r) {   # libraries, Bun and the malware rows
    $v = $r.Version; $fix = ''; $st = ''; $note = ''
    switch ($r.Product) {
        'Pillow'  { $fix = $PillowFix; $note = 'CVE-2026-112900 (Ghostscript RCE) and 5 more' }
        'Brotli'  {
            $fix = $BrotliFix; if ($r.Lib -eq 'brotlicffi') { $fix = $BrotliCffiFix }
            $note = 'CVE-2026-111497 (Node2Shell) in the Brotli decoder'
            if (Test-VerLt $v '1.0.3') { $st = 'PATCHED'; $note = 'older than the affected range (1.0.3+)' }
        }
        'LiteLLM' {
            if ($LiteLLMBad -contains $v) { $st = 'COMPROMISED'; $fix = '1.106.2'; $note = 'MALICIOUS RELEASE (credential stealer + backdoor) - rotate every credential used on this machine' }
            else { $fix = $LiteLLMFix; $note = 'April-2026 CVEs (CVSS 10.0 RCE)' }
        }
        'Next.js' {
            $b = Get-Branch $v 1; $fix = $NextFix[$b]; $note = 'use-cache RCE, image-optimisation RCE, Server Actions DoS (14 Oct 2026)'
            if (-not $fix) {
                if ([int]$b -gt 16) { $st = 'PATCHED'; $fix = '-'; $note = 'newer line' }
                else { $st = 'VULNERABLE'; $fix = $NextFix['15']; $r.Major = $true
                       $note = "Next.js $b has no fixed release - the project has to move to Next.js $($NextFix['15']) / $($NextFix['16']) (major upgrade)" }
            }
        }
        'sharp'   { $fix = $SharpFix; $note = 'librsvg RCE in image processing (CVE-2026-96889)' }
        'Bun'     { $fix = $BunFix; $note = 'CVE-2026-111497 (Node2Shell) in Bun''s Brotli decoder' }
        'LiteLLM malware' { $st = 'COMPROMISED'; $fix = 'removed'; $note = 'litellm 1.107.0 startup hooks (cook.pth / sitecustomize.py) - rotate every credential used on this machine' }
    }
    if (-not $st) { if (Test-VerLt $v $fix) { $st = 'VULNERABLE' } else { $st = 'PATCHED'; $note = '' } }
    $r.Status = $st; $r.Fixed = $fix; $r.Note = $note
}

# ---- CISA Known Exploited Vulnerabilities: recent additions vs. installed apps (and Windows itself)
function Test-WingetUpdate([string]$Name) {   # $true = winget offers a newer version | $false = none | $null = cannot tell
    if (-not $HasWinget) { return $null }
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & winget.exe list --name $Name --exact --upgrade-available --accept-source-agreements --disable-interactivity 2>&1 | Out-Null; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $eap }
    return ($code -eq 0)
}

function Add-Kev {
    $script:KevState = ''
    try { $kev = @((Get-Json $KevUrl).vulnerabilities) } catch { $script:KevState = 'CISA KEV list could not be downloaded'; return }
    $since = (Get-Date).AddDays(-$KevDays).ToString('yyyy-MM-dd')
    $recent = @($kev | Where-Object { "$($_.dateAdded)" -ge $since })
    # Windows itself: an actively exploited Windows CVE needs the newest cumulative update
    $win = @($recent | Where-Object { $_.vendorProject -eq 'Microsoft' -and $_.product -eq 'Windows' } | Sort-Object dateAdded)
    if ($win.Count) {
        $newest = $win[-1]; $cves = @($win | ForEach-Object { $_.cveID }) -join ', '
        $hf = @(Get-HotFix -ErrorAction SilentlyContinue | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn)
        $row = New-Row 'KEV: Microsoft Windows' "$((Get-CimInstance Win32_OperatingSystem).Version)" 'winupdate' 'Windows Update' ''
        $row.Key = 'KEV: Microsoft Windows|windows|'; $row.Owner = 'system'; $row.Fixed = "update after $($newest.dateAdded)"; $row.Kev = $cves
        $lastTxt = ''; if ($hf.Count) { $lastTxt = " (newest installed: $($hf[-1].HotFixID) on $($hf[-1].InstalledOn.ToString('yyyy-MM-dd')))" }
        if ($hf.Count -and $hf[-1].InstalledOn -ge [datetime]"$($newest.dateAdded)") { $row.Status = 'PATCHED'; $row.Note = "CISA KEV (actively exploited): $cves - a Windows update was installed after it was listed$lastTxt" }
        else { $row.Status = 'VULNERABLE'; $row.Note = "CISA KEV (actively exploited): $cves - no Windows update installed since $($newest.dateAdded)$lastTxt" }
        Add-Row $row
    }
    $skip = 'chrom|firefox|edge|java|node\.?js|php|python|kernel|windows|multiple products|android|ios|macos'
    foreach ($v in $recent) {
        if ("$($v.vendorProject) $($v.product)" -match $skip) { continue }
        $vend = Get-Norm $v.vendorProject; $prod = Get-Norm $v.product; $vend1 = Get-Norm (@("$($v.vendorProject)" -split '\s+')[0])
        foreach ($e in $script:Entries) {
            $n = Get-Norm $e.Name
            $hit = $n.Contains($vend + $prod) -or ($prod.Length -ge 5 -and $n.Contains($prod) -and ($n.Contains($vend1) -or (Get-Norm $e.Publisher).Contains($vend1)))
            if (-not $hit) { continue }
            $key = "KEV: $($e.Name)|app|"
            if ($script:RowIndex.ContainsKey($key)) { if ($script:RowIndex[$key].Kev -notlike "*$($v.cveID)*") { $script:RowIndex[$key].Kev += ", $($v.cveID)" }; continue }
            $row = New-Row "KEV: $($e.Name)" $e.Version 'winget' "app: $($e.Name)" ''
            $row.Key = $key; $row.Package = $e.Name; $row.Kev = $v.cveID; $row.KevDate = $v.dateAdded; $row.KevAction = ("$($v.requiredAction)" -replace '\s+', ' ')
            Add-Row $row
        }
    }
    foreach ($r in @($script:Rows | Where-Object { $_.Method -eq 'winget' })) {   # exposed while winget offers a newer version
        $r.Fixed = 'latest'; $u = Test-WingetUpdate $r.Package
        if ($u -eq $true) { $r.Status = 'VULNERABLE'; $r.Note = "CISA KEV (actively exploited, added $($r.KevDate)): $($r.Kev) - winget has a newer version" }
        elseif ($u -eq $false) { $r.Status = 'PATCHED'; $r.Note = "CISA KEV (actively exploited, added $($r.KevDate)): $($r.Kev) - newest version available through winget is installed; confirm with the vendor advisory: $($r.KevAction)" }
        else { $r.Status = 'REVIEW'; $r.Note = "CISA KEV (actively exploited, added $($r.KevDate)): $($r.Kev) - no winget to check for a newer version: $($r.KevAction)" }
    }
}

# Windows trust store: Microsoft blocks the compromised eMudhra intermediates through its own update channel.
function Add-CaStore {
    $g3  = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\AuthRoot -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'CN=emSign ECC Root CA - G3' })
    $dis = @(Get-ChildItem Cert:\LocalMachine\Disallowed -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'emSign|eMudhra' })
    $row = New-Row 'CA store' 'Windows' 'windows' 'Cert:\LocalMachine\Root' ''
    $row.Key = 'CA store|windows'; $row.Owner = 'system'; $row.Fixed = 'G3 distrusted'
    if ($dis.Count) { $row.Status = 'PATCHED'; $row.Note = "Windows distrust list holds $($dis.Count) eMudhra certificate(s)" }
    elseif ($g3.Count) { $row.Status = 'VULNERABLE'; $row.Note = 'emSign ECC Root CA - G3 is trusted and not in the Disallowed store' }
    else { $row.Status = 'PATCHED'; $row.Note = 'emSign ECC Root CA - G3 is not trusted on this machine' }
    Add-Row $row
}

function Get-NodeTarget([string]$v) {   # fixed version of the same line, or the nearest supported line for end-of-life ones
    $br = Get-Branch $v 1
    if ($NodeFix.ContainsKey($br)) { return $NodeFix[$br] }
    foreach ($m in @($NodeFix.Keys | Sort-Object { [int]$_ })) { if ([int]$m -gt [int]$br) { return $NodeFix[$m] } }
    return $null
}

function Set-Verdict($r) {
    if ($r.Product -eq 'CA store') { return }
    $v = $r.Version; $st = ''; $fix = ''; $note = ''
    if ($r.Method -eq 'store') { $r.Status = 'REVIEW'; $r.Note = 'Microsoft Store package - Windows Store keeps it updated'; return }
    if ($r.Product -like 'KEV:*') { return }   # rated by Add-Kev
    if ($r.Product -in 'Pillow', 'Brotli', 'LiteLLM', 'Next.js', 'sharp', 'Bun', 'LiteLLM malware') { Set-LibVerdict $r; return }
    if ($r.Product -eq 'Java') {   # rated on the eMudhra block list (CVE-2026-91403); the October CPU version is reported with it
        $major = Get-Branch $v 1; $fix = $JavaFix[$major]
        $f = Get-JavaBlockFile $r.Root; $n = Get-JavaFpCount $f
        if ($n -eq $EmudhraFps.Count) { $r.Status = 'PATCHED'; $note = 'eMudhra certificates blocked (CVE-2026-91403)' }
        else { $r.Status = 'VULNERABLE'; $note = "CVE-2026-91403: $n of $($EmudhraFps.Count) eMudhra certificates blocked in $(Split-Path $f -Leaf)" }
        if (-not $fix) { $fix = '-'; $note += "; Java $major is end-of-life (no more updates) - plan a move to Java 21 or 25" }
        elseif (Test-VerLt $v $fix) { $note += "; older than the October 2026 update ($fix)" }
        if ($r.Vendor) { $note += "; $($r.Vendor)" }
        if ($r.Embedded) { $note += "; built into $(if ($r.AppName) { $r.AppName } else { 'another application' })" }
        $r.Fixed = $fix; $r.Note = $note
        return
    }
    if ($r.Method -eq 'venv') {
        $r.Fixed = $CertifiFix
        if ($r.CertifiOld.Count) { $r.Status = 'VULNERABLE'; $r.Note = "$($r.CertifiOld.Count) certifi copies in virtualenvs still trust the compromised eMudhra CAs" }
        else { $r.Status = 'PATCHED'; $r.Note = 'no outdated certifi in any virtualenv' }
        return
    }
    switch ($r.Product) {
        'PHP' {
            $br = Get-Branch $v 2
            if ($PhpFix.ContainsKey($br)) { $fix = $PhpFix[$br] }
            elseif (Test-VerLt $br '8.2') { $st = 'EOL'; $fix = $PhpFix['8.2']; $note = "PHP $br is end-of-life - moved to PHP 8.2 (branch change)" }
            else { $st = 'PATCHED'; $note = 'newer branch' }
        }
        'Node.js' {
            $br = Get-Branch $v 1; $fix = Get-NodeTarget $v
            if (-not $NodeFix.ContainsKey($br)) {
                if ($fix) { $st = 'EOL'; $note = "Node.js $br is end-of-life - moved to Node.js $(Get-Branch $fix 1) (major version change)" }
                else { $st = 'PATCHED'; $note = 'newer release line' }
            }
        }
        'Python' {
            $br = Get-Branch $v 2
            if ($PyFix.ContainsKey($br)) { $fix = $PyFix[$br] }
            elseif (Test-VerLt $br '3.10') { $st = 'EOL'; $note = "Python $br is end-of-life" }
            else { $st = 'PATCHED'; $note = "no newer CPython $br release exists - only certifi matters" }
        }
        'Chrome'   { $fix = $ChromeFix }
        'Chromium' { $fix = $ChromeFix }
        'Edge'     { $fix = $EdgeFix }
        'Brave'    { $fix = $BraveFix }
        'Firefox'  {
            switch ((Get-Branch $v 1)) { '153' { $fix = '153.5.1'; $note = 'ESR' } '115' { $fix = '115.43.1'; $note = 'ESR' } default { $fix = $FirefoxFix } }
        }
    }
    if (-not $st) { if (Test-VerLt $v $fix) { $st = 'VULNERABLE' } else { $st = 'PATCHED' } }
    if ($r.Product -eq 'Python' -and $r.CertifiOld.Count) {
        $note = (@($note, "bundled certifi $($r.CertifiOld[0].Version) still trusts the compromised eMudhra CAs") | Where-Object { $_ }) -join '; '
        if ($st -eq 'PATCHED') { $st = 'VULNERABLE' }
    }
    if ($r.Embedded) { $note = (@($note, "built into $(if ($r.AppName) { $r.AppName } else { 'another application' })") | Where-Object { $_ }) -join '; ' }
    if ($r.Method -eq 'download-in-temp') { $note = (@($note, 'found in a temp folder') | Where-Object { $_ }) -join '; ' }
    $r.Status = $st; $r.Fixed = $fix; $r.Note = $note
}

function Add-Missing {
    foreach ($p in $Products) {
        if (-not ($script:Rows | Where-Object { $_.Product -eq $p })) {
            $row = New-Row $p '-' '-' '-' ''
            $row.Key = "$p|missing"; $row.Status = 'NOT FOUND'; $row.Fixed = '-'; $row.Owner = '-'; $row.Note = 'not installed on this machine'
            Add-Row $row
        }
    }
}

function Invoke-Detection {
    $script:Rows = @(); $script:RowIndex = @{}
    $script:Skipped = 0; $script:VenvRoots = @()
    $script:Entries = @(Get-UninstallEntries)
    $pyReg = Get-PythonRegistry
    $defaults = Get-DefaultExes
    foreach ($f in @(Find-ProgramFiles)) {
        switch ((Split-Path $f -Leaf).ToLower()) {
            'package.json' { Add-NpmCopy $f }
            'metadata'     { Add-PyDist $f }
            'cook.pth'     { Add-Ioc $f }
            default        { Add-Copy $f $pyReg $defaults }
        }
    }
    Add-StorePython
    Add-VenvRow
    Add-CaStore
    foreach ($r in $script:Rows) { Set-Verdict $r }
    Add-Kev
    Add-Missing
}

# ---- reports ----------------------------------------------------------------
function Get-Rank([string]$s) { switch ($s) { 'VULNERABLE' { 0 } 'COMPROMISED' { 0 } 'EOL' { 1 } 'REVIEW' { 2 } 'PATCHED' { 3 } default { 4 } } }
function Get-ProdRank([string]$p) {
    $order = 'LiteLLM malware', 'PHP', 'Node.js', 'Bun', 'Python', 'Java', 'Chrome', 'Chromium', 'Edge', 'Brave', 'Firefox', 'CA store', 'LiteLLM', 'Pillow', 'Brotli', 'Next.js', 'sharp'
    for ($i = 0; $i -lt $order.Count; $i++) { if ($order[$i] -eq $p) { return $i } }
    return 9
}
function Get-StatusColor([string]$s) { switch ($s) { 'VULNERABLE' { 'Red' } 'COMPROMISED' { 'Red' } 'EOL' { 'Red' } 'REVIEW' { 'Yellow' } 'PATCHED' { 'Green' } default { 'DarkGray' } } }

function Show-Report {
    $sorted = @($script:Rows | Sort-Object @{ e = { Get-Rank $_.Status } }, @{ e = { Get-ProdRank $_.Product } }, @{ e = { $_.Root } })
    Write-Host ("`n  {0,-11} {1,-9} {2,-15} {3,-15} {4}" -f 'STATUS', 'PRODUCT', 'VERSION', 'FIXED_IN', 'LOCATION')
    Write-Host "  $Line"
    foreach ($r in $sorted) {
        $fx = $r.Fixed; if (-not $fx) { $fx = '-' }
        Write-Host ('  {0,-11} ' -f $r.Status) -ForegroundColor (Get-StatusColor $r.Status) -NoNewline
        Write-Host ('{0,-9} {1,-15} {2,-15} {3}' -f (Get-DispProd $r.Product), $r.Version, $fx, (Get-ShortLoc $r.Root))
    }
    $bad = @($sorted | Where-Object { $_.Status -in 'VULNERABLE', 'EOL', 'REVIEW' })
    if ($bad.Count) {
        Write-Host "`n  Why" -ForegroundColor Cyan
        foreach ($r in $bad) {
            $def = ''; if ($r.Default) { $def = "  <- default '$($r.Default)'" }
            Write-Host ("    {0} {1} [{2}] {3}{4}" -f $r.Product, $r.Version, $r.Status, $r.Root, $def)
            if ($r.Note) { Write-Host "      $($r.Note)" -ForegroundColor DarkGray }
        }
    }
    Show-Summary
}

function Show-Summary {
    $c = @{}
    foreach ($s in 'VULNERABLE', 'COMPROMISED', 'EOL', 'REVIEW', 'PATCHED', 'NOT FOUND') { $c[$s] = @($script:Rows | Where-Object { $_.Status -eq $s }).Count }
    Write-Host ("`n  Summary: {0} vulnerable, {1} end-of-life, {2} review, {3} patched, {4} not installed" -f ($c['VULNERABLE'] + $c['COMPROMISED']), $c['EOL'], $c['REVIEW'], $c['PATCHED'], $c['NOT FOUND'])
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "  NOT FOUND (not installed): $($miss -join ', ')" -ForegroundColor DarkGray }
    $script:ResultBad = $c['VULNERABLE'] + $c['COMPROMISED'] + $c['EOL']
}

function Show-Brief {
    $found = @($script:Rows | Where-Object { $_.Status -ne 'NOT FOUND' })
    $ok = @($found | Where-Object { $_.Status -eq 'PATCHED' })
    Write-Host ("  Found {0} copies: {1} vulnerable, {2} end-of-life, {3} review, {4} already patched   (full table: -Scan)" -f `
        $found.Count, @($found | Where-Object { $_.Status -in 'VULNERABLE', 'COMPROMISED' }).Count, @($found | Where-Object { $_.Status -eq 'EOL' }).Count,
        @($found | Where-Object { $_.Status -eq 'REVIEW' }).Count, $ok.Count)
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "  NOT FOUND (not installed): $($miss -join ', ')" -ForegroundColor DarkGray }
}

function Write-JsonReport([string]$Path) {
    $find = @()
    foreach ($r in @($script:Rows | Where-Object { $_.Status -ne 'NOT FOUND' })) {
        $find += @{ product = $r.Product; version = $r.Version; fixed_in = $r.Fixed; status = $r.Status; method = $r.Method
                    location = $r.Root; exe = $r.Exe; owner = $r.Owner; app = $r.AppName; default_on_path = $r.Default; note = $r.Note }
    }
    $out = @{ host = $env:COMPUTERNAME; scanned_at = (Get-Date -Format s); as_admin = $IsAdmin; language_mode = "$($ExecutionContext.SessionState.LanguageMode)"
              findings = $find; not_found = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product }) }
    New-Item -ItemType Directory -Force -Path (Split-Path $Path -Parent) | Out-Null
    $out | ConvertTo-Json -Depth 5 | Set-Content -Path $Path -Encoding UTF8
}

# =============================================================================
# PLAN - every finding gets an automatic action
# =============================================================================
function Get-ProdToken([string]$p) { if ($p -like 'KEV:*') { return 'kev' }; switch ($p) { 'Node.js' { 'node' } 'Next.js' { 'next' } 'CA store' { 'ca' } 'LiteLLM malware' { 'litellm' } default { $p.ToLower() } } }
function Get-DispProd([string]$p) { if ($p -like 'KEV:*') { return 'KEV' }; if ($p -eq 'LiteLLM malware') { return 'MALWARE' }; return $p }   # fits the 8-wide column
function Test-Selected([string]$p) { (-not $OnlyList.Count) -or ($OnlyList -contains (Get-ProdToken $p)) }

function Get-MatchKey($r) {   # survives a patch: product + location + branch
    $br = ''
    if ($r.Product -in 'PHP', 'Python') { $br = Get-Branch $r.Version 2 }
    if ($r.Product -eq 'Node.js') { $br = Get-Branch $r.Version 1 }
    if ($r.Method -eq 'venv') { $br = '' }
    if ($r.Lib) { $br = $r.Lib }   # libraries: brotli and brotlicffi can share a site-packages
    return "$($r.Product)|$($r.Root)|$br"
}

function Set-Kind($r) {   # picks the action for one finding
    $m = $r.Method; $p = $r.Product; $kind = ''; $desc = ''
    $appStep = ''; if ($r.Embedded -and $r.AppName -and $HasWinget) { $appStep = "winget upgrade '$($r.AppName)', then " }
    if ($p -eq 'LiteLLM malware') { $kind = 'ioc'; $desc = 'quarantine the malicious startup files, stop the backdoor, block its server - then ROTATE credentials' }
    elseif ($m -eq 'pip') {
        if ($r.Status -eq 'COMPROMISED') { $kind = 'litellm'; $desc = "remove malicious litellm $($r.Version) and its startup files, install clean litellm - then ROTATE credentials" }
        else { $kind = 'pip'; $desc = "pip install -U '$(Get-LibSpec $r)' in this Python" }
    }
    elseif ($m -eq 'npm') {
        if ($r.Major) { $kind = 'external'; $desc = $r.Note }
        else { $kind = 'npm'; $desc = "update to $(Get-NpmSpec $r) in this project (package.json + lock file backed up)" }
    }
    elseif ($p -eq 'Bun') { $kind = 'bun'; $desc = "Bun $BunFix swapped in (SHA-256 checked)" }
    elseif ($m -eq 'winget') {
        if ($HasWinget) { $kind = 'kev'; $desc = "winget upgrade '$($r.Package)' (CISA KEV)" }
        else { $kind = 'external'; $desc = "no winget on this PC - update '$($r.Package)' from the vendor: $($r.KevAction)" }
    }
    elseif ($m -eq 'winupdate') { $kind = 'winupdate'; $desc = 'start Windows Update (scan, download, install) - restart when Windows asks' }
    elseif ($p -eq 'CA store') { $kind = 'ca'; $desc = 'mark emSign ECC Root CA - G3 as untrusted (certutil)' }
    elseif ($m -eq 'venv') { $kind = 'venvs'; $desc = "refresh certifi in $($r.Venvs.Count) virtualenvs" }
    elseif ($m -eq 'store') { $kind = 'external'; $desc = 'Microsoft Store package - Windows updates it' }
    elseif ($p -eq 'Python') {
        $needRt = $r.Fixed -and (Test-VerLt $r.Version $r.Fixed)
        if ($m -eq 'installer' -or ($m -eq 'installer-user' -and $r.Owner -eq $Me -and $r.Root -match '\\Programs\\Python\\')) {
            if ($needRt) { $kind = 'installer'; $desc = "Python $($r.Fixed) installer (python.org)" }
            else { $kind = 'certifi'; $desc = 'refresh certifi' }
        } elseif ($needRt -and $m -eq 'pymanager' -and $r.Owner -eq $Me) { $kind = 'pymanager'; $desc = "py install --update $(Get-Branch $r.Version 2)" }
        elseif ($needRt -and (Get-PyLayout $r)) { $kind = 'runtime'; $desc = "$($appStep)python.org $($r.Fixed) runtime files swapped in (site-packages kept)" }
        elseif ($needRt) { $kind = 'certifi'; $desc = "$($appStep)refresh certifi (MinGW/custom build: only its vendor can ship Python $($r.Fixed))" }
        else { $kind = 'certifi'; $desc = "$($appStep)refresh certifi in place" }
    }
    elseif ($p -eq 'Java') { $kind = 'java'; $desc = "$($appStep)add the eMudhra fingerprints to $(Split-Path (Get-JavaBlockFile $r.Root) -Leaf)" }
    elseif ($p -eq 'Node.js') {
        if ($m -eq 'msi') { $kind = 'installer'; $desc = "Node.js $($r.Fixed) MSI" }
        elseif ($r.Embedded -or -not (Test-Path -LiteralPath (Join-Path $r.Root 'node_modules\npm'))) { $kind = 'node-bin'; $desc = "$($appStep)swap node.exe for $($r.Fixed)" }
        else { $kind = 'replace'; $desc = "Node.js $($r.Fixed) swapped into the same folder" }
    }
    elseif ($p -eq 'PHP') { $kind = 'replace'; $desc = "PHP $($r.Fixed) zip copied over the folder (php.ini kept)" }
    elseif ($p -in 'Chrome', 'Edge', 'Firefox', 'Brave') {
        if ($m -eq 'installer') { $kind = 'installer'; $desc = "$p enterprise installer" }
        elseif ($m -eq 'installer-user' -and $r.Owner -eq $Me -and $p -in 'Chrome', 'Firefox') { $kind = 'user-installer'; $desc = "$p per-user installer" }
        elseif ($m -eq 'installer-user') { $kind = 'external'; $desc = "per-user install of $($r.Owner) - its own updater runs when $($r.Owner) signs in" }
        elseif ($p -eq 'Chrome' -or $r.Embedded) { $kind = 'chromium'; $desc = "$($appStep)Chrome for Testing $ChromeFix swapped in" }
        else { $kind = 'external'; $desc = "portable $p - no vendor package to swap in" }
    }
    elseif ($p -eq 'Chromium') { $kind = 'chromium'; $desc = "$($appStep)Chrome for Testing $ChromeFix swapped into the same folder" }
    $r.Kind = $kind; $r.Desc = $desc
}

function Build-Plan {
    $script:PickOrder = @(); $script:External = @()
    $cand = @($script:Rows | Where-Object { $_.Status -notin 'PATCHED', 'NOT FOUND' -and (Test-Selected $_.Product) } |
              Sort-Object @{ e = { Get-ProdRank $_.Product } }, @{ e = { Get-SortVer $_.Version } }, @{ e = { $_.Root } })
    foreach ($r in $cand) {
        Set-Kind $r
        $r.MatchKey = Get-MatchKey $r; $r.InPlan = $true
        if ($r.Kind -eq 'external') { $script:External += $r } else { $script:PickOrder += $r }
    }
}

function Get-ActionLabel($r) {
    switch ($r.Kind) {
        'installer' { 'installer' } 'user-installer' { 'installer' } 'replace' { 'replace' } 'node-bin' { 'replace' }
        'chromium' { 'replace' } 'runtime' { 'replace' } 'certifi' { 'certifi' } 'venvs' { 'certifi' } 'pymanager' { 'py update' }
        'ca' { 'distrust' } 'java' { 'blocklist' } 'pip' { 'pip update' } 'npm' { 'npm update' }
        'litellm' { 'clean' } 'ioc' { 'clean' } 'bun' { 'replace' } 'kev' { 'update' } 'winupdate' { 'win update' }
        default { '-' }
    }
}
function Get-EstMin($r) { switch ($r.Kind) { 'installer' { 2 } 'user-installer' { 2 } 'chromium' { 2 } 'runtime' { 2 } 'npm' { 2 } default { 1 } } }

function Show-Plan {
    Write-Host ("`n  {0,3}  {1,-8} {2,-16}    {3,-14} {4,-11} {5,4}  {6}" -f '#', 'PRODUCT', 'INSTALLED', 'FIXED IN', 'ACTION', 'TIME', 'LOCATION')
    Write-Host "  $Line"
    $i = 0; $total = 0
    foreach ($r in $script:PickOrder) {
        $i++; $m = Get-EstMin $r; $total += $m; $fx = $r.Fixed; if (-not $fx) { $fx = '-' }
        Write-Host ('  {0,3}  {1,-8} {2,-16} -> {3,-14} {4,-11} {5,3}m  {6}' -f $i, (Get-DispProd $r.Product), $r.Version, $fx, (Get-ActionLabel $r), $m, (Get-ShortLoc $r.Root))
    }
    if ($i -eq 0) { Write-Host '       (nothing to patch)' -ForegroundColor DarkGray }
    Write-Host "  $Line"
    Write-Host "  $i can be patched - all of them: ~$total min"
    Write-Host '  installer = the vendor''s official installer for the fixed version, upgrading this copy in place' -ForegroundColor DarkGray
    Write-Host '  replace   = the fixed release swapped into the same folder (runtimes inside apps: app update first)' -ForegroundColor DarkGray
    Write-Host '  certifi   = refresh the certificate bundle inside that Python (removes the compromised eMudhra CAs)' -ForegroundColor DarkGray
    Write-Host '  py update = py install --update   |   distrust = mark the emSign G3 root untrusted in Windows' -ForegroundColor DarkGray
    Write-Host '  blocklist = add the 16 eMudhra certificates to that Java''s blocked.certs (CVE-2026-91403)' -ForegroundColor DarkGray
    Write-Host '  pip / npm update = the fixed version installed in that Python environment / project (package.json + lock file backed up)' -ForegroundColor DarkGray
    Write-Host '  clean     = malicious files quarantined, backdoor stopped, clean version installed - credentials must be ROTATED' -ForegroundColor DarkGray
    Write-Host '  KEV       = on the CISA list of actively exploited vulnerabilities - updated to the newest version available' -ForegroundColor DarkGray
    Write-Host '  Old versions are backed up during the run and deleted once the fix is verified (-KeepBackups keeps them)' -ForegroundColor DarkGray
    if ($script:External.Count) {
        Write-Host "`n  Updated outside this script ($($script:External.Count)):" -ForegroundColor DarkGray
        foreach ($r in $script:External) { Write-Host "    - $($r.Product) $($r.Version)  $(Get-ShortLoc $r.Root): $($r.Desc)" -ForegroundColor DarkGray }
    }
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "`n  NOT FOUND (not installed, nothing to patch): $($miss -join ', ')" -ForegroundColor DarkGray }
}

function Set-Pick([string]$Spec) {   # all | none | 1,3,5-7 | php,node -> marks .Picked; $false on bad input
    foreach ($r in $script:PickOrder) { $r.Picked = $false }
    $s = ($Spec -replace '\s', '').ToLower()
    if (-not $s -or $s -eq 'all') { foreach ($r in $script:PickOrder) { $r.Picked = $true }; return $true }
    if ($s -eq 'none') { return $true }
    $n = $script:PickOrder.Count
    foreach ($tok in @($s -split ',' | Where-Object { $_ })) {
        if ($tok -match '^\d+$') { $a = [int]$tok; $b = $a }
        elseif ($tok -match '^(\d+)-(\d+)$') { $a = [int]$Matches[1]; $b = [int]$Matches[2] }
        else {
            $hit = $false
            foreach ($r in $script:PickOrder) { if ((Get-ProdToken $r.Product) -eq $tok) { $r.Picked = $true; $hit = $true } }
            if (-not $hit) { Write-Note "nothing in the list matches '$tok'"; return $false }
            continue
        }
        if ($a -lt 1 -or $b -gt $n -or $a -gt $b) { Write-Note "'$tok' is not a number between 1 and $n"; return $false }
        for ($i = $a; $i -le $b; $i++) { $script:PickOrder[$i - 1].Picked = $true }
    }
    return $true
}

function Select-Items {   # asks (or takes -Pick) which items to patch; $false = cancel
    if ($Pick) { if (-not (Set-Pick $Pick)) { return $false } }
    elseif ($Yes) { [void](Set-Pick 'all') }
    else {
        while ($true) {
            Write-Host "`n  Which copies should be patched?"
            Write-Host '    all          every numbered item'
            Write-Host '    1,3,5-7      only those numbers from the list above'
            Write-Host '    php,node     everything of those products (php node bun python java chrome chromium edge firefox brave ca litellm pillow brotli next sharp kev)'
            Write-Host '    none         cancel'
            $ans = Read-Host '  Your choice [all]'
            if (Set-Pick $ans) { break }
        }
    }
    $chosen = @($script:PickOrder | Where-Object { $_.Picked })
    if (-not $chosen.Count) { Write-Host '  Nothing selected - nothing changed.'; return $false }
    $total = 0; foreach ($r in $chosen) { $total += Get-EstMin $r }
    Write-Host "`n  Selected $($chosen.Count) of $($script:PickOrder.Count) item(s) from the plan above - estimated ~$total min"
    if (-not $Yes) {
        if ((Read-Host '  Type YES to start') -ne 'YES') { Write-Host '  Aborted - nothing changed.'; return $false }
    }
    return $true
}

# =============================================================================
# PATCH ACTIONS
# =============================================================================
function Get-RunningUnder([string]$Root) {
    $r = $Root.ToLower()
    @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.ToLower().StartsWith("$r\") })
}

function Save-Backup([string]$Path, [string]$Exclude) {   # zip of a folder or a single file, kept outside the scanned locations
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
    $zip = Join-Path $BackupDir ((($Path -replace '[:\\]+', '_').Trim('_')) + "-$Stamp.zip")
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
    New-Zip $Path $zip $Exclude
    if ($script:CurRow) { $script:CurRow.Backups += $zip }   # deleted once this item's fix is verified
    return $zip
}

function Assert-NotRunning([string]$Root) {
    $busy = @(Get-RunningUnder $Root)
    if ($busy.Count) { throw "close these first - they run from $Root`: $(($busy | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ', ')" }
}

# swaps a freshly extracted tree into the exact folder of the old one (shortcuts, PATH and services keep working)
function Install-Swap($r, [string]$NewTree) {
    Assert-NotRunning $r.Root
    $zip = Save-Backup $r.Root
    $leaf = Split-Path $r.Root -Leaf
    $old = "$($r.Root).vulnpatch-old"
    Rename-Item -LiteralPath $r.Root -NewName "$leaf.vulnpatch-old"
    try { Move-Item -LiteralPath $NewTree -Destination $r.Root }
    catch { Rename-Item -LiteralPath $old -NewName $leaf; throw "swap failed - old copy restored: $_" }
    Remove-Item -LiteralPath $old -Recurse -Force
    return "replaced in place (backup: $zip)"
}

function Invoke-AppUpdate($r) {   # runtime inside an app: let the app's own package update it first
    if (-not ($r.Embedded -and $r.AppName -and $HasWinget)) { return $false }
    Write-Host "    winget upgrade '$($r.AppName)' ..."
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # winget writes progress to stderr
    try { & winget.exe upgrade --name $r.AppName --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-Null }
    finally { $ErrorActionPreference = $old }
    $v = Get-FileVer $r.Exe
    return [bool]($v -and $r.Fixed -and -not (Test-VerLt $v $r.Fixed))
}

function Get-NodeZip([string]$Version, [string]$Arch) {
    $a = 'x64'; if ($Arch -eq 'x86') { $a = 'x86' } elseif ($Arch -eq 'arm64') { $a = 'arm64' }
    $name = "node-v$Version-win-$a.zip"
    $sums = Get-WebText "https://nodejs.org/dist/v$Version/SHASUMS256.txt"
    $line = @($sums -split "`n") | Where-Object { $_ -match "\s$([regex]::Escape($name))\s*$" } | Select-Object -First 1
    if (-not $line) { throw "no SHA-256 published for $name" }
    $zip = Get-Download "https://nodejs.org/dist/v$Version/$name" $name (@($line.Trim() -split '\s+')[0]) '' ''
    return @{ Zip = $zip; Folder = "node-v$Version-win-$a" }
}

function Update-NodeFolder($r) {
    $z = Get-NodeZip $r.Fixed $r.Arch
    $tmp = Join-Path (Split-Path $r.Root -Parent) ".vulnpatch-$Stamp"
    Expand-Zip $z.Zip $tmp
    try { return (Install-Swap $r (Join-Path $tmp $z.Folder)) } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force } }
}

function Update-NodeBinary($r) {   # node.exe shipped inside an app: same line (or nearest supported line) swapped in
    if (Invoke-AppUpdate $r) { return "updated by the application's own package ($($r.AppName))" }
    Assert-NotRunning $r.Root
    $z = Get-NodeZip $r.Fixed $r.Arch
    $tmp = Join-Path $env:TEMP "vulnpatch-node-$Stamp"
    Expand-Zip $z.Zip $tmp
    try {
        $bak = Save-Backup $r.Exe
        Copy-Item -LiteralPath (Join-Path $tmp "$($z.Folder)\node.exe") -Destination $r.Exe -Force
    } finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    return "node.exe $($r.Version) -> $($r.Fixed) (backup: $bak)"
}

function Update-PhpZip($r) {
    $br = Get-Branch $r.Fixed 2
    $all = Get-Json 'https://windows.php.net/downloads/releases/releases.json'
    $rel = $all.$br
    if (-not $rel -or (Test-VerLt $rel.version $r.Fixed)) { throw "windows.php.net does not offer PHP $($r.Fixed)+ for branch $br yet" }
    $arch = 'x64'; if ($r.Arch -eq 'x86') { $arch = 'x86' }
    $key = @($rel | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name } | Where-Object { $_ -match "^$($r.Flavor)-vs\d+-$arch$" })[0]
    if (-not $key) { throw "no $($r.Flavor.ToUpper()) $arch build of PHP $($rel.version) on windows.php.net" }
    $file = $rel.$key.zip
    $zip = Get-Download "https://windows.php.net/downloads/releases/$($file.path)" $file.path $file.sha256 '' ''
    Assert-NotRunning $r.Root
    $bak = Save-Backup $r.Root
    $tmp = Join-Path $env:TEMP "vulnpatch-php-$Stamp"
    Expand-Zip $zip $tmp
    Copy-Item -Path (Join-Path $tmp '*') -Destination $r.Root -Recurse -Force   # php.ini is not in the zip, extra extensions stay
    Remove-Item -LiteralPath $tmp -Recurse -Force
    return "PHP $($rel.version) $($r.Flavor.ToUpper()) $arch copied over the folder, php.ini kept (backup: $bak)"
}

function Get-CertifiPem {   # cacert.pem + version from the current certifi wheel on PyPI (SHA-256 checked)
    if ($script:CertifiPem) { return $script:CertifiPem }
    $j = Get-Json 'https://pypi.org/pypi/certifi/json'
    $w = @($j.urls) | Where-Object { $_.packagetype -eq 'bdist_wheel' } | Select-Object -First 1
    if (-not $w) { throw 'PyPI lists no certifi wheel' }
    $whl = Get-Download $w.url "certifi-$($j.info.version).zip" $w.digests.sha256 '' ''
    $tmp = Join-Path $DlDir "certifi-$($j.info.version)"
    if (-not (Test-Path -LiteralPath $tmp)) { Expand-Zip $whl $tmp }
    $script:CertifiPem = @{ Pem = (Join-Path $tmp 'certifi\cacert.pem'); Version = "$($j.info.version)" }
    return $script:CertifiPem
}

function Update-CertifiDirs($dirs) {   # replaces the CA bundle and version stamp; the code of each copy is untouched
    $c = Get-CertifiPem
    $n = 0
    foreach ($d in $dirs) {
        [void](Save-Backup $d.Dir)
        Copy-Item -LiteralPath $c.Pem -Destination (Join-Path $d.Dir 'cacert.pem') -Force
        $init = Join-Path $d.Dir '__init__.py'
        $txt = @(Get-Content -LiteralPath $init) | ForEach-Object { $_ -replace '^__version__ = "[^"]*"', "__version__ = `"$($c.Version)`"" }
        Set-Content -LiteralPath $init -Value $txt -Encoding ASCII
        $n++
    }
    return "certifi $($c.Version) bundle in $n place(s)"
}

function Update-Certifi($r) {
    $pre = ''
    if (Invoke-AppUpdate $r) { $pre = "app updated ($($r.AppName)); " }
    $dirs = @(Get-PyCertifiOld $r.Root $r.Version)
    if (-not $dirs.Count) { return "$($pre)certifi already current" }
    return $pre + (Update-CertifiDirs $dirs)
}

function Update-Venvs($r) { return (Update-CertifiDirs $r.CertifiOld) + " across $($r.Venvs.Count) virtualenvs" }

function Add-CertifiStep($r, [string]$Msg) {   # after a runtime update: the certifi copies in its site-packages too
    $dirs = @(Get-PyCertifiOld $r.Root $r.Version)
    if ($dirs.Count) { $Msg += '; ' + (Update-CertifiDirs $dirs) }
    return $Msg
}

function Update-PyManager($r) {
    $tag = Get-Branch $r.Version 2
    $py = Get-Command py.exe -ErrorAction SilentlyContinue
    if (-not $py) { return 'py is not on PATH - ' + (Update-PyRuntime $r) }
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $py.Source install --update $tag 2>&1; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    if ($code -ne 0) { return "py install --update $tag failed ($((@($out) | Select-Object -Last 1) -join ' ')) - " + (Update-PyRuntime $r) }
    return Add-CertifiStep $r "py install --update $tag"
}

function Get-PyReleaseFile([string]$Version, [string]$Name) {   # a python.org download, checked against python.org's SHA-256
    $relApi = Get-Json "https://www.python.org/api/v2/downloads/release/?name=Python%20$Version"
    $id = @(@($relApi)[0].resource_uri -split '/')[-2]
    $files = Get-Json "https://www.python.org/api/v2/downloads/release_file/?release=$id"
    $sha = (@($files) | Where-Object { $_.url -like "*/$Name" } | Select-Object -First 1).sha256_sum
    if (-not $sha) { throw "python.org lists no SHA-256 for $Name" }
    return Get-Download "https://www.python.org/ftp/python/$Version/$Name" $Name $sha '' ''
}

function Get-PyNuget([string]$Version, [string]$Arch) {   # python.org's NuGet package = a complete Python folder (SHA-512 from nuget.org)
    $id = 'python'; if ($Arch -eq 'x86') { $id = 'pythonx86' } elseif ($Arch -eq 'arm64') { $id = 'pythonarm64' }
    $reg = Get-Json "https://api.nuget.org/v3/registration5-semver1/$id/$Version.json"
    $cat = Get-Json $reg.catalogEntry
    if ("$($cat.authors)" -notmatch 'Python Software Foundation' -or $cat.packageHashAlgorithm -ne 'SHA512') { throw "unexpected nuget.org metadata for $id $Version" }
    return Get-Download $reg.packageContent "$id.$Version.zip" '' '' '' (ConvertFrom-B64Hex $cat.packageHash)
}

function Get-PyLayout($r) {   # full (python.org/MSVC folder) | embed (embeddable zip) | '' (MinGW or custom build: not swappable)
    $mm = (Get-Branch $r.Version 2) -replace '\.', ''
    if (-not (Test-Path -LiteralPath (Join-Path $r.Root "python$mm.dll"))) { return '' }
    if (Test-Path -LiteralPath (Join-Path $r.Root 'Lib\os.py')) { return 'full' }
    if (Test-Path -LiteralPath (Join-Path $r.Root "python$mm.zip")) { return 'embed' }
    return ''
}

# Python with no installer of its own (inside apps, zip/uv/pyenv/conda copies, other users' installs): the
# runtime files are replaced by python.org's signed build of the fixed version; site-packages stay untouched
function Update-PyRuntime($r) {
    if (Invoke-AppUpdate $r) { return Add-CertifiStep $r "updated by the application's own package ($($r.AppName))" }
    $layout = Get-PyLayout $r
    if (-not $layout) {
        $c = 'certifi already current'; $dirs = @(Get-PyCertifiOld $r.Root $r.Version); if ($dirs.Count) { $c = Update-CertifiDirs $dirs }
        throw "not a python.org-style folder (MinGW or custom build) - only its vendor can ship Python $($r.Fixed); $c"
    }
    Assert-NotRunning $r.Root
    $mm = (Get-Branch $r.Version 2) -replace '\.', ''
    $tmp = Join-Path $env:TEMP "vulnpatch-py-$Stamp"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
    if ($layout -eq 'full') { Expand-Zip (Get-PyNuget $r.Fixed $r.Arch) $tmp; $src = Join-Path $tmp 'tools' }
    else {
        $a = 'amd64'; if ($r.Arch -eq 'x86') { $a = 'win32' } elseif ($r.Arch -eq 'arm64') { $a = 'arm64' }
        Expand-Zip (Get-PyReleaseFile $r.Fixed "python-$($r.Fixed)-embed-$a.zip") $tmp; $src = $tmp
    }
    try {
        foreach ($f in 'python.exe', "python$mm.dll") {
            $sig = Get-AuthenticodeSignature -LiteralPath (Join-Path $src $f)
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') { throw "the downloaded $f is not signed by the Python Software Foundation" }
        }
        $bak = Save-Backup $r.Root 'Lib\site-packages'
        if ($layout -eq 'full') {
            $sp = Join-Path $src 'Lib\site-packages'; if (Test-Path -LiteralPath $sp) { Remove-Item -LiteralPath $sp -Recurse -Force }
            Copy-Tree (Join-Path $src 'Lib') (Join-Path $r.Root 'Lib') @('/E')
            foreach ($d in 'DLLs', 'include', 'libs') {
                if ((Test-Path -LiteralPath (Join-Path $src $d)) -and (Test-Path -LiteralPath (Join-Path $r.Root $d))) { Copy-Tree (Join-Path $src $d) (Join-Path $r.Root $d) @('/E') }
            }
            $top = @(Get-ChildItem -LiteralPath $src -File | Where-Object { $_.Name -like 'python*.dll' -or (Test-Path -LiteralPath (Join-Path $r.Root $_.Name)) } | ForEach-Object { $_.Name })
            Copy-Tree $src $r.Root $top
        } else {
            Copy-Tree $src $r.Root @('/XF', "python$mm._pth")   # the app's own search-path file is kept
        }
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force } }
    $now = Get-FileVer (Join-Path $r.Root 'python.exe')
    if (-not $now -or (Test-VerLt $now $r.Fixed)) { throw "python.exe still reports $now after the copy (backup: $bak)" }
    return Add-CertifiStep $r "python.org $($r.Fixed) runtime ($layout, PSF-signed) copied in, site-packages kept (backup: $bak)"
}

function Update-Chromium($r) {   # app update first, then Chrome for Testing (Google storage checksum)
    if (Invoke-AppUpdate $r) { return "updated by the application's own package ($($r.AppName))" }
    $j = Get-Json 'https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json'
    $plat = 'win64'; if ((Get-PeArch $r.Exe) -eq 'x86') { $plat = 'win32' }
    $url = (@($j.channels.Stable.downloads.chrome) | Where-Object { $_.platform -eq $plat } | Select-Object -First 1).url
    if (-not $url) { throw "no Chrome for Testing build for $plat" }
    $hdr = (& $Curl -sSI $url | Where-Object { $_ -match '^x-goog-hash:.*md5=' }) -join ' '
    if ($hdr -notmatch 'md5=([A-Za-z0-9+/=]+)') { throw 'Google storage did not return a checksum - refusing to use the download' }
    $zip = Get-Download $url "chrome-$plat-$($j.channels.Stable.version).zip" '' '' (ConvertFrom-B64Hex $Matches[1])
    $tmp = Join-Path (Split-Path $r.Root -Parent) ".vulnpatch-$Stamp"
    Expand-Zip $zip $tmp
    try {
        $tree = Join-Path $tmp "chrome-$plat"
        # keep the file name the app launches (Burp's browser is chrome.exe; Playwright's too)
        if ((Split-Path $r.Exe -Leaf) -ne 'chrome.exe') { Copy-Item -LiteralPath (Join-Path $tree 'chrome.exe') -Destination (Join-Path $tree (Split-Path $r.Exe -Leaf)) }
        return "Chrome for Testing $($j.channels.Stable.version): " + (Install-Swap $r $tree)
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force } }
}

function Set-CaDistrust($r) {
    $certs = @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\AuthRoot -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'CN=emSign ECC Root CA - G3' })
    if (-not $certs.Count) { return 'emSign ECC Root CA - G3 is not trusted here' }
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
    foreach ($c in $certs) {
        $file = Join-Path $WorkDir "emSign-ECC-Root-CA-G3-$($c.Thumbprint).cer"
        Export-Certificate -Cert $c -FilePath $file -Type CERT | Out-Null
        $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $out = & $CertUtil -f -addstore Disallowed $file 2>&1; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
        if ($code -ne 0) { throw "certutil could not add it to the Disallowed store: $(@($out) | Select-Object -Last 1)" }
    }
    return 'emSign ECC Root CA - G3 added to the Windows Disallowed (untrusted) store'
}

function Update-Chrome($r) {
    $msi = Get-Download 'https://dl.google.com/edgedl/chrome/install/GoogleChromeStandaloneEnterprise64.msi' "chrome-enterprise-$Stamp.msi" '' 'Google LLC' ''
    $code = Invoke-Installer $MsiExec "/i `"$msi`" /qn /norestart /l*v `"$LogDir\chrome-$Stamp.log`""
    if ($code -notin 0, 3010, 1641) { throw "Chrome MSI exited with $code (log: $LogDir\chrome-$Stamp.log)" }
    return 'Chrome Enterprise MSI installed (signed by Google LLC)'
}

function Update-ChromeUser($r) {
    $exe = Get-Download 'https://dl.google.com/chrome/install/ChromeStandaloneSetup64.exe' "ChromeStandaloneSetup64-$Stamp.exe" '' 'Google LLC' ''
    $code = Invoke-Installer $exe '/silent /install'
    if ($code -ne 0) { throw "Chrome per-user installer exited with $code" }
    return 'Chrome per-user installer run (signed by Google LLC)'
}

function Update-Edge($r) {
    $api = Get-Json 'https://edgeupdates.microsoft.com/api/products'
    $rel = @(@($api | Where-Object { $_.Product -eq 'Stable' })[0].Releases | Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' } |
             Sort-Object { [datetime]$_.PublishedTime } -Descending)[0]
    $art = @($rel.Artifacts | Where-Object { $_.ArtifactName -eq 'msi' })[0]
    if (-not $art) { throw 'Microsoft did not list an Edge MSI' }
    $msi = Get-Download $art.Location "MicrosoftEdgeEnterpriseX64-$($rel.ProductVersion).msi" $art.Hash '' ''
    $code = Invoke-Installer $MsiExec "/i `"$msi`" /qn /norestart /l*v `"$LogDir\edge-$Stamp.log`""
    if ($code -notin 0, 3010, 1641) { throw "Edge MSI exited with $code (log: $LogDir\edge-$Stamp.log)" }
    return "Edge Enterprise MSI $($rel.ProductVersion) installed (SHA-256 checked)"
}

function Get-FirefoxFile($r, [string]$Ext) {
    $rel = $r.Fixed; if ($r.Note -like 'ESR*') { $rel = "$($r.Fixed)esr" }
    $arch = 'win64'; $pa = Get-PeArch $r.Exe; if ($pa -eq 'x86') { $arch = 'win32' } elseif ($pa -eq 'arm64') { $arch = 'win64-aarch64' }
    $name = "Firefox Setup $rel.$Ext"
    $sums = Get-WebText "https://archive.mozilla.org/pub/firefox/releases/$rel/SHA256SUMS"
    $line = @($sums -split "`n") | Where-Object { $_.EndsWith("$arch/en-US/$name") } | Select-Object -First 1
    if (-not $line) { throw "no SHA-256 published for $arch/en-US/$name" }
    return Get-Download "https://archive.mozilla.org/pub/firefox/releases/$rel/$arch/en-US/$($name -replace ' ', '%20')" "firefox-$rel-$arch.$Ext" (@($line -split '\s+')[0]) '' ''
}

function Update-Firefox($r) {
    $msi = Get-FirefoxFile $r 'msi'
    $code = Invoke-Installer $MsiExec "/i `"$msi`" /qn /norestart INSTALL_DIRECTORY_PATH=`"$($r.Root)`" /l*v `"$LogDir\firefox-$Stamp.log`""
    if ($code -notin 0, 3010, 1641) { throw "Firefox MSI exited with $code (log: $LogDir\firefox-$Stamp.log)" }
    return "Firefox $($r.Fixed) MSI installed into $($r.Root) (SHA-256 checked)"
}

function Update-FirefoxUser($r) {
    $exe = Get-FirefoxFile $r 'exe'
    $code = Invoke-Installer $exe "/S /InstallDirectoryPath=`"$($r.Root)`""
    if ($code -ne 0) { throw "Firefox installer exited with $code" }
    return "Firefox $($r.Fixed) installed into $($r.Root) (SHA-256 checked)"
}

function Update-Brave($r) {
    $rels = Get-Json 'https://api.github.com/repos/brave/brave-browser/releases?per_page=40'
    $rel = @($rels | Where-Object { -not $_.prerelease -and $_.name -match '^Release v' -and (@($_.assets | ForEach-Object { $_.name }) -contains 'BraveBrowserStandaloneSilentSetup.exe') })[0]
    if (-not $rel) { throw 'no Brave release with a Windows installer found on GitHub' }
    $base = "https://github.com/brave/brave-browser/releases/download/$($rel.tag_name)"
    $sha = @((Get-WebText "$base/BraveBrowserStandaloneSilentSetup.exe.sha256").Trim() -split '\s+')[0]
    $exe = Get-Download "$base/BraveBrowserStandaloneSilentSetup.exe" "BraveSilentSetup-$($rel.tag_name).exe" $sha '' ''
    [void](Invoke-Installer $exe '' 10)
    $deadline = (Get-Date).AddMinutes(3)
    while ((Get-Date) -lt $deadline) {
        $v = Get-FileVer $r.Exe; if ($v -match '^\d{3,}\.(\d+\.\d+\.\d+)$') { $v = $Matches[1] }
        if ($v -and -not (Test-VerLt $v $BraveFix)) { break }
        Start-Sleep -Seconds 5
    }
    return "Brave $($rel.tag_name) standalone installer run (SHA-256 checked)"
}

function Update-NodeMsi($r) {
    $a = 'x64'; if ($r.Arch -eq 'x86') { $a = 'x86' } elseif ($r.Arch -eq 'arm64') { $a = 'arm64' }
    $name = "node-v$($r.Fixed)-$a.msi"
    $sums = Get-WebText "https://nodejs.org/dist/v$($r.Fixed)/SHASUMS256.txt"
    $line = @($sums -split "`n") | Where-Object { $_ -match "\s$([regex]::Escape($name))\s*$" } | Select-Object -First 1
    if (-not $line) { throw "no SHA-256 published for $name" }
    $msi = Get-Download "https://nodejs.org/dist/v$($r.Fixed)/$name" $name (@($line.Trim() -split '\s+')[0]) '' ''
    $code = Invoke-Installer $MsiExec "/i `"$msi`" /qn /norestart /l*v `"$LogDir\node-$Stamp.log`""
    if ($code -notin 0, 3010, 1641) { throw "Node.js MSI exited with $code (log: $LogDir\node-$Stamp.log)" }
    return "Node.js $($r.Fixed) MSI installed (SHA-256 checked)"
}

function Update-PythonInstaller($r) {
    $suffix = '-amd64'; if ($r.Arch -eq 'x86') { $suffix = '' } elseif ($r.Arch -eq 'arm64') { $suffix = '-arm64' }
    $exe = Get-PyReleaseFile $r.Fixed "python-$($r.Fixed)$suffix.exe"
    $allUsers = 0; if ($r.Method -eq 'installer') { $allUsers = 1 }
    $code = Invoke-Installer $exe "/quiet InstallAllUsers=$allUsers /log `"$LogDir\python-$($r.Fixed)-$Stamp.log`""
    if ($code -notin 0, 3010) { throw "Python installer exited with $code (log: $LogDir\python-$($r.Fixed)-$Stamp.log)" }
    return Add-CertifiStep $r "Python $($r.Fixed) installer upgraded this copy in place (SHA-256 checked)"
}

# ---- libraries, Bun, the litellm malware, CISA KEV apps, Windows Update ------
function Get-LibSpec($r) {   # pip requirement of the fixed release
    switch ($r.Lib) { 'pillow' { "pillow>=$PillowFix" } 'brotli' { "brotli>=$BrotliFix" } 'brotlicffi' { "brotlicffi>=$BrotliCffiFix" } 'litellm' { $LiteLLMSpec } }
}
# exact versions: a '^' would be eaten by cmd.exe when npm.cmd runs (npm still saves it as ^x.y.z)
function Get-NpmSpec($r) { if ($r.Lib -eq 'sharp') { return "sharp@$SharpFix" }; return "next@$($NextFix[(Get-Branch $r.Version 1)])" }

function Get-PyFor($r) {   # the interpreter that owns this site-packages (user site: the installed Python of that version)
    if ($r.Py -and (Test-Path -LiteralPath $r.Py)) { return $r.Py }
    if ($r.PyMode -eq 'user') {
        $c = @($script:Rows | Where-Object { $_.Product -eq 'Python' -and $_.Exe -and (Get-Branch $_.Version 2) -eq $r.PyVer } | Select-Object -First 1)
        if ($c.Count) { return $c[0].Exe }
    }
    return ''
}

function Invoke-Pip($r, [string[]]$PipArgs) {   # pip of that environment; last lines in $script:PipOut; $true on success
    $py = Get-PyFor $r
    if (-not $py) { $script:PipOut = "no Python interpreter found for $($r.Root)"; return $false }
    $extra = @(); if ($PipArgs[0] -eq 'install' -and $r.PyMode -eq 'user') { $extra += '--user' }
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = @(& $py -m pip @PipArgs @extra --no-input --disable-pip-version-check 2>&1); $code = $LASTEXITCODE } finally { $ErrorActionPreference = $eap }
    $script:PipOut = (@($out | ForEach-Object { "$_" } | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' ')
    return ($code -eq 0)
}

function Update-Pip($r) {   # Pillow / Brotli / LiteLLM: the fixed release inside that exact Python environment
    $need = ''; if ($r.Lib -eq 'pillow') { $need = '3.11' } elseif ($r.Lib -eq 'litellm') { $need = '3.10' }
    if ($need -and $r.PyVer -and (Test-VerLt $r.PyVer $need)) { throw "$($r.Product) $($r.Fixed) needs Python $need or newer - this environment runs Python $($r.PyVer) (move it to a newer Python)" }
    if (-not (Invoke-Pip $r @('--version'))) {   # e.g. uv venvs ship without pip
        $py = Get-PyFor $r
        if ($py) { $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; try { & $py -m ensurepip --upgrade 2>&1 | Out-Null } finally { $ErrorActionPreference = $eap } }
    }
    $spec = Get-LibSpec $r
    if (-not (Invoke-Pip $r @('install', '--upgrade', $spec))) { throw "pip failed: $script:PipOut" }
    return "pip install -U '$spec' (was $($r.Version))"
}

function Stop-LiteLLMBackdoor($r) {   # python processes of that environment, the backdoor's temp markers, its server in hosts
    $envRoot = $r.Root; if ($envRoot -match '^(.*)\\Lib\\site-packages$') { $envRoot = $Matches[1] }
    $killed = @()
    foreach ($p in @(Get-RunningUnder $envRoot)) { try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; $killed += $p.Id } catch { } }
    $ran = $false
    $temps = @(Join-Path $env:SystemRoot 'Temp') + @(Get-ChildItem (Join-Path $env:SystemDrive 'Users') -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' })
    foreach ($t in $temps) {
        if (Test-Path -LiteralPath (Join-Path $t '.pc_once_72129118c59f5636c0bb')) { $ran = $true }
        $lock = Join-Path $t 'remote_code_loader.lock'; if (Test-Path -LiteralPath $lock) { Remove-Item -LiteralPath $lock -Force -ErrorAction SilentlyContinue }
    }
    $hosts = Join-Path $Sys32 'drivers\etc\hosts'
    if (-not (Select-String -LiteralPath $hosts -Pattern '^[^#]*\swww\.litellm\.dev(\s|$)' -Quiet)) {
        [void](Save-Backup $hosts)
        Add-Content -LiteralPath $hosts -Value '0.0.0.0 www.litellm.dev litellm.dev   # vulnpatch: litellm 1.107.0 malware server' -Encoding ASCII
    }
    $msg = 'backdoor processes stopped'; if ($killed.Count) { $msg += " (PID $($killed -join ', '))" }
    $msg += ', www.litellm.dev blocked in hosts'
    if ($ran) { $msg += '; the stealer had already run here (marker file found)' }
    return $msg
}

function Move-LiteLLMIoc([string]$Sp) {   # the malicious startup files -> a quarantine zip; returns what was done
    $found = @(); $cache = Join-Path $Sp '__pycache__'
    $pth = Join-Path $Sp 'cook.pth'
    if ((Test-Path -LiteralPath $pth) -and (Test-LiteLLMIoc $pth)) {
        $found += $pth
        if (Test-Path -LiteralPath (Join-Path $Sp 'cook.py')) { $found += Join-Path $Sp 'cook.py' }
        $found += @(Get-ChildItem -LiteralPath $cache -Filter 'cook.*.pyc' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    $sc = Join-Path $Sp 'sitecustomize.py'
    if ((Test-Path -LiteralPath $sc) -and (Test-LiteLLMIoc $sc)) {
        $found += $sc
        $found += @(Get-ChildItem -LiteralPath $cache -Filter 'sitecustomize.*.pyc' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    if (-not $found.Count) { return 'no malicious startup files left in site-packages' }
    $q = Join-Path $BackupDir "quarantine\litellm-malware-$((($Sp -replace '[:\\]+', '_').Trim('_')))-$Stamp"
    New-Item -ItemType Directory -Force -Path $q | Out-Null
    foreach ($f in $found) { Move-Item -LiteralPath $f -Destination $q -Force }
    New-Zip $q "$q.zip"; Remove-Item -LiteralPath $q -Recurse -Force
    return "$($found.Count) malicious startup file(s) quarantined in $q.zip"
}

function Update-Ioc($r) {   # startup files left by litellm 1.107.0 (even after the package itself is gone)
    $stop = Stop-LiteLLMBackdoor $r
    $q = Move-LiteLLMIoc $r.Root
    return "$q; $stop - ROTATE every credential used on this machine (cloud, SSH, API keys, tokens)"
}

function Update-LiteLLM($r) {   # the malicious release: backdoor stopped, startup files out, package and cached wheel out, clean release in
    $stop = Stop-LiteLLMBackdoor $r
    $q = Move-LiteLLMIoc $r.Root
    [void](Invoke-Pip $r @('uninstall', '-y', 'litellm'))
    foreach ($d in @(Get-ChildItem -LiteralPath $r.Root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'litellm' -or $_.Name -like 'litellm-*.dist-info' })) {
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction SilentlyContinue   # whatever the uninstall left behind
    }
    [void](Invoke-Pip $r @('cache', 'remove', 'litellm'))
    if (-not (Invoke-Pip $r @('install', '--upgrade', $LiteLLMSpec))) { throw "malicious litellm removed, clean reinstall failed: $script:PipOut - $q; ROTATE credentials" }
    return "malicious litellm $($r.Version) removed, clean litellm installed; $q; $stop - ROTATE every credential used on this machine"
}

function Find-Npm {   # npm.cmd of the NEWEST Node.js on the machine (a current Node avoids engine errors)
    $cand = @(Join-Path $env:ProgramFiles 'nodejs\npm.cmd')
    $cand += @($script:Rows | Where-Object { $_.Product -eq 'Node.js' -and -not $_.Embedded } | ForEach-Object { Join-Path $_.Root 'npm.cmd' })
    $g = Get-Command npm.cmd -ErrorAction SilentlyContinue; if ($g) { $cand += $g.Source }
    $best = ''; $bv = ''
    foreach ($c in $cand) {
        $node = Join-Path (Split-Path $c -Parent) 'node.exe'
        if (-not (Test-Path -LiteralPath $c) -or -not (Test-Path -LiteralPath $node)) { continue }
        $v = Get-FileVer $node   # version resource - nothing is run
        if ($v -and (-not $bv -or (Test-VerLt $bv $v))) { $best = $c; $bv = $v }
    }
    return $best
}

function Get-ProjectPm([string]$Proj) {   # @{ Pm = npm|pnpm|yarn|bun; Spec = name@version from "packageManager" }
    $pj = Get-Content -LiteralPath (Join-Path $Proj 'package.json') -Raw -ErrorAction SilentlyContinue
    $res = @{ Pm = 'npm'; Spec = '' }
    if ($pj -match '"packageManager"\s*:\s*"([a-z]+)@([^"+]+)') { $res.Pm = $Matches[1]; $res.Spec = "$($Matches[1])@$($Matches[2])" }
    elseif ((Test-Path -LiteralPath (Join-Path $Proj 'bun.lock')) -or (Test-Path -LiteralPath (Join-Path $Proj 'bun.lockb'))) { $res.Pm = 'bun' }
    elseif (Test-Path -LiteralPath (Join-Path $Proj 'pnpm-lock.yaml')) { $res.Pm = 'pnpm' }
    elseif (Test-Path -LiteralPath (Join-Path $Proj 'yarn.lock')) { $res.Pm = 'yarn' }
    if ($res.Pm -notin 'npm', 'pnpm', 'yarn', 'bun') { $res.Pm = 'npm' }
    return $res
}

function Get-PmCommand($Pm, [string]$Npm, [string]$Proj) {   # the package manager to run: installed, or fetched for this run
    $dir = Split-Path $Npm -Parent
    switch ($Pm.Pm) {
        'npm' { return @($Npm) }
        'bun' {
            foreach ($c in (Join-Path $env:USERPROFILE '.bun\bin\bun.exe')) { if (Test-Path -LiteralPath $c) { return @($c) } }
            $b = @($script:Rows | Where-Object { $_.Product -eq 'Bun' -and $_.Exe -and (Test-Path -LiteralPath $_.Exe) } | Select-Object -First 1)
            if ($b.Count) { return @($b[0].Exe) }
            $g = Get-Command bun.exe -ErrorAction SilentlyContinue; if ($g) { return @($g.Source) }
            return @((Join-Path $dir 'npx.cmd'), '--yes', 'bun')
        }
        default {   # pnpm / yarn
            $c = Join-Path $dir "$($Pm.Pm).cmd"; if (Test-Path -LiteralPath $c) { return @($c) }
            $g = Get-Command "$($Pm.Pm).cmd" -ErrorAction SilentlyContinue; if ($g) { return @($g.Source) }
            $cp = Join-Path $dir 'corepack.cmd'
            if ($Pm.Spec -and (Test-Path -LiteralPath $cp)) { return @($cp, $Pm.Pm) }   # the exact version the project asks for
            if ($Pm.Spec) { return @((Join-Path $dir 'npx.cmd'), '--yes', $Pm.Spec) }
            if ($Pm.Pm -eq 'yarn') {
                if (Select-String -LiteralPath (Join-Path $Proj 'yarn.lock') -Pattern '^__metadata:' -Quiet -ErrorAction SilentlyContinue) {
                    if (Test-Path -LiteralPath $cp) { return @($cp, 'yarn') }; return @()   # Yarn 2+ only comes through corepack
                }
                return @((Join-Path $dir 'npx.cmd'), '--yes', 'yarn@1')
            }
            return @((Join-Path $dir 'npx.cmd'), '--yes', 'pnpm@latest')
        }
    }
}

function Set-Override([string]$Proj, [string]$NodeDir, [string]$Section, [string]$Name, [string]$Range) {   # package.json override, written with node (any workspace format)
    $js = Join-Path $env:TEMP "vulnpatch-override-$Stamp.js"
    Set-Content -LiteralPath $js -Encoding ASCII -Value @(
        'const fs = require("fs"), [file, section, name, range] = process.argv.slice(2);',
        'const j = JSON.parse(fs.readFileSync(file, "utf8"));',
        'let o = j; for (const part of section.split(".")) { o[part] = o[part] || {}; o = o[part]; }',
        'o[name] = range;',
        'fs.writeFileSync(file, JSON.stringify(j, null, 2) + "\n");')
    try { return (Invoke-InDir $Proj $NodeDir (Join-Path $NodeDir 'node.exe') @($js, (Join-Path $Proj 'package.json'), $Section, $Name, $Range)) }
    finally { Remove-Item -LiteralPath $js -Force -ErrorAction SilentlyContinue }
}

function Invoke-InDir([string]$Dir, [string]$NodeDir, [string]$Exe, [string[]]$CmdArgs) {   # last lines in $script:CmdOut; $true on success
    $oldPath = $env:Path; $env:Path = "$NodeDir;$oldPath"
    $env:COREPACK_ENABLE_DOWNLOAD_PROMPT = '0'; $env:COREPACK_ENABLE_STRICT = '0'; $env:CI = '1'   # no questions from corepack / pnpm
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    Push-Location -LiteralPath $Dir
    try { $out = @(& $Exe @CmdArgs 2>&1); $code = $LASTEXITCODE }
    finally { Pop-Location; $ErrorActionPreference = $eap; $env:Path = $oldPath; Remove-Item Env:\COREPACK_ENABLE_DOWNLOAD_PROMPT, Env:\COREPACK_ENABLE_STRICT, Env:\CI -ErrorAction SilentlyContinue }
    $script:CmdOut = (@($out | ForEach-Object { "$_" } | Where-Object { $_.Trim() } | Select-Object -Last 2) -join ' ')
    return ($code -eq 0)
}

function Update-Npm($r) {   # next / sharp: the fixed release inside the project, with the project's own package manager
    $spec = Get-NpmSpec $r; $ver = $spec.Substring($spec.IndexOf('@') + 1); $proj = $r.Root
    $npm = Find-Npm; if (-not $npm) { throw "no Node.js/npm found - run in the project: npm install $spec" }
    $nodeDir = Split-Path $npm -Parent
    $pm = Get-ProjectPm $proj
    $tool = @(Get-PmCommand $pm $npm $proj)
    if (-not $tool.Count) { throw "this project uses $($pm.Pm) and it could not be started - run in the project: $($pm.Pm) add $spec" }
    $exe = $tool[0]; $pre = @($tool | Select-Object -Skip 1)
    $bak = Join-Path $BackupDir "$((($proj -replace '[:\\]+', '_').Trim('_')))-npm-$Stamp"
    New-Item -ItemType Directory -Force -Path $bak | Out-Null
    $r.Backups += $bak
    foreach ($f in 'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb') {
        $p = Join-Path $proj $f; if (Test-Path -LiteralPath $p) { Copy-Item -LiteralPath $p -Destination $bak }
    }
    $pkg = Get-Content -LiteralPath (Join-Path $proj 'package.json') -Raw | ConvertFrom-Json
    $field = ''
    foreach ($s in 'dependencies', 'devDependencies', 'optionalDependencies') {
        $sec = $pkg.$s; if ($sec -and (@($sec.PSObject.Properties | ForEach-Object { $_.Name }) -contains $r.Lib)) { $field = $s; break }
    }
    if ($field) {   # a direct dependency: update it where it is listed
        if ($pm.Pm -eq 'npm') { $a = @('install', $spec, '--no-audit', '--no-fund') } else { $a = @('add', $spec) }
        if ($field -eq 'devDependencies') { if ($pm.Pm -in 'yarn', 'bun') { $a += '--dev' } else { $a += '--save-dev' } }
        $ok = Invoke-InDir $proj $nodeDir $exe (@($pre) + $a)
    } else {        # pulled in by another package (sharp via next): pin it with an override
        $section = 'overrides'; if ($pm.Pm -eq 'yarn') { $section = 'resolutions' } elseif ($pm.Pm -eq 'pnpm') { $section = 'pnpm.overrides' }
        $ok = Set-Override $proj $nodeDir $section $r.Lib $ver
        if ($ok) { if ($pm.Pm -eq 'npm') { $ok = Invoke-InDir $proj $nodeDir $exe @('install', '--no-audit', '--no-fund') } else { $ok = Invoke-InDir $proj $nodeDir $exe (@($pre) + @('install')) } }
    }
    $now = ''
    $m = Select-String -LiteralPath (Join-Path $proj "node_modules\$($r.Lib)\package.json") -Pattern '^\s*"version"\s*:\s*"([^"]+)"' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($m) { $now = $m.Matches[0].Groups[1].Value }
    if (-not $ok -or -not $now -or (Test-VerLt $now $r.Fixed)) { throw "$($pm.Pm) could not update $($r.Lib) (now $now): $script:CmdOut - backup: $bak" }
    return "$($pm.Pm): $($r.Lib) $($r.Version) -> $now (package.json backup: $bak)"
}

function Update-Bun($r) {   # Bun's own release, SHA-256 checked, swapped for bun.exe in place
    Assert-NotRunning $r.Root
    $base = "https://github.com/oven-sh/bun/releases/download/bun-v$BunFix"
    $name = 'bun-windows-x64'; if ($r.Arch -eq 'arm64') { $name = 'bun-windows-aarch64' }
    $sums = Get-WebText "$base/SHASUMS256.txt"
    $line = @($sums -split "`n") | Where-Object { $_ -match "\s$name\.zip\s*$" } | Select-Object -First 1
    if (-not $line) { throw "no SHA-256 published for $name.zip" }
    $zip = Get-Download "$base/$name.zip" "$name-$BunFix.zip" (@($line.Trim() -split '\s+')[0]) '' ''
    $tmp = Join-Path $env:TEMP "vulnpatch-bun-$Stamp"; Expand-Zip $zip $tmp
    try { $bak = Save-Backup $r.Exe; Copy-Item -LiteralPath (Join-Path $tmp "$name\bun.exe") -Destination $r.Exe -Force }
    finally { Remove-Item -LiteralPath $tmp -Recurse -Force }
    return "bun $($r.Version) -> $BunFix (SHA-256 checked, backup: $bak)"
}

function Update-Kev($r) {   # an app on the CISA KEV list: its newest version through winget
    Write-Host "    winget upgrade '$($r.Package)' ..."
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = @(& winget.exe upgrade --name $r.Package --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1) }
    finally { $ErrorActionPreference = $eap }
    if (Test-WingetUpdate $r.Package) { throw "winget could not update it: $((@($out | ForEach-Object { "$_" } | Where-Object { $_.Trim() }) | Select-Object -Last 1) -join ' ') - $($r.KevAction)" }
    return "updated to the newest version through winget (CISA KEV $($r.Kev))"
}

function Start-WindowsUpdate($r) {   # actively exploited Windows CVE: the newest cumulative update
    $uso = Join-Path $Sys32 'UsoClient.exe'
    if (-not (Test-Path -LiteralPath $uso)) { throw 'UsoClient.exe not found - run Windows Update from Settings' }
    $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { foreach ($a in 'StartScan', 'StartDownload', 'StartInstall') { & $uso $a 2>&1 | Out-Null; Start-Sleep -Seconds 3 } } finally { $ErrorActionPreference = $eap }
    return 'Windows Update started (scan, download and install run in the background) - restart the PC when Windows asks'
}

function Update-Java($r) {   # the eMudhra block list (CVE-2026-91403) - Oracle's own fix, for every vendor and every copy
    $pre = ''
    if ($r.Fixed -ne '-' -and (Invoke-AppUpdate $r)) { $pre = "app updated ($($r.AppName)); " }
    $f = Get-JavaBlockFile $r.Root
    $raw = ''; $have = @()
    if (Test-Path -LiteralPath $f) { $raw = Get-Content -LiteralPath $f -Raw; $have = @($raw -split "`r?`n" | ForEach-Object { $_.Trim().ToUpper() }) }
    $missing = @($EmudhraFps | Where-Object { $have -notcontains $_ })
    if (-not $missing.Count) { return "$($pre)eMudhra certificates already blocked" }
    $bak = ''; $made = $false
    if (Test-Path -LiteralPath $f) { $bak = Save-Backup $f }
    else { New-Item -ItemType Directory -Force -Path (Split-Path $f -Parent) | Out-Null; $raw = "Algorithm=SHA-256`n"; $made = $true }
    if ($raw -and -not $raw.EndsWith("`n")) { $raw += "`n" }   # the list must not run into the last line
    $raw += ($missing -join "`n") + "`n"
    Set-Content -LiteralPath $f -Value $raw -NoNewline -Encoding ASCII
    # no block list at all: write it under both names (JDK 8-15 read blacklisted.certs, newer ones blocked.certs)
    $other = Join-Path (Split-Path $f -Parent) 'blacklisted.certs'
    if ($made -and -not (Test-Path -LiteralPath $other)) { Set-Content -LiteralPath $other -Value $raw -NoNewline -Encoding ASCII }
    $n = Get-JavaFpCount $f
    if ($n -ne $EmudhraFps.Count) { throw "block list still incomplete ($n/$($EmudhraFps.Count)) in $f" }
    $b = ''; if ($bak) { $b = " (backup: $bak)" }
    return "$pre$($missing.Count) eMudhra certificates added to $f$b - running Java apps need a restart"
}

function Write-ItemLine($r, [int]$No, [int]$Total, [string]$Word, [string]$Colour, [string]$Reason) {   # the one line an item gets while patching
    if ($Reason.Length -gt 100) { $Reason = $Reason.Substring(0, 97) + '...' }
    $w = "$Total".Length
    Write-Host ("  [{0}/{1}] " -f "$No".PadLeft($w), $Total) -NoNewline
    Write-Host ('{0,-6} ' -f $Word) -ForegroundColor $Colour -NoNewline
    $line = '{0,-8} {1,-16} -> {2,-14} {3}' -f (Get-DispProd $r.Product), $r.Version, $r.Fixed, (Get-ShortLoc $r.Root)
    if ($Reason) { $line += "  - $Reason" }
    Write-Host $line
}

function Invoke-Patch {
    $todo = @($script:PickOrder | Where-Object { $_.Picked }); $n = 0
    Write-Host ''
    foreach ($r in $todo) {
        $n++
        $script:CurRow = $r   # backups made from here on belong to this item
        try {
            $msg = switch ($r.Kind) {
                'installer' {
                    switch ($r.Product) {
                        'Chrome'  { Update-Chrome $r }   'Edge'   { Update-Edge $r }    'Firefox' { Update-Firefox $r }
                        'Brave'   { Update-Brave $r }    'Python' { Update-PythonInstaller $r }
                        'Node.js' { Update-NodeMsi $r }
                    }
                }
                'user-installer' { if ($r.Product -eq 'Chrome') { Update-ChromeUser $r } else { Update-FirefoxUser $r } }
                'replace'   { if ($r.Product -eq 'PHP') { Update-PhpZip $r } else { Update-NodeFolder $r } }
                'node-bin'  { Update-NodeBinary $r }
                'certifi'   { Update-Certifi $r }
                'venvs'     { Update-Venvs $r }
                'pymanager' { Update-PyManager $r }
                'runtime'   { Update-PyRuntime $r }
                'java'      { Update-Java $r }
                'ioc'       { Update-Ioc $r }
                'litellm'   { Update-LiteLLM $r }
                'pip'       { Update-Pip $r }
                'npm'       { Update-Npm $r }
                'bun'       { Update-Bun $r }
                'kev'       { Update-Kev $r }
                'winupdate' { Start-WindowsUpdate $r }
                'chromium'  { Update-Chromium $r }
                'ca'        { Set-CaDistrust $r }
            }
            $r.Outcome = "done: $msg"; Write-ItemLine $r $n $todo.Count 'ok' 'Green' ''
        } catch {
            $r.Outcome = "failed: $($_.Exception.Message) (script line $($_.InvocationInfo.ScriptLineNumber))"
            Write-ItemLine $r $n $todo.Count 'FAILED' 'Red' $_.Exception.Message
        }
    }
    $script:CurRow = $null
}

function Show-Verify {
    $after = @{}; $script:Dropped = 0
    foreach ($x in $script:Rows) { if ($x.Status -ne 'NOT FOUND') { $after[(Get-MatchKey $x)] = $x } }
    Write-Host ("`n  {0,3}  {1,-16} {2,-8} {3,-16}    {4,-16} {5}" -f '#', 'RESULT', 'PRODUCT', 'BEFORE', 'AFTER', 'LOCATION')
    Write-Host "  $Line"
    $ok = 0; $bad = 0; $skip = 0; $details = @(); $i = 0
    foreach ($r in $script:PickOrder) {
        $i++
        $a = $after[$r.MatchKey]
        $ast = 'GONE'; $aver = '-'; if ($a) { $ast = $a.Status; $aver = $a.Version }
        $err = ''
        if ($ast -eq 'PATCHED' -or $ast -eq 'GONE') {
            $res = 'PATCHED'; if ($ast -eq 'GONE') { $res = 'REMOVED' }; $col = 'Green'; $ok++
            if (-not $KeepBackups -and $r.Backups.Count) {   # fix verified: no old version is left behind
                foreach ($b in @($r.Backups)) { if (Test-Path -LiteralPath $b) { Remove-Item -LiteralPath $b -Recurse -Force -ErrorAction SilentlyContinue; $script:Dropped++ } }
                $r.Backups = @(); $r.Outcome = ($r.Outcome -replace ' \((package\.json )?backup: [^)]*\)', '') -replace ', backup: [^)]*\)', ')'
            }
        }
        elseif (-not $r.Picked) { $res = 'NOT SELECTED'; $col = 'Yellow'; $skip++; $err = 'not selected in this run' }
        else {
            $res = 'STILL VULNERABLE'; $col = 'Red'; $bad++
            $why = $r.Outcome; if (-not $why) { $why = 'the fix ran but the copy still reports a vulnerable version' }
            if ($a -and $a.Note) { $why = "$why | now: $($a.Note)" }
            $details += "$i  $($r.Product) $($r.Version) ($($r.Root)): $why"
            $err = $why
        }
        Write-Host ('  {0,3}  ' -f $i) -NoNewline
        Write-Host ('{0,-16} ' -f $res) -ForegroundColor $col -NoNewline
        Write-Host ('{0,-8} {1,-16} -> {2,-16} {3}' -f (Get-DispProd $r.Product), $r.Version, $aver, (Get-ShortLoc $r.Root))
        Add-ReportRow $r.Product $r.Version $r.Fixed $aver $res $r.Desc $err $r.Root $r.Method $r.Outcome
    }
    foreach ($r in $script:External) {   # copies only their own updater can fix
        $a = $after[$r.MatchKey]; $aver = $r.Version; if ($a) { $aver = $a.Version }
        Add-ReportRow $r.Product $r.Version $r.Fixed $aver 'NOT PATCHED' '-' $r.Desc $r.Root $r.Method $r.Note
    }
    Write-Host "  $Line"
    Write-Host ("  Result: {0} patched, {1} still vulnerable, {2} not selected" -f $ok, $bad, $skip)
    $kept = @($script:PickOrder | ForEach-Object { @($_.Backups) } | Where-Object { $_ -and (Test-Path -LiteralPath $_) }).Count
    if ($KeepBackups) { Write-Host "  Backups kept (-KeepBackups): $kept in $BackupDir" }
    else {
        $txt = "  Backups: $($script:Dropped) deleted (fix verified - no old versions left)"
        if ($kept) { $txt += ", $kept kept in $BackupDir for items that are not confirmed (to restore them)" }
        Write-Host $txt
    }
    if ($details.Count) { Write-Host "`n  Why these are still vulnerable:"; foreach ($d in $details) { Write-Host "    $d" } }
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "  NOT FOUND (not installed): $($miss -join ', ')" -ForegroundColor DarkGray }
    $script:StillBad = $bad + $skip
}

function Show-RestartNeeded {
    $roots = @($script:PickOrder | Where-Object { $_.Picked -and $_.Outcome -like 'done*' } | ForEach-Object { $_.Root.ToLower() })
    $hits = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $p = "$($_.Path)".ToLower(); $p -and @($roots | Where-Object { $p.StartsWith("$_\") }).Count })
    if ($hits.Count) {
        $g = @($hits | Group-Object { $_.Path } | ForEach-Object { "$($_.Name) ($($_.Count))" })
        Write-Host "`n  Restart needed - still running the old code: " -ForegroundColor Yellow -NoNewline
        Write-Host ($g -join ', ')
    }
}

# ---- Excel-ready CSV report -------------------------------------------------
$script:ReportRows = @()

function Get-HostInfo {   # IP and MAC of the adapter that has the default gateway
    $nic = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)
    $main = @($nic | Where-Object { $_.DefaultIPGateway } | Select-Object -First 1)
    if (-not $main.Count) { $main = @($nic | Select-Object -First 1) }
    $script:HostIp = ''; $script:HostMac = ''
    if ($main.Count) {
        $script:HostIp = "$(@($main[0].IPAddress | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })[0])"
        $script:HostMac = "$($main[0].MACAddress)"
    }
    $script:RunAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $a = @(); if ($Scan) { $a += '-Scan' }; if ($Apply) { $a += '-Apply' }; if ($Pick) { $a += "-Pick $Pick" }
    if ($OnlyList.Count) { $a += "-Only $($OnlyList -join ',')" }; if ($Quick) { $a += '-Quick' }; if ($Yes) { $a += '-Yes' }
    $script:ArgsTxt = $a -join ' '
}

function ConvertTo-CsvLine([string[]]$Fields) { return (@($Fields | ForEach-Object { '"' + ("$_" -replace '"', '""') + '"' }) -join ',') }

function Add-ReportRow([string]$Product, [string]$Before, [string]$Fixed, [string]$After, [string]$Result, [string]$Action,
                       [string]$Err, [string]$Location, [string]$Method, [string]$Note) {
    if (-not $Fixed) { $Fixed = '-' }
    $script:ReportRows += ConvertTo-CsvLine @($env:COMPUTERNAME, $script:HostIp, $script:HostMac, $script:OsName,
        "vulnpatch-windows.ps1 $ScriptVersion $script:ArgsTxt".Trim(), $script:RunAt, $Mode,
        $Product, $Before, $Fixed, $After, $Result, $Action, $Err, $Location, $Method, $Note)
}

function Add-CurrentRows([switch]$SkipPlan) {   # one row per copy as found now (scan / plan), or the copies outside the plan
    foreach ($r in $script:Rows) {
        if ($SkipPlan -and $r.InPlan) { continue }
        if (-not $r.Desc -and $r.Status -notin 'PATCHED', 'NOT FOUND') { Set-Kind $r }
        $res = $r.Status; $after = ''; $act = $r.Desc; if (-not $act) { $act = '-' }
        if ($SkipPlan) {
            $after = $r.Version
            if ($res -eq 'PATCHED') { $res = 'ALREADY PATCHED' } elseif ($res -eq 'NOT FOUND') { $after = '-' } else { $res = 'NOT SELECTED (-Only)' }
        }
        Add-ReportRow $r.Product $r.Version $r.Fixed $after $res $act '' $r.Root $r.Method $r.Note
    }
}

function Get-ReportDir {   # the Desktop (else Downloads) of the person running the script; -Report overrides
    if ($Report -and $Report -notlike '*.csv') { return $Report }
    if ("$env:USERPROFILE" -like '*\systemprofile*') { return (Join-Path $env:PUBLIC 'Desktop') }   # SYSTEM (Intune / SCCM)
    $sf = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -ErrorAction SilentlyContinue
    $cand = @("$($sf.Desktop)", (Join-Path $env:USERPROFILE 'Desktop'),                        # OneDrive-redirected Desktop first
              "$($sf.'{374DE290-123F-4565-9164-39C4925E467B}')", (Join-Path $env:USERPROFILE 'Downloads'))
    foreach ($p in $cand) { if ($p -and (Test-Path -LiteralPath $p)) { return $p } }
    return (Join-Path $WorkDir 'reports')
}

# Containers, WSL distros and virtual machines are separate systems: their disks are image files that a
# scan of this machine cannot look into. They are listed so none is missed - run the script inside each.
function Get-InnerSystems {
    $list = @()
    $wsl = Join-Path $Sys32 'wsl.exe'
    if (Test-Path -LiteralPath $wsl) {
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'; $u8 = $env:WSL_UTF8; $env:WSL_UTF8 = '1'
        try { $names = @(& $wsl --list --quiet 2>$null) } catch { $names = @() } finally { $ErrorActionPreference = $eap; $env:WSL_UTF8 = $u8 }
        foreach ($n in $names) {
            $n = ("$n" -replace "`0", '').Trim()
            if ($n -notmatch '^[\w.\-]+$') { continue }
            if ($n -like 'docker-desktop*') { $list += @{ Kind = 'WSL distro'; Name = $n; How = 'Docker Desktop''s own system - keep Docker Desktop updated' } }
            else { $list += @{ Kind = 'WSL distro'; Name = $n; How = "run Patch_lin.sh inside it (wsl -d $n -u root)" } }
        }
    }
    if (Get-Command docker.exe -ErrorAction SilentlyContinue) {
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $cs = @(& docker.exe ps -a --format '{{.Names}} ({{.Image}}, {{.Status}})' 2>$null) } catch { $cs = @() } finally { $ErrorActionPreference = $eap }
        foreach ($c in $cs) { if ("$c".Trim()) { $list += @{ Kind = 'Docker container'; Name = "$c".Trim(); How = 'rebuild its image with patched packages (changes inside a container are lost)' } } }
    }
    $vbox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
    if (Test-Path -LiteralPath $vbox) {
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $vms = @(& $vbox list vms 2>$null) } catch { $vms = @() } finally { $ErrorActionPreference = $eap }
        foreach ($v in $vms) { if ("$v" -match '^"(.+)" \{') { $list += @{ Kind = 'VirtualBox VM'; Name = $Matches[1]; How = 'run the script inside the VM' } } }
    }
    $inv = Join-Path $env:APPDATA 'VMware\inventory.vmls'
    if (Test-Path -LiteralPath $inv) {
        foreach ($m in @(Select-String -LiteralPath $inv -Pattern '^vmlist\d+\.config = "(.+\.vmx)"')) {
            $list += @{ Kind = 'VMware VM'; Name = $m.Matches[0].Groups[1].Value; How = 'run the script inside the VM' }
        }
    }
    if ($IsAdmin -and (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
        try { foreach ($v in @(Get-VM -ErrorAction Stop)) { $list += @{ Kind = 'Hyper-V VM'; Name = "$($v.Name)"; How = 'run the script inside the VM' } } } catch { }
    }
    return $list
}

function Show-InnerSystems {
    if (-not $script:Inner.Count) { return }
    Write-Host "`n  NOT SCANNED - separate systems inside this machine ($($script:Inner.Count)):" -ForegroundColor Yellow
    foreach ($s in $script:Inner) { Write-Host "    - $($s.Kind): $($s.Name)  ->  $($s.How)" -ForegroundColor Yellow }
}

function Write-CsvReport {   # one report per machine (Desktop): a re-run updates it; rows of other hosts in a shared file are kept
    try {
        if ($Report -like '*.csv') { $f = $Report } else { $f = Join-Path (Get-ReportDir) "vulnpatch-report-$env:COMPUTERNAME.csv" }
        New-Item -ItemType Directory -Force -Path (Split-Path $f -Parent) | Out-Null
        foreach ($s in $script:Inner) { Add-ReportRow $s.Kind '-' '-' '-' 'NOT SCANNED' $s.How 'separate system - its disk cannot be scanned from this machine' $s.Name '-' '' }
        $head = ConvertTo-CsvLine @('Host', 'IP address', 'MAC address', 'OS', 'Script', 'Run at', 'Mode', 'Product', 'Version before',
                                    'Fixed in', 'Version after', 'Result', 'Action', 'Error / reason', 'Location', 'Install method', 'Note')
        $keep = @(); $state = 'created'
        if (Test-Path -LiteralPath $f) {
            $state = 'updated'
            $keep = @(Get-Content -LiteralPath $f -Encoding UTF8 | Select-Object -Skip 1 | Where-Object { $_ -and -not $_.StartsWith("`"$env:COMPUTERNAME`",") })
        }
        $enc = 'UTF8'; if ($PSVersionTable.PSVersion.Major -ge 6) { $enc = 'utf8BOM' }
        try { Set-Content -LiteralPath $f -Value (@($head) + $keep + @($script:ReportRows)) -Encoding $enc }
        catch {   # usually: the file is open in Excel
            $f = $f -replace '\.csv$', "-$Stamp.csv"; $state = 'saved under a new name - the old one is open in another program (Excel?)'
            Set-Content -LiteralPath $f -Value (@($head) + @($script:ReportRows)) -Encoding $enc
        }
        Write-Host "`n  Excel report $state`: $f" -ForegroundColor Cyan
    } catch { Write-Note "report not written: $($_.Exception.Message)" }
}

# =============================================================================
# MAIN - a function that returns the exit code, so the script also runs from memory
# (irm ... | iex) without 'exit' closing the PowerShell window
# =============================================================================
function Invoke-Main {
    $start = Get-Date
    $os = (Get-CimInstance Win32_OperatingSystem).Caption
    $modeTxt = switch ($Mode) { 'scan' { 'DETECTION ONLY' } 'plan' { 'DETECTION + PLAN (nothing will be changed)' } default { 'DETECT + PATCH + VERIFY' } }
    Write-Host "`n== vulnpatch: $env:COMPUTERNAME | $os | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $modeTxt ==" -ForegroundColor Cyan
    if (-not $FullLang) { Write-Host "  PowerShell language mode: $($ExecutionContext.SessionState.LanguageMode) (managed laptop) - using the compatible code paths" -ForegroundColor DarkGray }
    if ($Mode -eq 'apply' -and -not $IsAdmin) { Write-Host '  -Apply needs an elevated PowerShell (Run as administrator).' -ForegroundColor Red; return 2 }
    $script:Roots = Get-SearchRoots
    Write-Host "  searching: $($script:Roots -join ' ')"
    if (-not $IsAdmin) { Write-Note 'not elevated: other users'' folders cannot be read - run as administrator for full coverage' }

    Write-Step 'Detection: every copy on the machine'
    Invoke-Detection
    $script:OsName = $os; $script:ReportRows = @()
    Get-HostInfo
    $script:Inner = @(Get-InnerSystems)

    if ($Mode -eq 'scan') {
        Show-Report
        Show-InnerSystems
        $out = $Json; if (-not $out) { $out = Join-Path $env:TEMP "vulnscan-$env:COMPUTERNAME-$Stamp.json" }
        Write-JsonReport $out
        Write-Host "  JSON report: $out   ($([int]((Get-Date) - $start).TotalSeconds)s)"
        Add-CurrentRows; Write-CsvReport
        if ($script:ResultBad) { return 1 } else { return 0 }
    }

    Show-Brief
    Show-InnerSystems
    Build-Plan
    if (($script:PickOrder.Count + $script:External.Count) -eq 0) {
        Write-Step 'Nothing to patch - every copy found is already patched'
        Add-CurrentRows; Write-CsvReport
        return 0
    }
    Write-Step 'Patch plan'
    Show-Plan

    if ($Mode -eq 'plan') {
        Write-Host "`n  Nothing was changed. To patch: run it again with -Apply in an elevated PowerShell."
        Write-Host '  It will ask which numbers to patch (e.g. all | 1,3,5-7 | php,node), or pass -Pick to choose up front.'
        Add-CurrentRows; Write-CsvReport
        return 1
    }
    if (-not $script:PickOrder.Count) { return 1 }
    if (-not (Select-Items)) { return 1 }

    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    Start-Transcript -Path (Join-Path $LogDir "vulnpatch-$Stamp.log") | Out-Null
    try {
        Write-JsonReport (Join-Path $LogDir "before-$Stamp.json")
        Add-CurrentRows -SkipPlan     # report rows for the copies that needed nothing (taken before the re-scan)
        Write-Step 'Patching'
        Invoke-Patch
        Write-Step 'Verification: scanning the whole machine again'
        Invoke-Detection
        Write-JsonReport (Join-Path $LogDir "after-$Stamp.json")
        $script:StillBad = 0
        Show-Verify
        Show-RestartNeeded
        Write-Host "`n  Logs: $LogDir\vulnpatch-$Stamp.log   scans: before-$Stamp.json / after-$Stamp.json   ($([int]((Get-Date) - $start).TotalMinutes) min)"
    } catch {
        # unexpected stop: say exactly where, so it can be reported and fixed
        Write-Host "`n  STOPPED: $($_.Exception.GetType().FullName): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  at script line $($_.InvocationInfo.ScriptLineNumber): $("$($_.InvocationInfo.Line)".Trim())" -ForegroundColor Red
        Write-Host "  $($_.ScriptStackTrace -replace "`n", "`n  ")" -ForegroundColor DarkGray
        Write-Host "  PowerShell $($PSVersionTable.PSVersion) | language mode $($ExecutionContext.SessionState.LanguageMode) | log: $LogDir\vulnpatch-$Stamp.log"
        $script:StillBad = 1
    } finally {
        Write-CsvReport
        Stop-Transcript | Out-Null
    }
    if ($script:StillBad) { return 1 } else { return 0 }
}

$rc = @(Invoke-Main)[-1]
if ($PSCommandPath) { exit $rc }      # run from a file: exit code for fleet tools (Intune, SCCM, scripts)
$global:LASTEXITCODE = $rc            # run from memory: the window stays open with the results on screen
