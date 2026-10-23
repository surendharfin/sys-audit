<#
.SYNOPSIS
    vulnpatch-windows.ps1 - DETECT and PATCH in one file: the Windows counterpart of vulnpatch-linux.sh

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
      Windows CA store ......... the compromised emSign ECC Root CA - G3 is marked untrusted
    Every change is backed up first (C:\ProgramData\vulnpatch\backups). After patching the whole machine
    is scanned again and every copy is reported PATCHED / STILL VULNERABLE (with the reason).

    Works in Constrained Language Mode (AppLocker / WDAC managed laptops).

.PARAMETER Scan    Detection report only (and JSON).
.PARAMETER Apply   Detect, ask which numbers to patch, patch, verify. Needs an elevated PowerShell.
.PARAMETER Pick    With -Apply: choose without the prompt - all | 1,3,5-7 | php,node | none
.PARAMETER Only    Limit the plan to some products: php,node,python,chrome,chromium,edge,brave,firefox,ca
.PARAMETER Quick   Search the usual install folders only instead of every fixed drive.
.PARAMETER Json    Where to write the JSON report.
.PARAMETER Yes     No prompts (patches every plan item unless -Pick says otherwise).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Scan
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Apply
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\vulnpatch-windows.ps1 -Apply -Pick 1,3,5-7 -Yes
#>
[CmdletBinding()]
param(
    [switch]$Scan,
    [switch]$Apply,
    [string]$Pick,
    [string[]]$Only,
    [switch]$Quick,
    [string]$Json,
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
$Products   = 'PHP', 'Node.js', 'Python', 'Chrome', 'Edge', 'Firefox', 'Brave'   # listed as NOT FOUND when absent

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
                foreach (string f in Directory.EnumerateFiles(dir, "*.exe"))
                    if (want.Contains(Path.GetFileName(f))) hits.Add(f);
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
}
'@
$ExeNames  = 'php.exe', 'node.exe', 'python.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe'
$SkipParts = '\windows\winsxs', '\windows\servicing', '\windows\softwaredistribution', '\windows\installer', '\windows\assembly',
             '\windows\system32\driverstore', '\$recycle.bin', '\system volume information', '\windowsapps',
             '\edgewebview', '\edgecore', '\edgeupdate', '\programdata\vulnpatch', '\.vulnpatch-'

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
        } else {       # Constrained Language Mode: Windows' own dir /s
            $out = & $CmdExe /c "dir /s /b /a-d `"$(Join-Path $r '*.exe')`" 2>nul"
            foreach ($p in @($out)) {
                if (-not $p) { continue }
                if ($ExeNames -notcontains (Split-Path $p -Leaf).ToLower()) { continue }
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
            $list += @{ Name = "$($e.DisplayName)"; Version = "$($e.DisplayVersion)"; Location = $loc; Icon = $icon; Scope = $k.Hive }
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
       Outcome = ''; MatchKey = ''; Target = ''; Venvs = @() }
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

function Add-Copy([string]$Exe, $PyReg, $Defaults) {
    $name = (Split-Path $Exe -Leaf).ToLower()
    $prod = switch ($name) {
        'php.exe' { 'PHP' } 'node.exe' { 'Node.js' } 'python.exe' { 'Python' } 'msedge.exe' { 'Edge' }
        'firefox.exe' { 'Firefox' } 'brave.exe' { 'Brave' }
        'chrome.exe' { if ($Exe -match '\\Google\\Chrome') { 'Chrome' } else { 'Chromium' } }
    }
    if (-not $prod) { return }
    $root = Split-Path $Exe -Parent
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
    if ($prod -eq 'Brave' -and $ver -match '^\d{3,}\.(\d+\.\d+\.\d+)$') { $ver = $Matches[1] }   # 155.1.97.59 -> 1.97.59
    if (-not $ver) { $script:Skipped++; return }
    if ($prod -eq 'Python' -and $ver -notmatch '^[23]\.') { $script:Skipped++; return }   # e.g. the Python install manager's launcher
    $entry = Find-Uninstall $prod $root
    $row = New-Row $prod $ver (Get-MethodOf $prod $root $entry $PyReg) $root $Exe
    if ($entry) { $row.Package = $entry.Name }
    if ($row.Method -eq 'bundled-in-app') {
        $row.Embedded = $true
        $app = Find-OwningApp $root; if ($app) { $row.AppName = $app.Name }
    }
    if ($prod -in 'PHP', 'Node.js', 'Python') { $row.Arch = Get-PeArch $Exe }
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
    foreach ($exe in @(Find-ProgramFiles)) { Add-Copy $exe $pyReg $defaults }
    Add-StorePython
    Add-VenvRow
    Add-CaStore
    foreach ($r in $script:Rows) { Set-Verdict $r }
    Add-Missing
}

# ---- reports ----------------------------------------------------------------
function Get-Rank([string]$s) { switch ($s) { 'VULNERABLE' { 0 } 'EOL' { 1 } 'REVIEW' { 2 } 'PATCHED' { 3 } default { 4 } } }
function Get-ProdRank([string]$p) {
    $order = 'PHP', 'Node.js', 'Python', 'Chrome', 'Chromium', 'Edge', 'Brave', 'Firefox', 'CA store'
    for ($i = 0; $i -lt $order.Count; $i++) { if ($order[$i] -eq $p) { return $i } }
    return 9
}
function Get-StatusColor([string]$s) { switch ($s) { 'VULNERABLE' { 'Red' } 'EOL' { 'Red' } 'REVIEW' { 'Yellow' } 'PATCHED' { 'Green' } default { 'DarkGray' } } }

function Show-Report {
    $sorted = @($script:Rows | Sort-Object @{ e = { Get-Rank $_.Status } }, @{ e = { Get-ProdRank $_.Product } }, @{ e = { $_.Root } })
    Write-Host ("`n  {0,-11} {1,-9} {2,-15} {3,-15} {4}" -f 'STATUS', 'PRODUCT', 'VERSION', 'FIXED_IN', 'LOCATION')
    Write-Host "  $Line"
    foreach ($r in $sorted) {
        $fx = $r.Fixed; if (-not $fx) { $fx = '-' }
        Write-Host ('  {0,-11} ' -f $r.Status) -ForegroundColor (Get-StatusColor $r.Status) -NoNewline
        Write-Host ('{0,-9} {1,-15} {2,-15} {3}' -f $r.Product, $r.Version, $fx, (Get-ShortLoc $r.Root))
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
    foreach ($s in 'VULNERABLE', 'EOL', 'REVIEW', 'PATCHED', 'NOT FOUND') { $c[$s] = @($script:Rows | Where-Object { $_.Status -eq $s }).Count }
    Write-Host ("`n  Summary: {0} vulnerable, {1} end-of-life, {2} review, {3} patched, {4} not installed" -f $c['VULNERABLE'], $c['EOL'], $c['REVIEW'], $c['PATCHED'], $c['NOT FOUND'])
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "  NOT FOUND (not installed): $($miss -join ', ')" -ForegroundColor DarkGray }
    $script:ResultBad = $c['VULNERABLE'] + $c['EOL']
}

function Show-Brief {
    $found = @($script:Rows | Where-Object { $_.Status -ne 'NOT FOUND' })
    $ok = @($found | Where-Object { $_.Status -eq 'PATCHED' })
    Write-Host ("  Found {0} copies: {1} vulnerable, {2} end-of-life, {3} review, {4} already patched   (full table: -Scan)" -f `
        $found.Count, @($found | Where-Object { $_.Status -eq 'VULNERABLE' }).Count, @($found | Where-Object { $_.Status -eq 'EOL' }).Count,
        @($found | Where-Object { $_.Status -eq 'REVIEW' }).Count, $ok.Count)
    if ($ok.Count) {
        Write-Host '  Already patched - nothing to do:'
        foreach ($r in $ok) { Write-Host ('    - {0,-8} {1,-24} {2}' -f $r.Product, $r.Version, (Get-ShortLoc $r.Root)) -ForegroundColor Green }
    }
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
function Get-ProdToken([string]$p) { switch ($p) { 'Node.js' { 'node' } 'CA store' { 'ca' } default { $p.ToLower() } } }
function Test-Selected([string]$p) { (-not $OnlyList.Count) -or ($OnlyList -contains (Get-ProdToken $p)) }

function Get-MatchKey($r) {   # survives a patch: product + location + branch
    $br = ''
    if ($r.Product -in 'PHP', 'Python') { $br = Get-Branch $r.Version 2 }
    if ($r.Product -eq 'Node.js') { $br = Get-Branch $r.Version 1 }
    if ($r.Method -eq 'venv') { $br = '' }
    return "$($r.Product)|$($r.Root)|$br"
}

function Set-Kind($r) {   # picks the action for one finding
    $m = $r.Method; $p = $r.Product; $kind = ''; $desc = ''
    $appStep = ''; if ($r.Embedded -and $r.AppName -and $HasWinget) { $appStep = "winget upgrade '$($r.AppName)', then " }
    if ($p -eq 'CA store') { $kind = 'ca'; $desc = 'mark emSign ECC Root CA - G3 as untrusted (certutil)' }
    elseif ($m -eq 'venv') { $kind = 'venvs'; $desc = "refresh certifi in $($r.Venvs.Count) virtualenvs" }
    elseif ($m -eq 'store') { $kind = 'external'; $desc = 'Microsoft Store package - Windows updates it' }
    elseif ($p -eq 'Python') {
        $needRt = $r.Fixed -and (Test-VerLt $r.Version $r.Fixed)
        if ($m -eq 'installer' -or ($m -eq 'installer-user' -and $r.Owner -eq $Me -and $r.Root -match '\\Programs\\Python\\')) {
            if ($needRt) { $kind = 'installer'; $desc = "Python $($r.Fixed) installer (python.org)" }
            else { $kind = 'certifi'; $desc = 'refresh certifi' }
        } elseif ($needRt -and $m -eq 'pymanager' -and $r.Owner -eq $Me) { $kind = 'pymanager'; $desc = "py install --update $(Get-Branch $r.Version 2)" }
        elseif ($needRt) { $kind = 'runtime'; $desc = "$($appStep)python.org $($r.Fixed) runtime files swapped in (site-packages kept)" }
        else { $kind = 'certifi'; $desc = "$($appStep)refresh certifi in place" }
    }
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
        $r.MatchKey = Get-MatchKey $r
        if ($r.Kind -eq 'external') { $script:External += $r } else { $script:PickOrder += $r }
    }
}

function Get-ActionLabel($r) {
    switch ($r.Kind) {
        'installer' { 'installer' } 'user-installer' { 'installer' } 'replace' { 'replace' } 'node-bin' { 'replace' }
        'chromium' { 'replace' } 'runtime' { 'replace' } 'certifi' { 'certifi' } 'venvs' { 'certifi' } 'pymanager' { 'py update' }
        'ca' { 'distrust' }
        default { '-' }
    }
}
function Get-EstMin($r) { switch ($r.Kind) { 'installer' { 2 } 'user-installer' { 2 } 'chromium' { 2 } 'runtime' { 2 } default { 1 } } }

function Show-Plan {
    Write-Host ("`n  {0,3}  {1,-8} {2,-16}    {3,-14} {4,-11} {5,4}  {6}" -f '#', 'PRODUCT', 'INSTALLED', 'FIXED IN', 'ACTION', 'TIME', 'LOCATION')
    Write-Host "  $Line"
    $i = 0; $total = 0
    foreach ($r in $script:PickOrder) {
        $i++; $m = Get-EstMin $r; $total += $m; $fx = $r.Fixed; if (-not $fx) { $fx = '-' }
        Write-Host ('  {0,3}  {1,-8} {2,-16} -> {3,-14} {4,-11} {5,3}m  {6}' -f $i, $r.Product, $r.Version, $fx, (Get-ActionLabel $r), $m, (Get-ShortLoc $r.Root))
    }
    if ($i -eq 0) { Write-Host '       (nothing to patch)' -ForegroundColor DarkGray }
    Write-Host "  $Line"
    Write-Host "  $i can be patched - all of them: ~$total min"
    Write-Host '  installer = the vendor''s official installer for the fixed version, upgrading this copy in place' -ForegroundColor DarkGray
    Write-Host '  replace   = the fixed release swapped into the same folder (runtimes inside apps: app update first)' -ForegroundColor DarkGray
    Write-Host '  certifi   = refresh the certificate bundle inside that Python (removes the compromised eMudhra CAs)' -ForegroundColor DarkGray
    Write-Host '  py update = py install --update   |   distrust = mark the emSign G3 root untrusted in Windows' -ForegroundColor DarkGray
    Write-Host '  Every change is backed up first to C:\ProgramData\vulnpatch\backups' -ForegroundColor DarkGray
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
            Write-Host '    php,node     everything of those products (php node python chrome chromium edge firefox brave ca)'
            Write-Host '    none         cancel'
            $ans = Read-Host '  Your choice [all]'
            if (Set-Pick $ans) { break }
        }
    }
    $chosen = @($script:PickOrder | Where-Object { $_.Picked })
    if (-not $chosen.Count) { Write-Host '  Nothing selected - nothing changed.'; return $false }
    $total = 0; foreach ($r in $chosen) { $total += Get-EstMin $r }
    Write-Host "`n  Selected $($chosen.Count) item(s) - estimated ~$total min:"
    $i = 0
    foreach ($r in $script:PickOrder) {
        $i++
        if ($r.Picked) { Write-Host ('  {0,3}  {1,-8} {2,-16} -> {3,-14} {4}' -f $i, $r.Product, $r.Version, $r.Fixed, $r.Desc) }
    }
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

function Invoke-Patch {
    foreach ($r in @($script:PickOrder | Where-Object { $_.Picked })) {
        Write-Step "$($r.Product) $($r.Version) -> $($r.Fixed)  $($r.Root)"
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
                'chromium'  { Update-Chromium $r }
                'ca'        { Set-CaDistrust $r }
            }
            $r.Outcome = "done: $msg"; Write-Ok "$msg"
        } catch {
            $r.Outcome = "failed: $($_.Exception.Message)"; Write-Note $r.Outcome
            Write-Host "      (script line $($_.InvocationInfo.ScriptLineNumber))" -ForegroundColor DarkGray
        }
    }
}

function Show-Verify {
    $after = @{}
    foreach ($x in $script:Rows) { if ($x.Status -ne 'NOT FOUND') { $after[(Get-MatchKey $x)] = $x } }
    Write-Host ("`n  {0,3}  {1,-16} {2,-8} {3,-16}    {4,-16} {5}" -f '#', 'RESULT', 'PRODUCT', 'BEFORE', 'AFTER', 'LOCATION')
    Write-Host "  $Line"
    $ok = 0; $bad = 0; $skip = 0; $details = @(); $i = 0
    foreach ($r in $script:PickOrder) {
        $i++
        $a = $after[$r.MatchKey]
        $ast = 'GONE'; $aver = '-'; if ($a) { $ast = $a.Status; $aver = $a.Version }
        if ($ast -eq 'PATCHED' -or $ast -eq 'GONE') { $res = 'PATCHED'; if ($ast -eq 'GONE') { $res = 'REMOVED' }; $col = 'Green'; $ok++ }
        elseif (-not $r.Picked) { $res = 'NOT SELECTED'; $col = 'Yellow'; $skip++ }
        else {
            $res = 'STILL VULNERABLE'; $col = 'Red'; $bad++
            $why = $r.Outcome; if ($a -and $a.Note) { $why = "$why | now: $($a.Note)" }
            $details += "$i  $($r.Product) $($r.Version) ($($r.Root)): $why"
        }
        Write-Host ('  {0,3}  ' -f $i) -NoNewline
        Write-Host ('{0,-16} ' -f $res) -ForegroundColor $col -NoNewline
        Write-Host ('{0,-8} {1,-16} -> {2,-16} {3}' -f $r.Product, $r.Version, $aver, (Get-ShortLoc $r.Root))
    }
    Write-Host "  $Line"
    Write-Host ("  Result: {0} patched, {1} still vulnerable, {2} not selected" -f $ok, $bad, $skip)
    if ($details.Count) { Write-Host "`n  Why these are still vulnerable:"; foreach ($d in $details) { Write-Host "    $d" } }
    $miss = @($script:Rows | Where-Object { $_.Status -eq 'NOT FOUND' } | ForEach-Object { $_.Product })
    if ($miss.Count) { Write-Host "  NOT FOUND (not installed): $($miss -join ', ')" -ForegroundColor DarkGray }
    $script:StillBad = $bad + $skip
}

function Show-RestartNeeded {
    $roots = @($script:PickOrder | Where-Object { $_.Picked -and $_.Outcome -like 'done*' } | ForEach-Object { $_.Root.ToLower() })
    $hits = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $p = "$($_.Path)".ToLower(); $p -and @($roots | Where-Object { $p.StartsWith("$_\") }).Count })
    if ($hits.Count) {
        Write-Host "`n  Restart needed - these processes still run the old code:" -ForegroundColor Yellow
        foreach ($h in $hits) { Write-Host "    PID $($h.Id)  $($h.Path)" }
    }
}

# =============================================================================
# MAIN
# =============================================================================
$start = Get-Date
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$modeTxt = switch ($Mode) { 'scan' { 'DETECTION ONLY' } 'plan' { 'DETECTION + PLAN (nothing will be changed)' } default { 'DETECT + PATCH + VERIFY' } }
Write-Host "`n== vulnpatch: $env:COMPUTERNAME | $os | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $modeTxt ==" -ForegroundColor Cyan
if (-not $FullLang) { Write-Host "  PowerShell language mode: $($ExecutionContext.SessionState.LanguageMode) (managed laptop) - using the compatible code paths" -ForegroundColor DarkGray }
if ($Mode -eq 'apply' -and -not $IsAdmin) { Write-Host '  -Apply needs an elevated PowerShell (Run as administrator).' -ForegroundColor Red; exit 2 }
$script:Roots = Get-SearchRoots
Write-Host "  searching: $($script:Roots -join ' ')"
if (-not $IsAdmin) { Write-Note 'not elevated: other users'' folders cannot be read - run as administrator for full coverage' }

Write-Step 'Detection: every copy on the machine'
Invoke-Detection

if ($Mode -eq 'scan') {
    Show-Report
    if (-not $Json) { $Json = Join-Path $env:TEMP "vulnscan-$env:COMPUTERNAME-$Stamp.json" }
    Write-JsonReport $Json
    Write-Host "  JSON report: $Json   ($([int]((Get-Date) - $start).TotalSeconds)s)"
    if ($script:ResultBad) { exit 1 } else { exit 0 }
}

Show-Brief
Build-Plan
if (($script:PickOrder.Count + $script:External.Count) -eq 0) { Write-Step 'Nothing to patch - every copy found is already patched'; exit 0 }
Write-Step 'Patch plan'
Show-Plan

if ($Mode -eq 'plan') {
    Write-Host "`n  Nothing was changed. To patch: run this script with -Apply in an elevated PowerShell."
    Write-Host '  It will ask which numbers to patch (e.g. all | 1,3,5-7 | php,node), or pass -Pick to choose up front.'
    exit 1
}
if (-not $script:PickOrder.Count) { exit 1 }
if (-not (Select-Items)) { exit 1 }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path (Join-Path $LogDir "vulnpatch-$Stamp.log") | Out-Null
try {
    Write-JsonReport (Join-Path $LogDir "before-$Stamp.json")
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
    Stop-Transcript | Out-Null
}
if ($script:StillBad) { exit 1 } else { exit 0 }
