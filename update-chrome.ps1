<#
.SYNOPSIS
    System audit + updater for Chrome, Firefox, Edge, Node.js, Python, PHP on Windows.

.DESCRIPTION
    PHASE 1 (AUDIT): For each tool, reports Installed/Not-installed and current version.
    PHASE 2 (UPDATE): For each tool that IS installed, triggers an update to the latest version
                      using the tool's own updater (preferred, no admin) or winget as fallback.
    Written to work under Windows Constrained Language Mode: uses hashtables, no .NET method calls.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File "D:\chrome Update\system-audit-update.ps1"
#>

$ErrorActionPreference = 'SilentlyContinue'

$logDir = "$env:ProgramData\SystemAudit"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$log = Join-Path $logDir "audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Say($msg, $color = 'White') {
    Write-Host $msg -ForegroundColor $color
    Add-Content -Path $log -Value $msg
}
function Line { Say ("-" * 70) }

Say ""
Say "============================================================" Cyan
Say "    SYSTEM AUDIT  -  $env:COMPUTERNAME  -  $(Get-Date)"      Cyan
Say "============================================================" Cyan

# ----- Audit targets: Name | Detect-type | CLI cmd | winget id | pinned target -----
$Names   = @('Google Chrome','Mozilla Firefox','Microsoft Edge','Node.js','Python','PHP')
$Detect  = @('chrome','firefox','edge','cli','cli','cli')
$Cmds    = @($null,$null,$null,'node','python','php')
$Winget  = @('Google.Chrome','Mozilla.Firefox','Microsoft.Edge','OpenJS.NodeJS','Python.Python.3.15','PHP.PHP.8.5')
$Target  = @($null,$null,$null,'26.12.1','3.14.9','8.5.12')
# PHP fallback target (used only if 8.5.12 isn't in winget yet)
$PhpFallback = '8.4.27'

# Parallel result arrays (CLM-safe)
$Found   = @($false,$false,$false,$false,$false,$false)
$OldVer  = @('-','-','-','-','-','-')
$NewVer  = @('-','-','-','-','-','-')

function Get-ExeVersion($paths) {
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $v = (Get-Item $p).VersionInfo.ProductVersion
            return @{ Installed = $true; Version = $v }
        }
    }
    return @{ Installed = $false; Version = $null }
}

function Get-ChromeVersion {
    return Get-ExeVersion @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
}
function Get-FirefoxVersion {
    return Get-ExeVersion @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
        "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe"
    )
}
function Get-EdgeVersion {
    return Get-ExeVersion @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
    )
}
function Get-CliVersion($cmd) {
    $g = Get-Command $cmd -ErrorAction SilentlyContinue
    if (-not $g) { return @{ Installed = $false; Version = $null } }
    $raw = & $cmd --version 2>&1 | Select-Object -First 1
    return @{ Installed = $true; Version = "$raw".Trim() }
}

# ---------- PHASE 1: AUDIT ----------
Say ""
Say ">>> PHASE 1: AUDIT" Yellow
Line

for ($i = 0; $i -lt $Names.Count; $i++) {
    switch ($Detect[$i]) {
        'chrome'  { $info = Get-ChromeVersion }
        'firefox' { $info = Get-FirefoxVersion }
        'edge'    { $info = Get-EdgeVersion }
        default   { $info = Get-CliVersion $Cmds[$i] }
    }
    $Found[$i]  = $info.Installed
    if ($info.Installed) {
        $OldVer[$i] = $info.Version
        $tgt = if ($Target[$i]) { "  (target: $($Target[$i]))" } else { '' }
        Say ("  [FOUND]      {0,-18}  version: {1}{2}" -f $Names[$i], $info.Version, $tgt) Green
    } else {
        Say ("  [NOT FOUND]  {0,-18}  (not installed)" -f $Names[$i]) Red
    }
}

# ---------- PHASE 2: UPDATE ----------
Say ""
Say ">>> PHASE 2: UPDATE" Yellow
Line

$hasWinget = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
if (-not $hasWinget) {
    Say "  winget NOT found - CLI tools (Node/Python/PHP) cannot auto-update." Red
    Say "  Install App Installer from Microsoft Store, OR get winget from" DarkGray
    Say "  https://aka.ms/getwinget to enable Node/Python/PHP updates." DarkGray
}

for ($i = 0; $i -lt $Names.Count; $i++) {
    if (-not $Found[$i]) {
        Say ("  [SKIP]       {0,-18}  not installed - skipping" -f $Names[$i]) DarkGray
        continue
    }

    Say ("  [UPDATING]   {0,-18}  current: {1}" -f $Names[$i], $OldVer[$i]) Cyan

    switch ($Detect[$i]) {
        'chrome' {
            $gu = "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
            if (Test-Path $gu) {
                & $gu /ua /installsource scheduler
                Start-Sleep -Seconds 3
                Say "               Google Update triggered (no admin needed)." DarkGray
            } elseif ($hasWinget) {
                winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
            }
        }
        'edge' {
            $eu = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
            if (Test-Path $eu) {
                & $eu /ua /installsource scheduler
                Start-Sleep -Seconds 3
                Say "               Microsoft Edge Update triggered (no admin needed)." DarkGray
            } elseif ($hasWinget) {
                winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
            }
        }
        'firefox' {
            if ($hasWinget) {
                winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
            } else {
                Say "               winget missing - Firefox self-updates on next launch." DarkGray
            }
        }
        default {
            if ($hasWinget) {
                $t = $Target[$i]
                if ($t) {
                    Say "               Target: $t (pinned)" DarkGray
                    winget install --id $Winget[$i] --version $t --silent --accept-source-agreements --accept-package-agreements --force 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0 -and $Names[$i] -eq 'PHP') {
                        Say "               PHP $t unavailable - trying fallback $PhpFallback (PHP 8.4 branch)." DarkGray
                        winget install --id 'PHP.PHP.8.4' --version $PhpFallback --silent --accept-source-agreements --accept-package-agreements --force 2>&1 | Out-Null
                    }
                    if ($LASTEXITCODE -ne 0) {
                        Say "               Pinned $t unavailable - falling back to latest in winget." DarkGray
                        winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
                    }
                } else {
                    winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
                }
            } else {
                Say "               No updater available (winget missing)." Red
                continue
            }
        }
    }

    Start-Sleep -Seconds 2
    switch ($Detect[$i]) {
        'chrome'  { $after = Get-ChromeVersion }
        'firefox' { $after = Get-FirefoxVersion }
        'edge'    { $after = Get-EdgeVersion }
        default   { $after = Get-CliVersion $Cmds[$i] }
    }
    if ($after.Version) { $NewVer[$i] = $after.Version }

    if ($NewVer[$i] -eq $OldVer[$i]) {
        Say ("               No change or update staged: {0}" -f $NewVer[$i]) DarkGray
    } else {
        Say ("               UPDATED  {0}  ->  {1}" -f $OldVer[$i], $NewVer[$i]) Green
    }
}

# ---------- SUMMARY ----------
Say ""
Say ">>> SUMMARY" Yellow
Line
Say ("  {0,-18} {1,-10} {2,-32} {3}" -f 'Tool','Status','Old Version','New Version')
Line
for ($i = 0; $i -lt $Names.Count; $i++) {
    $status = if ($Found[$i]) { 'FOUND' } else { 'MISSING' }
    Say ("  {0,-18} {1,-10} {2,-32} {3}" -f $Names[$i], $status, $OldVer[$i], $NewVer[$i])
}
Line
Say "Full log: $log" DarkGray
Say ""
