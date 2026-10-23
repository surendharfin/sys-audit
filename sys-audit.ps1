<#
.SYNOPSIS
    System audit + updater for Chrome, Firefox, Edge, Node.js, Python, PHP on Windows.

.DESCRIPTION
    PHASE 1 (AUDIT): For each tool, reports Installed/Not-installed and current version.
    PHASE 2 (UPDATE): For each installed tool, triggers an update to the latest version
                      using the tool's own updater (preferred, no admin) or winget as fallback.
    Written to work under Windows Constrained Language Mode: uses hashtables, no .NET method calls.

.EXAMPLE
    irm https://raw.githubusercontent.com/surendharfin/sys-audit/refs/heads/main/sys-audit.ps1 | iex
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
$Winget  = @('Google.Chrome','Mozilla.Firefox','Microsoft.Edge','OpenJS.NodeJS','Python.Python.3.14','PHP.PHP.8.5')
$Target  = @($null,$null,$null,'',  '3.14.9','')

# Branch-aware targets: pick the right patch for whichever major.minor the user is on
$NodeTargets = @{
    '22' = '22.23.4'
    '24' = '24.22.1'
    '26' = '26.12.1'
}
$PhpTargets = @{
    '8.2' = '8.2.35'
    '8.3' = '8.3.36'
    '8.4' = '8.4.27'
    '8.5' = '8.5.12'
}

# Parallel result arrays (CLM-safe)
$Found   = @($false,$false,$false,$false,$false,$false)
$OldVer  = @('-','-','-','-','-','-')
$NewVer  = @('-','-','-','-','-','-')

function Get-ExeVersion($paths) {
    foreach ($p in $paths) {
        if (Test-Path $p) {
            $item = Get-Item $p
            $vi   = $item.VersionInfo
            $v    = $null
            if ($vi) {
                if ($vi.ProductVersion)  { $v = "$($vi.ProductVersion)".Trim() }
                if (-not $v -and $vi.FileVersion) { $v = "$($vi.FileVersion)".Trim() }
            }
            # Fallback: Chrome/Edge store a version-named subdir next to chrome.exe
            if (-not $v) {
                $appDir = Split-Path $p -Parent
                $subdirs = Get-ChildItem $appDir -Directory -ErrorAction SilentlyContinue |
                           Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
                           Sort-Object Name -Descending
                if ($subdirs) { $v = $subdirs[0].Name }
            }
            if ($v) { return @{ Installed = $true; Version = $v; Path = $p } }
        }
    }
    return @{ Installed = $false; Version = $null; Path = $null }
}

function Get-ChromeVersion {
    $exe = Get-ExeVersion @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    if (-not $exe.Installed) { return $exe }
    # Consult registry pv for staged update
    $regPaths = @(
        "HKLM:\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}",
        "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}"
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            $pv = (Get-ItemProperty $rp -ErrorAction SilentlyContinue).pv
            if ($pv) {
                $vA = $pv -as [version]
                $vB = $exe.Version -as [version]
                if ($vA -and $vB -and $vA -gt $vB) { return @{ Installed = $true; Version = $pv } }
            }
        }
    }
    return $exe
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

    # Reject Microsoft Store app-execution-alias stub (small reparse point that opens the Store)
    $src = "$($g.Source)"
    if ($src -like "*WindowsApps*") {
        if ((Test-Path $src) -and (Get-Item $src).Length -lt 1024) {
            return @{ Installed = $false; Version = $null }
        }
    }

    $raw = & $cmd --version 2>&1 | Select-Object -First 1
    if (-not $raw) { $raw = & $cmd -V 2>&1 | Select-Object -First 1 }
    $v = "$raw".Trim()
    if (-not $v) { return @{ Installed = $false; Version = $null } }
    return @{ Installed = $true; Version = $v }
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
        default   {
            $info = Get-CliVersion $Cmds[$i]
            if (-not $info.Installed -and $Cmds[$i] -eq 'node')   { $info = Get-CliVersion 'nodejs' }
            if (-not $info.Installed -and $Cmds[$i] -eq 'python') {
                $info = Get-CliVersion 'python3'
                if (-not $info.Installed) { $info = Get-CliVersion 'py' }
            }
        }
    }
    $Found[$i] = $info.Installed
    if ($info.Installed) {
        $OldVer[$i] = $info.Version

        if ($Names[$i] -eq 'Node.js') {
            $m = [regex]::Match($info.Version, 'v?(\d+)\.')
            if ($m.Success) {
                $major = $m.Groups[1].Value
                if ($NodeTargets.ContainsKey($major)) { $Target[$i] = $NodeTargets[$major] }
            }
        }
        elseif ($Names[$i] -eq 'PHP') {
            $m = [regex]::Match($info.Version, '(\d+\.\d+)\.')
            if ($m.Success) {
                $branch = $m.Groups[1].Value
                if ($PhpTargets.ContainsKey($branch)) { $Target[$i] = $PhpTargets[$branch] }
            }
        }

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
            # Preferred: SYSTEM-level scheduled task (actually installs, no admin needed from user)
            $taskNames = @('GoogleUpdateTaskMachineUA','GoogleUpdateTaskMachineCore','GoogleUpdaterTaskSystem')
            $taskRun = $false
            foreach ($tn in $taskNames) {
                $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                if ($t) {
                    Start-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                    Say "               Scheduled task '$tn' started (runs as SYSTEM, installs latest)." DarkGray
                    $taskRun = $true
                    break
                }
            }
            if (-not $taskRun) {
                $gu = "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
                if (Test-Path $gu) {
                    & $gu /ua /installsource scheduler
                    Say "               GoogleUpdate.exe /ua triggered (may need SYSTEM to actually install)." DarkGray
                }
            }
            # Wait longer so the SYSTEM task has time to download+stage
            Start-Sleep -Seconds 15
        }
        'edge' {
            $taskNames = @('MicrosoftEdgeUpdateTaskMachineUA','MicrosoftEdgeUpdateTaskMachineCore')
            $taskRun = $false
            foreach ($tn in $taskNames) {
                $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                if ($t) {
                    Start-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                    Say "               Scheduled task '$tn' started (runs as SYSTEM, installs latest)." DarkGray
                    $taskRun = $true
                    break
                }
            }
            if (-not $taskRun) {
                $eu = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
                if (Test-Path $eu) {
                    & $eu /ua /installsource scheduler
                    Say "               MicrosoftEdgeUpdate.exe /ua triggered." DarkGray
                }
            }
            Start-Sleep -Seconds 15
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
                $t  = $Target[$i]
                $id = $Winget[$i]

                if ($Names[$i] -eq 'PHP' -and $t) {
                    $branch = ($t -split '\.')[0..1] -join '.'
                    $id = "PHP.PHP.$branch"
                }
                if ($Names[$i] -eq 'Node.js' -and $t) {
                    $major = [int](($t -split '\.')[0])
                    if ($major -in 22,24,26) { $id = 'OpenJS.NodeJS.LTS' } else { $id = 'OpenJS.NodeJS' }
                }

                if ($t) {
                    Say "               Target: $t (winget id: $id)" DarkGray
                    winget install --id $id --version $t --silent --accept-source-agreements --accept-package-agreements --force 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Say "               Pinned $t unavailable - falling back to latest in branch." DarkGray
                        winget upgrade --id $id --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
                    }
                } else {
                    winget upgrade --id $id --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
                }
            } else {
                Say "               No updater available (winget missing)." Red
                continue
            }
        }
    }

    switch ($Detect[$i]) {
        'chrome'  { $after = Get-ChromeVersion }
        'firefox' { $after = Get-FirefoxVersion }
        'edge'    { $after = Get-EdgeVersion }
        default   { $after = Get-CliVersion $Cmds[$i] }
    }
    if ($after.Version) { $NewVer[$i] = $after.Version }

    # For Chrome: check registry 'pv' - if newer than exe, update is downloaded but needs restart
    if ($Detect[$i] -eq 'chrome') {
        $pv = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}" -ErrorAction SilentlyContinue).pv
        if (-not $pv) {
            $pv = (Get-ItemProperty "HKLM:\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}" -ErrorAction SilentlyContinue).pv
        }
        if ($pv -and ($pv -ne $NewVer[$i])) {
            Say ("               Update staged: $pv  (apply by closing ALL Chrome windows + tray, then reopen)") Yellow
            $NewVer[$i] = $pv
        }
    }

    if ($NewVer[$i] -eq $OldVer[$i]) {
        Say ("               No change: {0}" -f $NewVer[$i]) DarkGray
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
