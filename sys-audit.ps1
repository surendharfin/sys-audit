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

# ----- Auto-elevate: if not Admin, relaunch this script elevated via UAC -----
# Admin check: try writing into C:\Windows\System32\ (only admins can) - works under CLM
$isAdmin = $false
$testFile = Join-Path $env:windir "System32\.sa-admin-test-$(Get-Random)"
try {
    New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
    Remove-Item $testFile -Force -ErrorAction SilentlyContinue
    $isAdmin = $true
} catch { $isAdmin = $false }

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host "  Not running as Administrator." -ForegroundColor Yellow
    Write-Host "  Chrome/Edge updates require admin to install MSIs." -ForegroundColor Yellow
    Write-Host "  Relaunching elevated via UAC..." -ForegroundColor Yellow
    Write-Host "========================================================" -ForegroundColor Yellow
    Write-Host ""
    $url = 'https://raw.githubusercontent.com/surendharfin/sys-audit/refs/heads/main/sys-audit.ps1'
    $cmd = "irm $url | iex; Write-Host ''; Write-Host 'Done. Press any key to close.' -ForegroundColor Green; [void][System.Console]::ReadKey(`$true)"
    try {
        Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-Command",$cmd -ErrorAction Stop
        Write-Host "Elevated PowerShell launched. Follow the output in the new window." -ForegroundColor Green
    } catch {
        Write-Host "UAC was DENIED. Chrome/Edge cannot be updated without admin." -ForegroundColor Red
        Write-Host "To retry: right-click the Start menu -> 'Terminal (Admin)' -> re-run the irm command." -ForegroundColor Red
    }
    return
}

Write-Host "Running as Administrator - proceeding with full install flow." -ForegroundColor Green

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
$Target  = @($null,'158.0.1',$null,'',  '3.14.9','')

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
function Download-Fast($url, $dest) {
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Start-BitsTransfer -Source $url -Destination $dest -Priority Foreground -ErrorAction Stop
        if ((Test-Path $dest) -and (Get-Item $dest).Length -gt 50MB) { return $true }
    } catch { }
    if (Get-Command curl.exe -ErrorAction SilentlyContinue) {
        & curl.exe -L --http2 --compressed --fail -o $dest $url 2>&1 | Out-Null
        if ((Test-Path $dest) -and (Get-Item $dest).Length -gt 50MB) { return $true }
    }
    try { Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing; return $true } catch { return $false }
}

function Install-ChromeStableLatest {
    Say "               Scheduled task path failed - trying direct MSI install (UAC required)..." Yellow
    $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
    $msi = "$env:TEMP\chrome-stable.msi"
    $sw  = Get-Date
    if (-not (Download-Fast $url $msi)) {
        Say "               Download failed. Check proxy/firewall." Red; return
    }
    $mb   = "{0:N1}" -f ((Get-Item $msi).Length / 1MB)
    $secs = "{0:N1}" -f ((Get-Date) - $sw).TotalSeconds
    Say "               Downloaded $mb MB in ${secs}s" Green
    Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    try {
        $p = Start-Process msiexec.exe `
             -ArgumentList "/i `"$msi`" /qn /norestart REBOOT=ReallySuppress" `
             -Verb RunAs -Wait -PassThru -ErrorAction Stop
        Say "               msiexec exit code: $($p.ExitCode)" DarkGray
    } catch {
        Say "               UAC denied or run as Administrator to install." Red
    }
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
}

function Install-FirefoxExact($ver) {
    if (-not $ver) { return }
    Say "               Downloading Firefox $ver installer from Mozilla..." Yellow
    $url = "https://download.mozilla.org/?product=firefox-$ver&os=win64&lang=en-US"
    $exe = "$env:TEMP\firefox-$ver-setup.exe"
    $sw  = Get-Date
    if (-not (Download-Fast $url $exe)) {
        Say "               Download failed. Firefox $ver may not exist yet." Red
        return
    }
    $mb   = "{0:N1}" -f ((Get-Item $exe).Length / 1MB)
    $secs = "{0:N1}" -f ((Get-Date) - $sw).TotalSeconds
    Say "               Downloaded $mb MB in ${secs}s" Green
    Get-Process firefox -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    try {
        $p = Start-Process $exe -ArgumentList "/S" -Verb RunAs -Wait -PassThru -ErrorAction Stop
        Say "               Firefox installer exit code: $($p.ExitCode)" DarkGray
    } catch {
        Say "               UAC denied or installer failed." Red
    }
    Remove-Item $exe -Force -ErrorAction SilentlyContinue
}

function Install-EdgeStableLatest {
    Say "               Scheduled task path failed - trying direct MSI install (UAC required)..." Yellow
    $url = 'https://go.microsoft.com/fwlink/?linkid=2093437'
    $msi = "$env:TEMP\edge-stable.msi"
    $sw  = Get-Date
    if (-not (Download-Fast $url $msi)) {
        Say "               Download failed. Check proxy/firewall." Red; return
    }
    $mb   = "{0:N1}" -f ((Get-Item $msi).Length / 1MB)
    $secs = "{0:N1}" -f ((Get-Date) - $sw).TotalSeconds
    Say "               Downloaded $mb MB in ${secs}s" Green
    Get-Process msedge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    try {
        $p = Start-Process msiexec.exe `
             -ArgumentList "/i `"$msi`" /qn /norestart REBOOT=ReallySuppress" `
             -Verb RunAs -Wait -PassThru -ErrorAction Stop
        Say "               msiexec exit code: $($p.ExitCode)" DarkGray
    } catch {
        Say "               UAC denied or run as Administrator to install." Red
    }
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
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
            $tryTask = {
                $taskRun = $false
                foreach ($tn in @('GoogleUpdateTaskMachineUA','GoogleUpdateTaskMachineCore','GoogleUpdaterTaskSystem')) {
                    $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                    if ($t) {
                        try { Start-ScheduledTask -TaskName $tn -ErrorAction Stop; return $tn } catch { }
                    }
                }
                return $null
            }
            $ran = & $tryTask
            if ($ran) {
                Say "               Scheduled task '$ran' started (SYSTEM). Waiting..." DarkGray
                Start-Sleep -Seconds 20
            }
            # Fallback: direct MSI install (needs admin)
            $after = Get-ChromeVersion
            if ($after.Version -eq $OldVer[$i]) {
                Install-ChromeStableLatest
            }
        }
        'edge' {
            $tryTask = {
                foreach ($tn in @('MicrosoftEdgeUpdateTaskMachineUA','MicrosoftEdgeUpdateTaskMachineCore')) {
                    $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
                    if ($t) {
                        try { Start-ScheduledTask -TaskName $tn -ErrorAction Stop; return $tn } catch { }
                    }
                }
                return $null
            }
            $ran = & $tryTask
            if ($ran) {
                Say "               Scheduled task '$ran' started (SYSTEM). Waiting..." DarkGray
                Start-Sleep -Seconds 20
            }
            $after = Get-EdgeVersion
            if ($after.Version -eq $OldVer[$i]) {
                Install-EdgeStableLatest
            }
        }
        'firefox' {
            if ($Target[$i]) {
                Install-FirefoxExact $Target[$i]
            } elseif ($hasWinget) {
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
