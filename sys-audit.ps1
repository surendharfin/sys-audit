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
$Target  = @('156.0.8078.48',$null,$null,'',  '3.14.9','')
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

# Chrome: version 156.x is Beta/Early-Stable (Stable is still 155.x)
# Direct enterprise MSI by channel:
$ChromeStableMsi = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
$ChromeBetaMsi   = 'https://dl.google.com/chrome/install/beta/googlechromebetastandaloneenterprise64.msi'
$ChromeDevMsi    = 'https://dl.google.com/chrome/install/dev/googlechromedevstandaloneenterprise64.msi'

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
    # Scan all channels - pick the highest version found
    $candidates = @(
        "$env:ProgramFiles\Google\Chrome Beta\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome Beta\Application\chrome.exe",
        "$env:ProgramFiles\Google\Chrome Dev\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome Dev\Application\chrome.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    $best = $null
    $bestPath = $null
    foreach ($p in $candidates) {
        if (Test-Path $p) {
            $v = (Get-Item $p).VersionInfo.ProductVersion
            if ($v) {
                if (-not $best) { $best = $v; $bestPath = $p; continue }
                # Compare as [version] when possible
                $vA = $v     -as [version]
                $vB = $best  -as [version]
                if ($vA -and $vB -and $vA -gt $vB) { $best = $v; $bestPath = $p }
            }
        }
    }
    if (-not $best) { return @{ Installed = $false; Version = $null } }

    # If we're on Stable (and only Stable), also consult registry pv for staged updates
    if ($bestPath -notlike "*Chrome Beta*" -and $bestPath -notlike "*Chrome Dev*") {
        $regPaths = @(
            "HKLM:\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}",
            "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}"
        )
        foreach ($rp in $regPaths) {
            if (Test-Path $rp) {
                $pv = (Get-ItemProperty $rp -ErrorAction SilentlyContinue).pv
                if ($pv) {
                    $vA = $pv  -as [version]
                    $vB = $best -as [version]
                    if ($vA -and $vB -and $vA -gt $vB) { $best = $pv }
                }
            }
        }
    }
    return @{ Installed = $true; Version = $best }
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

    # Reject the Microsoft Store app-execution-alias stub (empty Python/Node that opens the Store)
    $src = "$($g.Source)"
    if ($src -like "*WindowsApps*AppInstaller*" -or $src -like "*WindowsApps\Microsoft.*") {
        # Try to read the alias target; if it's a reparse-point stub with 0 bytes it's not real
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
            # Node may be installed as 'nodejs' on some systems
            if (-not $info.Installed -and $Cmds[$i] -eq 'node') {
                $info = Get-CliVersion 'nodejs'
            }
            # Python aliases: python3, py
            if (-not $info.Installed -and $Cmds[$i] -eq 'python') {
                $info = Get-CliVersion 'python3'
                if (-not $info.Installed) { $info = Get-CliVersion 'py' }
            }
        }
    }
    $Found[$i]  = $info.Installed
    if ($info.Installed) {
        $OldVer[$i] = $info.Version

        # Branch-aware target resolution
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
            $t = $Target[$i]
            # If a specific Chrome target is pinned, always use the channel-specific MSI
            if ($t) {
                $major = 0
                $parts = $t.Split('.')
                if ($parts.Count -gt 0) { $major = [int]$parts[0] }

                if ($major -ge 157)      { $msiUrl = $ChromeDevMsi;    $channel = 'Dev'    }
                elseif ($major -ge 156)  { $msiUrl = $ChromeBetaMsi;   $channel = 'Beta'   }
                else                     { $msiUrl = $ChromeStableMsi; $channel = 'Stable' }

                Say "               Target $t -> Chrome $channel channel MSI" DarkGray
                $msi = Join-Path $env:TEMP "chrome-$channel.msi"
                if (Test-Path $msi) { Remove-Item $msi -Force -ErrorAction SilentlyContinue }

                $dlOk = $false
                $sw = Get-Date

                # Method 1: BITS
                try {
                    Import-Module BitsTransfer -ErrorAction Stop
                    Say "               Downloading via BITS..." DarkGray
                    Start-BitsTransfer -Source $msiUrl -Destination $msi -Priority Foreground -ErrorAction Stop
                    if ((Test-Path $msi) -and (Get-Item $msi).Length -gt 50MB) { $dlOk = $true }
                } catch {
                    Say "               BITS failed: $($_.Exception.Message)" DarkGray
                }
                # Method 2: curl
                if (-not $dlOk -and (Get-Command curl.exe -ErrorAction SilentlyContinue)) {
                    Say "               Downloading via curl..." DarkGray
                    & curl.exe -L --http2 --compressed --fail -o $msi $msiUrl 2>&1 | Out-Null
                    if ((Test-Path $msi) -and (Get-Item $msi).Length -gt 50MB) { $dlOk = $true }
                }
                # Method 3: IWR
                if (-not $dlOk) {
                    Say "               Downloading via Invoke-WebRequest..." DarkGray
                    try { Invoke-WebRequest -Uri $msiUrl -OutFile $msi -UseBasicParsing; $dlOk = $true } catch { }
                }

                if ($dlOk) {
                    $elapsed = (Get-Date) - $sw
                    $secs    = "{0:N1}" -f $elapsed.TotalSeconds
                    $bytes   = (Get-Item $msi).Length
                    $mb      = "{0:N1}" -f ($bytes / 1MB)
                    Say "               Downloaded $mb MB in ${secs}s" Green

                    # Close Chrome to avoid in-use file conflicts
                    Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2

                    Say "               Installing MSI (UAC prompt - click YES)..." Yellow
                    $msiLog = Join-Path $logDir "chrome-$channel-msi.log"
                    try {
                        $p = Start-Process msiexec.exe `
                             -ArgumentList "/i `"$msi`" /qn /norestart REBOOT=ReallySuppress /L*v `"$msiLog`"" `
                             -Verb RunAs -Wait -PassThru -ErrorAction Stop
                        Say "               msiexec exit code: $($p.ExitCode)" DarkGray
                        if ($p.ExitCode -eq 0) {
                            Say "               Install OK. Chrome $channel is now at $env:ProgramFiles\Google\Chrome $channel\" Green
                        } else {
                            Say "               Install returned non-zero. See $msiLog" Red
                        }
                    } catch {
                        Say "               UAC denied or msiexec failed: $($_.Exception.Message)" Red
                        Say "               Hint: right-click PowerShell -> Run as Administrator, then re-run." Yellow
                    }
                    Remove-Item $msi -Force -ErrorAction SilentlyContinue
                } else {
                    Say "               Could not download Chrome $channel MSI. Check network/proxy." Red
                }
            } else {
                $gu = "${env:ProgramFiles(x86)}\Google\Update\GoogleUpdate.exe"
                if (Test-Path $gu) {
                    & $gu /ua /installsource scheduler
                    Start-Sleep -Seconds 3
                    Say "               Google Update triggered (no admin needed)." DarkGray
                } elseif ($hasWinget) {
                    winget upgrade --id $Winget[$i] --silent --accept-source-agreements --accept-package-agreements 2>&1 | Out-Null
                }
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
                $t  = $Target[$i]
                $id = $Winget[$i]

                # Branch-aware winget id for PHP (PHP.PHP.8.2 / .8.3 / .8.4 / .8.5)
                if ($Names[$i] -eq 'PHP' -and $t) {
                    $branch = ($t -split '\.')[0..1] -join '.'
                    $id = "PHP.PHP.$branch"
                }
                # Branch-aware winget id for Node (OpenJS.NodeJS = Current, OpenJS.NodeJS.LTS = latest LTS)
                if ($Names[$i] -eq 'Node.js' -and $t) {
                    $major = [int](($t -split '\.')[0])
                    # 22, 24 = even LTS lines; 26 is incoming LTS
                    if ($major -in 22,24,26) { $id = 'OpenJS.NodeJS.LTS' } else { $id = 'OpenJS.NodeJS' }
                }

                if ($t) {
                    Say "               Target: $t (pinned, winget id: $id)" DarkGray
                    winget install --id $id --version $t --silent --accept-source-agreements --accept-package-agreements --force 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Say "               Pinned $t unavailable in winget - falling back to latest in branch." DarkGray
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
