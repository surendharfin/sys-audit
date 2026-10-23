<#
.SYNOPSIS
    Downloads Google's current Chrome Enterprise MSI and installs/upgrades silently.

.DESCRIPTION
    - Detects 64/32-bit OS and picks the matching MSI from dl.google.com
    - Downloads to %TEMP% using TLS 1.2
    - Closes running Chrome processes
    - Installs silently with msiexec (/qn /norestart REBOOT=ReallySuppress)
    - Logs to %ProgramData%\ChromeUpdate\
    - Reports new installed version

    MUST be run as Administrator.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File "D:\chrome Update\update-chrome.ps1"
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# --- Elevation check ---
$current = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $current.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script must be run as Administrator. Re-launching elevated..."
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# --- Logging ---
$logDir = "$env:ProgramData\ChromeUpdate"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$log = Join-Path $logDir "chrome-update.log"
function Log([string]$msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $log -Value $line
    Write-Host $line
}

Log "===== Chrome update started on $env:COMPUTERNAME ====="

# --- Current version (BEFORE) ---
$exePaths = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
)
$before = $null
foreach ($p in $exePaths) {
    if (Test-Path $p) { $before = (Get-Item $p).VersionInfo.ProductVersion; break }
}
if (-not $before) { $before = 'not installed' }
Log "[BEFORE] Current Chrome version: $before"

# --- Pick MSI ---
if ([Environment]::Is64BitOperatingSystem) {
    $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
    $arch = '64-bit'
} else {
    $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi'
    $arch = '32-bit'
}
$msi = Join-Path $env:TEMP 'googlechrome_enterprise.msi'
Log "OS architecture: $arch"
Log "Downloading: $url"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
    Log "Downloaded to $msi ($([math]::Round((Get-Item $msi).Length / 1MB, 2)) MB)"
} catch {
    Log "ERROR: download failed - $($_.Exception.Message)"
    exit 1
}

# --- Close Chrome ---
Log "Closing any running Chrome processes..."
Get-Process chrome -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# --- Install ---
$msiLog = Join-Path $logDir "msi-install.log"
Log "Running msiexec..."
$p = Start-Process msiexec.exe `
    -ArgumentList "/i `"$msi`" /qn /norestart REBOOT=ReallySuppress /L*v `"$msiLog`"" `
    -Wait -PassThru
$rc = $p.ExitCode
Log "msiexec exit code: $rc"

Remove-Item $msi -Force -ErrorAction SilentlyContinue

# --- Version after ---
Start-Sleep -Seconds 2
$after = $null
foreach ($p in $exePaths) {
    if (Test-Path $p) { $after = (Get-Item $p).VersionInfo.ProductVersion; break }
}
$regVer = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}" -ErrorAction SilentlyContinue).pv
if (-not $regVer) {
    $regVer = (Get-ItemProperty "HKLM:\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D9E530F96}" -ErrorAction SilentlyContinue).pv
}

if (-not $after) { $after = 'unknown' }
Log "[AFTER] Installed executable version: $after"
Log "[AFTER] Registry version            : $regVer"

$banner = @"

----------------------------------------------
 Old version : $before
 New version : $after
 Registry    : $regVer
"@
if ($before -eq $after) {
    $banner += "`n Status      : No change (already latest or install failed)"
} else {
    $banner += "`n Status      : UPDATED  $before  ->  $after"
}
$banner += "`n----------------------------------------------`n"

Add-Content -Path $log -Value $banner
Write-Host $banner -ForegroundColor Cyan

Log "===== Chrome update finished (exit $rc) ====="

if ($rc -eq 0) {
    Write-Host "SUCCESS. Full log: $log" -ForegroundColor Green
} else {
    Write-Host "FAILED (msiexec exit $rc). See $msiLog" -ForegroundColor Red
}

exit $rc
