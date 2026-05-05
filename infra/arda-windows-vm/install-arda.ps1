#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the ARDA Ring-0 Telemetry Collector on a Windows VM.

.DESCRIPTION
    1. Downloads Python 3.12 embeddable zip (no installer, portable)
    2. Bootstraps pip into the embed
    3. Installs pywin32 + requests
    4. Copies the ARDA source tree from a network share or local path
    5. Registers ARDACollector as a Windows Service
    6. Starts the service

.PARAMETER ArdaSrc
    Path to the arda_windows source directory ("Arda Windows\src" from the repo).
    Defaults to a USB/network share path; override as needed.
    Example: -ArdaSrc "\\192.168.100.1\arda\src"

.PARAMETER PythonVersion
    Python 3.x version to embed. Default: 3.12.10

.EXAMPLE
    # From a USB drive mounted as E:
    PowerShell -ExecutionPolicy Bypass -File install-arda.ps1 -ArdaSrc E:\arda\src

    # From a network share (host forwards SMB on port 4445 → guest 445)
    PowerShell -ExecutionPolicy Bypass -File install-arda.ps1 -ArdaSrc \\127.0.0.1\arda\src
#>

param(
    [string]$ArdaSrc     = "\\192.168.100.1\arda\src",
    [string]$PythonVersion = "3.12.10"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ARDA_ROOT    = "C:\ARDA"
$PYTHON_DIR   = "$ARDA_ROOT\python"
$SRC_DEST     = "$ARDA_ROOT\src"
$SVC_SCRIPT   = "$ARDA_ROOT\src\arda_windows\service\arda_collector_svc.py"
$PY_EXE       = "$PYTHON_DIR\python.exe"
$ARCH         = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "win32" }
$EMBED_URL    = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-$ARCH.zip"
$PIP_URL      = "https://bootstrap.pypa.io/get-pip.py"

function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "    OK: $msg"  -ForegroundColor Green }

# ── 1. Create directory structure ─────────────────────────────────────────
Write-Step "Creating ARDA directory at $ARDA_ROOT"
New-Item -ItemType Directory -Force -Path $ARDA_ROOT     | Out-Null
New-Item -ItemType Directory -Force -Path $PYTHON_DIR    | Out-Null
New-Item -ItemType Directory -Force -Path $SRC_DEST      | Out-Null
Write-OK "directories created"

# ── 2. Download and extract Python embeddable ─────────────────────────────
$embedZip = "$ARDA_ROOT\python-embed.zip"
if (-not (Test-Path $PY_EXE)) {
    Write-Step "Downloading Python $PythonVersion embeddable..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $EMBED_URL -OutFile $embedZip -UseBasicParsing
    Write-Step "Extracting..."
    Expand-Archive -Path $embedZip -DestinationPath $PYTHON_DIR -Force
    Remove-Item $embedZip
    Write-OK "Python at $PY_EXE"
} else {
    Write-OK "Python already present, skipping download"
}

# ── 3. Enable site-packages in the embed (edit ._pth file) ────────────────
Write-Step "Enabling site-packages in embeddable Python..."
$pthFile = Get-ChildItem "$PYTHON_DIR\python*._pth" | Select-Object -First 1
if ($pthFile) {
    $content = Get-Content $pthFile.FullName
    # Uncomment "import site" line
    $content = $content -replace "^#import site", "import site"
    # Add src to sys.path
    if ($content -notcontains $SRC_DEST) {
        $content += $SRC_DEST
    }
    $content | Set-Content $pthFile.FullName
    Write-OK "._pth updated: $($pthFile.Name)"
} else {
    Write-Host "    WARNING: no ._pth file found" -ForegroundColor Yellow
}

# ── 4. Bootstrap pip ──────────────────────────────────────────────────────
$pipExe = "$PYTHON_DIR\Scripts\pip.exe"
if (-not (Test-Path $pipExe)) {
    Write-Step "Bootstrapping pip..."
    $getPip = "$ARDA_ROOT\get-pip.py"
    Invoke-WebRequest -Uri $PIP_URL -OutFile $getPip -UseBasicParsing
    & $PY_EXE $getPip --no-warn-script-location
    Remove-Item $getPip
    Write-OK "pip installed"
} else {
    Write-OK "pip already present"
}

# ── 5. Install dependencies ───────────────────────────────────────────────
Write-Step "Installing pywin32 and requests..."
& $PY_EXE -m pip install --no-warn-script-location pywin32 requests
Write-OK "dependencies installed"

# ── 6. Run pywin32 post-install ───────────────────────────────────────────
Write-Step "Running pywin32 post-install script..."
$pywin32PostInstall = Get-ChildItem "$PYTHON_DIR\Scripts\pywin32_postinstall.py" -ErrorAction SilentlyContinue
if ($pywin32PostInstall) {
    & $PY_EXE $pywin32PostInstall.FullName -install
} else {
    # Newer pywin32 bundles the script differently
    & $PY_EXE -c "import pywin32_bootstrap" -ErrorAction SilentlyContinue
}
Write-OK "pywin32 post-install done"

# ── 7. Copy ARDA source ───────────────────────────────────────────────────
Write-Step "Copying ARDA source from $ArdaSrc..."
if (-not (Test-Path $ArdaSrc)) {
    Write-Host "    ERROR: ArdaSrc not found: $ArdaSrc" -ForegroundColor Red
    Write-Host "    Copy 'Arda Windows\src' to the VM manually then re-run this step." -ForegroundColor Yellow
    Write-Host "    You can also pass -ArdaSrc to specify the path." -ForegroundColor Yellow
    exit 1
}
Copy-Item -Path "$ArdaSrc\*" -Destination $SRC_DEST -Recurse -Force
Write-OK "ARDA source copied to $SRC_DEST"

# ── 8. Register Windows Service ───────────────────────────────────────────
Write-Step "Registering ARDACollector service..."
$svcName = "ARDACollector"

# Remove if already exists (clean reinstall)
if (Get-Service -Name $svcName -ErrorAction SilentlyContinue) {
    Write-Host "    Stopping and removing existing service..."
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    & $PY_EXE $SVC_SCRIPT remove
}

& $PY_EXE $SVC_SCRIPT install
Write-OK "service registered"

# Set service to auto-start and set description
Set-Service -Name $svcName -StartupType Automatic
$svcObj = Get-WmiObject -Class Win32_Service -Filter "Name='$svcName'"
$svcObj.Change($null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null) | Out-Null

Write-OK "service set to auto-start"

# ── 9. Start the service ──────────────────────────────────────────────────
Write-Step "Starting ARDACollector..."
Start-Service -Name $svcName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $svcName
if ($svc.Status -eq "Running") {
    Write-OK "ARDACollector is RUNNING"
} else {
    Write-Host "    WARNING: service status is $($svc.Status)" -ForegroundColor Yellow
    Write-Host "    Check Event Viewer > Windows Logs > Application for errors." -ForegroundColor Yellow
}

# ── 10. Quick smoke test (HTTP) ───────────────────────────────────────────
Write-Step "Smoke-testing ARDA HTTP API on 127.0.0.1:7331..."
Start-Sleep -Seconds 5
try {
    $health  = Invoke-RestMethod -Uri "http://127.0.0.1:7331/health"    -TimeoutSec 10
    $summary = Invoke-RestMethod -Uri "http://127.0.0.1:7331/summary"   -TimeoutSec 10
    $sv      = Invoke-RestMethod -Uri "http://127.0.0.1:7331/sovereignty" -TimeoutSec 10
    Write-OK "health:      $($health.status)"
    Write-OK "platform:    $($summary.platform)"
    Write-OK "sovereignty: $($sv.state)"
    Write-Host ""
    Write-Host "ARDA Collector is live on http://127.0.0.1:7331" -ForegroundColor Green
    Write-Host "From the Linux host (port 7331 is forwarded): curl http://localhost:7331/health" -ForegroundColor Green
} catch {
    Write-Host "    HTTP check failed: $_" -ForegroundColor Yellow
    Write-Host "    The service may still be initialising; try again in 10 s." -ForegroundColor Yellow
}
