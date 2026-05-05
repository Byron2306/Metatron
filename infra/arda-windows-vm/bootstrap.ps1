#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Zero-touch ARDA Collector bootstrap — runs automatically via autounattend.xml
    FirstLogonCommands on a fresh Windows 11 VM.

.DESCRIPTION
    1.  Enables RDP and disables NLA so xfreerdp3 can connect from the Linux host
    2.  Downloads Python 3.12 embeddable (no MSI, no UAC)
    3.  Enables site-packages, bootstraps pip
    4.  Installs pywin32 + requests; runs pywin32_postinstall
    5.  Downloads arda-src.zip from GitHub (latest main branch)
    6.  Extracts source to C:\ARDA\src
    7.  Registers and starts ARDACollector Windows service (binds 0.0.0.0:7331)
    8.  Smoke-tests the HTTP API
    9.  Writes a full transcript to C:\ARDA\bootstrap.log

    Progress and errors are also written to C:\arda-bootstrap.log (next to the
    script) for easy retrieval via: curl http://127.0.0.1:7331/  (after step 7).

    The HTTP server on the Linux host (10.0.2.2:8888) is used as a fast fallback
    for the zip if GitHub is slow.  Primary URL is always GitHub raw.

.NOTES
    Source: infra/arda-windows-vm/bootstrap.ps1 in the Metatron repo.
    Called by: autounattend.xml FirstLogonCommands (Order 2).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Constants ─────────────────────────────────────────────────────────────
$ARDA_ROOT      = "C:\ARDA"
$PYTHON_DIR     = "$ARDA_ROOT\python"
$SRC_DEST       = "$ARDA_ROOT\src"
$SVC_SCRIPT     = "$ARDA_ROOT\src\arda_windows\service\arda_collector_svc.py"
$PY_EXE         = "$PYTHON_DIR\python.exe"
$LOG_FILE       = "$ARDA_ROOT\bootstrap.log"

$PYTHON_VERSION = "3.12.10"
$ARCH           = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "win32" }
$EMBED_URL      = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-embed-$ARCH.zip"
$PIP_URL        = "https://bootstrap.pypa.io/get-pip.py"

# GitHub raw — primary source for ARDA code
$ARDA_ZIP_URL   = "https://github.com/Byron2306/Metatron/raw/main/arda-src.zip"
# HTTP server fallback (Linux host reachable from guest via QEMU NAT)
$ARDA_ZIP_LOCAL = "http://10.0.2.2:8888/arda-src.zip"

# ── Logging helpers ───────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $ARDA_ROOT | Out-Null
Start-Transcript -Path $LOG_FILE -Append -NoClobber:$false

function Write-Step { param($msg) Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-OK   { param($msg) Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "    WARN: $msg" -ForegroundColor Yellow }

Write-Host "==================================================" -ForegroundColor Magenta
Write-Host "  ARDA Bootstrap  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
Write-Host "==================================================" -ForegroundColor Magenta

# ── Step 1: Enable RDP + disable NLA ──────────────────────────────────────
Write-Step "Enabling RDP (no NLA)"

# Allow RDP connections
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name fDenyTSConnections -Value 0 -Type DWord

# Disable Network Level Authentication so plain xfreerdp3 works without Kerberos
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 0 -Type DWord

# Open firewall for RDP
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue

Write-OK "RDP enabled, NLA disabled"

# ── Step 2: Create directory structure ────────────────────────────────────
Write-Step "Creating ARDA directory layout"
@($ARDA_ROOT, $PYTHON_DIR, $SRC_DEST) | ForEach-Object {
    New-Item -ItemType Directory -Force -Path $_ | Out-Null
}
Write-OK "C:\ARDA ready"

# ── Step 3: Download Python embeddable ────────────────────────────────────
$embedZip = "$ARDA_ROOT\python-embed.zip"
if (-not (Test-Path $PY_EXE)) {
    Write-Step "Downloading Python $PYTHON_VERSION embeddable..."
    Invoke-WebRequest -Uri $EMBED_URL -OutFile $embedZip -UseBasicParsing
    Write-Step "Extracting Python..."
    Expand-Archive -Path $embedZip -DestinationPath $PYTHON_DIR -Force
    Remove-Item $embedZip -Force
    Write-OK "Python at $PY_EXE"
} else {
    Write-OK "Python already present, skipping download"
}

# ── Step 4: Enable site-packages in the embeddable ._pth file ─────────────
Write-Step "Configuring Python path"
$pthFile = Get-ChildItem "$PYTHON_DIR\python*._pth" -ErrorAction SilentlyContinue |
           Select-Object -First 1
if ($pthFile) {
    $content = Get-Content $pthFile.FullName
    # Uncomment "import site" to enable third-party packages
    $content = $content -replace '^#import site', 'import site'
    # Add ARDA src root so `import arda_windows` works
    if ($content -notcontains $SRC_DEST) {
        $content += $SRC_DEST
    }
    $content | Set-Content $pthFile.FullName
    Write-OK "._pth updated: $($pthFile.Name)"
} else {
    Write-Warn "No ._pth file found — site-packages may not load"
}

# ── Step 5: Bootstrap pip ─────────────────────────────────────────────────
$pipExe = "$PYTHON_DIR\Scripts\pip.exe"
if (-not (Test-Path $pipExe)) {
    Write-Step "Bootstrapping pip..."
    $getPip = "$ARDA_ROOT\get-pip.py"
    Invoke-WebRequest -Uri $PIP_URL -OutFile $getPip -UseBasicParsing
    & $PY_EXE $getPip --no-warn-script-location *>&1
    Remove-Item $getPip -Force
    Write-OK "pip installed"
} else {
    Write-OK "pip already present"
}

# ── Step 6: Install Python dependencies ───────────────────────────────────
Write-Step "Installing pywin32 and requests..."
& $PY_EXE -m pip install --no-warn-script-location pywin32 requests *>&1
Write-OK "dependencies installed"

# ── Step 7: Run pywin32 post-install (copies DLLs to System32) ────────────
Write-Step "Running pywin32 post-install..."
$postInstallScript = Get-ChildItem "$PYTHON_DIR\Scripts\pywin32_postinstall.py" `
    -ErrorAction SilentlyContinue | Select-Object -First 1

if ($postInstallScript) {
    & $PY_EXE $postInstallScript.FullName -install *>&1
    Write-OK "pywin32 post-install done"
} else {
    # Fallback: newer pywin32 ships as a wheel with a different layout
    Write-Warn "pywin32_postinstall.py not found — trying direct DLL copy fallback"
    $pywin32Dlls = Get-ChildItem "$PYTHON_DIR\Lib\site-packages\pywin32_system32\" `
        -Filter "*.dll" -ErrorAction SilentlyContinue
    $sys32 = "$env:SystemRoot\System32"
    foreach ($dll in $pywin32Dlls) {
        Copy-Item $dll.FullName -Destination $sys32 -Force
        Write-OK "Copied $($dll.Name) to System32"
    }
}

# ── Step 8: Download arda-src.zip ─────────────────────────────────────────
$ardaZip   = "$ARDA_ROOT\arda-src.zip"
$unpackDir = "$ARDA_ROOT\unpack"

Write-Step "Downloading ARDA source..."
$downloaded = $false

# Try GitHub raw first
try {
    Invoke-WebRequest -Uri $ARDA_ZIP_URL -OutFile $ardaZip -UseBasicParsing -TimeoutSec 60
    Write-OK "Downloaded from GitHub: $ARDA_ZIP_URL"
    $downloaded = $true
} catch {
    Write-Warn "GitHub download failed: $_"
}

# Fallback: Linux host HTTP server (works during dev, not in CI)
if (-not $downloaded) {
    try {
        Invoke-WebRequest -Uri $ARDA_ZIP_LOCAL -OutFile $ardaZip -UseBasicParsing -TimeoutSec 15
        Write-OK "Downloaded from host HTTP server: $ARDA_ZIP_LOCAL"
        $downloaded = $true
    } catch {
        Write-Warn "Host HTTP server fallback also failed: $_"
    }
}

if (-not $downloaded) {
    throw "Could not download arda-src.zip from any source. Check internet access."
}

# ── Step 9: Extract + copy ARDA source ────────────────────────────────────
Write-Step "Extracting ARDA source..."
if (Test-Path $unpackDir) { Remove-Item $unpackDir -Recurse -Force }
Expand-Archive -Path $ardaZip -DestinationPath $unpackDir -Force
Remove-Item $ardaZip -Force

# The zip contains "Arda Windows/src/arda_windows/..." — copy arda_windows subtree
$innerSrc = Join-Path $unpackDir "Arda Windows\src\arda_windows"
if (-not (Test-Path $innerSrc)) {
    # Try alternate layout (flat src/arda_windows inside zip)
    $innerSrc = Get-ChildItem $unpackDir -Recurse -Directory -Filter "arda_windows" |
                Select-Object -First 1 -ExpandProperty FullName
}

if (-not $innerSrc -or -not (Test-Path $innerSrc)) {
    throw "Could not find arda_windows directory inside the zip. Check arda-src.zip contents."
}

$destArda = "$SRC_DEST\arda_windows"
if (Test-Path $destArda) { Remove-Item $destArda -Recurse -Force }
Copy-Item -Path $innerSrc -Destination $destArda -Recurse -Force
Remove-Item $unpackDir -Recurse -Force

Write-OK "ARDA source installed to $destArda"

# ── Step 10: Register and start ARDACollector service ──────────────────────
Write-Step "Registering ARDACollector Windows service..."
$svcName = "ARDACollector"

# Stop and unregister old instance if present
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "    Removing existing service instance..."
    Stop-Service $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & $PY_EXE $SVC_SCRIPT remove *>&1
}

& $PY_EXE $SVC_SCRIPT install *>&1
Set-Service -Name $svcName -StartupType Automatic
Write-OK "Service registered (auto-start)"

Write-Step "Starting ARDACollector..."
Start-Service -Name $svcName
Start-Sleep -Seconds 5

$svc = Get-Service -Name $svcName
if ($svc.Status -eq "Running") {
    Write-OK "ARDACollector is RUNNING"
} else {
    Write-Warn "Service status: $($svc.Status) — check Event Viewer > Application"
}

# ── Step 11: Open firewall for ARDA API ───────────────────────────────────
Write-Step "Opening firewall for ARDA port 7331..."
$fwRule = Get-NetFirewallRule -DisplayName "ARDA Collector" -ErrorAction SilentlyContinue
if (-not $fwRule) {
    New-NetFirewallRule -DisplayName "ARDA Collector" `
        -Direction Inbound -Protocol TCP -LocalPort 7331 `
        -Action Allow -Profile Any | Out-Null
}
Write-OK "Firewall rule set"

# ── Step 12: Smoke test the HTTP API ──────────────────────────────────────
Write-Step "Smoke-testing ARDA HTTP API on http://127.0.0.1:7331 ..."
Start-Sleep -Seconds 6

$ok = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:7331/health" -TimeoutSec 8
        Write-OK "health: $($health.status)"

        $summary = Invoke-RestMethod -Uri "http://127.0.0.1:7331/summary" -TimeoutSec 8
        Write-OK "platform: $($summary.platform)"

        $sv = Invoke-RestMethod -Uri "http://127.0.0.1:7331/sovereignty" -TimeoutSec 8
        Write-OK "sovereignty: $($sv.state)"

        $ok = $true
        break
    } catch {
        Write-Warn "Attempt $attempt failed: $_ — retrying in 5 s..."
        Start-Sleep -Seconds 5
    }
}

if ($ok) {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║   ARDA Collector is LIVE on http://0.0.0.0:7331     ║" -ForegroundColor Green
    Write-Host "║   From Linux host:  curl http://127.0.0.1:7331/health ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
} else {
    Write-Warn "HTTP API did not respond after 5 attempts."
    Write-Warn "Check: Get-Service ARDACollector | Get-EventLog Application -Source ARDACollector"
    Write-Warn "Log:   $LOG_FILE"
}

Write-Host ""
Write-Host "Bootstrap complete at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
Stop-Transcript
