#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ARDA_ROOT = "C:\ARDA"
$PYTHON_DIR = Join-Path $ARDA_ROOT "python"
$SRC_DEST = Join-Path $ARDA_ROOT "src"
$SVC_SCRIPT = Join-Path $SRC_DEST "arda_windows\service\arda_collector_svc.py"
$PY_EXE = Join-Path $PYTHON_DIR "python.exe"
$LOG_FILE = Join-Path $ARDA_ROOT "bootstrap.log"

$PYTHON_VERSION = "3.12.10"
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "win32" }
$EMBED_URL = "https://www.python.org/ftp/python/$PYTHON_VERSION/python-$PYTHON_VERSION-embed-$ARCH.zip"
$PIP_URL = "https://bootstrap.pypa.io/get-pip.py"
$ARDA_ZIP_URL = "https://github.com/Byron2306/Metatron/raw/main/arda-src.zip"
$ARDA_ZIP_LOCAL = "http://10.0.2.2:8888/arda-src.zip"

function Write-Step([string]$m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Write-OK([string]$m) { Write-Host "    OK: $m" -ForegroundColor Green }
function Write-Warn([string]$m) { Write-Host "    WARN: $m" -ForegroundColor Yellow }

New-Item -ItemType Directory -Force -Path $ARDA_ROOT | Out-Null
Start-Transcript -Path $LOG_FILE -Append | Out-Null

Write-Host "ARDA bootstrap starting: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta

Write-Step "Enable RDP and disable NLA"
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0 -Type DWord
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0 -Type DWord
Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
Write-OK "RDP enabled"

Write-Step "Create ARDA directories"
foreach ($p in @($ARDA_ROOT, $PYTHON_DIR, $SRC_DEST)) {
    New-Item -ItemType Directory -Force -Path $p | Out-Null
}
Write-OK "Directories ready"

Write-Step "Install embedded Python"
$embedZip = Join-Path $ARDA_ROOT "python-embed.zip"
if (-not (Test-Path $PY_EXE)) {
    Invoke-WebRequest -Uri $EMBED_URL -OutFile $embedZip -UseBasicParsing
    Expand-Archive -Path $embedZip -DestinationPath $PYTHON_DIR -Force
    Remove-Item -Path $embedZip -Force
    Write-OK "Python installed"
} else {
    Write-OK "Python already present"
}

Write-Step "Configure embedded Python"
$pthFile = Get-ChildItem -Path (Join-Path $PYTHON_DIR "python*._pth") -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $pthFile) {
    $content = Get-Content -Path $pthFile.FullName
    $content = $content -replace '^#import site', 'import site'
    if ($content -notcontains $SRC_DEST) {
        $content += $SRC_DEST
    }
    Set-Content -Path $pthFile.FullName -Value $content
    Write-OK ("Updated {0}" -f $pthFile.Name)
} else {
    Write-Warn "No ._pth file found"
}

Write-Step "Install pip"
$pipExe = Join-Path $PYTHON_DIR "Scripts\pip.exe"
if (-not (Test-Path $pipExe)) {
    $getPip = Join-Path $ARDA_ROOT "get-pip.py"
    Invoke-WebRequest -Uri $PIP_URL -OutFile $getPip -UseBasicParsing
    & $PY_EXE $getPip --no-warn-script-location
    Remove-Item -Path $getPip -Force
    Write-OK "pip installed"
} else {
    Write-OK "pip already present"
}

Write-Step "Install Python dependencies"
& $PY_EXE -m pip install --no-warn-script-location pywin32 requests
Write-OK "Dependencies installed"

Write-Step "Run pywin32 post-install"
$postInstallScript = Get-ChildItem -Path (Join-Path $PYTHON_DIR "Scripts\pywin32_postinstall.py") -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -ne $postInstallScript) {
    & $PY_EXE $postInstallScript.FullName -install
    Write-OK "pywin32 postinstall done"
} else {
    Write-Warn "pywin32_postinstall.py not found, copying DLLs fallback"
    $dllPath = Join-Path $PYTHON_DIR "Lib\site-packages\pywin32_system32"
    $sys32 = Join-Path $env:SystemRoot "System32"
    $dlls = Get-ChildItem -Path $dllPath -Filter "*.dll" -ErrorAction SilentlyContinue
    foreach ($dll in $dlls) {
        Copy-Item -Path $dll.FullName -Destination $sys32 -Force
    }
    Write-OK "Fallback DLL copy complete"
}

Write-Step "Download ARDA source zip"
$ardaZip = Join-Path $ARDA_ROOT "arda-src.zip"
$downloaded = $false
try {
    Invoke-WebRequest -Uri $ARDA_ZIP_URL -OutFile $ardaZip -UseBasicParsing -TimeoutSec 60
    $downloaded = $true
    Write-OK "Downloaded from GitHub"
} catch {
    Write-Warn ("GitHub download failed: {0}" -f $_)
}
if (-not $downloaded) {
    try {
        Invoke-WebRequest -Uri $ARDA_ZIP_LOCAL -OutFile $ardaZip -UseBasicParsing -TimeoutSec 20
        $downloaded = $true
        Write-OK "Downloaded from host HTTP server"
    } catch {
        Write-Warn ("Host download failed: {0}" -f $_)
    }
}
if (-not $downloaded) {
    throw "Could not download arda-src.zip"
}

Write-Step "Extract and install ARDA source"
$unpackDir = Join-Path $ARDA_ROOT "unpack"
if (Test-Path $unpackDir) { Remove-Item -Path $unpackDir -Recurse -Force }
Expand-Archive -Path $ardaZip -DestinationPath $unpackDir -Force
Remove-Item -Path $ardaZip -Force

$innerSrc = Join-Path $unpackDir "Arda Windows\src\arda_windows"
if (-not (Test-Path $innerSrc)) {
    $candidate = Get-ChildItem -Path $unpackDir -Recurse -Directory -Filter "arda_windows" | Select-Object -First 1
    if ($null -ne $candidate) {
        $innerSrc = $candidate.FullName
    }
}
if (-not (Test-Path $innerSrc)) {
    throw "Could not find arda_windows in extracted zip"
}
$destArda = Join-Path $SRC_DEST "arda_windows"
if (Test-Path $destArda) { Remove-Item -Path $destArda -Recurse -Force }
Copy-Item -Path $innerSrc -Destination $destArda -Recurse -Force
if (Test-Path $unpackDir) { Remove-Item -Path $unpackDir -Recurse -Force }
Write-OK "ARDA source installed"

Write-Step "Register and start ARDACollector service"
$svcName = "ARDACollector"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    & $PY_EXE $SVC_SCRIPT remove
}
& $PY_EXE $SVC_SCRIPT install
Set-Service -Name $svcName -StartupType Automatic
Start-Service -Name $svcName
Start-Sleep -Seconds 5
$svc = Get-Service -Name $svcName
if ($svc.Status -eq "Running") {
    Write-OK "ARDACollector running"
} else {
    Write-Warn ("Service status is {0}" -f $svc.Status)
}

# ---------------------------------------------------------------------------
Write-Step "Install Sysmon64 (runtime telemetry layer)"
$sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonSvc) {
    $sysmonDir  = "C:\Tools\Sysmon"
    $sysmonZip  = "$sysmonDir\Sysmon.zip"
    $sysmonExe  = "$sysmonDir\Sysmon64.exe"
    if (-not (Test-Path $sysmonDir)) { New-Item -ItemType Directory -Path $sysmonDir -Force | Out-Null }
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
            -OutFile $sysmonZip -UseBasicParsing -TimeoutSec 60
        Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
        if (Test-Path $sysmonExe) {
            & $sysmonExe -accepteula -i 2>&1 | Out-Null
            Start-Sleep -Seconds 3
            $chk = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if ($null -ne $chk -and $chk.Status -eq "Running") {
                Write-OK "Sysmon64 installed and running"
            } else {
                Write-Warn "Sysmon64 installed but not yet running"
            }
        } else {
            Write-Warn "Sysmon64.exe not found after extract"
        }
    } catch {
        Write-Warn ("Sysmon install failed: {0}" -f $_)
    }
} else {
    Write-OK ("Sysmon64 already installed: status={0}" -f $sysmonSvc.Status)
}

# ---------------------------------------------------------------------------
Write-Step "Open firewall for ARDA API port 7331"
$fwRule = Get-NetFirewallRule -DisplayName "ARDA Collector" -ErrorAction SilentlyContinue
if ($null -eq $fwRule) {
    New-NetFirewallRule -DisplayName "ARDA Collector" -Direction Inbound -Protocol TCP -LocalPort 7331 -Action Allow -Profile Any | Out-Null
}
Write-OK "Firewall rule ready"

Write-Step "Smoke-test ARDA API"
Start-Sleep -Seconds 6
$ok = $false
for ($attempt = 1; $attempt -le 5; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:7331/health" -TimeoutSec 8
        $summary = Invoke-RestMethod -Uri "http://127.0.0.1:7331/summary" -TimeoutSec 8
        $sv = Invoke-RestMethod -Uri "http://127.0.0.1:7331/sovereignty" -TimeoutSec 8
        Write-OK ("health={0} platform={1} sovereignty={2}" -f $health.status, $summary.platform, $sv.state)
        $ok = $true
        break
    } catch {
        Write-Warn ("Attempt {0} failed: {1}" -f $attempt, $_)
        Start-Sleep -Seconds 5
    }
}
if (-not $ok) {
    Write-Warn "API did not respond after retries"
}

Write-Host "Bootstrap complete: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Magenta
Stop-Transcript
