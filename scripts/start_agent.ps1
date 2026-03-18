# Start the Unified Agent and capture logs
# Usage (run from repo root):
#   powershell -ExecutionPolicy Bypass -File .\scripts\start_agent.ps1 -ServerUrl "http://localhost:8001" -DisableLanDiscovery $true

param(
    [string]$ServerUrl = "http://localhost:8001",
    [switch]$DisableLanDiscovery
)

# Activate venv for this session
Write-Host "Activating virtualenv..."
& .\.venv\Scripts\Activate.ps1

if ($DisableLanDiscovery) {
    Write-Host "Setting DISABLE_LAN_DISCOVERY=1 for this session"
    $env:DISABLE_LAN_DISCOVERY = '1'
}

# Ensure Python uses UTF-8 for stdout/stderr on Windows consoles
if (-not $env:PYTHONUTF8) { $env:PYTHONUTF8 = '1' }
if (-not $env:PYTHONIOENCODING) { $env:PYTHONIOENCODING = 'utf-8' }

$python = Join-Path $PWD ".venv\Scripts\python.exe"
$outLog = Join-Path $PWD "agent.out.log"
$errLog = Join-Path $PWD "agent.err.log"

Write-Host "Starting agent (server: $ServerUrl). Logs: $outLog, $errLog"

# Start in background and redirect stdout/stderr
# Note: -NoNewWindow and -WindowStyle cannot be used together on some PowerShell versions.
Start-Process -FilePath $python `
  -ArgumentList ".\unified_agent\core\agent.py --server $ServerUrl" `
  -WorkingDirectory $PWD `
  -RedirectStandardOutput $outLog -RedirectStandardError $errLog -WindowStyle Hidden

# Wait up to 10s for the stdout log to be created, then tail it
$maxWait = 10
$waited = 0
while (-not (Test-Path $outLog) -and $waited -lt $maxWait) {
    Start-Sleep -Seconds 1
    $waited += 1
}

if (-not (Test-Path $outLog)) {
    Write-Host "Log file not created after $maxWait seconds. Check $errLog for errors."
    if (Test-Path $errLog) {
        Write-Host "---- Recent stderr ----"
        Get-Content $errLog -Tail 50
    }
} else {
    Write-Host "Tailing stdout log (press Ctrl+C to stop)"
    Get-Content $outLog -Tail 100 -Wait
}
