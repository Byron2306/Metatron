@echo off
REM ============================================================================
REM SERAPH AI DEFENDER - Windows Installation Script
REM ============================================================================
REM This batch file installs and configures the Seraph Defender Agent on Windows
REM Run as Administrator for best results
REM ============================================================================

setlocal enabledelayedexpansion

echo.
echo  ========================================
echo   SERAPH AI DEFENDER - Windows Installer
echo  ========================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as Administrator. Some features may not work.
    echo [INFO] Right-click this file and select "Run as administrator"
    echo.
    pause
)

REM Configuration - SET YOUR SERVER URL HERE
set "SERAPH_SERVER=https://your-seraph-server.com"
set "INSTALL_DIR=%USERPROFILE%\SeraphDefender"
set "AGENT_SCRIPT=seraph_defender_v7.py"

REM Parse command line arguments
:parse_args
if "%~1"=="" goto :end_parse
if /i "%~1"=="--server" (
    set "SERAPH_SERVER=%~2"
    shift
    shift
    goto :parse_args
)
if /i "%~1"=="--dir" (
    set "INSTALL_DIR=%~2"
    shift
    shift
    goto :parse_args
)
shift
goto :parse_args
:end_parse

echo [INFO] Server URL: %SERAPH_SERVER%
echo [INFO] Install Directory: %INSTALL_DIR%
echo.

REM Create installation directory
echo [STEP 1/6] Creating installation directory...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo [OK] Directory created: %INSTALL_DIR%
) else (
    echo [OK] Directory exists: %INSTALL_DIR%
)

REM Check for Python
echo.
echo [STEP 2/6] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    pause
    exit /b 1
)
for /f "tokens=2" %%a in ('python --version 2^>^&1') do set PYTHON_VER=%%a
echo [OK] Python %PYTHON_VER% found

REM Install required packages
echo.
echo [STEP 3/6] Installing required Python packages...
echo [INFO] Installing psutil, requests, watchdog...
pip install --quiet --upgrade psutil requests watchdog
if %errorlevel% neq 0 (
    echo [WARNING] Some packages may have failed to install
) else (
    echo [OK] Packages installed successfully
)

REM Download the agent script
echo.
echo [STEP 4/6] Downloading Seraph Defender Agent...
set "DOWNLOAD_URL=%SERAPH_SERVER%/api/swarm/agent/download/v7"
powershell -Command "& { try { Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALL_DIR%\%AGENT_SCRIPT%' -UseBasicParsing; Write-Host '[OK] Agent downloaded successfully' } catch { Write-Host '[ERROR] Failed to download agent: ' $_.Exception.Message; exit 1 } }"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to download agent script
    echo [INFO] Trying alternative method...
    curl -o "%INSTALL_DIR%\%AGENT_SCRIPT%" "%DOWNLOAD_URL%" 2>nul
    if %errorlevel% neq 0 (
        echo [ERROR] Download failed. Check your server URL and network connection.
        pause
        exit /b 1
    )
)

REM Create startup script
echo.
echo [STEP 5/6] Creating startup configuration...
set "STARTUP_BAT=%INSTALL_DIR%\start_seraph.bat"
(
echo @echo off
echo cd /d "%INSTALL_DIR%"
echo python %AGENT_SCRIPT% --monitor --api-url %SERAPH_SERVER%
echo pause
) > "%STARTUP_BAT%"
echo [OK] Startup script created: %STARTUP_BAT%

REM Create Windows Task Scheduler entry for auto-start
echo.
echo [STEP 6/6] Configuring auto-start...
set "TASK_NAME=SeraphDefender"
schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Removing existing scheduled task...
    schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1
)

REM Create VBS wrapper for hidden startup
set "VBS_LAUNCHER=%INSTALL_DIR%\seraph_launcher.vbs"
(
echo Set WshShell = CreateObject^("WScript.Shell"^)
echo WshShell.Run chr^(34^) ^& "%INSTALL_DIR%\start_seraph.bat" ^& chr^(34^), 0
echo Set WshShell = Nothing
) > "%VBS_LAUNCHER%"

schtasks /create /tn "%TASK_NAME%" /tr "wscript.exe \"%VBS_LAUNCHER%\"" /sc onlogon /rl highest /f >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Auto-start configured - agent will run on login
) else (
    echo [WARNING] Could not configure auto-start. Run manually or add to Startup folder.
)

REM Create desktop shortcut
echo.
echo Creating desktop shortcut...
set "SHORTCUT=%USERPROFILE%\Desktop\Seraph Defender.lnk"
powershell -Command "& { $WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut('%SHORTCUT%'); $SC.TargetPath = '%STARTUP_BAT%'; $SC.WorkingDirectory = '%INSTALL_DIR%'; $SC.IconLocation = 'shell32.dll,48'; $SC.Save() }"
if %errorlevel% equ 0 (
    echo [OK] Desktop shortcut created
)

REM Installation complete
echo.
echo  ========================================
echo   INSTALLATION COMPLETE!
echo  ========================================
echo.
echo  Agent Location: %INSTALL_DIR%\%AGENT_SCRIPT%
echo  Dashboard URL:  http://localhost:8080
echo  Server URL:     %SERAPH_SERVER%
echo.
echo  To start the agent now, press any key or run:
echo  %STARTUP_BAT%
echo.
echo  The agent will also start automatically on login.
echo.
pause

REM Start the agent
echo.
echo [INFO] Starting Seraph Defender Agent...
start "" "%STARTUP_BAT%"

echo.
echo [OK] Agent started! Dashboard available at http://localhost:8080
echo.
timeout /t 5

exit /b 0
