@echo off
rem Wrapper batch file for the PowerShell installer
set INSTALL_DIR=%~dp0\..\agent-install
set SERVER_URL=https://seraph.local
set CLIENT_CERT=C:\certs\agent.pem
set SERVER_CA=C:\certs\ca.pem

powershell -ExecutionPolicy Bypass -File "%~dp0install_unified_agent.ps1" ^
    -InstallDir "%INSTALL_DIR%" ^
    -ServerUrl "%SERVER_URL%" ^
    -ClientCert "%CLIENT_CERT%" ^
    -ServerCA "%SERVER_CA%"


pausenecho Done.  Edit the variables above or supply your own when running.