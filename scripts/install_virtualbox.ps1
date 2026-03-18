<#
Install VirtualBox automatically.
Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\install_virtualbox.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\install_virtualbox.ps1 -InstallerUrl "https://download.virtualbox.org/virtualbox/7.0.10/VirtualBox-7.0.10-158379-Win.exe"

Notes:
- This script will relaunch itself elevated if necessary.
- It attempts to discover the latest VirtualBox Windows installer if no URL is given.
- The installer is run silently (/S). You may be prompted by the installer for UAC if not elevated.
#>
param(
    [string]$InstallerUrl = "",
    [switch]$AutoAccept
)

function Is-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Is-Admin)) {
    Write-Host "Elevating to Administrator..."
    Start-Process -FilePath pwsh -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File \"$PSCommandPath\" $($MyInvocation.UnboundArguments)" -Verb RunAs
    exit
}

# Try to discover latest version if no URL provided
if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
    try {
        Write-Host "Discovering latest VirtualBox version..."
        $version = (Invoke-RestMethod -Uri 'https://download.virtualbox.org/virtualbox/LATEST.TXT' -UseBasicParsing).Trim()
        Write-Host "Latest version: $version"
        $indexHtml = Invoke-WebRequest -Uri "https://download.virtualbox.org/virtualbox/$version/" -UseBasicParsing
        $link = $indexHtml.Links | Where-Object { $_.href -match 'VirtualBox-.*-Win.exe$' } | Select-Object -First 1
        if ($null -eq $link) { throw "Could not find Windows installer link for $version" }
        $InstallerUrl = "https://download.virtualbox.org/virtualbox/$version/$($link.href)"
        Write-Host "Installer URL: $InstallerUrl"
    }
    catch {
        Write-Warning "Automatic discovery failed: $_"
        Write-Host "Please provide a direct installer URL via -InstallerUrl or visit https://www.virtualbox.org/wiki/Downloads to copy the Windows installer link."
        exit 1
    }
}

# Download installer
$tempDir = Join-Path $env:TEMP "vbox_install"
New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
$installerPath = Join-Path $tempDir ([IO.Path]::GetFileName($InstallerUrl))
Write-Host "Downloading VirtualBox installer to $installerPath ..."
Invoke-WebRequest -Uri $InstallerUrl -OutFile $installerPath -UseBasicParsing

# Run installer silently
Write-Host "Running installer (silent)... this may take a few minutes."
$args = "/S"
$proc = Start-Process -FilePath $installerPath -ArgumentList $args -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Warning "Installer exited with code $($proc.ExitCode). You may need to run the installer interactively or check the installer logs."
} else {
    Write-Host "Installer completed successfully (exit code 0)."
}

# Verify VBoxManage
try {
    $v = & VBoxManage --version
    Write-Host "VBoxManage version: $v"
}
catch {
    Write-Warning "VBoxManage not found after installation. You may need to log out/log in or restart the shell."
}

Write-Host "Done. If you want to automatically import a VM, run scripts\provision_cuckoo_vm.ps1 -OvaUrl <OVA_URL> or provide the official Kali OVA URL."