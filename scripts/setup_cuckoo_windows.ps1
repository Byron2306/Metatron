<#
setup_cuckoo_windows.ps1
Combined installer + VM provisioning for VirtualBox on Windows.
Usage (run from an elevated PowerShell prompt or the script will relaunch elevated):
  powershell -ExecutionPolicy Bypass -File .\scripts\setup_cuckoo_windows.ps1 -OvaUrl "https://.../kali.ova" -VmName "cuckoo-kali"

Parameters:
  -InstallerUrl : optional VirtualBox installer URL (auto-discovered if omitted)
  -OvaUrl       : direct OVA download URL (will prompt if omitted)
  -VmName       : VM name to import as (default: cuckoo-kali)
  -HostOnlyAdapter : host-only adapter name (default: vboxnet0)
  -AutoAccept   : run installer non-interactively where possible

This script:
  - Ensures elevated privileges
  - Downloads & installs VirtualBox if `VBoxManage` is not found
  - Downloads the OVA, imports it into VirtualBox
  - Configures networking (NAT + host-only), resources, and snapshot 'clean'
  - Prints a `vms.conf` snippet for Cuckoo registration
#>
param(
    [string]$InstallerUrl = "",
    [string]$OvaUrl = "",
    [string]$VmName = "cuckoo-kali",
    [string]$HostOnlyAdapter = "vboxnet0",
    [switch]$AutoAccept
)

function Is-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Relaunch elevated if not admin
if (-not (Is-Admin)) {
    Write-Host "Relaunching elevated..."
    $pwshCmd = (Get-Command pwsh -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    if (-not $pwshCmd) { $pwshCmd = 'powershell' }
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
    if ($MyInvocation.UnboundArguments.Count -gt 0) { $argList += $MyInvocation.UnboundArguments }
    Start-Process -FilePath $pwshCmd -ArgumentList $argList -Verb RunAs
    exit
}

# Ensure UTF-8 for subprocess Python-like output if needed
if (-not $env:PYTHONUTF8) { $env:PYTHONUTF8 = '1' }
if (-not $env:PYTHONIOENCODING) { $env:PYTHONIOENCODING = 'utf-8' }

# Helper to discover VirtualBox installer if not provided
function Get-LatestVirtualBoxInstallerUrl {
    try {
        Write-Host "Discovering latest VirtualBox version..."
        $version = (Invoke-RestMethod -Uri 'https://download.virtualbox.org/virtualbox/LATEST.TXT' -UseBasicParsing).Trim()
        $indexHtml = Invoke-WebRequest -Uri "https://download.virtualbox.org/virtualbox/$version/" -UseBasicParsing
        $link = $indexHtml.Links | Where-Object { $_.href -match 'VirtualBox-.*-Win.exe$' } | Select-Object -First 1
        if ($null -eq $link) { throw "Could not find Windows installer link for $version" }
        return "https://download.virtualbox.org/virtualbox/$version/$($link.href)"
    }
    catch {
        Write-Warning "Could not auto-discover VirtualBox installer: $_"
        return ""
    }
}

# Install VirtualBox if necessary
if (-not (Get-Command VBoxManage -ErrorAction SilentlyContinue)) {
    Write-Host "VBoxManage not found. Installing VirtualBox..."
    if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
        $InstallerUrl = Get-LatestVirtualBoxInstallerUrl
        if ([string]::IsNullOrWhiteSpace($InstallerUrl)) {
            Write-Warning "Installer URL not found automatically. Please provide -InstallerUrl or install VirtualBox manually from https://www.virtualbox.org/wiki/Downloads"
            exit 1
        }
    }

    $tempDir = Join-Path $env:TEMP "vbox_install"
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
    $installerPath = Join-Path $tempDir ([IO.Path]::GetFileName($InstallerUrl))
    Write-Host "Downloading VirtualBox installer to $installerPath"
    Invoke-WebRequest -Uri $InstallerUrl -OutFile $installerPath -UseBasicParsing

    Write-Host "Running VirtualBox installer..."
    $args = if ($AutoAccept) { "/S" } else { "/S" }
    $proc = Start-Process -FilePath $installerPath -ArgumentList $args -Wait -PassThru
    if ($proc.ExitCode -ne 0) {
        Write-Warning "VirtualBox installer exited with code $($proc.ExitCode). You may need to run it interactively."
    }

    # Refresh PATH for current session if possible
    $vboxPath = "${env:ProgramFiles}\Oracle\VirtualBox"
    if (Test-Path $vboxPath) {
        $env:PATH = $vboxPath + ";" + $env:PATH
    }

    if (-not (Get-Command VBoxManage -ErrorAction SilentlyContinue)) {
        Write-Warning "VBoxManage still not found. You may need to restart your shell or log off/log on. Attempting to continue..."
    } else {
        Write-Host "VBoxManage installed: $((VBoxManage --version) -join '')"
    }
}
else {
    Write-Host "VBoxManage found: $(VBoxManage --version)"
}

# Provision VM: download OVA and import
if ([string]::IsNullOrWhiteSpace($OvaUrl)) {
    Write-Host "No OVA URL provided. Please provide the direct OVA URL (e.g., official Kali VirtualBox OVA)."
    Write-Host "Kali images: https://www.kali.org/get-kali/ -> VirtualBox Images -> copy link for OVA"
    $OvaUrl = Read-Host "OVA URL"
    if ([string]::IsNullOrWhiteSpace($OvaUrl)) { Write-Error "No OVA URL provided. Exiting."; exit 1 }
}

$fileName = [IO.Path]::GetFileName($OvaUrl)
$dest = Join-Path $PWD $fileName
Write-Host "Downloading $fileName to $dest ..."
Invoke-WebRequest -Uri $OvaUrl -OutFile $dest -UseBasicParsing

# If the download is a .7z archive (Kali provides VirtualBox images as .7z), try to extract an OVA/OVF using 7z
$extractedImagePath = $null
if ($dest -match '\.7z$') {
    $sevenZip = Get-Command 7z -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }
    if ($sevenZip) {
        Write-Host "7z found; extracting archive to temporary folder..."
        $extractDir = Join-Path $env:TEMP ("extract_{0}" -f ([guid]::NewGuid().ToString()))
        New-Item -Path $extractDir -ItemType Directory -Force | Out-Null
        & $sevenZip x $dest -o$extractDir -y | Out-Null
        # find ova or ovf inside
        $found = Get-ChildItem -Path $extractDir -Recurse -Include *.ova,*.ovf -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $extractedImagePath = $found.FullName; Write-Host "Found extracted image: $extractedImagePath" }
        else { Write-Warning "No .ova/.ovf found inside archive after extraction." }
    }
    else {
        Write-Warning "7z not found; cannot extract .7z archive. Please install 7-Zip or provide a direct OVA/OVF URL."
    }
}

# Prefer ovftool if available (helps with some malformed OVAs); otherwise import OVA directly
$ovftoolCmd = Get-Command ovftool -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }
if ($ovftoolCmd) {
    Write-Host "ovftool found: using it to convert OVA -> OVF before import"
    $ovaConvertDir = Join-Path $env:TEMP ("ova_convert_{0}" -f ([guid]::NewGuid().ToString()))
    New-Item -Path $ovaConvertDir -ItemType Directory -Force | Out-Null
    $ovfTarget = Join-Path $ovaConvertDir ("${VmName}.ovf")
    Write-Host "Converting OVA to OVF: $dest -> $ovfTarget"
    if ($extractedImagePath) { $sourceForConversion = $extractedImagePath } else { $sourceForConversion = $dest }
    & $ovftoolCmd --lax $sourceForConversion $ovfTarget
    if (Test-Path $ovfTarget) {
        Write-Host "Importing OVF into VirtualBox as VM '$VmName'..."
        VBoxManage import $ovfTarget --vsys 0 --vmname $VmName
    }
    else {
        Write-Warning "ovftool conversion failed or OVF not found; falling back to direct OVA import"
        if ($extractedImagePath) { $sourceForImport = $extractedImagePath } else { $sourceForImport = $dest }
        Write-Host "Importing image into VirtualBox as VM '$VmName'..."
        VBoxManage import $sourceForImport --vsys 0 --vmname $VmName
    }
}
else {
    if ($extractedImagePath) { $sourceForImport = $extractedImagePath } else { $sourceForImport = $dest }
    Write-Host "ovftool not found; importing image into VirtualBox as VM '$VmName'..."
    VBoxManage import $sourceForImport --vsys 0 --vmname $VmName
}

# Configure networking: nic1 NAT, nic2 host-only
Write-Host "Configuring VM networking (NAT + Host-only: $HostOnlyAdapter)"
VBoxManage modifyvm $VmName --nic1 nat --nic2 hostonly --hostonlyadapter2 $HostOnlyAdapter

# Set resources
Write-Host "Setting VM resources: 4096MB RAM, 2 CPUs"
VBoxManage modifyvm $VmName --memory 4096 --cpus 2

# Ensure VM is powered off, then take snapshot
try {
    $info = & VBoxManage showvminfo $VmName --machinereadable
    if ($info -match 'VMState="running"') {
        Write-Host "VM is running. Powering off..."
        VBoxManage controlvm $VmName poweroff
    }
}
catch { }

Write-Host "Creating snapshot 'clean'"
VBoxManage snapshot $VmName take clean --description "Clean baseline for Cuckoo analysis"

Write-Host "Provisioning complete. Add the following to your Cuckoo vms.conf (adjust IP/interface as needed):"
Write-Host "----"
Write-Host "[vm1]"
Write-Host "label = $VmName"
Write-Host "platform = linux"
Write-Host "snapshot = clean"
Write-Host "ip = 10.0.2.15  # adjust if different"
Write-Host "interface = host-only"
Write-Host "----"

Write-Host "Final notes: start the VM, install Guest Additions, disable updates, create a clean baseline, then ensure Cuckoo can access/drive the VM (VirtualBox webservice or local VirtualBox)."
