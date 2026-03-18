<#
Provision a Cuckoo guest VM in VirtualBox.
Usage:
  # Prompt for OVA URL
  powershell -ExecutionPolicy Bypass -File .\scripts\provision_cuckoo_vm.ps1

  # Or provide OVA URL and VM name
  powershell -ExecutionPolicy Bypass -File .\scripts\provision_cuckoo_vm.ps1 -OvaUrl "https://.../kali.ova" -VmName "cuckoo-kali"

Requirements:
- VirtualBox installed and `VBoxManage` available in PATH.
- Script will relaunch elevated if not run as Admin.

What it does:
- Downloads the specified OVA (prompts if not provided)
- Imports the OVA into VirtualBox with the given VM name
- Configures a NAT adapter + host-only adapter (host-only adapter name may be adjusted)
- Creates a snapshot named 'clean'

Important: Review networking settings after import. Adjust host-only adapter name if needed (commonly vboxnet0).
#>
param(
    [string]$OvaUrl = "",
    [string]$VmName = "cuckoo-kali",
    [string]$HostOnlyAdapter = "vboxnet0"
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

if ([string]::IsNullOrWhiteSpace($OvaUrl)) {
    Write-Host "No OVA URL supplied. Please paste the direct OVA download URL for the guest (e.g., official Kali VirtualBox OVA)."
    Write-Host "Official Kali downloads: https://www.kali.org/get-kali/ -> VirtualBox Images -> copy link for OVA"
    $OvaUrl = Read-Host "OVA URL"
    if ([string]::IsNullOrWhiteSpace($OvaUrl)) { Write-Error "No OVA URL provided. Exiting."; exit 1 }
}

# Prepare download path
$dest = Join-Path $PWD "${VmName}.ova"
Write-Host "Downloading OVA to $dest ..."
Invoke-WebRequest -Uri $OvaUrl -OutFile $dest -UseBasicParsing

# Import OVA
Write-Host "Importing OVA into VirtualBox as VM '$VmName'..."
VBoxManage import $dest --vsys 0 --vmname $VmName

# Configure networking: nic1 NAT, nic2 host-only
Write-Host "Configuring VM networking (NAT + Host-only: $HostOnlyAdapter)"
VBoxManage modifyvm $VmName --nic1 nat --nic2 hostonly --hostonlyadapter2 $HostOnlyAdapter

# Optional: set memory/cpu defaults (adjust as needed)
Write-Host "Setting VM resources: 4096MB RAM, 2 CPUs"
VBoxManage modifyvm $VmName --memory 4096 --cpus 2

# Ensure VM is powered off, then take snapshot
try {
    $state = (VBoxManage showvminfo $VmName --machinereadable) -join "`n"
    if ($state -match 'VMState="running"') {
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
Write-Host "Remember to install Guest Additions inside the VM and take any additional clean baseline steps (disable updates, create non-root user, etc.)."
