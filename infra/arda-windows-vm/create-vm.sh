#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# create-vm.sh — one-shot ARDA Windows VM setup
#
# Creates the disk image, swtpm state directory, and a writeable copy of the
# OVMF NVRAM (pre-loaded with Microsoft Secure Boot keys).
#
# Usage:
#   export WIN_ISO=/path/to/Win11_24H2.iso   # required
#   export VM_DIR=$HOME/vms/arda-windows     # optional, this is the default
#   ./create-vm.sh
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VM_DIR="${VM_DIR:-$HOME/vms/arda-windows}"
DISK_SIZE="${DISK_SIZE:-80G}"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
OVMF_VARS_SRC="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"   # Microsoft SB keys

echo "==> Creating VM directory: $VM_DIR"
mkdir -p "$VM_DIR/swtpm"

# ── Disk image ────────────────────────────────────────────────────────────
DISK="$VM_DIR/win11.qcow2"
if [[ -f "$DISK" ]]; then
  echo "    disk already exists ($DISK), skipping"
else
  echo "==> Creating ${DISK_SIZE} disk image..."
  qemu-img create -f qcow2 "$DISK" "$DISK_SIZE"
fi

# ── OVMF NVRAM copy (mutable; holds Secure Boot key state) ────────────────
OVMF_VARS="$VM_DIR/OVMF_VARS.fd"
if [[ ! -f "$OVMF_VARS" ]]; then
  echo "==> Copying OVMF VARS (MS Secure Boot keys)..."
  cp "$OVMF_VARS_SRC" "$OVMF_VARS"
else
  echo "    OVMF_VARS already present, skipping"
fi

# ── swtpm state init (TPM 2.0) ────────────────────────────────────────────
if [[ ! -f "$VM_DIR/swtpm/tpm2-00.permall" ]]; then
  echo "==> Initialising swtpm state (TPM 2.0)..."
  swtpm_setup \
    --tpmstate "$VM_DIR/swtpm" \
    --tpm2 \
    --createek \
    --allow-signing \
    --decryption \
    --overwrite \
    --display
else
  echo "    swtpm state already initialised, skipping"
fi

# ── Summary ───────────────────────────────────────────────────────────────
cat <<EOF

VM scaffold ready at: $VM_DIR

Next steps:
  1. Point WIN_ISO to your Windows 11 ISO:
       export WIN_ISO=/path/to/Win11_24H2.iso
  2. Start the VM:
       VM_DIR=$VM_DIR WIN_ISO=\$WIN_ISO ./start-vm.sh
  3. Complete the Windows installer (RDP or GTK window on display :0)
  4. Inside Windows, run as Administrator:
       PowerShell -ExecutionPolicy Bypass -File install-arda.ps1
  5. From this host, validate:
       python3 validate-providers.py

EOF
