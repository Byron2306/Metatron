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

# ── Unattend ISO (hands-free install) ─────────────────────────────────────
UNATTEND_ISO="$VM_DIR/unattend.iso"
if [[ ! -f "$UNATTEND_ISO" ]]; then
  echo "==> Building unattend ISO (autounattend.xml + bootstrap.ps1)..."
  if command -v genisoimage &>/dev/null; then
    VM_DIR="$VM_DIR" OUT_ISO="$UNATTEND_ISO" bash "$SCRIPT_DIR/make-unattend-iso.sh"
  else
    echo "    WARNING: genisoimage not found — skipping unattend ISO."
    echo "    Install it:  sudo apt-get install -y genisoimage"
    echo "    Then build:  VM_DIR=$VM_DIR ./make-unattend-iso.sh"
  fi
else
  echo "    unattend ISO already exists: $UNATTEND_ISO"
fi

# ── Summary ───────────────────────────────────────────────────────────────
cat <<EOF

VM scaffold ready at: $VM_DIR

Fully automated install (recommended):
  1. Build the unattend ISO if not already built:
       VM_DIR=$VM_DIR ./make-unattend-iso.sh
  2. Start the VM with the Windows ISO:
       export WIN_ISO=/path/to/Win11_Enterprise_Eval.iso
       VM_DIR=$VM_DIR WIN_ISO=\$WIN_ISO ./start-vm.sh
     Windows installs itself, creates user Byron, installs ARDA, and starts
     the collector automatically.  No keyboard input required.
  3. From this host, validate (wait ~20 min for install + bootstrap):
       curl http://127.0.0.1:7331/health
       python3 validate-providers.py

Manual install (fallback if autounattend.xml doesn't match your ISO edition):
  1. Start VM as above — it will open an interactive Windows Setup GUI.
  2. Inside Windows, download bootstrap.ps1 and run as Administrator:
       iwr http://10.0.2.2:8888/infra/arda-windows-vm/bootstrap.ps1 -UseBasicParsing | iex
  3. Validate from host:
       curl http://127.0.0.1:7331/health

EOF
