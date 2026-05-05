#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# make-unattend-iso.sh — packages autounattend.xml + bootstrap.ps1 into a
# bootable ISO that Windows Setup reads automatically.
#
# Windows Setup scans every attached drive at boot for autounattend.xml at
# the root.  Mount the output ISO as a second CD-ROM in QEMU and the install
# proceeds completely hands-free.
#
# Prerequisites (Ubuntu/Debian):
#   sudo apt-get install -y genisoimage
#
# Usage:
#   ./make-unattend-iso.sh                   # output: ./unattend.iso
#   VM_DIR=$HOME/vms/arda-windows ./make-unattend-iso.sh  # output in VM_DIR
# ---------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_DIR="${VM_DIR:-$HOME/vms/arda-windows}"
OUT_ISO="${OUT_ISO:-$VM_DIR/unattend.iso}"

# ── Check dependencies ────────────────────────────────────────────────────
for cmd in genisoimage; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found. Install it with:"
    echo "  sudo apt-get install -y genisoimage"
    exit 1
  fi
done

# ── Stage files ───────────────────────────────────────────────────────────
STAGE="$(mktemp -d)"
trap "rm -rf '$STAGE'" EXIT

echo "==> Staging unattend files..."
cp "$SCRIPT_DIR/autounattend.xml" "$STAGE/autounattend.xml"
cp "$SCRIPT_DIR/bootstrap.ps1"    "$STAGE/bootstrap.ps1"

# Also copy install-arda.ps1 so it's available inside the VM from the CD
if [[ -f "$SCRIPT_DIR/install-arda.ps1" ]]; then
  cp "$SCRIPT_DIR/install-arda.ps1" "$STAGE/install-arda.ps1"
fi

echo "    autounattend.xml"
echo "    bootstrap.ps1"

# ── Build ISO ─────────────────────────────────────────────────────────────
mkdir -p "$VM_DIR"

echo "==> Building ISO: $OUT_ISO"
genisoimage \
  -o "$OUT_ISO" \
  -J \
  -R \
  -joliet-long \
  -V "ARDA_UNATTEND" \
  "$STAGE"

echo ""
echo "==> Done: $OUT_ISO"
ls -lh "$OUT_ISO"
echo ""
echo "Mount this ISO as a second CD-ROM in QEMU:"
echo "  -drive file=$OUT_ISO,if=ide,media=cdrom,index=2,readonly=on"
echo ""
echo "Or set UNATTEND_ISO=$OUT_ISO before running start-vm.sh"
