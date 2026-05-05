#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# start-vm.sh — starts swtpm then QEMU with TPM 2.0 + UEFI Secure Boot
#
# Port forwards into the guest:
#   5985  →  WinRM (used by validate-providers.py)
#   7331  →  ARDA Collector HTTP API (localhost inside guest)
#   3389  →  RDP (for manual access)
#
# Usage:
#   export WIN_ISO=/path/to/Win11_24H2.iso   # omit after first boot
#   export VM_DIR=$HOME/vms/arda-windows
#   ./start-vm.sh
# ---------------------------------------------------------------------------
set -euo pipefail

VM_DIR="${VM_DIR:-$HOME/vms/arda-windows}"
WIN_ISO="${WIN_ISO:-}"
RAM_MB="${RAM_MB:-6144}"
VCPUS="${VCPUS:-4}"
DISPLAY_MODE="${DISPLAY_MODE:-gtk}"    # gtk | sdl | vnc | none

OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
OVMF_VARS="$VM_DIR/OVMF_VARS.fd"
DISK="$VM_DIR/win11.qcow2"
TPM_SOCK="$VM_DIR/swtpm.sock"
TPM_LOG="$VM_DIR/swtpm.log"
PID_FILE="$VM_DIR/qemu.pid"

# ── Sanity checks ─────────────────────────────────────────────────────────
[[ -d "$VM_DIR" ]] || { echo "ERROR: VM_DIR not found: $VM_DIR — run create-vm.sh first"; exit 1; }
[[ -f "$DISK" ]]   || { echo "ERROR: disk not found: $DISK — run create-vm.sh first"; exit 1; }
[[ -f "$OVMF_VARS" ]] || { echo "ERROR: OVMF_VARS not found — run create-vm.sh first"; exit 1; }

# ── Kill stale swtpm ──────────────────────────────────────────────────────
if [[ -S "$TPM_SOCK" ]]; then
  echo "==> Removing stale swtpm socket..."
  rm -f "$TPM_SOCK"
fi

# ── Start swtpm ───────────────────────────────────────────────────────────
echo "==> Starting swtpm (TPM 2.0)..."
swtpm socket \
  --tpmstate "dir=$VM_DIR/swtpm" \
  --ctrl "type=unixio,path=$TPM_SOCK" \
  --tpm2 \
  --daemon \
  --log "file=$TPM_LOG,level=5"

# Give swtpm a moment to bind the socket
sleep 1
[[ -S "$TPM_SOCK" ]] || { echo "ERROR: swtpm failed to create socket — check $TPM_LOG"; exit 1; }
echo "    swtpm running (log: $TPM_LOG)"

# ── Build QEMU args ───────────────────────────────────────────────────────
QEMU_ARGS=(
  -enable-kvm
  -m "$RAM_MB"
  -smp "cores=$VCPUS,threads=2"

  # Machine: Q35 + SMM required for Secure Boot
  -machine "q35,smm=on,accel=kvm"
  -cpu host

  # UEFI firmware (Secure Boot)
  -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
  -drive "if=pflash,format=raw,file=$OVMF_VARS"
  -global "driver=cfi.pflash01,property=secure,value=on"

  # TPM 2.0 (swtpm socket)
  -chardev "socket,id=chrtpm,path=$TPM_SOCK"
  -tpmdev "emulator,id=tpm0,chardev=chrtpm"
  -device "tpm-tis,tpmdev=tpm0"

  # Primary disk (VirtIO for speed; Windows needs VirtIO driver from ISO)
  -drive "file=$DISK,if=virtio,cache=writeback,aio=native,discard=unmap"

  # Network: user-mode NAT with host port forwards
  -netdev "user,id=net0,hostfwd=tcp::5985-:5985,hostfwd=tcp::7331-:7331,hostfwd=tcp::3389-:3389"
  -device "virtio-net-pci,netdev=net0"

  # Misc virtio devices
  -device virtio-balloon-pci
  -device virtio-rng-pci

  # Display
  -vga virtio

  # Name / identity
  -name "ARDA-Windows-VM,process=arda-win"

  # PID tracking
  -pidfile "$PID_FILE"
)

# Attach Windows ISO only if provided (skip after first boot)
if [[ -n "$WIN_ISO" ]]; then
  if [[ ! -f "$WIN_ISO" ]]; then
    echo "ERROR: WIN_ISO not found: $WIN_ISO"; exit 1
  fi
  QEMU_ARGS+=(-cdrom "$WIN_ISO" -boot "order=dc,once=d")
  echo "==> Booting from ISO: $WIN_ISO"
else
  QEMU_ARGS+=(-boot "order=c")
  echo "==> Booting from disk (no ISO)"
fi

# Display backend
case "$DISPLAY_MODE" in
  gtk)  QEMU_ARGS+=(-display gtk) ;;
  sdl)  QEMU_ARGS+=(-display sdl) ;;
  vnc)  QEMU_ARGS+=(-display "vnc=:5,password=off") ; echo "==> VNC on :5905" ;;
  none) QEMU_ARGS+=(-display none -daemonize) ;;
  *)    echo "Unknown DISPLAY_MODE=$DISPLAY_MODE"; exit 1 ;;
esac

# ── Launch QEMU ───────────────────────────────────────────────────────────
echo "==> Starting QEMU (RAM=${RAM_MB}MB vCPUs=$VCPUS)..."
echo "    RDP     → localhost:3389"
echo "    WinRM   → localhost:5985"
echo "    ARDA    → localhost:7331"
echo ""

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
