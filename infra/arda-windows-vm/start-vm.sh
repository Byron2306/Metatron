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
UNATTEND_ISO="${UNATTEND_ISO:-$VM_DIR/unattend.iso}"
VIRTIO_ISO="${VIRTIO_ISO:-$HOME/Downloads/virtio-win.iso}"
RAM_MB="${RAM_MB:-6144}"
VCPUS="${VCPUS:-4}"
DISPLAY_MODE="${DISPLAY_MODE:-gtk}"    # gtk | sdl | vnc | none
DISK_IF="${DISK_IF:-ide}"              # ide | virtio (virtio needs VirtIO ISO during install)

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

  # Primary disk
  # ide:    works out-of-the-box during unattended install (no driver ISO needed)
  # virtio: faster for a running VM, but needs VirtIO ISO during initial install
  -drive "file=$DISK,if=$DISK_IF,cache=writeback"

  # Network: user-mode NAT with host port forwards
  # 10.0.2.2 inside the guest reaches the Linux host (for HTTP server, etc.)
  -netdev "user,id=net0,hostfwd=tcp::5985-:5985,hostfwd=tcp::7331-:7331,hostfwd=tcp::3389-:3389,hostfwd=tcp::8888-:8888"
  -device "e1000,netdev=net0"

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

# ── CD-ROM slots ──────────────────────────────────────────────────────────
# index=0  Windows installer ISO  (only during initial install)
# index=1  VirtIO driver ISO      (only needed when DISK_IF=virtio)
# index=2  Unattend ISO           (autounattend.xml + bootstrap.ps1)

CD_INDEX=0

# Windows installer ISO
if [[ -n "$WIN_ISO" ]]; then
  if [[ ! -f "$WIN_ISO" ]]; then
    echo "ERROR: WIN_ISO not found: $WIN_ISO"; exit 1
  fi
  QEMU_ARGS+=(-drive "file=$WIN_ISO,if=ide,media=cdrom,index=$CD_INDEX,readonly=on")
  QEMU_ARGS+=(-boot "order=dc,once=d")
  echo "==> Booting from ISO: $WIN_ISO"
  CD_INDEX=$((CD_INDEX + 1))
else
  QEMU_ARGS+=(-boot "order=c")
  echo "==> Booting from disk (no ISO)"
fi

# VirtIO driver ISO (only attach when using virtio disk; not needed for ide)
if [[ "$DISK_IF" == "virtio" ]] && [[ -f "$VIRTIO_ISO" ]]; then
  QEMU_ARGS+=(-drive "file=$VIRTIO_ISO,if=ide,media=cdrom,index=$CD_INDEX,readonly=on")
  echo "==> VirtIO driver ISO attached: $VIRTIO_ISO"
  CD_INDEX=$((CD_INDEX + 1))
elif [[ "$DISK_IF" == "virtio" ]]; then
  echo "    NOTE: VirtIO ISO not found — Windows may not see the disk during install"
  echo "    Download: wget -O ~/Downloads/virtio-win.iso https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
fi

# Unattend ISO — Windows Setup finds autounattend.xml automatically
# Build it first if it doesn't exist: ./make-unattend-iso.sh
if [[ -f "$UNATTEND_ISO" ]]; then
  QEMU_ARGS+=(-drive "file=$UNATTEND_ISO,if=ide,media=cdrom,index=$CD_INDEX,readonly=on")
  echo "==> Unattend ISO attached: $UNATTEND_ISO (hands-free install)"
  CD_INDEX=$((CD_INDEX + 1))
else
  echo "    NOTE: No unattend ISO found at $UNATTEND_ISO"
  echo "    Build it with: VM_DIR=$VM_DIR ./make-unattend-iso.sh"
  echo "    Without it, Windows Setup will require keyboard input."
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
