#!/bin/bash
# Build ARDA OS BPF LSM kernel module
# Requires: clang, linux-headers, bpftool
# Must run as root to load the module

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OBJ="$SCRIPT_DIR/arda_physical_lsm.o"
PIN="/sys/fs/bpf/arda_lsm"
MAP_DIR="/sys/fs/bpf/arda_maps"

echo "=== ARDA OS BPF LSM Build ==="
echo "Source: $SCRIPT_DIR/arda_physical_lsm.c"

# Build
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I"$SCRIPT_DIR" \
  -c "$SCRIPT_DIR/arda_physical_lsm.c" \
  -o "$OBJ"

echo "Built: $OBJ"

if [ "$1" = "--load" ]; then
  if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: --load requires root"
    exit 1
  fi

  # Mount bpffs if needed
  if ! mountpoint -q /sys/fs/bpf; then
    mount -t bpf bpf /sys/fs/bpf
  fi

  mkdir -p "$MAP_DIR"

  # Remove old pin if exists
  rm -f "$PIN"

  bpftool prog load "$OBJ" "$PIN" type lsm
  echo "Loaded: $PIN"

  # Pin maps
  PROG_INFO=$(bpftool prog show pinned "$PIN" -j)
  MAP_IDS=$(echo "$PROG_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin); print(' '.join(map(str,d.get('map_ids',[]))))")
  for MID in $MAP_IDS; do
    M_INFO=$(bpftool map show id "$MID" -j)
    M_NAME=$(echo "$M_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('name',''))")
    if echo "$M_NAME" | grep -q "arda_harmony"; then
      bpftool map pin id "$MID" "$MAP_DIR/arda_harmony"
      echo "Pinned harmony map: $MAP_DIR/arda_harmony"
    elif echo "$M_NAME" | grep -q "arda_state"; then
      bpftool map pin id "$MID" "$MAP_DIR/arda_state"
      echo "Pinned state map: $MAP_DIR/arda_state"
    fi
  done

  echo "=== ARDA LSM loaded and armed ==="
fi
