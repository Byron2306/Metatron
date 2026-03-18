#!/usr/bin/env bash
# register_cuckoo_vm.sh
# Append a VM entry to a Cuckoo vms.conf file or print the snippet
# Usage: ./scripts/register_cuckoo_vm.sh -f /path/to/vms.conf -n vmname -i 10.0.2.15

set -euo pipefail
VM_NAME=${VM_NAME:-cuckoo-guest}
IP=${IP:-10.0.2.15}
VMCONF=${1:-}

if [ -z "$VMCONF" ]; then
  echo "No vms.conf path provided. Printing snippet instead."
  cat <<EOF
[${VM_NAME}]
label = ${VM_NAME}
platform = linux
snapshot = clean
ip = ${IP}
interface = default
EOF
  exit 0
fi

if [ ! -f "$VMCONF" ]; then
  echo "vms.conf not found at $VMCONF" >&2
  exit 1
fi

# Append snippet
cat >> "$VMCONF" <<EOF

[${VM_NAME}]
label = ${VM_NAME}
platform = linux
snapshot = clean
ip = ${IP}
interface = default
EOF

echo "Appended VM entry to $VMCONF"
