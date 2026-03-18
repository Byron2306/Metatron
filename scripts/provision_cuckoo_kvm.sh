#!/usr/bin/env bash
set -euo pipefail

# provision_cuckoo_kvm.sh
# Automate headless KVM/libvirt VM provisioning for Cuckoo
# Usage: sudo ./scripts/provision_cuckoo_kvm.sh [IMAGE_URL] [VM_NAME]
# Example: sudo ./scripts/provision_cuckoo_kvm.sh https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img cuckoo-guest

IMAGE_URL=${1:-}
VM_NAME=${2:-cuckoo-guest}
IMG_DIR=${IMG_DIR:-/var/lib/libvirt/images}
CLOUD_ISO=${IMG_DIR}/${VM_NAME}-cidata.iso
QCOW_IMG=${IMG_DIR}/${VM_NAME}.qcow2
MEMORY_MB=${MEMORY_MB:-4096}
VCPUS=${VCPUS:-2}

if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root (sudo)." >&2
  exit 1
fi

# Helper: install dependencies (apt or yum)
install_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils genisoimage wget
  elif command -v yum >/dev/null 2>&1; then
    yum install -y qemu-kvm libvirt libvirt-client libguestfs-tools virt-install cloud-utils wget
  else
    echo "Unsupported package manager. Please install: qemu-kvm, libvirt, virt-install, cloud-image-utils/genisoimage, wget" >&2
    exit 1
  fi
}

echo "Installing dependencies (if missing)..."
install_deps

if [ -z "$IMAGE_URL" ]; then
  echo "No image URL provided. Choose a baseline image to download:"
  echo "1) Kali (you must paste the official Kali cloud image URL)"
  echo "2) Ubuntu Jammy 22.04 LTS (recommended fallback)"
  read -p "Select 1 or 2: " choice
  if [ "${choice}" = "1" ]; then
    read -p "Paste direct Kali cloud qcow2 URL: " IMAGE_URL
    if [ -z "$IMAGE_URL" ]; then echo "No URL entered, exiting."; exit 1; fi
  else
    IMAGE_URL="https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    echo "Using Ubuntu Jammy image: $IMAGE_URL"
  fi
fi

mkdir -p "$IMG_DIR"

TMP_DOWNLOAD="/tmp/${VM_NAME}_image"
rm -f "$TMP_DOWNLOAD"

echo "Downloading image: $IMAGE_URL"
wget -O "$TMP_DOWNLOAD" "$IMAGE_URL"

# Convert to qcow2 if needed
file_magic=$(file -b --mime-type "$TMP_DOWNLOAD")
if [ "$file_magic" = "application/x-gzip" ] || [ "$file_magic" = "application/octet-stream" ] || [ "$file_magic" = "application/x-xz" ] || [[ "$TMP_DOWNLOAD" == *.img ]]; then
  echo "Converting downloaded image to qcow2..."
  qemu-img convert -O qcow2 "$TMP_DOWNLOAD" "$QCOW_IMG"
else
  echo "Assuming downloaded image is qcow2/raw; copying to $QCOW_IMG"
  qemu-img convert -O qcow2 "$TMP_DOWNLOAD" "$QCOW_IMG"
fi

# Create cloud-init user-data and meta-data
USER_DATA="/tmp/${VM_NAME}_user-data.yaml"
META_DATA="/tmp/${VM_NAME}_meta-data.yaml"

cat > "$USER_DATA" <<EOF
#cloud-config
users:
  - name: cuckoo
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    passwd: $(echo 'cuckoo' | openssl passwd -6 -stdin)
ssh_pwauth: True
chpasswd:
  list: |
    cuckoo:cuckoo
  expire: False
packages:
  - qemu-guest-agent
runcmd:
  - systemctl enable --now qemu-guest-agent.service || true
EOF

cat > "$META_DATA" <<EOF
instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

# Build cloud-init ISO
cloud-localds --label cidata "$CLOUD_ISO" "$USER_DATA" "$META_DATA"

# Import VM via virt-install (headless, import existing disk)
echo "Importing VM into libvirt as $VM_NAME"

virt-install --name "$VM_NAME" \
  --memory "$MEMORY_MB" --vcpus "$VCPUS" \
  --disk path="$QCOW_IMG",format=qcow2,bus=virtio \
  --disk path="$CLOUD_ISO",device=cdrom \
  --import --os-type linux --noautoconsole --network network=default,model=virtio || true

# Ensure VM is defined
virsh define --file <(virt-xml "$VM_NAME" --export) 2>/dev/null || true

# Create a snapshot named 'clean'
echo "Creating snapshot 'clean' for $VM_NAME"
virsh snapshot-create-as --domain "$VM_NAME" --name clean --description "Clean baseline" --disk-only --atomic || true

# Output Cuckoo vms.conf snippet
cat <<EOF

Provisioning complete.
Add this block to your Cuckoo 'vms.conf' (adjust IP/interface as needed):

[${VM_NAME}]
label = ${VM_NAME}
platform = linux
snapshot = clean
ip = 10.0.2.15
interface = default

EOF

echo "Done. Start the VM to perform initial guest customization, install guest agents/guest additions if needed, then shutdown and ensure the 'clean' snapshot is valid."
