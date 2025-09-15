#!/bin/bash

# --- Configuration ---
TAP_IFACE="pxetest-tap"
BRIDGE_IFACE="virbr-mgmt"
VM_DISK1="testdisk.qcow2"
VM_DISK2="testdisk-vdb.qcow2"
VM_MEMORY="6134" # MB
VM_CPUS="4"
VNC_PORT="10" # VNC will be on 0.0.0.0:5910
VM_MAC_ADDRESS="52:54:00:12:34:56"
PXE_ROM_FILE="./pxe-e1000.rom" # Path to your PXE ROM file (adjust as needed)
SEABIOS_LOG_FILE="/tmp/seabios_debug.log" # Path for SeaBIOS debug output

# --- Function to clean up on exit ---
cleanup() {
    echo "Cleaning up tap interface and bridge..."
    # Remove tap interface from bridge
    sudo ip link set "$TAP_IFACE" down 2>/dev/null
    sudo brctl delif "$BRIDGE_IFACE" "$TAP_IFACE" 2>/dev/null
    # Delete tap interface
    sudo ip tuntap del dev "$TAP_IFACE" mode tap 2>/dev/null
    echo "Cleanup complete."
}

# Register cleanup function to run on script exit or interruption
trap cleanup EXIT INT TERM

# --- Create disk images if they don't exist or if $1 is set ---
if [ ! -z "$1" ] || [ ! -f "$VM_DISK1" ] || [ ! -f "$VM_DISK2" ]; then
    echo "Creating disk images: $VM_DISK1 and $VM_DISK2..."
    qemu-img create -f qcow2 "$VM_DISK1" 40G
    qemu-img create -f qcow2 "$VM_DISK2" 40G
else
    echo "Disk images already exist or no force flag provided. Skipping creation."
fi

# --- Setup Tap Interface and Bridge ---
echo "Setting up tap interface '$TAP_IFACE' and connecting to '$BRIDGE_IFACE'..."

# Check if virbr-mgmt exists
if ! ip link show "$BRIDGE_IFACE" &> /dev/null; then
    echo "Error: Bridge '$BRIDGE_IFACE' does not exist. Please create it and configure DHCP/TFTP services."
    exit 1
fi

# Create the tap interface
sudo ip tuntap add dev "$TAP_IFACE" mode tap user "$(whoami)"

# Bring the tap interface up
sudo ip link set "$TAP_IFACE" up

# Add the tap interface to the bridge
sudo brctl addif "$BRIDGE_IFACE" "$TAP_IFACE"

echo "Tap interface '$TAP_IFACE' is now connected to '$BRIDGE_IFACE'."

# --- QEMU Command for PXE Boot ---
echo "Starting QEMU for PXE boot..."
set -x
qemu-system-x86_64 \
    -smp "$VM_CPUS" \
    -enable-kvm \
    -m "$VM_MEMORY" \
    -nographic \
    -boot n \
    -netdev tap,id=net0,ifname="$TAP_IFACE",script=no,downscript=no \
    -device virtio-net-pci,netdev=net0,mac="$VM_MAC_ADDRESS" \
    -drive file="$VM_DISK1",format=qcow2,if=virtio \
    -drive file="$VM_DISK2",format=qcow2,if=virtio \
    -vnc "0.0.0.0:$VNC_PORT" 

echo "QEMU process finished."

# \
#     -chardev file,id=seabios,path="$SEABIOS_LOG_FILE" \
#     -device isa-debugcon,iobase=0x402,chardev=seabios \
#     -cdrom /home/sadas/workspace/go-workspace/src/github.com/simplyboot/tools/ipxe/src/bin/ipxe.iso
