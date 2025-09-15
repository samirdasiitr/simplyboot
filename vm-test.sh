if [ ! -z $1 ]; then
	qemu-img create -f qcow2 testdisk.qcow2 40G
	qemu-img create -f qcow2 testdisk-vdb.qcow2 40G
fi
ip tuntap add dev tap110 mode tap
ip link set tap110 up
brctl addif virbr0 tap110
#qemu-system-x86_64 -smp 4 -enable-kvm -m 4096 -kernel /boot/vmlinuz-6.11.0-26-generic -initrd initrd.img \
#	-append "root=/dev/sda1 rw console=ttyS0 nodeconfigserver=192.168.122.160 nodeconfigserverport=7174 rsyncserver=192.168.122.160" \
qemu-system-x86_64 -smp 4 -enable-kvm -m 4096 \
       	-nographic \
	-drive file=testdisk.qcow2,format=qcow2,if=virtio \
	-drive file=testdisk-vdb.qcow2,format=qcow2,if=virtio \
        -netdev tap,id=net0,script=no,downscript=no,ifname=tap110 \
        -device virtio-net-pci,netdev=net0,mac=52:54:00:10:20:88 \
	-vnc 0.0.0.0:10 \
	-boot n
