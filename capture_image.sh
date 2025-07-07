#!/usr/bin/env bash

rsync_exclude_file=/tmp/rsync-exclude-list.$$
output_dir=$1

if [ -z $output_dir ]; then
  echo "Error: output dir not set!"
  echo "$0: <output dir>"
  exit 1
fi

cat > $rsync_exclude_file <<EOF
lost+found/
/proc/*
/sys/*
/boot/efi
/etc/machine-id
/cm/*
/tmp/*
/var/run/*
/run/*
/var/cache/apt/*
/usr/share/man/*
/usr/share/man-db/*
/data-disk/*
/home/sadas/*
/swap.img*
/root/.local/*
/root/.cache/*
/root/.vagrant.d/*
/snap/*
/var/lib/libvirt/*
/var/lib/docker/*
/var/lib/containerd/*
$output_dir
EOF

set -ex
sudo rsync -azP --info=progress2,name0 --no-inc-recursive --exclude-from $rsync_exclude_file / $output_dir
