#!/usr/bin/env bash

cat > rsyncd.conf <<EOF
uid = root
gid = root
use chroot = yes
max connections = 300
timeout = 300
pid file = ./rsyncd.pid
log file = ./rsyncd.log
lock file = ./rsyncd.lock

[images]
  path = $PWD/images
  comment = rootfs
  read only = yes
  list = yes
  exclude from = ./rsync-exclude.list
EOF

rsync --daemon --config rsyncd.conf --address 192.168.122.1
