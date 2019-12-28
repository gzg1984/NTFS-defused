#!/bin/sh
dmesg -c > /dev/null
insmod ntfs.ko
echo 1 > /proc/sys/fs/ntfs-debug
mkdir -p /run/temp
mount -t ntfs ntfs.img /run/temp
ls /run/temp
