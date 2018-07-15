#!/bin/sh
if [ `id -u` -eq "0" ]
then
	echo "check user: pass"
else
	echo "Only can be run as ROOT"
	exit 0
fi

dmesg -c > /dev/null
if [ -f ../ntfs.ko ]
then
	echo "### ntfs.ko is ready to insmod"
else
	echo "### ntfs.ko is not ready, build it first"
	cd ../
	make
	cd script
fi
if [ -f ../ntfs.ko ]
then
	insmod ../ntfs.ko
else
	file ../ntfs.ko
	exit 0
fi

mkdir -p /run/temp
mount -t ntfs-gordon ntfs.img /run/temp -o loop
echo 1 > /proc/sys/fs/ntfs-debug

exit 0
