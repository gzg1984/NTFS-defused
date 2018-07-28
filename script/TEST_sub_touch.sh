#!/bin/sh
if [ `id -u` -eq "0" ]
then
	echo "check user: pass"
else
	echo "Only can be run as ROOT"
	exit 0
fi

mkdir -p /run/temp
mount -t ntfs-3g ntfs.img /run/temp -o loop
mkdir /run/temp/a
umount /run/temp

./LoadModule.sh

# Test Content
touch /run/temp/a/b
dmesg -c >  ${0}.kernel.log

./UnLoadModule.sh
