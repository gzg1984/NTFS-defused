#!/bin/sh
if [ `id -u` -eq "0" ]
then
	echo "check user: pass"
else
	echo "Only can be run as ROOT"
	exit 0
fi

umount /run/temp
rmmod ntfs
dmesg  -c > umount_rmmod.log
