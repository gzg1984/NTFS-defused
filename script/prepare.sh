#!/bin/sh

# Step 1 create image
if [ $# -eq 0 -o $1 == "image" ]
then
	dd if=/dev/zero of=ntfs.img bs=1024 count=10240
	losetup /dev/loop9 ntfs.img
	mkfs.ntfs /dev/loop9
	mkdir -p /tmp/tempntfs
	mount /dev/loop9 /tmp/tempntfs
	count=56
	while :
	do
		[ $count -eq 0 ]&&break
		count=`expr $count - 1 `
		touch /tmp/tempntfs/test_$count
	done
	umount /tmp/tempntfs
	losetup -d /dev/loop9 
fi

# Step 2 Load Module
if [ $# -eq 0 -o $1 == "load" ]
then
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
		echo 1 > /proc/sys/fs/ntfs-debug
	else
		file ../ntfs.ko
		exit 0
	fi
fi

# Step 3 Mount Image
if [ $# -eq 0 -o $1 == "mount" ]
then
	TYPE_NAME=`cat /sys/fs/ntfs/features/mount_type`

	mkdir -p /run/temp
	mount -t ${TYPE_NAME} ntfs.img /run/temp -o loop
fi

exit 0
