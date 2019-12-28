#!/bin/sh
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
