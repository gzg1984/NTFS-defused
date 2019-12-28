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
mount ntfs.img /run/temp -o loop
echo 1 > /proc/sys/fs/ntfs-debug
ls /run/temp
######################
TestLoopCount=100

while :
do
echo -n "Creating test..."
touch /run/temp/abc123
result=`ls /run/temp/abc123 2>/dev/null|wc -l`
[ "$result" -eq "1" ]&&echo "Pass"
[ "$result" -eq "1" ]||echo "Failed"

echo -n "Removing test..."
rm /run/temp/abc123
result=`ls /run/temp/abc123 2>/dev/null|wc -l`
[ "$result" -eq "0" ]&&echo "Pass"
[ "$result" -eq "0" ]||echo "Failed"

[ "$TestLoopCount" -eq "0" ]&&break
TestLoopCount=`expr $TestLoopCount - 1`
done


#####################
umount /run/temp
rmmod ntfs.ko
