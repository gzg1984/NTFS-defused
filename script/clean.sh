#!/bin/sh
if [ `id -u` -eq "0" ]
then
	echo "check user: pass"
else
	echo "Only can be run as ROOT"
	exit 0
fi

mounttype=`./prepare.sh type`
if [ "$?" -ne 0 ]
then
	echo "Error:$mounttype"
	exit 255
fi

mountrecord=`mount|grep  ${mounttype}`
mountpoint=`echo ${mountrecord}|awk '{print $3}'`
if [ `echo $mountpoint|wc -l` -eq 0 ]
then
	echo "no mount point"
else
	echo -n "umount  ${mountpoint}..."
	umount ${mountpoint}
	echo "Done"
fi

if [ `lsmod|grep ntfs|wc -l` -eq 0 ] 
then
	echo "no installed module"
else
	echo -n "remove ntfs module..."
	rmmod ntfs
	dmesg  -c > umount_rmmod.log
	echo "Done"
fi
