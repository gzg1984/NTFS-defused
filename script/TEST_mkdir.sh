#!/bin/sh
if [ `id -u` -eq "0" ]
then
	echo "check user: pass"
else
	echo "Only can be run as ROOT"
	exit 0
fi

./LoadModule.sh

# Test Content
mkdir /run/temp/a
dmesg -c >  TEST_inode_operations_lookup.kernel.log

./UnLoadModule.sh
