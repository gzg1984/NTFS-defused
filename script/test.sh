#!/bin/sh

echo -n "Check mount Point..."
mounttype=`./prepare.sh type`
if [ "$?" -ne 0 ]
then
	echo "Error:$mounttype"
	exit 255
fi


mountrecord=`mount|grep  ${mounttype}`
recordline=`echo ${mountrecord}|wc -l`
if [ ${recordline} -eq "0" ]
then
	echo "Failed... Found No mount point for type ${mounttype}"
	exit 255
fi
mountpoint=`echo ${mountrecord}|awk '{print $3}'`
echo "Pass...found mount point at $mountpoint"

echo -n "Enable Debug..."
echo 1 > /proc/sys/fs/ntfs-debug
echo "Done"

if [ "$1" == "sys" ]
then
	for i in /sys/fs/ntfs/*
	do
		if [ -d $i ]
		then
			for j in $i/*
			do
				if [ -f $j ]
				then
					echo $j
					echo -n "	"
					cat $j
					echo
				fi
			done
		fi
	done
fi

if [ "$1" == "ls" ]
then
	echo "### Testing ls ###"
	ls ${mountpoint}
	echo "### Testing ls Done###"
fi

if [ "$1" == "touch" ]
then
	echo "### Testing Create and Delete ###"
	TestLoopCount=100

	touchTargetTest() {
		TARGETFILE=$1

		echo -n "Creating test..."
		touch $TARGETFILE
		result=`ls $TARGETFILE 2>/dev/null|wc -l`
		[ "$result" -eq "1" ]&&echo "Pass"
		[ "$result" -eq "1" ]||echo "Failed"
		return $result
	}
	deleteTargetTest() {
		TARGETFILE=$1

		echo -n "Removing test..."
		rm ${TARGETFILE}
		result=`ls ${TARGETFILE} 2>/dev/null|wc -l`
		[ "$result" -eq "0" ]&&echo "Pass"
		[ "$result" -eq "0" ]||echo "Failed"
		return $result
	}

	while :
	do
		touchTargetTest ${mountpoint}/abc123
		[ "$?" -eq "1" ]||break

		deleteTargetTest ${mountpoint}/abc123
		[ "$?" -eq "0" ]||break

		[ "$TestLoopCount" -eq "0" ]&&break
		TestLoopCount=`expr $TestLoopCount - 1`
	done
	echo "### Testing Create and Delete Done ###"
fi


#./TEST_sub_touch.sh
