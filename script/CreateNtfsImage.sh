#!/bin/sh
dd if=/dev/zero of=ntfs.img bs=1024 count=102400
losetup /dev/loop9 ntfs.img
mkfs.ntfs /dev/loop9
losetup -d /dev/loop9 
