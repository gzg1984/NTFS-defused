# Rules for making the NTFS driver.
ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_NTFS_FS) += ntfs.o

ntfs-y := aops.o attrib.o collate.o compress.o debug.o file.o \
	  mst.o runlist.o super.o sysctl.o \
	  unistr.o upcase.o mft.o \
	  inode.o ntfs_inode.o 
# For Index Entry Handler
ntfs-y += dir.o index.o index_root.o namei.o \
	index_entry_create.o \
	index_entry_delete.o
# For compatition
ntfs-y += compat.o

ntfs-$(CONFIG_NTFS_RW) += bitmap.o lcnalloc.o logfile.o quota.o usnjrnl.o

ccflags-y := -DNTFS_VERSION=\"2.1.33\"
ccflags-$(CONFIG_NTFS_DEBUG)	+= -DDEBUG
ccflags-$(CONFIG_NTFS_RW)	+= -DNTFS_RW
else

KERNEL_SRC ?= /lib/modules/`uname -r`/build

modules:
	CONFIG_NTFS_FS=m CONFIG_NTFS_RW=y CONFIG_NTFS_DEBUG=y $(MAKE) -C $(KERNEL_SRC) M=$$PWD modules


.PHONY : install help clean test reload_ko
help:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD help

modules_install : modules
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD modules_install

clean:
	make -C $(KERNEL_SRC) M=`pwd` clean
	find . -name "*~"|xargs rm

# For test, Why we don't use script ?
# Because we can use the Makefile dependency as comments
#
fstest/Makefile:
	git submodule init fstest

fstest/fstest:fstest/Makefile
	make -C fstest

/run/temp:
	mkdir -p /run/temp

script/ntfs.img:
	dd if=/dev/zero of=script/ntfs.img bs=1024 count=102400
	losetup /dev/loop9 script/ntfs.img
	mkfs.ntfs /dev/loop9
	losetup -d /dev/loop9 

reload_ko:ntfs.ko
	cp ./ntfs.ko /lib/modules/`uname -r`/
	depmod -A
	@modprobe -r ntfs
	modprobe ntfs
	echo 1 > /proc/sys/fs/ntfs-debug

test: fstest/fstest /run/temp reload_ko script/ntfs.img
	mount -t ntfs-gordon script/ntfs.img /run/temp -o loop
	#For create
	fstest/fstest create /run/temp/create_test 0777
	#fstest/fstest unlink /run/temp/create_test 
	#fstest/fstest create /run/temp/create_test 0666
	#fstest/fstest unlink /run/temp/create_test 
	#fstest/fstest mkdir /run/temp/create_test 0777
	#fstest/fstest rmdir /run/temp/create_test 
	#fstest/fstest mkdir /run/temp/create_test 0777
	#fstest/fstest create /run/temp/create_test/1 0666
	#fstest/fstest unlink /run/temp/create_test/1 0666
	#fstest/fstest rmdir /run/temp/create_test 
	umount /run/temp
	modprobe -r ntfs
	dmesg  -c > test.log

endif

