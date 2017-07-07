# Rules for making the NTFS driver.
ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_NTFS_FS) += ntfs.o

ntfs-y := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
	  index.o inode.o mft.o mst.o namei.o runlist.o super.o sysctl.o \
	  unistr.o upcase.o

ntfs-$(CONFIG_NTFS_RW) += bitmap.o lcnalloc.o logfile.o quota.o usnjrnl.o

ccflags-y := -DNTFS_VERSION=\"2.1.32\"
ccflags-$(CONFIG_NTFS_DEBUG)	+= -DDEBUG
ccflags-$(CONFIG_NTFS_RW)	+= -DNTFS_RW
else

KERNEL ?= /lib/modules/`uname -r`/build

default:
	CONFIG_NTFS_FS=m CONFIG_NTFS_RW=y CONFIG_NTFS_DEBUG=y $(MAKE) -C $(KERNEL) M=$$PWD


.PHONY : install help clean
help:
	$(MAKE) -C $(KERNEL) M=$$PWD help

install : default
	$(MAKE) -C $(KERNEL) M=$$PWD modules_install
	depmod -A

clean:
	make -C $(KERNEL) M=`pwd` clean

endif
