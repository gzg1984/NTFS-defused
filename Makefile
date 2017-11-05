# Rules for making the NTFS driver.
ifneq ($(KERNELRELEASE),)
obj-$(CONFIG_NTFS_FS) += ntfs.o


ntfs-y := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
	  index.o  mst.o namei.o runlist.o super.o sysctl.o \
	  unistr.o upcase.o mft.o \
	  inode.o ntfs_inode.o

ntfs-$(CONFIG_NTFS_RW) += bitmap.o lcnalloc.o logfile.o quota.o usnjrnl.o

ccflags-y := -DNTFS_VERSION=\"2.1.33\"
ccflags-$(CONFIG_NTFS_DEBUG)	+= -DDEBUG
ccflags-$(CONFIG_NTFS_RW)	+= -DNTFS_RW
else

KERNEL_SRC ?= /lib/modules/`uname -r`/build

modules:
	CONFIG_NTFS_FS=m CONFIG_NTFS_RW=y CONFIG_NTFS_DEBUG=y $(MAKE) -C $(KERNEL_SRC) M=$$PWD modules


.PHONY : install help clean
help:
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD help

modules_install : modules
	$(MAKE) -C $(KERNEL_SRC) M=$$PWD modules_install

clean:
	make -C $(KERNEL_SRC) M=`pwd` clean

endif
