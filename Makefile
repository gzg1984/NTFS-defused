# Rules for making the NTFS driver as individual module for kernel 2.6.14

#obj-$(CONFIG_NTFS_FS) += ntfs.o
obj-m += ntfs.o

#ntfs-objs := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
#	     index.o inode.o mft.o mst.o namei.o runlist.o super.o sysctl.o \
#	     unistr.o upcase.o ntfs_g.h
#

###########20090928 shut
#ntfs-objs := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
#	     index.o inode.o mft.o mst.o namei.o runlist.o super.o sysctl.o \
#	     unistr.o upcase.o ntfs_g.o

ntfs-objs := aops.o attrib.o collate.o compress.o debug.o dir.o file.o \
	     index.o inode.o mft.o mst.o namei.o runlist.o super.o \
	     unistr.o upcase.o ntfs_g.o bitmap.o lcnalloc.o logfile.o quota.o usnjrnl.o

EXTRA_CFLAGS = -DNTFS_VERSION=\"2.1.29\"
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -DNTFS_RW

KERNEL ?= /lib/modules/`uname -r`/build

all:
	make -C $(KERNEL) M=`pwd` modules

install:
	make -C $(KERNEL) M=`pwd` modules
	make -C $(KERNEL) M=`pwd` modules_install
	depmod -A

clean:
	make -C $(KERNEL) M=`pwd` clean

