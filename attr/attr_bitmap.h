#include "../inode.h"

#ifndef ATTR_BITMAP
#define ATTR_BITMAP

static inline struct inode *ntfs_bitmap_vfs_inode_get(struct inode *base_vi)
{
	return ntfs_attr_iget(base_vi, AT_BITMAP, I30, 4);
}
#endif