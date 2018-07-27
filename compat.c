#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/bit_spinlock.h>
#include <linux/bio.h>
#include <linux/version.h>
#include "compat.h"

#define _FORCE_CHOOSEN_ 1

extern int ntfs_read_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))||(_FORCE_CHOOSEN_==1)
	return submit_bh(REQ_OP_READ, 0, bh);
#else
	return submit_bh(READ, bh);
#endif
}

extern int ntfs_write_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))||(_FORCE_CHOOSEN_==1)
	return submit_bh(REQ_OP_WRITE, 0, bh);
#else
	return submit_bh(WRITE, bh);
#endif
}

extern void ntfs_clean_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))||(_FORCE_CHOOSEN_==1)
	clean_bdev_bh_alias(bh);
#else
	unmap_underlying_metadata(bh->b_bdev,
			bh->b_blocknr);
#endif
}

extern ssize_t ntfs_write_iocb(struct kiocb *iocb, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	struct inode *vi = file_inode(file);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))||(_FORCE_CHOOSEN_==1)
	inode_unlock(vi);
	iocb->ki_pos += written;
	if (likely(written > 0))
		written = generic_write_sync(iocb, written);
#else
	mutex_unlock(&vi->i_mutex);
	if (likely(written > 0)) {
		err = generic_write_sync(file, iocb->ki_pos, written);
		if (err < 0)
			written = 0;
	}
	iocb->ki_pos += written;
#endif
	return written;

}

