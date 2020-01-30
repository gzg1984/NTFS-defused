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
#include <linux/aio.h>
#include "compat.h"

extern int ntfs_read_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
	return submit_bh(REQ_OP_READ, 0, bh);
#else
	return submit_bh(READ, bh);
#endif
}

extern int ntfs_write_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
	return submit_bh(REQ_OP_WRITE, 0, bh);
#else
	return submit_bh(WRITE, bh);
#endif
}

extern void ntfs_clean_bh(struct buffer_head *bh)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
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
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
	inode_unlock(vi);
	iocb->ki_pos += written;
	if (likely(written > 0))
		written = generic_write_sync(iocb, written);
#else
	int err = 0;
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

void ntfs_block_invalidatepage(struct page *page, unsigned int offset, unsigned int length)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
	block_invalidatepage(page, offset,length);
#else
	block_invalidatepage_range(page, offset, length);
#endif
}

struct page *ntfs_find_get_page_flags(struct address_space *mapping, pgoff_t offset, int fgp_flags)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
	return find_get_page_flags(mapping, offset, fgp_flags);
#else
	return find_get_page(mapping, offset);
#endif
}
/*
ssize_t ntfs_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0))||(_FORCE_CHOOSEN_==1)
	return generic_write_checks(iocb,from);

#else
	int generic_write_checks(struct file *file, loff_t *pos, size_t *count, int isblk);

#endif
}
*/

