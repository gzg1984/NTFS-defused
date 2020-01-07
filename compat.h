#ifndef _COMPAT_H_
#define _COMPAT_H_
#include <linux/version.h>
extern int ntfs_read_bh(struct buffer_head *bh);
extern int ntfs_write_bh(struct buffer_head *bh);
extern void ntfs_clean_bh(struct buffer_head *bh);
extern ssize_t ntfs_write_iocb(struct kiocb *iocb, ssize_t written);
extern void ntfs_block_invalidatepage(struct page *page, unsigned int offset, unsigned int length);
extern struct page *ntfs_find_get_page_flags(struct address_space *mapping, pgoff_t offset, int fgp_flags);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,10,0))
#define FGP_ACCESSED            0x00000001
#define FGP_LOCK                0x00000002
#endif /* macro dependon version*/

#endif /* end of compat.h tag */

