#ifndef _COMPAT_H_
#define _COMPAT_H_
extern int ntfs_read_bh(struct buffer_head *bh);
extern int ntfs_write_bh(struct buffer_head *bh);
extern void ntfs_clean_bh(struct buffer_head *bh);
extern ssize_t ntfs_write_iocb(struct kiocb *iocb, ssize_t written);
#endif

