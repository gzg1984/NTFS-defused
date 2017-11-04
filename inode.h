/*
 * inode.h - Defines for inode structures NTFS Linux kernel driver. Part of
 *	     the Linux-NTFS project.
 *
 * Copyright (c) 2001-2007 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LINUX_NTFS_INODE_H
#define _LINUX_NTFS_INODE_H

#include <linux/atomic.h>

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>

#include "layout.h"
#include "volume.h"
#include "types.h"
#include "runlist.h"
#include "debug.h"
#include "ntfs_inode.h"

/**
 * ntfs_attr - ntfs in memory attribute structure
 * @mft_no:	mft record number of the base mft record of this attribute
 * @name:	Unicode name of the attribute (NULL if unnamed)
 * @name_len:	length of @name in Unicode characters (0 if unnamed)
 * @type:	attribute type (see layout.h)
 *
 * This structure exists only to provide a small structure for the
 * ntfs_{attr_}iget()/ntfs_test_inode()/ntfs_init_locked_inode() mechanism.
 *
 * NOTE: Elements are ordered by size to make the structure as compact as
 * possible on all architectures.
 */
typedef struct {
	unsigned long mft_no;
	ntfschar *name;
	u32 name_len;
	ATTR_TYPE type;
} ntfs_attr;

typedef int (*test_t)(struct inode *, void *);

extern int ntfs_test_inode(struct inode *vi, ntfs_attr *na);

extern struct inode *ntfs_iget(struct super_block *sb, unsigned long mft_no);
extern struct inode *ntfs_attr_iget(struct inode *base_vi, ATTR_TYPE type,
		ntfschar *name, u32 name_len);
extern struct inode *ntfs_index_iget(struct inode *base_vi, ntfschar *name,
		u32 name_len);

extern struct inode *ntfs_alloc_big_inode(struct super_block *sb);
extern void ntfs_destroy_big_inode(struct inode *inode);
extern void ntfs_evict_big_inode(struct inode *vi);


static inline void ntfs_init_big_inode(struct inode *vi)
{
	ntfs_inode *ni = NTFS_I(vi);
	__ntfs_init_inode(vi->i_sb, ni);
	ni->mft_no = vi->i_ino;
}


extern int ntfs_read_inode_mount(struct inode *vi);

extern int ntfs_show_options(struct seq_file *sf, struct dentry *root);

extern struct inode *ntfs_bitmap_vfs_inode_lookup(struct inode* vi);
int ntfs_transfer_ia_pos_to_address(struct inode* vdir,u8* paget_map_kaddr,s64 ia_pos,
INDEX_ALLOCATION** p_index_allocation,s64* p_ia_start,u8** index_header_end);

/* s64 pos_byte_to_block(s64 pos,ntfs_inode* ndir) */
#define pos_byte_to_block(pos,ndir) ((pos) >> (ndir)->itype.index.block_size_bits)

typedef int (*ie_looper)(void* dir,INDEX_ENTRY *, void *);
extern int ntfs_index_walk_entry_in_header(void* dir,INDEX_HEADER* ih,
		                loff_t* p_skip_pos, 
				ie_looper func,void* parameter);


#ifdef NTFS_RW

extern int ntfs_truncate(struct inode *vi);
extern void ntfs_truncate_vfs(struct inode *vi);

extern int ntfs_setattr(struct dentry *dentry, struct iattr *attr);

extern int __ntfs_write_inode(struct inode *vi, int sync);

static inline void ntfs_commit_inode(struct inode *vi)
{
	if (!is_bad_inode(vi))
		__ntfs_write_inode(vi, 1);
	return;
}

extern int get_available_pos_in_index_allocation_since_pos(struct inode *vdir, s64* p_ia_pos);

#else

static inline void ntfs_truncate_vfs(struct inode *vi) {}

#endif /* NTFS_RW */

#endif /* _LINUX_NTFS_INODE_H */
