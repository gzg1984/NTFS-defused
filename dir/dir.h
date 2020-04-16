/*
 * dir.h - Defines for directory handling in NTFS Linux kernel driver. Part of
 *	   the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Anton Altaparmakov
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

#ifndef _LINUX_NTFS_DIR_H
#define _LINUX_NTFS_DIR_H

#include <linux/buffer_head.h>
#include <linux/slab.h>

#include "../layout.h"
#include "../types.h"
#include "../inode.h"

#include "../aops.h"
#include "../mft.h"
#include "../debug.h"
#include "../ntfs.h"
#include "../compat.h"
#include "../attrib.h"

#include "../lcnalloc.h"
#include "../index.h"


#define is_exceed_root(pos, vol) ((pos) >= vol->mft_record_size)
#define mark_actor_exceed_root(actor, vol) (actor->pos = vol->mft_record_size)

int ntfs_dir_iterate(struct file *file, struct dir_context *actor);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
int ntfs_readdir(struct file *filp, void *dirent, filldir_t filldir);
#endif

static inline int is_exceed_dir_end(const loff_t pos, const struct inode *vnode)
{
	struct super_block *sb = vnode->i_sb;
	ntfs_volume *vol = NTFS_SB(sb);
	/* Are we at end of dir yet? */
	loff_t i_size = i_size_read(vnode);
	/* vol->mft_record_size is the for the root index */
	/* i_size is for the allocated index */
	if (pos >= i_size + vol->mft_record_size)
	{
		return true;
	}
	return false;
}

static inline int ntfs_emit_dots(struct file *filp, void *dirent, filldir_t filldir)
{
	int rc = 0 ;
	struct inode *vdir = filp->f_path.dentry->d_inode;

	if (0 /* . */ == filp->f_pos)
	{
		rc = filldir(dirent, ".", 1, filp->f_pos, vdir->i_ino, DT_DIR);
		if (rc)
			return false;
		filp->f_pos = 1;
	}
	if (1 /* .. */ == filp->f_pos)
	{
		rc = filldir(dirent, "..", 2, filp->f_pos,
					 parent_ino(filp->f_path.dentry), DT_DIR);
		if (rc)
			return false;
		filp->f_pos = 2;
	}
	return true;
}


#define DIR_POS_TO_INDEX_ALLOCATION_POS(fpos,vol) ((s64)fpos - vol->mft_record_size)

#endif /* _LINUX_NTFS_FS_DIR_H */
