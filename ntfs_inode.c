/*
 * ntfs_inode.c - NTFS kernel module ntfs_inode handler 
 *
 * Copyright (c) 2017 Gordon
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
#include <linux/stddef.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/bitmap.h>

#include "ntfs.h"
#include "index.h"
#include "inode.h"

struct inode* ntfs_vfs_inode_lookup_by_name(ntfs_volume *vol,ntfs_inode *dir_ni, 
		const ntfschar *uname,
		const int uname_len)
{
	MFT_REF mref;
	struct inode *tmp_ino;
	ntfs_name *name = NULL;
	/*
	 * Find the inode number for the quota file by looking up the filename
	 * $Quota in the extended system files directory $Extend.
	 */
	inode_lock(VFS_I(dir_ni));
	mref = ntfs_lookup_inode_by_name(dir_ni, uname, uname_len, &name);
	inode_unlock(VFS_I(dir_ni));
	if (IS_ERR_MREF(mref)) 
	{
		if (MREF_ERR(mref) == -ENOENT) 
		{
			return ERR_PTR(-ENOENT);
		}
		else
		{
			return ERR_PTR(-EIO);
		}
	}
	/* We do not care for the type of match that was found. */
	kfree(name);
	/* Get the inode. */
	tmp_ino = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(tmp_ino) || is_bad_inode(tmp_ino)) {
		if (!IS_ERR(tmp_ino))
			iput(tmp_ino);
		ntfs_error(vol->sb, "Failed to load mref %llu.",mref);
		return ERR_PTR(-EIO);
	}
	return tmp_ino;
}

