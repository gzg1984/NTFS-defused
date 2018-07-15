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
int ntfs_inode_copy_ir(ntfs_inode* dir_ntfs_inode,/* output */INDEX_ROOT** pir)
{
	MFT_RECORD * m = NULL;
	ntfs_attr_search_ctx * ctx = NULL;
	int rc = 0 ;

	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ntfs_inode);
	if (IS_ERR(m)) {
		rc = PTR_ERR(m);
		m = NULL;
		goto out;
	}
	ctx = ntfs_attr_get_search_ctx(dir_ntfs_inode, m);
	if (unlikely(!ctx)) {
		rc = -ENOMEM;
		goto out;
	}
	/* Find the index root attribute in the mft record. */
	rc = ntfs_search_attr_index_root(ctx);
	if (unlikely(rc)) 
	{
		ntfs_error(VFS_I(dir_ntfs_inode)->i_sb , 
				"Index root attribute missing in directory "
				"inode 0x%lx.", VFS_I(dir_ntfs_inode)->i_ino);
		/* keep rc as error code */
		goto out;
	}
	/*
	 * Copy the index root attribute value to a buffer so that we can put
	 * the search context and unmap the mft record before calling the
	 * filldir() callback.  We need to do this because of NFSd which calls
	 * ->lookup() from its filldir callback() and this causes NTFS to
	 * deadlock as ntfs_lookup() maps the mft record of the directory and
	 * we have got it mapped here already.  The only solution is for us to
	 * unmap the mft record here so that a call to ntfs_lookup() is able to
	 * map the mft record without deadlocking.
	 */
	rc = le32_to_cpu(ctx->attr->data.resident.value_length);
	/* use rc as data length */
	(*pir) = kmalloc(rc, GFP_NOFS);
	if (unlikely(!(*pir))) {
		rc = -ENOMEM;
		goto out;
	}

	/* Copy the index root value (it has been verified in read_inode). */
	memcpy((*pir), (u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset), rc);
	rc = 0 ;
out:
	if (ctx)
	{
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
	}
	if (m)
	{
		unmap_mft_record(dir_ntfs_inode);
		m = NULL;
	}
	return rc;
}

