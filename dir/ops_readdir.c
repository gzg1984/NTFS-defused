/**
 * ops_readdir.c - kernel interface for dir readding before Kernel V4
 * Copyright (c) 2017-2020 Gordon (aka. Zhigang Gao)
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

#include "dir.h"
#include "../attrib.h"
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
/**
 * ntfs_filldir - ntfs specific filldir method
 * @vol:	current ntfs volume
 * @fpos:	position in the directory
 * @ndir:	ntfs inode of current directory
 * @ia_page:	page in which the index allocation buffer @ie is in resides
 * @ie:		current index entry
 * @name:	buffer to use for the converted name
 * @dirent:	vfs filldir callback context
 * @filldir:	vfs filldir callback
 *
 * Convert the Unicode @name to the loaded NLS and pass it to the @filldir
 * callback.
 *
 * If @ia_page is not NULL it is the locked page containing the index
 * allocation block containing the index entry @ie.
 *
 * Note, we drop (and then reacquire) the page lock on @ia_page across the
 * @filldir() call otherwise we would deadlock with NFSd when it calls ->lookup
 * since ntfs_lookup() will lock the same page.  As an optimization, we do not
 * retake the lock if we are returning a non-zero value as ntfs_readdir()
 * would need to drop the lock immediately anyway.
 */
static int ntfs_filldir(ntfs_volume *vol, loff_t fpos,
						ntfs_inode *ndir,
						struct page *ia_page,
						INDEX_ENTRY *ie,
						u8 *name,
						void *dirent,
						filldir_t filldir)
{
	unsigned long mref;
	int name_len, rc;
	unsigned dt_type;
	FILE_NAME_TYPE_FLAGS name_type;

	name_type = ie->key.file_name.file_name_type;
	if (name_type == FILE_NAME_DOS)
	{
		ntfs_debug("Skipping DOS name space entry.");
		return 0;
	}
	if (MREF_LE(ie->data.dir.indexed_file) == FILE_ROOT)
	{
		ntfs_debug("Skipping root directory self reference entry.");
		return 0;
	}
	if (MREF_LE(ie->data.dir.indexed_file) < FILE_first_user &&
		!NVolShowSystemFiles(vol))
	{
		ntfs_debug("Skipping system file.");
		return 0;
	}
	name_len = ntfs_ucstonls(vol, (ntfschar *)&ie->key.file_name.file_name,
							 ie->key.file_name.file_name_length, &name,
							 NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1);
	if (name_len <= 0)
	{
		ntfs_warning(vol->sb, "Skipping unrepresentable inode 0x%llx.",
					 (long long)MREF_LE(ie->data.dir.indexed_file));
		return 0;
	}
	if (ie->key.file_name.file_attributes &
		FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT)
		dt_type = DT_DIR;
	else
		dt_type = DT_REG;
	mref = MREF_LE(ie->data.dir.indexed_file);
	/*
	 * Drop the page lock otherwise we deadlock with NFS when it calls
	 * ->lookup since ntfs_lookup() will lock the same page.
	 */
	if (ia_page)
		unlock_page(ia_page);
	ntfs_debug("Calling filldir for %s with len %i, fpos 0x%llx, inode "
			   "0x%lx, DT_%s.",
			   name, name_len, fpos, mref,
			   dt_type == DT_DIR ? "DIR" : "REG");
	rc = filldir(dirent, name, name_len, fpos, mref, dt_type);
	/* Relock the page but not if we are aborting ->readdir. */
	if (!rc && ia_page)
		lock_page(ia_page);
	return rc;
}
static int fill_from_root(struct file *filp,
						void *dirent,
						ntfs_volume *vol,
						ntfs_inode *ndir,
						u8 *name,
						filldir_t filldir)
{
	MFT_RECORD *m = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	loff_t ir_pos;
	int err = 0;
	int rc = 0;
	struct inode *vdir = filp->f_path.dentry->d_inode;
	INDEX_ROOT *ir = NULL;
	u8 *index_end;
	loff_t fpos = filp->f_pos;
	INDEX_ENTRY *ie;

	/* Get hold of the mft record for the directory. */
	m = map_mft_record(ndir);
	if (IS_ERR(m))
	{
		err = PTR_ERR(m);
		m = NULL;
		return err;
	}

	ctx = ntfs_attr_get_search_ctx(ndir, m);
	if (unlikely(!ctx))
	{
		err = -ENOMEM;
		return err;
	}
	/* Get the offset into the index root attribute. */
	ir_pos = (loff_t)fpos;
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL,
						   0, ctx);
	if (unlikely(err))
	{
		ntfs_error(vdir->i_sb, "Index root attribute missing in directory "
					   "inode 0x%lx.",
				   vdir->i_ino);
		return err;
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
	ir = kmalloc(rc, GFP_NOFS);
	if (unlikely(!ir))
	{
		err = -ENOMEM;
		return err;
	}
	/* Copy the index root value (it has been verified in read_inode). */
	memcpy(ir, (u8 *)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset), rc);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ndir);
	ctx = NULL;
	m = NULL;
	index_end = (u8 *)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY *)((u8 *)&ir->index +
						 le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry or until filldir tells us it has had enough
	 * or signals an error (both covered by the rc test).
	 */
	for (;; ie = (INDEX_ENTRY *)((u8 *)ie + le16_to_cpu(ie->length)))
	{
		ntfs_debug("In index root, offset 0x%zx.", (u8 *)ie - (u8 *)ir);
		/* Bounds checks. */
		err=-1;
		if (unlikely((u8 *)ie < (u8 *)ir || (u8 *)ie + sizeof(INDEX_ENTRY_HEADER) > index_end ||
					 (u8 *)ie + le16_to_cpu(ie->key_length) >
						 index_end))
			goto err_out;
		/* The last entry cannot contain a name. */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Skip index root entry if continuing previous readdir. */
		if (ir_pos > (u8 *)ie - (u8 *)ir)
			continue;
		/* Advance the position even if going to skip the entry. */
		fpos = (u8 *)ie - (u8 *)ir;
		/* Submit the name to the filldir callback. */
		rc = ntfs_filldir(vol, fpos, ndir, NULL, ie, name, dirent,
						  filldir);
		if (rc)
		{
			kfree(ir);
			return 1;
		}
	}
	/* We are done with the index root and can free the buffer. */

	err = 0;
err_out:
	kfree(ir);
	ir = NULL;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(ndir);
	return err;
}

/*
 * We use the same basic approach as the old NTFS driver, i.e. we parse the
 * index root entries and then the index allocation entries that are marked
 * as in use in the index bitmap.
 *
 * While this will return the names in random order this doesn't matter for
 * ->readdir but OTOH results in a faster ->readdir.
 *
 * VFS calls ->readdir without BKL but with i_mutex held. This protects the VFS
 * parts (e.g. ->f_pos and ->i_size, and it also protects against directory
 * modifications).
 *
 * Locking:  - Caller must hold i_mutex on the directory.
 *	     - Each page cache page in the index allocation mapping must be
 *	       locked whilst being accessed otherwise we may find a corrupt
 *	       page due to it being under ->writepage at the moment which
 *	       applies the mst protection fixups before writing out and then
 *	       removes them again after the write is complete after which it
 *	       unlocks the page.
 */
int ntfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
	s64 ia_pos, ia_start, prev_ia_pos;
	loff_t fpos = filp->f_pos;
	struct inode  *vdir = filp->f_path.dentry->d_inode;
	struct super_block *sb = vdir->i_sb;
	ntfs_inode *ndir = NTFS_I(vdir);
	ntfs_volume *vol = NTFS_SB(sb);
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *name = NULL;
	int rc, err;
	struct address_space *ia_mapping;
	struct page *ia_page = NULL;
	u8 *kaddr, *index_end;

	rc = err = 0;

	/* Are we at end of dir yet? */
	if (is_exceed_dir_end(filp->f_pos, vdir))
		goto done;

	/* Emulate . and .. for all directories. */
	if (!ntfs_emit_dots(filp, dirent, filldir))
		goto done;

	/* first init after emit */
	fpos = filp->f_pos;

	/*
	 * Allocate a buffer to store the current name being processed
	 * converted to format determined by current NLS.
	 */
	name = kmalloc(NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1, GFP_NOFS);
	if (unlikely(!name))
	{
		err = -ENOMEM;
		goto err_out;
	}
	/* Are we jumping straight into the index allocation attribute? */
	if (!is_exceed_root(fpos, vol)){
		err =  fill_from_root(filp, dirent, vol, ndir, name, filldir);
		if (err < 0 ) 
			goto err_out;
		if (err > 0 ) 
			goto abort;
	}


	/* If there is no index allocation attribute we are finished. */
	if (!NInoIndexAllocPresent(ndir))
		goto EOD;
	/* Advance fpos to the beginning of the index allocation. */
	fpos = vol->mft_record_size;


	kaddr = NULL;
	prev_ia_pos = -1LL;
	/* Get the offset into the index allocation attribute. */
	ia_pos = (s64) DIR_POS_TO_INDEX_ALLOCATION_POS(fpos, vol);

	ia_mapping = vdir->i_mapping;

find_next_index_buffer:
	rc = get_available_pos_in_index_allocation_since_pos( vdir, &ia_pos);
	if(rc)
	{
		err = rc ;
		goto err_out;
	}
	else if (ia_pos == ( i_size_read(vdir) + vol->mft_record_size))
	{
		goto unm_EOD;
	}


	/* If the current index buffer is in the same page we reuse the page. */
	if ((prev_ia_pos & (s64)PAGE_CACHE_MASK) !=
		(ia_pos & (s64)PAGE_CACHE_MASK))
	{
		prev_ia_pos = ia_pos;
		if (likely(ia_page != NULL))
		{
			unlock_page(ia_page);
			ntfs_unmap_page(ia_page);
		}
		/*
		 * Map the page cache page containing the current ia_pos,
		 * reading it from disk if necessary.
		 */
		ia_page = ntfs_map_page(ia_mapping, ia_pos >> PAGE_CACHE_SHIFT);
		if (IS_ERR(ia_page))
		{
			ntfs_error(sb, "Reading index allocation data failed.");
			err = PTR_ERR(ia_page);
			ia_page = NULL;
			goto err_out;
		}
		lock_page(ia_page);
		kaddr = (u8 *)page_address(ia_page);
	}



	/* Get the current index buffer. */
	ia = (INDEX_ALLOCATION *)(kaddr + (ia_pos & ~PAGE_CACHE_MASK &
									   ~(s64)(ndir->itype.index.block_size - 1)));
	/* Bounds checks. */
	if (unlikely((u8 *)ia < kaddr || (u8 *)ia > kaddr + PAGE_CACHE_SIZE))
	{
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
					   "inode 0x%lx or driver bug.",
				   vdir->i_ino);
		goto err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic)))
	{
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
					   "corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				   (unsigned long long)ia_pos >>
					   ndir->itype.index.vcn_size_bits,
				   vdir->i_ino);
		goto err_out;
	}
	if (unlikely(sle64_to_cpu(ia->index_block_vcn) != (ia_pos &
													   ~(s64)(ndir->itype.index.block_size - 1)) >>
														  ndir->itype.index.vcn_size_bits))
	{
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
					   "different from expected VCN (0x%llx). "
					   "Directory inode 0x%lx is corrupt or driver "
					   "bug. ",
				   (unsigned long long)
					   sle64_to_cpu(ia->index_block_vcn),
				   (unsigned long long)ia_pos >>
					   ndir->itype.index.vcn_size_bits,
				   vdir->i_ino);
		goto err_out;
	}
	if (unlikely(le32_to_cpu(ia->index.allocated_size) + 0x18 !=
				 ndir->itype.index.block_size))
	{
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
					   "0x%lx has a size (%u) differing from the "
					   "directory specified size (%u). Directory "
					   "inode is corrupt or driver bug.",
				   (unsigned long long)ia_pos >>
					   ndir->itype.index.vcn_size_bits,
				   vdir->i_ino,
				   le32_to_cpu(ia->index.allocated_size) + 0x18,
				   ndir->itype.index.block_size);
		goto err_out;
	}
	index_end = (u8 *)ia + ndir->itype.index.block_size;
	if (unlikely(index_end > kaddr + PAGE_CACHE_SIZE))
	{
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
					   "0x%lx crosses page boundary. Impossible! "
					   "Cannot access! This is probably a bug in the "
					   "driver.",
				   (unsigned long long)ia_pos >>
					   ndir->itype.index.vcn_size_bits,
				   vdir->i_ino);
		goto err_out;
	}
	ia_start = ia_pos & ~(s64)(ndir->itype.index.block_size - 1);
	index_end = (u8 *)&ia->index + le32_to_cpu(ia->index.index_length);
	if (unlikely(index_end > (u8 *)ia + ndir->itype.index.block_size))
	{
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
					   "inode 0x%lx exceeds maximum size.",
				   (unsigned long long)ia_pos >>
					   ndir->itype.index.vcn_size_bits,
				   vdir->i_ino);
		goto err_out;
	}
	/* The first index entry in this index buffer. */
	ie = (INDEX_ENTRY *)((u8 *)&ia->index +
						 le32_to_cpu(ia->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry or until filldir tells us it has had enough
	 * or signals an error (both covered by the rc test).
	 */
	for (;; ie = (INDEX_ENTRY *)((u8 *)ie + le16_to_cpu(ie->length)))
	{
		ntfs_debug("In index allocation, offset 0x%llx.",
				   (unsigned long long)ia_start +
					   (unsigned long long)((u8 *)ie - (u8 *)ia));
		/* Bounds checks. */
		if (unlikely((u8 *)ie < (u8 *)ia || (u8 *)ie + sizeof(INDEX_ENTRY_HEADER) > index_end ||
					 (u8 *)ie + le16_to_cpu(ie->key_length) >
						 index_end))
			goto err_out;
		/* The last entry cannot contain a name. */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Skip index block entry if continuing previous readdir. */
		if (ia_pos - ia_start > (u8 *)ie - (u8 *)ia)
			continue;
		/* Advance the position even if going to skip the entry. */
		fpos = (u8 *)ie - (u8 *)ia +
			   (sle64_to_cpu(ia->index_block_vcn) << ndir->itype.index.vcn_size_bits) +
			   vol->mft_record_size;
		/*
		 * Submit the name to the @filldir callback.  Note,
		 * ntfs_filldir() drops the lock on @ia_page but it retakes it
		 * before returning, unless a non-zero value is returned in
		 * which case the page is left unlocked.
		 */
		rc = ntfs_filldir(vol, fpos, ndir, ia_page, ie, name, dirent,
						  filldir);
		if(rc)
		{
			/* @ia_page is already unlocked in this case. */
			ntfs_unmap_page(ia_page);
			ia_pos = ia_start + ndir->itype.index.block_size;
			filp->f_pos = ia_pos + vol->mft_record_size;
			fpos = ia_pos + vol->mft_record_size;
			goto abort;
		}
	}
	ia_pos = ia_start + ndir->itype.index.block_size;
	filp->f_pos = ia_pos + vol->mft_record_size;
	fpos = ia_pos + vol->mft_record_size;
	goto find_next_index_buffer;
unm_EOD:
	if (ia_page)
	{
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
EOD:
	/* We are finished, set fpos to EOD. */
	fpos = i_size_read(vdir) + vol->mft_record_size;
abort:
	kfree(name);
done:
#ifdef DEBUG
	if (!rc)
		ntfs_debug("EOD, fpos 0x%llx, returning 0.", fpos);
	else
		ntfs_debug("filldir returned %i, fpos 0x%llx, returning 0.",
				   rc, fpos);
#endif
	filp->f_pos = fpos;
	return 0;
err_out:
	if (ia_page)
	{
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
	//kfree(ir);
	kfree(name);
	//if (ctx)
	//	ntfs_attr_put_search_ctx(ctx);
	//if (m)
	//	unmap_mft_record(ndir);
	if (!err)
		err = -EIO;
	ntfs_debug("Failed. Returning error code %i.", -err);
	filp->f_pos = fpos;
	return err;
}
#endif
