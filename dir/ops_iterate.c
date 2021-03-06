/**
 * dir.c - NTFS kernel directory operations.
 * Part of the NTFS-defused.git
 *
 * Copyright (c) 2017 Gordon
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

#include <linux/buffer_head.h>
#include <linux/slab.h>

#include "dir.h"
#include "../aops.h"
#include "../mft.h"
#include "../debug.h"
#include "../ntfs.h"
#include "../compat.h"

/**
 * ntfs_loop_filldir - ntfs specific filldir method
 * designed for the looper ntfs_index_walk_entry_in_header
 * @dir:	ntfs inode(or vfs inode) of current directory
 * @ie:		current index entry
 * @actor:	what to feed the entries to
 *
 * Convert the Unicode @name to the loaded NLS and pass it to the @filldir
 * callback.
 *
 * If @ia_page is not NULL it is the locked page containing the index
 * allocation block containing the index entry @ie.
 *
 */
static int ntfs_loop_filldir(void *_dir, INDEX_ENTRY *ie, void *_actor)
{
	struct inode *vdir = _dir;
	struct super_block *sb = vdir->i_sb;
	ntfs_volume *vol = NTFS_SB(sb);
	u8 *name = NULL;
	struct dir_context *actor = _actor;
	unsigned long mref;
	int name_len;
	unsigned dt_type;
	FILE_NAME_TYPE_FLAGS name_type;
	int rc;

	/*
	 * Allocate a buffer to store the current name being processed
	 * converted to format determined by current NLS.
	 */
	name = kmalloc(NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1, GFP_NOFS);
	if (unlikely(!name)) {
		ntfs_debug("No enough Memory for $name.");
		return -ENOMEM;
	}

	name_type = ie->key.file_name.file_name_type;
	if (name_type == FILE_NAME_DOS) {
		ntfs_debug("Skipping DOS name space entry.");
		rc =  0;
		goto out;
	}
	if (MREF_LE(ie->data.dir.indexed_file) == FILE_ROOT) {
		ntfs_debug("Skipping root directory self reference entry.");
		rc =  0;
		goto out;
	}
	if (MREF_LE(ie->data.dir.indexed_file) < FILE_first_user &&
			!NVolShowSystemFiles(vol)) {
		ntfs_debug("Skipping system file.");
		rc =  0;
		goto out;
	}
	name_len = ntfs_ucstonls(vol, (ntfschar*)&ie->key.file_name.file_name,
			ie->key.file_name.file_name_length, &name,
			NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1);
	if (name_len <= 0) {
		ntfs_warning(vol->sb, "Skipping unrepresentable inode 0x%llx.",
				(long long)MREF_LE(ie->data.dir.indexed_file));
		rc =  0;
		goto out;
	}
	if (ie->key.file_name.file_attributes &
			FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT)
		dt_type = DT_DIR;
	else
		dt_type = DT_REG;
	mref = MREF_LE(ie->data.dir.indexed_file);
	ntfs_debug("Calling filldir for %s with len %i, fpos 0x%llx, inode "
			"0x%lx, DT_%s.", name, name_len, actor->pos, mref,
			dt_type == DT_DIR ? "DIR" : "REG");
	if (!dir_emit(actor, name, name_len, mref, dt_type))
	{
		rc = 1;
		goto out;
	}
	rc = 0 ;
out:
	kfree(name);
	return rc;
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
extern int index_root_iterate(struct inode *vdir,
						loff_t *p_skip_pos,
						ie_looper func,
						void *parameter);

int ntfs_dir_iterate(struct file *file, struct dir_context *actor)
{
	s64 ia_pos, ia_start, prev_ia_pos;
	loff_t ih_offset;
	struct inode *vdir = file_inode(file);
	struct super_block *sb = vdir->i_sb;
	ntfs_inode *ndir = NTFS_I(vdir);
	ntfs_volume *vol = NTFS_SB(sb);
	INDEX_ALLOCATION *ia;
	int rc, err;
	struct address_space *ia_mapping;
	struct page *ia_page = NULL;
	u8 *kaddr, *index_end;

	ntfs_debug("Entering Phase: For inode 0x%lx, fpos 0x%llx.",
			vdir->i_ino, actor->pos);
	rc = err = 0;

	/* Are we at end of dir yet? */
	if (is_exceed_dir_end(actor->pos, vdir))
		return 0;

	/* Emulate . and .. for all directories. */
	if (!dir_emit_dots(file, actor))
		return 0;

	/* Are we jumping straight into the index allocation attribute? */
	if (!is_exceed_root(actor->pos, vol)) {
		rc = index_root_iterate(vdir,
			&(actor->pos),
			ntfs_loop_filldir, actor);
		if (1 ==  rc)
			goto abort;
		else if (rc) {
			err =  rc;
			goto err_out;
		} else /* rc == 0 */ {
			/* We are done with the index root
			and can free the buffer. */
			/* If there is no index allocation attribute
			we are finished. */
			if (!NInoIndexAllocPresent(ndir))
				goto EOD;
			/* Advance fpos to the beginning
			of the index allocation. */
			mark_actor_exceed_root(actor, vol);
		}
	}

	ntfs_debug("Index Allocation Phase: Starting");

	kaddr = NULL;
	prev_ia_pos = -1LL;
	/* Get the offset into the index allocation attribute. */
	ia_pos = (s64) DIR_POS_TO_INDEX_ALLOCATION_POS(actor->pos, vol);

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
	if ((prev_ia_pos & (s64)PAGE_MASK) !=
			(ia_pos & (s64)PAGE_MASK)) 
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
		ia_page = ntfs_map_page(ia_mapping, ia_pos >> PAGE_SHIFT);
		if (IS_ERR(ia_page)) 
		{
			ntfs_error(sb, "Reading index allocation data failed.");
			err = PTR_ERR(ia_page);
			ia_page = NULL;
			goto err_out;
		}
		lock_page(ia_page);
		kaddr = (u8*)page_address(ia_page);
	}

	/* Get the current index buffer. */
	rc = ntfs_transfer_ia_pos_to_address(vdir, kaddr, ia_pos,
			&ia, &ia_start, &index_end);
	if (rc)
	{
		err = rc;
		goto err_out;
	}
	/* Get the offset into the index root attribute. */
	ntfs_debug("Starting Handling Index Allocation block %lld",
			pos_byte_to_block(ia_pos,ndir));
	unlock_page(ia_page);
	ih_offset = ia_pos - ia_start;
	rc = ntfs_index_walk_entry_in_header(vdir,&(ia->index),
			&ih_offset,ntfs_loop_filldir,actor);
	if ( 1 ==  rc )
	{
		/** ntfs_loop_filldir return 1 **/
		ia_pos = ia_start + ih_offset;
		actor->pos = ia_pos + vol->mft_record_size;
		ntfs_unmap_page(ia_page);
		goto abort;
	}
	else if ( rc )
	{
		err =  rc;
		goto err_out;
	}
	else 
	{
		/* mark actor->pos to exceed this block */
		ia_pos = ia_start + ndir->itype.index.block_size;
		actor->pos = ia_pos + vol->mft_record_size;
		lock_page(ia_page);
		goto find_next_index_buffer;
	}
unm_EOD:
	ntfs_debug("Ending Phase: releasing memory");
	if (ia_page) {
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
EOD:
	/* We are finished, set fpos to EOD. */
	actor->pos = i_size_read(vdir) + vol->mft_record_size;
abort:
	return 0;
err_out:
	if (ia_page) 
	{
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
	if (!err)
		err = -EIO;
	ntfs_debug("Failed. Returning error code %i.", -err);
	return err;
}
