/*
 * index.c - NTFS kernel index handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
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

#include <linux/slab.h>

#include "aops.h"
#include "collate.h"
#include "debug.h"
#include "index.h"
#include "ntfs.h"

/**
 ** The little endian Unicode string $I30 as a global constant.
 **/
ntfschar I30[5] = { cpu_to_le16('$'), cpu_to_le16('I'),
	cpu_to_le16('3'),       cpu_to_le16('0'), 0 };

static int ntfs_ir_make_space(ntfs_index_context *icx, int data_size);

void what_handling(const ntfs_inode* ni)
{
#ifdef DEBUG
	char* static_known_name = "Not specified";
	char* static_known_Attribute = "Not specified";
	switch(ni->mft_no)
	{
		case 0:
			static_known_name = "$MFT";
			break;
		case 1:
			static_known_name = "$MFTMirr";
			break;
		case 2:	
			static_known_name = "$LogFile";
			break;
		case 3:
			static_known_name = "$Volume";
			break;
		case 4:
			static_known_name = "$AttrDef";
			break;
		case 5:
			static_known_name = ". (dot)";
			break;
		default:
			if (ni->mft_no > 24 )
				static_known_name = "Ordinary File/Directory";
			break;
	}
	switch(le32_to_cpu(ni->type))
	{
		case 0x10:
			static_known_Attribute = "$STANDARD_INFORMATION";
			break;
		case 0x20:
			static_known_Attribute = "$ATTRIBUTE_LIST";
			break;
		case 0xA0:
			static_known_Attribute = "$INDEX_ALLOCATION";
			break;
		default:
			static_known_Attribute = "Unknown?";
			break;

	}
	printk("NTFS mft_no:[0x%lx][%s], Attribute Type:[0x%x][%s]\n",
			ni->mft_no,
			static_known_name,
			le32_to_cpu(ni->type),
			static_known_Attribute);
#endif
}

/**
 * ntfs_index_ctx_get - allocate and initialize a new index context
 * @idx_ni:	ntfs index inode with which to initialize the context
 *
 * Allocate a new index context, initialize it with @idx_ni and return it.
 * Return NULL if allocation failed.
 *
 * Locking:  Caller must hold i_mutex on the index inode.
 */
ntfs_index_context *ntfs_index_ctx_get(ntfs_inode *idx_ni)
{
	ntfs_index_context *ictx;

	ictx = kmem_cache_alloc(ntfs_index_ctx_cache, GFP_NOFS);
	if (ictx)
		*ictx = (ntfs_index_context){ .idx_ni = idx_ni };
	return ictx;
}

/**
 * ntfs_index_ctx_put - release an index context
 * @ictx:	index context to free
 *
 * Release the index context @ictx, releasing all associated resources.
 *
 * Locking:  Caller must hold i_mutex on the index inode.
 */
void ntfs_index_ctx_put(ntfs_index_context *ictx)
{
	if (ictx->entry) {
		if (ictx->is_in_root) {
			if (ictx->actx)
				ntfs_attr_put_search_ctx(ictx->actx);
			/*TODO: banish the base_ni pointer */
			if (ictx->base_ni && ictx->base_ni->page)
				unmap_mft_record(ictx->base_ni);
		} else {
			struct page *page = ictx->page;
			if (page) {
				BUG_ON(!PageLocked(page));
				unlock_page(page);
				ntfs_unmap_page(page);
			}
		}
	}
	if(ictx->imperfect_match_name)
	{
		kfree(ictx->imperfect_match_name);
		ictx->imperfect_match_name=NULL;
	}
	kmem_cache_free(ntfs_index_ctx_cache, ictx);
	return;
}


void* attribute_get_value_address(ATTR_RECORD* attr)
{
	return ((u8*)attr) + attr->data.resident.value_offset;
}
u64 index_entry_mref(INDEX_ENTRY* ie)
{
	return le64_to_cpu(ie->data.dir.indexed_file);
}

/*INDEX_ENTRY* ie*/
#define index_entry_file_name(ie) ((ie)->key.file_name)
#define ie_file_name(ie) (index_entry_file_name(ie).file_name)
#define ie_file_name_length(ie) (index_entry_file_name(ie).file_name_length)
#define ie_file_name_type(ie) (index_entry_file_name(ie).file_name_type)

int ntfs_lookup_inode_by_name_in_index_head(       ntfs_volume *vol,ntfs_attr_search_ctx *temp_search_ctx,
		INDEX_HEADER *ih, const ntfschar *uname,
		const int uname_len, ntfs_name **res, 
		/* output */
		INDEX_ENTRY** pie,u64* pmref)
{
	int rc;
	u8 *index_end;
	struct super_block *sb = vol->sb;
	ntfs_name *name = NULL;

	/* The end byte of this index header */
	index_end = (u8*) ntfs_ie_get_end(ih);
	/* The first index entry. */
	(*pie) = ntfs_ie_get_first(ih);

	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; (*pie) = ntfs_ie_get_next(*pie)) 
	{
		ntfs_dump_index_entry(*pie);
		/* Bounds checks. */
		if ((u8*)(*pie) < (u8*)temp_search_ctx->mrec || (u8*)(*pie) +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)(*pie) + le16_to_cpu((*pie)->key_length) >
				index_end)
			return -EIO;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if ( (*pie)->flags & INDEX_ENTRY_END )
		{
			/* return 0 with zero mref */
			break;
		}

		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
					(ntfschar*)&(*pie)->key.file_name.file_name,
					(*pie)->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) 
		{
found_it:
			/*
			 * We have a perfect match, so we don't need to care
			 * about having matched imperfectly before, so we can
			 * free name and set *res to NULL.
			 * However, if the perfect match is a short file name,
			 * we need to signal this through *res, so that
			 * ntfs_lookup() can fix dcache aliasing issues.
			 * As an optimization we just reuse an existing
			 * allocation of *res.
			 */
			if (index_entry_file_name(*pie).file_name_type == FILE_NAME_DOS) {
				if (!name) {
					name = kmalloc(sizeof(ntfs_name),
							GFP_NOFS);
					if (!name) {
						return -ENOMEM;
					}
				}
				name->mref = index_entry_mref(*pie);
				name->type = FILE_NAME_DOS;
				name->len = 0;
				*res = name;
			} else {
				kfree(name);
				*res = NULL;
			}
			/* return 0 with mref */
			(*pmref) = index_entry_mref(*pie);
			return 0;
		}
		/*
		 * For a case insensitive mount, we also perform a case
		 * insensitive comparison (provided the file name is not in the
		 * POSIX namespace). If the comparison matches, and the name is
		 * in the WIN32 namespace, we cache the filename in *res so
		 * that the caller, ntfs_lookup(), can work on it. If the
		 * comparison matches, and the name is in the DOS namespace, we
		 * only cache the mft reference and the file name type (we set
		 * the name length to zero for simplicity).
		 */
		if (!NVolCaseSensitive(vol) &&
				(*pie)->key.file_name.file_name_type &&
				ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&(*pie)->key.file_name.file_name,
				(*pie)->key.file_name.file_name_length,
				IGNORE_CASE, vol->upcase, vol->upcase_len)) {
			int name_size = sizeof(ntfs_name);
			u8 type = index_entry_file_name(*pie).file_name_type;
			u8 len = index_entry_file_name(*pie).file_name_length;

			/* Only one case insensitive matching name allowed. */
			if (name) {
				ntfs_error(sb, "Found already allocated name "
						"in phase 1. Please run chkdsk "
						"and if that doesn't find any "
						"errors please report you saw "
						"this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net.");
				return -EIO;
			}

			if (type != FILE_NAME_DOS)
				name_size += len * sizeof(ntfschar);
			name = kmalloc(name_size, GFP_NOFS);
			if (!name) {
				return -ENOMEM;
			}
			name->mref = le64_to_cpu((*pie)->data.dir.indexed_file);
			name->type = type;
			if (type != FILE_NAME_DOS) {
				name->len = len;
				memcpy(name->name, index_entry_file_name(*pie).file_name,
						len * sizeof(ntfschar));
			} else
				name->len = 0;
			*res = name;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&(index_entry_file_name(*pie).file_name),
				index_entry_file_name(*pie).file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&(index_entry_file_name(*pie).file_name),
				index_entry_file_name(*pie).file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it;
	}
	return 0;
}
int ntfs_lookup_inode_by_name_in_index_allocation(       ntfs_volume *vol,
		INDEX_ALLOCATION* ia, u8* index_end,
		INDEX_HEADER *ih, const ntfschar *uname,
		const int uname_len, ntfs_name **res, 
		/* output */
		INDEX_ENTRY** pie,u64* pmref)
{
	int rc;
	ntfs_name *name = NULL;
	struct super_block *sb = vol->sb;
/* The first index entry. */
	(*pie) = ntfs_ie_get_first(ih);
	*pmref=0;

	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; (*pie) = ntfs_ie_get_next(*pie)) {
		/* Bounds check. */
		if ((u8*)(*pie) < (u8*)ia || (u8*)(*pie) +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)(*pie) + le16_to_cpu((*pie)->key_length) >
				index_end) {
			/*
			ntfs_error(sb, "Index entry out of bounds in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
					*/
			return  -ENOMEM;
		}
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if ((*pie)->flags & INDEX_ENTRY_END)
			break;
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&(*pie)->key.file_name.file_name,
				(*pie)->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) {
found_it2:
			/*
			 * We have a perfect match, so we don't need to care
			 * about having matched imperfectly before, so we can
			 * free name and set *res to NULL.
			 * However, if the perfect match is a short file name,
			 * we need to signal this through *res, so that
			 * ntfs_lookup() can fix dcache aliasing issues.
			 * As an optimization we just reuse an existing
			 * allocation of *res.
			 */
			if ((*pie)->key.file_name.file_name_type == FILE_NAME_DOS) {
				if (!name) {
					name = kmalloc(sizeof(ntfs_name),
							GFP_NOFS);
					if (!name) {
						return  -ENOMEM;
					}
				}
				name->mref = le64_to_cpu(
						(*pie)->data.dir.indexed_file);
				name->type = FILE_NAME_DOS;
				name->len = 0;
				*res = name;
			} else {
				kfree(name);
				*res = NULL;
			}
			(*pmref) = le64_to_cpu((*pie)->data.dir.indexed_file);
			return 0;
		}
		/*
		 * For a case insensitive mount, we also perform a case
		 * insensitive comparison (provided the file name is not in the
		 * POSIX namespace). If the comparison matches, and the name is
		 * in the WIN32 namespace, we cache the filename in *res so
		 * that the caller, ntfs_lookup(), can work on it. If the
		 * comparison matches, and the name is in the DOS namespace, we
		 * only cache the mft reference and the file name type (we set
		 * the name length to zero for simplicity).
		 */
		if (!NVolCaseSensitive(vol) &&
				(*pie)->key.file_name.file_name_type &&
				ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&(*pie)->key.file_name.file_name,
				(*pie)->key.file_name.file_name_length,
				IGNORE_CASE, vol->upcase, vol->upcase_len)) {
			int name_size = sizeof(ntfs_name);
			u8 type = (*pie)->key.file_name.file_name_type;
			u8 len = (*pie)->key.file_name.file_name_length;

			/* Only one case insensitive matching name allowed. */
			if (name) {
				ntfs_error(sb, "Found already allocated name "
						"in phase 2. Please run chkdsk "
						"and if that doesn't find any "
						"errors please report you saw "
						"this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net.");
				return -EIO;
			}

			if (type != FILE_NAME_DOS)
				name_size += len * sizeof(ntfschar);
			name = kmalloc(name_size, GFP_NOFS);
			if (!name) {
				return  -ENOMEM;
			}
			name->mref = le64_to_cpu((*pie)->data.dir.indexed_file);
			name->type = type;
			if (type != FILE_NAME_DOS) {
				name->len = len;
				memcpy(name->name, (*pie)->key.file_name.file_name,
						len * sizeof(ntfschar));
			} else
				name->len = 0;
			*res = name;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&(*pie)->key.file_name.file_name,
				(*pie)->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&(*pie)->key.file_name.file_name,
				(*pie)->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it2;
	}
	return 0;
}

MFT_REF _ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
		const int uname_len, ntfs_name **res)
{
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	u64 mref;
	ntfs_attr_search_ctx *temp_search_ctx;
	int err, rc;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;
	ntfs_name *name = NULL;

	BUG_ON(!S_ISDIR(VFS_I(dir_ni)->i_mode));
	BUG_ON(NInoAttr(dir_ni));
	/************************************************************/
	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return ERR_MREF(PTR_ERR(m));
	}
	temp_search_ctx = ntfs_attr_get_search_ctx(dir_ni, m);
	if (unlikely(!temp_search_ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_search_attr_index_root(temp_search_ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	/* Get to the index root value (it's been verified in read_inode). */
	ir = (INDEX_ROOT*) attribute_get_value_address(temp_search_ctx->attr);

	mref=0;
	rc = ntfs_lookup_inode_by_name_in_index_head(vol,temp_search_ctx,&(ir->index), 
			uname, uname_len, res,&ie , &mref);
	if(rc)
	{
		err = rc ;
		goto dir_err_out;
	}
	else if (mref)
	{
		ntfs_attr_put_search_ctx(temp_search_ctx);
		unmap_mft_record(dir_ni);
		return mref;
	}
	else
	{
		/* loop to end but no mref found 
		 * keep searching
		 * **/
	}
	/************************************************************/
	/*
	 * We have finished with this index without success. Check for the
	 * presence of a child node and if not present return -ENOENT, unless
	 * we have got a matching name cached in name in which case return the
	 * mft reference associated with it.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		if (name) {
			ntfs_attr_put_search_ctx(temp_search_ctx);
			unmap_mft_record(dir_ni);
			return name->mref;
		}
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto err_out;
	} /* Child node present, descend into it. */
	/* Consistency check: Verify that an index allocation exists. */
	if (!NInoIndexAllocPresent(dir_ni)) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one. Directory inode 0x%lx is "
				"corrupt or driver bug.", dir_ni->mft_no);
		goto err_out;
	}
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = ntfs_ie_get_vcn(ie);
	ia_mapping = VFS_I(dir_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record. Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(temp_search_ctx);
	unmap_mft_record(dir_ni);
	m = NULL;
	temp_search_ctx = NULL;
descend_into_child_node:
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	page = ntfs_map_page(ia_mapping, vcn <<
			dir_ni->itype.index.vcn_size_bits >> PAGE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map directory index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + 
			offset_in_page(vcn << dir_ni->itype.index.vcn_size_bits) );
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug.", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)vcn, dir_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				dir_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + dir_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				dir_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	/***************************************/
	rc =  ntfs_lookup_inode_by_name_in_index_allocation(vol,
		ia,index_end,
		&ia->index, uname,
		uname_len, res, 
		/* output */
		&ie,&mref);
	if(rc == -EIO)
	{
		unlock_page(page);
		ntfs_unmap_page(page);
		err = rc ;
		goto dir_err_out;
	}
	if(rc == -ENOMEM)
	{
		err = rc ;
		goto unm_err_out;
	}
	else if (mref)
	{
		unlock_page(page);
		ntfs_unmap_page(page);
		return mref;
	}
	else
	{
		/* loop to end but no mref found 
		 *                  * keep searching
		 *                                   * **/
	}

	/***************************************/
	/*
	 * We have finished with this index buffer without success. Check for
	 * the presence of a child node.
	 */
	if (ie->flags & INDEX_ENTRY_NODE) {
		if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
			ntfs_error(sb, "Index entry with child node found in "
					"a leaf node in directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/* Child node present, descend into it. */
		old_vcn = vcn;
		vcn = sle64_to_cpup((sle64*)((u8*)ie +
				le16_to_cpu(ie->length) - 8));
		if (vcn >= 0) {
			/* If vcn is in the same page cache page as old_vcn we
			 * recycle the mapped page. */
			if (old_vcn << vol->cluster_size_bits >>
					PAGE_SHIFT == vcn <<
					vol->cluster_size_bits >>
					PAGE_SHIFT)
				goto fast_descend_into_child_node;
			unlock_page(page);
			ntfs_unmap_page(page);
			goto descend_into_child_node;
		}
		ntfs_error(sb, "Negative child node vcn in directory inode "
				"0x%lx.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/*
	 * No child node present, return -ENOENT, unless we have got a matching
	 * name cached in name in which case return the mft reference
	 * associated with it.
	 */
	if (name) {
		unlock_page(page);
		ntfs_unmap_page(page);
		return name->mref;
	}
	ntfs_debug("Entry not found.");
	err = -ENOENT;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (temp_search_ctx)
		ntfs_attr_put_search_ctx(temp_search_ctx);
	if (m)
		unmap_mft_record(dir_ni);
	if (name) {
		kfree(name);
		*res = NULL;
	}
	return ERR_MREF(err);
dir_err_out:
	ntfs_error(sb, "Corrupt directory.  Aborting lookup.");
	goto err_out;
}
typedef int (*ie_comparer) (const ntfschar *,const int ,INDEX_ENTRY *, void *);

/* Walk through the Index Root and try to locate the Index Entry ,
 * return 0 means perfectly match */
int ie_bounds_checks(INDEX_ENTRY*ie, u8* start, u8* end)
{
	/* Bounds checks. */
	/* Is data corrupted ? */
	if ((u8*)ie < start || 
	(u8*)ie + sizeof(INDEX_ENTRY_HEADER) > end ||
	(u8*)ie + le16_to_cpu(ie->key_length) > end)
	{
		return -EIO;
	}
	else
	{
		return 0;
	}
}
int _ntfs_ir_lookup_by_name_with_call_back(
		const ntfschar* uname,
		const int uname_len,
		ie_comparer func, ntfs_index_context *ictx )
{
	u8 *index_end;
	INDEX_ROOT* ir;
	INDEX_ENTRY* ie;
	ntfs_attr_search_ctx* temp_search_ctx = ictx->actx;
	int rc;

	/* Get to the index root value (it's been verified in read_inode). */
	ir = (INDEX_ROOT*)get_current_attribute(temp_search_ctx);
	/* The first index entry. */
	ie = ntfs_index_root_get_first_entry(ir);
	index_end = ntfs_index_root_get_end_position(ir);

	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */

	ictx->ir = ir;
	for (;; ie = ntfs_ie_get_next(ie)) 
	{
		ntfs_dump_index_entry(ie);
		ictx->entry = ie;

		/* Bounds checks. */
		/* Is data corrupted ? */
		if(ie_bounds_checks(ie,(u8*)temp_search_ctx->mrec,index_end) )
		{
			ntfs_debug("Bounce check error, Corrupt directory.  Aborting lookup.");
			return -EIO;
		}
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if ( ntfs_ie_end(ie))
		{
			ntfs_debug("Walk till end but not found.");
			return SHOULD_CHECK_SUBNODE;
		}

		/* actually call 
		 * comparer_with_imperfect_name  for lookup
		 * or
		 * comparer_with_perfect_name for insert
		 */
		rc = func(uname,uname_len,ie,ictx);
		if( PERFECT_MATCH == rc )
		{
			ntfs_debug("Done.");
			return PERFECT_MATCH;
		}
		else if (SHOULD_CHECK_SUBNODE == rc )
		{
			return SHOULD_CHECK_SUBNODE;
		}
		else if (SHOULD_CONTINUE == rc )
		{
			continue ;
		}
		else
		{
			return rc;
		}
	}
}
int _ntfs_index_lookup_ia_with_call_back (const ntfschar* uname,const int uname_len,
		ie_comparer func,ntfs_index_context *ictx)
{
	int rc;
	INDEX_ALLOCATION *ia = ictx->ia ;
	INDEX_ENTRY *ie = ntfs_ie_get_first(&ia->index);
	u8* index_end = (u8*) ntfs_ie_get_end(&ia->index);

	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = ntfs_ie_get_next(ie)) 
	{
		ntfs_dump_index_entry(ie);
		/* Bounds check. */
		if(ie_bounds_checks(ie,(u8*)ia,index_end) )
		{
			ntfs_debug("Bounce check error, Corrupt directory.  Aborting lookup.");
			return -EIO;
		}
		ictx->entry = ie;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ntfs_ie_end(ie))
		{
			ntfs_debug("Walk till end but not found.");
		       	return SHOULD_CHECK_SUBNODE;
		}
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		BUG_ON(!PageLocked(ictx->page));
		/* actually call 
		 * comparer_with_imperfect_name  for lookup
		 * or
		 * comparer_with_perfect_name for insert
		 */
		rc = func(uname,uname_len,ie,ictx);
		if( PERFECT_MATCH == rc )
		{
			ntfs_debug("Done.");
			return PERFECT_MATCH;
		}
		else if (SHOULD_CHECK_SUBNODE == rc )
		{
			return SHOULD_CHECK_SUBNODE;
		}
		else if (SHOULD_CONTINUE == rc )
		{
			continue ;
		}
		else
		{
			return rc;
		}
	}
}
int _ntfs_index_lookup_ir_with_call_back (const ntfschar* uname,const int uname_len,
		ie_comparer func,ntfs_index_context *ictx)
{
	ntfs_attr_search_ctx *temp_search_ctx;
	ntfs_volume *vol = ictx->idx_ni->vol;
	struct super_block *sb = vol->sb;
	int err;

	/* Get hold of the mft record for the directory. */
	if(!ictx->m)
	{
		ictx->m = map_mft_record(ictx->idx_ni);
		if (IS_ERR(ictx->m)) 
		{
			ntfs_error(sb, "map_mft_record() failed with error code %ld.",
					-PTR_ERR(ictx->m));
			return ERR_MREF(PTR_ERR(ictx->m));
		}
	}
	/* Allocate and initilize the temp search context **/
	temp_search_ctx = ntfs_attr_get_search_ctx(ictx->idx_ni, ictx->m);
	if (unlikely(!temp_search_ctx)) 
	{
		return  -ENOMEM;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_search_attr_index_root(temp_search_ctx);
	if (unlikely(err)) 
	{
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					ictx->idx_ni->mft_no);
			err = -EIO;
		}
		ntfs_attr_put_search_ctx(temp_search_ctx);
		temp_search_ctx = NULL;
		return err;
	}
	ntfs_debug("Entering Phase 1.");

	/* Walk through the Index Root and try to locate the Index Entry ,
	 * return 0 means perfectly match */
	ictx->is_in_root = true;
	ictx->actx = temp_search_ctx;
	ictx->ia = NULL;
	ictx->page = NULL;
	ictx->base_ni = ictx->idx_ni;
	return _ntfs_ir_lookup_by_name_with_call_back(uname,uname_len,
			func,ictx);

}
int _ntfs_index_lookup_with_call_back (const ntfschar* uname,const int uname_len,
		ie_comparer func,void* parameter)

{
	ntfs_index_context *ictx=parameter;
	
	ntfs_volume *vol = ictx->idx_ni->vol;
	struct super_block *sb = vol->sb;

	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	int err;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;

	BUG_ON(!S_ISDIR(VFS_I(ictx->idx_ni)->i_mode));
	BUG_ON(NInoAttr(ictx->idx_ni));

	/** Phase 1: index root **/
	old_vcn = VCN_INDEX_ROOT_PARENT;
	err = _ntfs_index_lookup_ir_with_call_back (uname,uname_len,
		       	func,ictx);
	if(PERFECT_MATCH == err)
	{
		ictx->parent_vcn[ictx->pindex] = old_vcn;
		ntfs_debug("Locate the file in Index Root");
		return err;
	}
	else if ( SHOULD_CHECK_SUBNODE != err  )
	{
		ntfs_debug("_ntfs_ir_lookup_by_name error");
		goto err_out;
	}
	else if (!(ictx->entry->flags & INDEX_ENTRY_NODE)) 
	{
		/*
		 * We have finished with this index without success. Check for the
		 * presence of a child node and if not present return -ENOENT, unless
		 * we have got a matching name cached in name in which case return the
		 * mft reference associated with it.
		 */
		ntfs_debug("Entry not found in INDEX_ROOT and there is no subnode");
		/* should keep the mapped mft as result */
		return -ENOENT;
	}
	else
	{
		/* Consistency check: Verify that an index allocation exists. */
		if (!NInoIndexAllocPresent(ictx->idx_ni)) {
			ntfs_error(sb, "No index allocation attribute but index entry "
					"requires one. Directory inode 0x%lx is "
					"corrupt or driver bug.", ictx->idx_ni->mft_no);
			ictx->entry = NULL;
			ntfs_attr_put_search_ctx(ictx->actx);
			ictx->actx = NULL;
			ictx->m = NULL;
			unmap_mft_record(ictx->idx_ni);
			goto err_out;
		}
		/* Child node present, descend into it. */
		/* continue to check the subnode */

		/* Get the starting vcn of the index_block holding the child node. */
		vcn = ntfs_ie_get_subnode_pos(ictx->entry);

		/*
		 * We are done with the index root and the mft record. Release them,
		 * otherwise we deadlock with ntfs_map_page().
		 */
		ictx->entry = NULL;
		ntfs_attr_put_search_ctx(ictx->actx);
		ictx->actx = NULL;
		ictx->m = NULL;
		unmap_mft_record(ictx->idx_ni);
	}

	ntfs_debug("Entering Phase 2.");
	/* Phase 2:
	 * searching in Index_Allocation , accroding to the VCN */
	/* The mapping of the directory is only for the INDEX_ALLOCATION */
	ia_mapping = VFS_I(ictx->idx_ni)->i_mapping;
descend_into_child_node:
	ictx->parent_vcn[ictx->pindex] = old_vcn;
	if (ntfs_icx_parent_inc(ictx)) {
		goto err_out;
	}
	old_vcn = vcn;
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	ntfs_debug("Mapping page for VCN 0x%llx",vcn);
	page = ntfs_map_page(ia_mapping, ntfs_vcn_to_pos(vcn,ictx->idx_ni) >> PAGE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map directory index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + offset_in_page(ntfs_vcn_to_pos(vcn,ictx->idx_ni)));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)vcn, ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug.", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			ictx->idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)vcn, ictx->idx_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				ictx->idx_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + ictx->idx_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + ictx->idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)vcn, ictx->idx_ni->mft_no);
		goto unm_err_out;
	}

	ictx->is_in_root = false;
	ictx->ia = ia;
	ictx->actx = NULL;
	ictx->base_ni = NULL;
	ictx->page = page;
	err = _ntfs_index_lookup_ia_with_call_back (uname,uname_len,
		       	func,ictx);
	if (-EIO == err)
	{
		ntfs_error(sb, "Index entry out of bounds in "
				"directory inode 0x%lx.",
				ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	else if ( SHOULD_CHECK_SUBNODE == err )
	{
		/* go on and handle ie */
		ie = ictx->entry;
	}
	else if ( PERFECT_MATCH == err )
	{
		ictx->parent_vcn[ictx->pindex] = vcn;
		return PERFECT_MATCH;
	}
	else
	{
		goto unm_err_out;
	}
	/*
	 * We have finished with this index buffer without success. Check for
	 * the presence of a child node.
	 */
	if (ie->flags & INDEX_ENTRY_NODE) {
		if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
			ntfs_error(sb, "Index entry with child node found in "
					"a leaf node in directory inode 0x%lx.",
					ictx->idx_ni->mft_no);
			goto unm_err_out;
		}
		/* Child node present, descend into it. */
		old_vcn = vcn;
		vcn = sle64_to_cpup((sle64*)((u8*)ie +
				le16_to_cpu(ie->length) - 8));
		if (vcn >= 0) {
			/* If vcn is in the same page cache page as old_vcn we
			 * recycle the mapped page. */
			if (old_vcn << vol->cluster_size_bits >>
					PAGE_SHIFT == vcn <<
					vol->cluster_size_bits >>
					PAGE_SHIFT)
				goto fast_descend_into_child_node;
			unlock_page(page);
			ntfs_unmap_page(page);
			goto descend_into_child_node;
		}
		ntfs_error(sb, "Negative child node vcn in directory inode "
				"0x%lx.", ictx->idx_ni->mft_no);
		goto unm_err_out;
	}
	/*
	 * No child node present, return -ENOENT, unless we have got a matching
	 * name cached in name in which case return the mft reference
	 * associated with it.
	 */
	ntfs_debug("Entry not found.");
	err = -ENOENT;
	/* keep the page mapped and locked **/
	return err;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	ntfs_debug("done.");
	return err;
}
MFT_REF ie_mref(INDEX_ENTRY* ie)
{
	return le64_to_cpu(ie->data.dir.indexed_file);
}
int comparer_with_perfect_name(const ntfschar *uname,const int uname_len,
		INDEX_ENTRY *ie, void *parameter)
{
	ntfs_index_context *ictx=parameter;
	ntfs_inode *idx_ni=ictx->idx_ni;
	ntfs_volume *vol = idx_ni->vol;
	int rc = 0;

	/*
	 * We perform a case sensitive comparison and if that matches
	 * we are done and return the mft reference of the inode (i.e.
	 * the inode number together with the sequence number for
	 * consistency checking). We convert it to cpu format before
	 * returning.
	 */

	if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie_file_name(ie),
				ie_file_name_length(ie),
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) 
	{
		set_index_context_with_result(ictx,ie);
		ntfs_debug("Done.");
		return PERFECT_MATCH;

	}
	/*
	 * Not a perfect match, need to do full blown collation so we
	 * know which way in the B+tree we have to go.
	 */
	rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie_file_name(ie),
				ie_file_name_length(ie),
			       	1, IGNORE_CASE, vol->upcase, vol->upcase_len);
	/*
	 * If uname collates before the name of the current entry, there
	 * is definitely no such name in this index but we might need to
	 * descend into the B+tree so we just break out of the loop.
	 */
	if (rc == -1)
	{
		ntfs_debug("IGNORE_CASE compare not found before possible position, just record the INDEX_ENTRY and return");
		return SHOULD_CHECK_SUBNODE;
	}
	/* The names are not equal, continue the search. */
	if (rc)
	{
		return SHOULD_CONTINUE;
	}

	/*
	 * 0 == rc  get here
	 * Names match with case insensitive comparison, now try the
	 * case sensitive comparison, which is required for proper
	 * collation.
	 */
	rc = ntfs_collate_names(uname, uname_len,
			(ntfschar*)&ie_file_name(ie),
			ie_file_name_length(ie),
			1, CASE_SENSITIVE, vol->upcase, vol->upcase_len);
	if (rc == -1)
	{
		ntfs_debug("not found before possible position, just record the INDEX_ENTRY and return");
		return SHOULD_CHECK_SUBNODE;
	}
	if (rc)
	{
		return SHOULD_CONTINUE;
	}
	/*
	 * Perfect match, this will never happen as the
	 * ntfs_are_names_equal() call will have gotten a match but we
	 * still treat it correctly.
	 */
	return PERFECT_MATCH;
}
int comparer_with_imperfect_name(const ntfschar *uname,const int uname_len,
		INDEX_ENTRY *ie, void *parameter)
{
	ntfs_index_context *ictx=parameter;
	ntfs_inode *idx_ni=ictx->idx_ni;
	ntfs_volume *vol = idx_ni->vol;
	struct super_block *sb = vol->sb;
	int rc = 0;


	/*
	 * We perform a case sensitive comparison and if that matches
	 * we are done and return the mft reference of the inode (i.e.
	 * the inode number together with the sequence number for
	 * consistency checking). We convert it to cpu format before
	 * returning.
	 */

	if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie_file_name(ie),
				ie_file_name_length(ie),
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) 
	{
		if (ie_file_name_type(ie) == FILE_NAME_DOS) {
			if (!ictx->imperfect_match_name) 
			{
				ictx->imperfect_match_name = kmalloc(sizeof(ntfs_name),
						GFP_NOFS);
				if (!ictx->imperfect_match_name) 
				{
					return -ENOMEM;
				}
			}
			ictx->imperfect_match_name->mref = index_entry_mref(ie);
			ictx->imperfect_match_name->type = FILE_NAME_DOS;
			ictx->imperfect_match_name->len = 0;
		} else {
			kfree(ictx->imperfect_match_name);
			ictx->imperfect_match_name = NULL;
		}
		ntfs_debug("Done.");
		return PERFECT_MATCH;
	}

	/*
	 * For a case insensitive mount, we also perform a case
	 * insensitive comparison (provided the file name is not in the
	 * POSIX namespace). If the comparison matches, and the name is
	 * in the WIN32 namespace, we cache the filename in *res so
	 * that the caller, ntfs_lookup(), can work on it. If the
	 * comparison matches, and the name is in the DOS namespace, we
	 * only cache the mft reference and the file name type (we set
	 * the name length to zero for simplicity).
	 */
	if (!NVolCaseSensitive(vol) &&
		ie_file_name_type(ie) &&
		ntfs_are_names_equal(uname, uname_len,
			(ntfschar*)&ie_file_name(ie),
			ie_file_name_length(ie),
			IGNORE_CASE, vol->upcase, vol->upcase_len)) 
	{
		int name_size = sizeof(ntfs_name);
		u8 type = ie_file_name_type(ie);
		u8 len = ie_file_name_length(ie);

		/* Only one case insensitive matching name allowed. */
		if (ictx->imperfect_match_name ) 
		{
			ntfs_error(sb, "Found already allocated name "
					"in phase 1. Please run chkdsk "
					"and if that doesn't find any "
					"errors please report you saw "
					"this message to "
					"linux-ntfs-dev@lists."
					"sourceforge.net.");
			return -EIO;
		}

		if (type != FILE_NAME_DOS)
			name_size += len * sizeof(ntfschar);
		ictx->imperfect_match_name  = kmalloc(name_size, GFP_NOFS);
		if (!ictx->imperfect_match_name ) 
		{
			return -ENOMEM;
		}
		ictx->imperfect_match_name->mref = index_entry_mref(ie);
		ictx->imperfect_match_name->type = type;
		if (type != FILE_NAME_DOS) {
			ictx->imperfect_match_name->len = len;
			memcpy(ictx->imperfect_match_name->name,
				       	ie_file_name(ie),
					len * sizeof(ntfschar));
		} 
		else
		{
			ictx->imperfect_match_name->len = 0;
		}
	}

	/*
	 * Not a perfect match, need to do full blown collation so we
	 * know which way in the B+tree we have to go.
	 */
	rc = ntfs_collate_names(uname, uname_len,
			(ntfschar*)&ie_file_name(ie),
			ie_file_name_length(ie),
			1, IGNORE_CASE, vol->upcase, vol->upcase_len);
	/*
	 * If uname collates before the name of the current entry, there
	 * is definitely no such name in this index but we might need to
	 * descend into the B+tree so we just break out of the loop.
	 */
	if (rc == -1)
	{
		ntfs_debug("IGNORE_CASE compare not found before possible position, just record the INDEX_ENTRY and return");
		return SHOULD_CHECK_SUBNODE;
	}
	/* The names are not equal, continue the search. */
	if (rc)
	{
		return SHOULD_CONTINUE;
	}

	/*
	 * 0 == rc  get here
	 * Names match with case insensitive comparison, now try the
	 * case sensitive comparison, which is required for proper
	 * collation.
	 */
	rc = ntfs_collate_names(uname, uname_len,
			(ntfschar*)&ie_file_name(ie),
			ie_file_name_length(ie),
			1, CASE_SENSITIVE, vol->upcase, vol->upcase_len);
	if (rc == -1)
	{
		ntfs_debug("not found before possible position, just record the INDEX_ENTRY and return");
		return SHOULD_CHECK_SUBNODE;
	}
	if (rc)
	{
		return SHOULD_CONTINUE;
	}
	/*
	 * Perfect match, this will never happen as the
	 * ntfs_are_names_equal() call will have gotten a match but we
	 * still treat it correctly.
	 */
	return PERFECT_MATCH;
}
MFT_REF ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
		const int uname_len, ntfs_name ** const res)
{
	int rc;
	ntfs_index_context *icx;
	u64 mref;

	ntfs_debug("Entering. ");

	icx =  ntfs_index_ctx_get(dir_ni);
	if (!icx)
	{
		mref = ERR_MREF(PTR_ERR(icx));
		goto out;
	}

	rc =  _ntfs_index_lookup_with_call_back (uname,uname_len,
			comparer_with_imperfect_name,icx);
	if (PERFECT_MATCH == rc) /* found */
	{
		ntfs_debug("Found Target.");
		ntfs_dump_index_entry(icx->entry);

		/*transfer the icx->entry to mref and *res */
		mref = ie_mref(icx->entry);

		/* the caller of lookup will release the name **/
		if(res)
		{
			*res = icx->imperfect_match_name;
			icx->imperfect_match_name = NULL; 
		}
	}
	else /* not found */
	{
		mref = ERR_MREF(rc);
	}
out:
	if(icx)
	{
		ntfs_index_ctx_put(icx);
		icx=NULL;
	}
	return mref;
}

/**
 * ntfs_index_lookup - find a key in an index and return its index entry
 * @key:	[IN] key for which to search in the index
 * @key_len:	[IN] length of @key in bytes
 * @ictx:	[IN/OUT] context describing the index and the returned entry
 *
 * Before calling ntfs_index_lookup(), @ictx must have been obtained from a
 * call to ntfs_index_ctx_get().
 *
 * Look for the @key in the index specified by the index lookup context @ictx.
 * ntfs_index_lookup() walks the contents of the index looking for the @key.
 *
 * If the @key is found in the index, 0 is returned and @ictx is setup to
 * describe the index entry containing the matching @key.  @ictx->entry is the
 * index entry and @ictx->data and @ictx->data_len are the index entry data and
 * its length in bytes, respectively.
 *
 * If the @key is not found in the index, -ENOENT is returned and @ictx is
 * setup to describe the index entry whose key collates immediately after the
 * search @key, i.e. this is the position in the index at which an index entry
 * with a key of @key would need to be inserted.
 *
 * If an error occurs return the negative error code and @ictx is left
 * untouched.
 *
 * When finished with the entry and its data, call ntfs_index_ctx_put() to free
 * the context and other associated resources.
 *
 * If the index entry was modified, call flush_dcache_index_entry_page()
 * immediately after the modification and either ntfs_index_entry_mark_dirty()
 * or ntfs_index_entry_write() before the call to ntfs_index_ctx_put() to
 * ensure that the changes are written to disk.
 *
 * Locking:  - Caller must hold i_mutex on the index inode.
 *	     - Each page cache page in the index allocation mapping must be
 *	       locked whilst being accessed otherwise we may find a corrupt
 *	       page due to it being under ->writepage at the moment which
 *	       applies the mst protection fixups before writing out and then
 *	       removes them again after the write is complete after which it 
 *	       unlocks the page.
 */
int ntfs_index_lookup(const void *key, const int key_len,
		ntfs_index_context *ictx)
{
	VCN vcn, old_vcn;
	ntfs_inode *idx_ni = ictx->idx_ni;
	ntfs_volume *vol = idx_ni->vol;
	struct super_block *sb = vol->sb;
	ntfs_inode *base_ni = idx_ni->ext.base_ntfs_ino;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end, *kaddr;
	ntfs_attr_search_ctx *actx;
	struct address_space *ia_mapping;
	struct page *page;
	int rc, err = 0;

	ntfs_debug("Entering.");
	BUG_ON(!NInoAttr(idx_ni));
	BUG_ON(idx_ni->type != AT_INDEX_ALLOCATION);
	BUG_ON(idx_ni->nr_extents != -1);
	BUG_ON(!base_ni);
	BUG_ON(!key);
	BUG_ON(key_len <= 0);
	if (!ntfs_is_collation_rule_supported(
			idx_ni->itype.index.collation_rule)) {
		ntfs_error(sb, "Index uses unsupported collation rule 0x%x.  "
				"Aborting lookup.", le32_to_cpu(
				idx_ni->itype.index.collation_rule));
		return -EOPNOTSUPP;
	}
	/* Get hold of the mft record for the index inode. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return PTR_ERR(m);
	}
	actx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!actx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, idx_ni->name, idx_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in inode "
					"0x%lx.", idx_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	/* Get to the index root value (it has been verified in read_inode). */
	ir = (INDEX_ROOT*)((u8*)actx->attr +
			le16_to_cpu(actx->attr->data.resident.value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	old_vcn = VCN_INDEX_ROOT_PARENT;
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)actx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end)
			goto idx_err_out;
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Further bounds checks. */
		if ((u32)sizeof(INDEX_ENTRY_HEADER) +
				le16_to_cpu(ie->key_length) >
				le16_to_cpu(ie->data.vi.data_offset) ||
				(u32)le16_to_cpu(ie->data.vi.data_offset) +
				le16_to_cpu(ie->data.vi.data_length) >
				le16_to_cpu(ie->length))
			goto idx_err_out;
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ir_done:
			ictx->is_in_root = true;
			ictx->ir = ir;
			ictx->actx = actx;
			ictx->base_ni = base_ni;
			ictx->ia = NULL;
			ictx->page = NULL;
done:
			ictx->entry = ie;
			ictx->data = (u8*)ie +
					le16_to_cpu(ie->data.vi.data_offset);
			ictx->data_len = le16_to_cpu(ie->data.vi.data_length);
			ntfs_debug("Done.");


			ictx->parent_vcn[ictx->pindex] = old_vcn;

			return err;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, idx_ni->itype.index.collation_rule, key,
				key_len, &ie->key, le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ir_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index without success.  Check for the
	 * presence of a child node and if not present setup @ictx and return
	 * -ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto ir_done;
	} /* Child node present, descend into it. */
	/* Consistency check: Verify that an index allocation exists. */
	if (!NInoIndexAllocPresent(idx_ni)) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one.  Inode 0x%lx is corrupt or "
				"driver bug.", idx_ni->mft_no);
		goto err_out;
	}
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	ia_mapping = VFS_I(idx_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record.  Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(actx);
	unmap_mft_record(base_ni);
	m = NULL;
	actx = NULL;
descend_into_child_node:
	ictx->parent_vcn[ictx->pindex] = old_vcn;
	if (ntfs_icx_parent_inc(ictx)) {
		goto err_out;
	}
	old_vcn = vcn;


	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	page = ntfs_map_page(ia_mapping, vcn <<
			idx_ni->itype.index.vcn_size_bits >> PAGE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + ((vcn <<
			idx_ni->itype.index.vcn_size_bits) & ~PAGE_MASK));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed.  Corrupt inode "
				"0x%lx or driver bug.", idx_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Index record with vcn 0x%llx is corrupt.  "
				"Corrupt inode 0x%lx.  Run chkdsk.",
				(long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx).  Inode "
				"0x%lx is corrupt or driver bug.",
				(unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of inode 0x%lx has "
				"a size (%u) differing from the index "
				"specified size (%u).  Inode is corrupt or "
				"driver bug.", (unsigned long long)vcn,
				idx_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				idx_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + idx_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of inode 0x%lx "
				"crosses page boundary.  Impossible!  Cannot "
				"access!  This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				idx_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of inode "
				"0x%lx exceeds maximum size.",
				(unsigned long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_error(sb, "Index entry out of bounds in inode "
					"0x%lx.", idx_ni->mft_no);
			goto unm_err_out;
		}
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Further bounds checks. */
		if ((u32)sizeof(INDEX_ENTRY_HEADER) +
				le16_to_cpu(ie->key_length) >
				le16_to_cpu(ie->data.vi.data_offset) ||
				(u32)le16_to_cpu(ie->data.vi.data_offset) +
				le16_to_cpu(ie->data.vi.data_length) >
				le16_to_cpu(ie->length)) {
			ntfs_error(sb, "Index entry out of bounds in inode "
					"0x%lx.", idx_ni->mft_no);
			goto unm_err_out;
		}
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ia_done:
			ictx->is_in_root = false;
			ictx->actx = NULL;
			ictx->base_ni = NULL;
			ictx->ia = ia;
			ictx->page = page;
			ictx->parent_vcn[ictx->pindex] = vcn;
			goto done;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, idx_ni->itype.index.collation_rule, key,
				key_len, &ie->key, le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ia_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index buffer without success.  Check for
	 * the presence of a child node and if not present return -ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto ia_done;
	}
	if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
		ntfs_error(sb, "Index entry with child node found in a leaf "
				"node in inode 0x%lx.", idx_ni->mft_no);
		goto unm_err_out;
	}
	/* Child node present, descend into it. */
	old_vcn = vcn;
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	if (vcn >= 0) {
		/*
		 * If vcn is in the same page cache page as old_vcn we recycle
		 * the mapped page.
		 */
		if (old_vcn << vol->cluster_size_bits >>
				PAGE_SHIFT == vcn <<
				vol->cluster_size_bits >>
				PAGE_SHIFT)
			goto fast_descend_into_child_node;
		unlock_page(page);
		ntfs_unmap_page(page);
		goto descend_into_child_node;
	}
	ntfs_error(sb, "Negative child node vcn in inode 0x%lx.",
			idx_ni->mft_no);
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (m)
		unmap_mft_record(base_ni);
	return err;
idx_err_out:
	ntfs_error(sb, "Corrupt index.  Aborting lookup.");
	goto err_out;
}


/*
static s64 ntfs_ibm_vcn_to_pos(ntfs_index_context *icx, VCN vcn)
{
        return ntfs_ib_vcn_to_pos(icx, vcn) / icx->idx_ni->itype.index.block_size;
}
*/
static s64 ntfs_ibm_pos_to_vcn(ntfs_index_context *icx, s64 pos)
{
        return ntfs_ib_pos_to_vcn(icx, pos * icx->idx_ni->itype.index.block_size);
}

/* Walk through all BITMAP data, 
 * looking for a 0 ,
 * set it to 1 ,write to disk , 
 * and return the position */
VCN ntfs_ibm_get_free(ntfs_index_context *icx)
{
	u8 *bm;
	s64 vcn;
        s64 bmp_allocated_size;
	struct inode *bmp_vi;
	int err = -ENOENT;
        struct address_space *bmp_mapping;
        struct page *bmp_page = NULL;


        s64 bmp_pos;
        int cur_bmp_pos;

	ntfs_debug("Entering Inode 0x%lx, getting index bitmap.", VFS_I(icx->idx_ni)->i_ino);

	bmp_vi = ntfs_attr_iget(VFS_I(icx->idx_ni), AT_BITMAP, icx->idx_ni->name, icx->idx_ni->name_len);
	if (IS_ERR(bmp_vi)) {
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "Failed to get bitmap attribute.");
		err = PTR_ERR(bmp_vi);
		goto err_out;
	}
        bmp_allocated_size = i_size_read(bmp_vi);
	ntfs_debug("bmp_allocated_size is [%lld] PAGE_SIZE is [%lu]",
		bmp_allocated_size, PAGE_SIZE);

	bmp_mapping = bmp_vi->i_mapping;
	/* Start from 0 */
	bmp_pos = 0;
	if (unlikely(bmp_pos >> 3 >= i_size_read(bmp_vi))) {
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "Current index allocation position exceeds "
				"index bitmap size.");
		goto iput_err_out;
	}
	/* Get the starting bit position in the current bitmap page. */
	cur_bmp_pos = bmp_pos & ((PAGE_SIZE * 8) - 1); /* bit in page */
	bmp_pos &= ~(u64)((PAGE_SIZE * 8) - 1); /* bit before this page */
get_next_bmp_page:
	ntfs_debug("Reading bitmap with page index 0x%llx, bit ofs 0x%llx",
			(unsigned long long)bmp_pos >> (3 + PAGE_SHIFT),
			(unsigned long long)bmp_pos &
			(unsigned long long)((PAGE_SIZE * 8) - 1));
	bmp_page = ntfs_map_page(bmp_mapping,
			bmp_pos >> (3 + PAGE_SHIFT));
	if (IS_ERR(bmp_page)) {
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "Reading index bitmap failed.");
		err = PTR_ERR(bmp_page);
		bmp_page = NULL;
		goto error_out;
	}
	/* directly mapped virtual address, no need to free */
	bm = (u8*)page_address(bmp_page);
	/* Find next index block NOT in use. */
	while ((bm[cur_bmp_pos >> 3] & (1 << (cur_bmp_pos & 7)))) 
	{
		cur_bmp_pos++;
		/*
		 * If we have reached the end of the bitmap page, get the next
		 * page, and put away the old one.
		 * cur_bmp_pos should not exceed PAGE_SIZE*8
		 */
		if (unlikely((cur_bmp_pos >> 3) >= PAGE_SIZE)) {
			ntfs_unmap_page(bmp_page);
			bmp_pos += PAGE_SIZE * 8;
			cur_bmp_pos = 0;
			goto get_next_bmp_page;
		}
		/* If we have reached the end of the bitmap, we are done. */
		if (unlikely(((bmp_pos + cur_bmp_pos) >> 3) >= bmp_allocated_size))
		{
			ntfs_error(VFS_I(icx->idx_ni)->i_sb, "Need New data block for BITMAP, Not support now.");
			goto err_out;
		}
	}
	ntfs_debug("Handling index buffer [bit before page]0x%llx, [bit in page]0x%llx",
			(unsigned long long)bmp_pos , (unsigned long long)cur_bmp_pos);
	vcn = ntfs_ibm_pos_to_vcn(icx, bmp_pos + cur_bmp_pos);
//out:	
	ntfs_debug("allocated vcn: %lld\n", (long long)vcn);

	/* Set the bit to 1 and write to disk */
	/*TODO: use __ntfs_bitmap_set_bits_in_run ? */
	/* modify the content of the page */
	bm[cur_bmp_pos >> 3] |= (1 << (cur_bmp_pos & 7));
	/* Write to disk */
	flush_dcache_page(bmp_page);
	set_page_dirty(bmp_page);
	ntfs_unmap_page(bmp_page);
	/* End of set bitmap */

	iput(bmp_vi);
	return vcn;
err_out:
iput_err_out:
	if(bmp_vi)
	{
		iput(bmp_vi);
	}
error_out:
        if (bmp_page) 
                ntfs_unmap_page(bmp_page);

	return (VCN)-1;
}
/**
 * ntfs_directory_context_write 
 * - perform buffered write to a dirictory
 * @icx:	directory information to write to
 * 		which contain the icx->ia with fresh data
 *
 * It is a sibling function of ntfs_file_data_write
 */
int ntfs_directory_context_write(ntfs_index_context *icx)
{
	/* page of ib is locked **/
	INDEX_BLOCK *ib=icx->ia;

	s64 status;
       	s64 vcn = sle64_to_cpu(ib->index_block_vcn);
	const s64 pos = ntfs_ib_vcn_to_pos(icx, vcn);
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
	//s64 written;
	struct inode *vi = VFS_I(idx_ni);

	//struct address_space *mapping = VFS_I(idx_ni)->i_mapping;
	struct page *pages[NTFS_MAX_PAGES_PER_CLUSTER];
	size_t bytes;
	unsigned nr_pages;
	ntfs_volume *vol = idx_ni->vol;
	VCN last_vcn;
	LCN lcn;

	what_handling(idx_ni);
	ntfs_debug("pos 0x%llx. vcn: %lld\n",  
			(long long)pos,(long long)vcn);
	/* First of all , do some check **/
	BUG_ON(bk_size%NTFS_BLOCK_SIZE);
	/*
	 * Determine the number of pages per cluster for non-resident
	 * attributes.
	 */
	nr_pages = 1;
	if (vol->cluster_size > PAGE_SIZE && NInoNonResident(idx_ni))
		nr_pages = ntfs_pages_count_in_cluster(vol);
	last_vcn = -1;
	{
		VCN vcn;
		pgoff_t idx, start_idx;
		unsigned ofs, do_pages;
	       	//unsigned u;
		//size_t copied;

		start_idx = idx = pos >> PAGE_SHIFT;
		ofs = pos & ~PAGE_MASK;
		bytes = PAGE_SIZE - ofs;
		do_pages = 1;
		ntfs_debug("ofs 0x%llx. bytes: %lld\n",  
				(long long)ofs,(long long)bytes);
		/*TODO:Not supported for now **/
		if (nr_pages > 1) {
			ntfs_debug("nr_pages is %d,not rupported\n",nr_pages);  
			return -EINVAL;
			vcn = pos >> vol->cluster_size_bits;
			if (vcn != last_vcn) {
				last_vcn = vcn;
				/*
				 * Get the lcn of the vcn the write is in.  If
				 * it is a hole, need to lock down all pages in
				 * the cluster.
				 */
				down_read(&idx_ni->runlist.lock);
				lcn = ntfs_attr_vcn_to_lcn_nolock(idx_ni, pos >>
						vol->cluster_size_bits, false);
				up_read(&idx_ni->runlist.lock);
				if (unlikely(lcn < LCN_HOLE)) {
					if (lcn == LCN_ENOMEM)
						status = -ENOMEM;
					else {
						status = -EIO;
						ntfs_error(vol->sb, "Cannot "
								"perform write to "
								"inode 0x%lx, "
								"attribute type 0x%x, "
								"because the attribute "
								"is corrupt.",
								vi->i_ino, (unsigned)
								le32_to_cpu(idx_ni->type));
					}
					ntfs_error(vol->sb,"should me break?");
				}
				if (lcn == LCN_HOLE) {
					start_idx = (pos & ~(s64)
							vol->cluster_size_mask)
						>> PAGE_SHIFT;
					bytes = vol->cluster_size - (pos &
							vol->cluster_size_mask);
					do_pages = nr_pages;
				}
			}
		}
		if(do_pages != 1)
		{
			ntfs_error(vol->sb,"Connot perfor multi page write");
			return -EINVAL;
		}
		/* Not supported code end */
		if (bytes > bk_size)
			bytes = bk_size;

		{
//			pgoff_t start_idx = pos >> PAGE_SHIFT;
			pages[0]=icx->page;
#if 0
			/*
			 * For non-resident attributes, we need to fill any holes with
			 * actual clusters and ensure all bufferes are mapped.  We also
			 * need to bring uptodate any buffers that are only partially
			 * being written to.
			 *
			 * no need for locked page
			 */
			if (NInoNonResident(idx_ni)) {
				status = ntfs_prepare_pages_for_non_resident_write(
						pages, 1/* only handle 1 page */, pos, bk_size);
				if (unlikely(status)) {
					return status;
				}
			}
#endif
			/* In other write, we need copy from the source,
			 * but here we don't need */

			flush_dcache_page(pages[0]);
			status = 0;
#if 0
			status = ntfs_commit_pages_after_write(pages, 1,
					pos, bk_size);
			if (!status)
				written = bk_size;
			if (unlikely(status < 0))
				return -EINVAL;
#endif
			cond_resched();
		}
	}


	/*********************************************/

#if 0
	if (written != bk_size)
	{
		return STATUS_ERROR;
	}
	else
	{
		return STATUS_OK;
	}
#endif
	return status;
}

/**
 * ntfs_directory_data_write - perform buffered write to a dirictory
 * @icx:	directory information to write to
 * @ib:	index block that need to write
 *
 * It is a sibling function of ntfs_file_data_write
 */
int ntfs_directory_data_write(ntfs_index_context *icx, INDEX_BLOCK *ib)
{
	//s64 ret;
	s64 status;
       	s64 vcn = sle64_to_cpu(ib->index_block_vcn);
	const s64 pos = ntfs_ib_vcn_to_pos(icx, vcn);
       	//const s64 bk_cnt = 1;
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
       	void *src = ib;
	s64 written;
       	//s64 i;
	struct inode *vi = VFS_I(idx_ni);

	struct address_space *mapping = VFS_I(idx_ni)->i_mapping;
	//int err;
	struct page *pages[NTFS_MAX_PAGES_PER_CLUSTER];
	size_t bytes;
	unsigned nr_pages;
	ntfs_volume *vol = idx_ni->vol;
	VCN last_vcn;
	LCN lcn;


	what_handling(idx_ni);
	ntfs_debug("pos 0x%llx. vcn: %lld\n",  
			(long long)pos,(long long)vcn);
	/* First of all , do some check **/
	BUG_ON(bk_size%NTFS_BLOCK_SIZE);
	/*
	 * Determine the number of pages per cluster for non-resident
	 * attributes.
	 */
	nr_pages = 1;
	if (vol->cluster_size > PAGE_SIZE && NInoNonResident(idx_ni))
		nr_pages = ntfs_pages_count_in_cluster(vol);
	last_vcn = -1;
	{
		VCN vcn;
		pgoff_t idx, start_idx;
		unsigned ofs, do_pages;
	       	//unsigned u;
		//size_t copied;

		start_idx = idx = pos >> PAGE_SHIFT;
		ofs = pos & ~PAGE_MASK;
		bytes = PAGE_SIZE - ofs;
		do_pages = 1;
		ntfs_debug("ofs 0x%llx. bytes: %lld\n",  
				(long long)ofs,(long long)bytes);
		/*TODO:Not supported for now **/
		if (nr_pages > 1) {
			ntfs_debug("nr_pages is %d,not rupported\n",nr_pages);  
			return -EINVAL;
			vcn = pos >> vol->cluster_size_bits;
			if (vcn != last_vcn) {
				last_vcn = vcn;
				/*
				 * Get the lcn of the vcn the write is in.  If
				 * it is a hole, need to lock down all pages in
				 * the cluster.
				 */
				down_read(&idx_ni->runlist.lock);
				lcn = ntfs_attr_vcn_to_lcn_nolock(idx_ni, pos >>
						vol->cluster_size_bits, false);
				up_read(&idx_ni->runlist.lock);
				if (unlikely(lcn < LCN_HOLE)) {
					if (lcn == LCN_ENOMEM)
						status = -ENOMEM;
					else {
						status = -EIO;
						ntfs_error(vol->sb, "Cannot "
								"perform write to "
								"inode 0x%lx, "
								"attribute type 0x%x, "
								"because the attribute "
								"is corrupt.",
								vi->i_ino, (unsigned)
								le32_to_cpu(idx_ni->type));
					}
					ntfs_error(vol->sb,"should me break?");
				}
				if (lcn == LCN_HOLE) {
					start_idx = (pos & ~(s64)
							vol->cluster_size_mask)
						>> PAGE_SHIFT;
					bytes = vol->cluster_size - (pos &
							vol->cluster_size_mask);
					do_pages = nr_pages;
				}
			}
		}
		/* Not supported code end */
		if (bytes > bk_size)
			bytes = bk_size;

		/*
		   err = pre_write_mst_fixup((NTFS_RECORD*) ((u8*)src ), bk_size);
		   if (err < 0) {
		   / * Abort write at this position. * /
		   ntfs_error(VFS_I(icx->idx_ni)->i_sb, "%s #1", __FUNCTION__);
		   if (!i)
		   return err;
		   }
		   */
		/***************************************/
		{
			pgoff_t start_idx = pos >> PAGE_SHIFT;

			/* Get and lock @do_pages starting at index @start_idx. */
			status =  ntfs_grab_one_cache_page(mapping,
					start_idx, pages);

			if (unlikely(status))
				return status;
			/*
			 * For non-resident attributes, we need to fill any holes with
			 * actual clusters and ensure all bufferes are mapped.  We also
			 * need to bring uptodate any buffers that are only partially
			 * being written to.
			 */
			if (NInoNonResident(idx_ni)) {
				status = ntfs_prepare_pages_for_non_resident_write(
						pages, 1/* only handle 1 page */, pos, bk_size);
				if (unlikely(status)) {
					unlock_page(pages[0]);
					put_page(pages[0]);
					return status;
				}
			}
			{
				char *kaddr = kmap_atomic(pages[0]);
				memcpy(kaddr,src,bk_size);

			}
			ntfs_flush_dcache_pages(pages , 1);
			status = 0;
			status = ntfs_commit_pages_after_write(pages, 1,
					pos, bk_size);
			if (!status)
				written = bk_size;
			do {
				unlock_page(pages[--do_pages]);
				put_page(pages[do_pages]);
			} while (do_pages);
			if (unlikely(status < 0))
				return -EINVAL;
			cond_resched();
		}
	}


	/*********************************************/

	/* Quickly deprotect the data again. 
	post_write_mst_fixup((NTFS_RECORD*)((u8*)src ));*/

	if (written != bk_size)
	{
		return STATUS_ERROR;
	}
	else
	{
		return STATUS_OK;
	}
}

ssize_t ntfs_prepare_directory_for_write(ntfs_index_context *icx, INDEX_BLOCK *ib)
{
	s64 end, ll;
	ssize_t err;
	unsigned long flags;
	s64 vcn = sle64_to_cpu(ib->index_block_vcn);
	const loff_t pos = ntfs_ib_vcn_to_pos(icx, vcn);
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
	ntfs_volume *vol = idx_ni->vol;


	what_handling(idx_ni);
	ntfs_debug(" pos 0x%llx, prepare size 0x%x.", 
			(unsigned long long)pos, bk_size);
	/* The first byte after the last cluster being written to. */
	end = (pos + bk_size + vol->cluster_size_mask) &
			~(u64)vol->cluster_size_mask;
	/*
	 * If the write goes beyond the allocated size, extend the allocation
	 * to cover the whole of the write, rounded up to the nearest cluster.
	 */
	read_lock_irqsave(&idx_ni->size_lock, flags);
	ll = idx_ni->allocated_size;
	read_unlock_irqrestore(&idx_ni->size_lock, flags);
	if (end > ll) {
		/*
		 * Extend the allocation without changing the data size.
		 *
		 * Note we ensure the allocation is big enough to at least
		 * write some data but we do not require the allocation to be
		 * complete, i.e. it may be partial.
		 */
		ll = ntfs_attr_extend_allocation(idx_ni, end, -1, pos);
		if (likely(ll >= 0)) {
			BUG_ON(pos >= ll);
			/* If the extension was partial truncate the write. */
			if (end > ll) {
				ntfs_debug("Need Truncating writing ");
			}
		} else {
			err = ll;
			read_lock_irqsave(&idx_ni->size_lock, flags);
			ll = idx_ni->allocated_size;
			read_unlock_irqrestore(&idx_ni->size_lock, flags);
			/* Perform a partial write if possible or fail. */
			if (pos < ll) {
				ntfs_debug("Need Truncating writing "
						"because of extending the allocation "
						"failed (error %d).", (int)-err);
			} else {
				if (err != -ENOSPC)
					ntfs_error(vol->sb, "Cannot perform "
							"write to inode "
							"extending the "
							"allocation failed "
							"(error %ld).", (long)-err);
				else
					ntfs_debug("Cannot perform write "
							"because there is not "
							"space left.");
				goto out;
			}
		}
	}
	/*
	 * If the write starts beyond the initialized size, extend it up to the
	 * beginning of the write and initialize all non-sparse space between
	 * the old initialized size and the new one.  This automatically also
	 * increments the vfs inode->i_size to keep it above or equal to the
	 * initialized_size.
	 */
	read_lock_irqsave(&idx_ni->size_lock, flags);
	ll = idx_ni->initialized_size;
	ntfs_debug(" idx_ni->initialized_size is [%lld] pos [%lld]",
		       	idx_ni->initialized_size,pos);
	read_unlock_irqrestore(&idx_ni->size_lock, flags);
	if (pos > ll) {
		/*
		 * Wait for ongoing direct i/o to complete before proceeding.
		 * New direct i/o cannot start as we hold i_mutex.
		 */
		inode_dio_wait(VFS_I(idx_ni));
		err = ntfs_attr_extend_initialized(idx_ni, pos);
		if (unlikely(err < 0))
			ntfs_error(vol->sb, "Cannot perform write to inode "
					"extending the initialized size "
					"failed (error %d).", (int)-err);
	}
out:
	return 0;
}

INDEX_ENTRY *ntfs_ie_dup(INDEX_ENTRY *ie)
{
	INDEX_ENTRY *dup;
	
	ntfs_debug("Entering\n");
	
	dup = kmalloc(le16_to_cpu(ie->length),GFP_ATOMIC);
	if (dup)
		memcpy(dup, ie, le16_to_cpu(ie->length));
	
	return dup;
}


/*
 * NOTE: 'ie' must be a copy of a real index entry.
 */
int ntfs_ie_add_vcn(INDEX_ENTRY **ie)
{
	INDEX_ENTRY *p, *old = *ie;
	 
	old->length = cpu_to_le16(le16_to_cpu(old->length) + sizeof(VCN));
	p = krealloc(old, le16_to_cpu(old->length),GFP_ATOMIC);
	if (!p)
		return STATUS_ERROR;
	
	p->flags |= INDEX_ENTRY_NODE;
	*ie = p;

	return STATUS_OK;
}

static leVCN *ntfs_ie_get_vcn_addr(INDEX_ENTRY *ie)
{
	        return (leVCN *)((u8 *)ie + le16_to_cpu(ie->length) - sizeof(leVCN));
}

/**
 *  *  Get the subnode vcn to which the index entry refers.
 *   */
VCN ntfs_ie_get_vcn(INDEX_ENTRY *ie)
{
	        return sle64_to_cpup(ntfs_ie_get_vcn_addr(ie));
}

void ntfs_ie_set_vcn(INDEX_ENTRY *ie, VCN vcn)
{
	        *ntfs_ie_get_vcn_addr(ie) = cpu_to_sle64(vcn);
}

INDEX_ENTRY *ntfs_ie_get_by_pos(INDEX_HEADER *ih, int pos)
{
	INDEX_ENTRY *ie;

	ntfs_debug("pos: %d\n", pos);

	ie = ntfs_ie_get_first(ih);

	while (pos-- > 0)
		ie = ntfs_ie_get_next(ie);

	return ie;
}

/**
 * ntfs_ir_truncate - Truncate index root attribute
 * 
 * Returns STATUS_OK, STATUS_RESIDENT_ATTRIBUTE_FILLED_MFT or STATUS_ERROR.
 */
extern int ntfs_ir_truncate(ntfs_index_context *icx, int data_size)
{			  
	/*
	   ntfs_attr *na;
	   */
	int ret;

	/* icx->actx is released now */
	/* We should locate the INDEX_ROOT again **/
	ntfs_volume *vol = icx->idx_ni->vol;
	struct super_block *sb = vol->sb;
	ntfs_attr_search_ctx *temp_search_ctx;


	ntfs_debug("Entering\n");
	/* Get hold of the mft record for the directory. */
	if(!icx->m)
	{
		icx->m = map_mft_record(icx->idx_ni);
		if (IS_ERR(icx->m))
		{
			ntfs_error(sb, "map_mft_record() failed with error code %ld.",
					-PTR_ERR(icx->m));
			return ERR_MREF(PTR_ERR(icx->m));
		}
	}
	/* Allocate and initilize the temp search context **/
	temp_search_ctx = ntfs_attr_get_search_ctx(icx->idx_ni, icx->m);
	if (unlikely(!temp_search_ctx)) {
		ret = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	ret = ntfs_search_attr_index_root(temp_search_ctx);
	if (unlikely(ret)) {
		if (ret == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					icx->idx_ni->mft_no);
			ret = -EIO;
		}
		goto err_out;
	}



	/**
	  na = ntfs_attr_open(icx->ni, AT_INDEX_ROOT, icx->name, icx->name_len);
	  if (!na) {
	  ntfs_log_perror("Failed to open INDEX_ROOT");
	  return STATUS_ERROR;
	  }
	  */
	/*
	 *  INDEX_ROOT must be resident and its entries can be moved to 
	 *  INDEX_BLOCK, so ENOSPC isn't a real error.
	 */
	ret = ntfs_resident_attr_value_resize(temp_search_ctx->mrec, 
			temp_search_ctx->attr, data_size + offsetof(INDEX_ROOT, index) );
	/*Gzged changed 
	  ret = ntfs_attr_truncate(na, data_size + offsetof(INDEX_ROOT, index));
	  */
	if (ret == STATUS_OK) 
	{
		/*
		   icx->ir = ntfs_ir_lookup2(icx->ni, icx->name, icx->name_len);
		   if (!icx->ir)
		   return STATUS_ERROR;
		   */

		INDEX_ROOT* ir = (INDEX_ROOT*)((u8*)temp_search_ctx->attr +
					le16_to_cpu(temp_search_ctx->attr->data.resident.value_offset));
		ir->index.allocated_size = cpu_to_le32(data_size);

	} else if (ret == -EPERM)
	{
		ntfs_debug("Failed to truncate INDEX_ROOT");
	}

	/**
	  ntfs_attr_close(na);
	  */
err_out:
	if (icx->m)
	{
		icx->m=NULL;
		unmap_mft_record(icx->idx_ni);
	}
	ntfs_debug("Will return %d",ret);
	return ret;
}

/**
 * ntfs_ir_make_space - Make more space for the index root attribute
 * 
 * On success return STATUS_OK or STATUS_KEEP_SEARCHING.
 * On error return STATUS_ERROR.
 */
static int ntfs_ir_make_space(ntfs_index_context *icx, int data_size)
{			  
	int ret;
	ntfs_debug("Entering for new size %d",data_size);
	ret = ntfs_ir_truncate(icx, data_size);
	/* TODO
	if (ret == STATUS_RESIDENT_ATTRIBUTE_FILLED_MFT) 
	{
		ret = ntfs_ir_reparent(icx);
		if (ret == STATUS_OK)
			ret = STATUS_KEEP_SEARCHING;
		else
			ntfs_log_perror("Failed to nodify INDEX_ROOT");
	}
	*/
	ntfs_debug("Done ret %d",ret);
	return ret;
}

/**
 *  Insert @ie index entry at @pos entry. Used @ih values should be ok already.
 */
void ntfs_ie_insert(INDEX_HEADER *ih, INDEX_ENTRY *ie, INDEX_ENTRY *pos)
{
	int ie_size = le16_to_cpu(ie->length);
	ntfs_debug("Entering");
	ih->index_length = cpu_to_le32(le32_to_cpu(ih->index_length) + ie_size);
	memmove((u8 *)pos + ie_size, pos, le32_to_cpu(ih->index_length) - ((u8 *)pos - (u8 *)ih) - ie_size);
	memcpy(pos, ie, ie_size);
	ntfs_debug("done");
}

/* Insert Index_Entry into
 * Index_Root or Index_Allocation 
 *
 * @ntfs_index_context: is only used for directory,
 * 	it contains Index_Root and Index_Allocation,
 * 	which contain Index_Entry
 * @ie: is the Index_Entry which should be insert
*/
int ntfs_ie_add(ntfs_inode *idx_ni, INDEX_ENTRY *ie)
{
	INDEX_HEADER *ih;
	int allocated_size, new_size;
	int ret = STATUS_ERROR;
	ntfs_index_context *icx;

	ntfs_debug("Entering. ");

	icx =  ntfs_index_ctx_get(idx_ni);
        if (!icx)
        {
                ret = PTR_ERR(icx);
                goto out;
        }

	/* Create Enough Space in Index_Root or Index_Allocation */
	while (1) 
	{
		ret = ntfs_lookup_inode_by_index_entry(ie, icx /*output*/ );
		if (!ret) 
		{
			ntfs_debug("Index already have such entry");
			goto err_out;
		}
		if (ret != -ENOENT) 
		{
			ntfs_debug("Failed to find place for new entry");
			goto err_out;
		}

		/* Found the place that should store the new INDEX_ENTRY,
		 * detail is in icx */
		if (icx->is_in_root)
		{
			BUG_ON(!icx->ir);
			ih = &(icx->ir->index);
		}
		else
		{
			BUG_ON(!icx->ia);
			ih = &(icx->ia->index);
		}

		allocated_size = le32_to_cpu(ih->allocated_size);
		new_size = le32_to_cpu(ih->index_length) + le16_to_cpu(ie->length);
	
		ntfs_debug("index block sizes: allocated: %d  needed: %d", 
				allocated_size, new_size);
		if (new_size <= allocated_size)
		{
			/* Loop till there is enough space */
			break;
		}
		/** else  it will make space for new index entry **/
		if (icx->is_in_root) 
		{
			ntfs_index_ctx_put(icx);
			icx=ntfs_index_ctx_get(idx_ni);
			ret = ntfs_ir_make_space(icx, new_size);
			if ( ret )
			{
				ntfs_debug("ntfs_ir_make_space err ret %d",ret);
				goto err_out;
			}
			else
			{
				ntfs_debug("ntfs_ir_make_space done ret %d",ret);
			}
		} 
		else 
		{
			if(in_atomic_preempt_off())
			{
				ntfs_debug("in_atomic_preempt_off is off before ntfs_split_current_index_allocation ");
			}
			else
			{
				ntfs_debug("in_atomic_preempt_off is on before ntfs_split_current_index_allocation ");
		       	}
			ret = ntfs_split_current_index_allocation(icx);
			if (ret )
			{
				goto err_out;
			}
			if(in_atomic_preempt_off())
			{
				ntfs_debug("in_atomic_preempt_off is off after ntfs_split_current_index_allocation ");
			}
			else
			{
				ntfs_debug("in_atomic_preempt_off is on after ntfs_split_current_index_allocation ");
		       	}
		}
		
		ntfs_debug("Before clean");
		/*FIXME: Gzged mod
		ntfs_inode_mark_dirty(icx->actx->ntfs_ino);
		***/
		/*FIXME: Gzged will fix these in furture 
		flush_dcache_mft_record_page(icx->actx->ntfs_ino);
		mark_mft_record_dirty(icx->actx->ntfs_ino);*/

		/*FIXME: Gzged mod ntfs_index_ctx_reinit(icx); ***/
		ntfs_index_ctx_put(icx);
		icx=ntfs_index_ctx_get(idx_ni);
		ntfs_debug("After clean");
	}
	
	ntfs_debug("Got Enough Space");
	/* Insert the INDEX_ENTRY into the ih */
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off before ntfs_ie_insert ");
	}
	else
	{
		ntfs_debug("in_atomic_preempt_off is on before ntfs_ie_insert ");
	}
	ntfs_ie_insert(ih, ie, icx->entry);
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off after ntfs_ie_insert ");
	}
	else
	{
		ntfs_debug("in_atomic_preempt_off is on after ntfs_ie_insert ");
	}

	ntfs_index_entry_flush_dcache_page(icx);
	ntfs_index_entry_mark_dirty(icx);

	ret = STATUS_OK;
err_out:
out:
	if(icx)
	{
		ntfs_index_ctx_put(icx);
		icx=NULL;
	}
	ntfs_debug("%s", ret ? "Failed" : "Done");
	return ret;
}

int ntfs_lookup_inode_by_index_entry (const INDEX_ENTRY *ie, ntfs_index_context *ictx)
{
	return ntfs_lookup_inode_by_filename(((void *)&ie->key), 
			 /*output*/ ictx);
}
int ntfs_search_attr_index_root( /* input & output */ntfs_attr_search_ctx *temp_search_ctx)
{
	return ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL, 0, temp_search_ctx);
}
void set_index_context_with_result(ntfs_index_context* ictx,INDEX_ENTRY* ie)
{
	ictx->data = (u8*)ie + le16_to_cpu(ie->data.vi.data_offset);
	ictx->data_len = le16_to_cpu(ie->data.vi.data_length);
}
void ntfs_dump_file_name_attr(const char* prompt,const FILE_NAME_ATTR* filename)
{
#ifdef DEBUG
#define TEMP_LENGTH 400
	int i = 0;
	char temp_name[TEMP_LENGTH];
	snprintf(temp_name,TEMP_LENGTH," %c ", (char)(filename->file_name[i]));
	for(i = 1 ; i < filename->file_name_length ; i++ )
	{
		snprintf(temp_name,TEMP_LENGTH,"%s%c",temp_name,(char)(filename->file_name[i]));
	}
	ntfs_debug("%s:[%s]",prompt, temp_name);
#endif
}

void ntfs_dump_index_entry(INDEX_ENTRY* ie)
{
#ifdef DEBUG
	ntfs_dump_file_name_attr("Index Entry Simple Name",&(ie->key.file_name));
	if (ie->flags & INDEX_ENTRY_NODE)
	{
		ntfs_debug("Index Entry Subnode Virtual Cluster Number:[0x%llX]",
			       	ntfs_ie_get_vcn(ie));
	}
	if (ie->flags & INDEX_ENTRY_END)
	{
		ntfs_debug("Last Entry");
	}
#endif
	return;
}
/* Walk through the Index Root and try to locate the Index Entry ,
 * return 0 means perfectly match */
int _ntfs_ir_lookup_by_name(
		const ntfschar* uname,
		const int uname_len,
		/* input */ ntfs_attr_search_ctx* temp_search_ctx,
		/* output */ INDEX_ENTRY** pie, 
		/* output */ ntfs_index_context *ictx)
{
	u8 *index_end;
	INDEX_ROOT* ir;
	INDEX_ENTRY* ie= *pie;
	ntfs_volume *vol = ictx->base_ni->vol;
	int rc;


	/* Get to the index root value (it's been verified in read_inode). */
	ir = (INDEX_ROOT*)get_current_attribute(temp_search_ctx);

	/* The first index entry. */
	ie = ntfs_index_root_get_first_entry(ir);
	index_end = ntfs_index_root_get_end_position(ir);

	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */

	for (;; ie = ntfs_ie_get_next(ie)) 
	{
		ntfs_dump_index_entry(ie);
		/* Bounds checks. */
		ictx->is_in_root = true;
		ictx->ir = ir;
		ictx->entry = ie;
		ictx->actx = temp_search_ctx;
		ictx->ia = NULL;
		ictx->page = NULL;

		/* Is data corrupted ? */
		if ((u8*)ie < (u8*)temp_search_ctx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end)
		{
			ntfs_debug("Bounce check error, Corrupt directory.  Aborting lookup.");
			return -EIO;
		}
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if ( ntfs_ie_end(ie))
		{
			ntfs_debug("Walk till end but not found.");
			*pie=ie;
			return SHOULD_CHECK_SUBNODE;
		}
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */

		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) {
			set_index_context_with_result(ictx,ie);
			*pie=ie;
			ntfs_debug("Done.");
			return PERFECT_MATCH;

		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
		{
			ntfs_debug("IGNORE_CASE compare not found before possible position, just record the INDEX_ENTRY and return");
			*pie=ie;
			return SHOULD_CHECK_SUBNODE;
		}
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
		{
			ntfs_debug("not found before possible position, just record the INDEX_ENTRY and return");
			*pie=ie;
			return SHOULD_CHECK_SUBNODE;
		}
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		panic("Should Never Got Here");; /* Or should Panic */
	}
}
int ntfs_index_root_lookup_entry_by_filename(
		/* input */ const FILE_NAME_ATTR *filename,
		/* input */ ntfs_attr_search_ctx* temp_search_ctx,
		/* output */ INDEX_ENTRY** pie, 
		/* output */ ntfs_index_context *ictx)
{
	const ntfschar* uname = filename->file_name ;
	const int uname_len = filename->file_name_length;
	ntfs_dump_file_name_attr("The file we are looking for",filename);

	return _ntfs_ir_lookup_by_name(uname,uname_len,temp_search_ctx,
		       	/* output */ pie,  ictx);
}

int ntfs_icx_parent_inc(ntfs_index_context *icx)
{
	icx->pindex++;
	if (icx->pindex >= MAX_PARENT_VCN) {
		ntfs_debug("Index is over %d level deep", MAX_PARENT_VCN);
		return STATUS_ERROR;
	}
	return STATUS_OK;
}

/*
static int ntfs_icx_parent_dec(ntfs_index_context *icx)
{
	icx->pindex--;
	if (icx->pindex < 0) {
		ntfs_debug("Corrupt index pointer (%d)", icx->pindex);
		return STATUS_ERROR;
	}
	return STATUS_OK;
}
*/

/**
 * ntfs_lookup_inode_by_key - fill ictx with information of the file 
 *                             which have the given name as key
 * @filename:	input, FILE_NAME_ATTR
 * 		normally it is INDEX_ENTRY.key
 *
 * @ictx:	output, return the information of found file 
 *
 * Author: Gao Zhigang
 * Caller is in index.c
 *
 * Look for an inode with name @key in the directory with inode @ictx->idx_ni.
 * ntfs_lookup_inode_by_key() walks the contents of the directory looking for
 * the Unicode name. If the name is found in the directory, the corresponding
 * inode number (>= 0) is returned as a mft reference in cpu format, i.e. it
 * is a 64-bit number containing the sequence number.
 *
 * On error, a negative value is returned corresponding to the error code. In
 * particular if the inode is not found -ENOENT is returned. Note that you
 * can't just check the return value for being negative, you have to check the
 * inode number for being negative which you can extract using MREC(return
 * value).
 *
 */
int _ntfs_index_lookup (const ntfschar* uname,const int uname_len,
		/* output */ ntfs_index_context *ictx)
{
	ntfs_inode* dir_ni = ictx->idx_ni ;
	
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;

	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	ntfs_attr_search_ctx *temp_search_ctx;
	int err, rc;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;

	BUG_ON(!S_ISDIR(VFS_I(dir_ni)->i_mode));
	BUG_ON(NInoAttr(dir_ni));
	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ni);
	if (IS_ERR(m)) 
	{
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return ERR_MREF(PTR_ERR(m));
	}
	/* Allocate and initilize the temp search context **/
	temp_search_ctx = ntfs_attr_get_search_ctx(dir_ni, m);
	if (unlikely(!temp_search_ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_search_attr_index_root(temp_search_ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	ntfs_debug("Entering Phase 1.");
	old_vcn = VCN_INDEX_ROOT_PARENT;

	/* Phase 1: 
	 * Walk through the Index Root and try to locate the Index Entry ,
	 * return 0 means perfectly match */
	ictx->base_ni = dir_ni;
	err = _ntfs_ir_lookup_by_name(uname,uname_len,
			temp_search_ctx,
			/* output */ &ie, 
			/* output */ ictx);
	if(!err)
	{
		ictx->parent_vcn[ictx->pindex] = old_vcn;
		ntfs_debug("Locate the file in Index Root, Not really error.");
		return err;
	}
	else if (err < 0 )
	{
		ntfs_debug("_ntfs_ir_lookup_by_name error");
	}
	else if (!(ie->flags & INDEX_ENTRY_NODE)) 
	{
		/*
		 * We have finished with this index without success. Check for the
		 * presence of a child node and if not present return -ENOENT, unless
		 * we have got a matching name cached in name in which case return the
		 * mft reference associated with it.
		 */
		ntfs_debug("Entry not found in INDEX_ROOT and there is no subnode");
		/* return with dir_ni mapped and locked.
		 * if we need to modify it,
		 * unmap it first.*/
		return  -ENOENT;
	}
	else
	{
		/* Consistency check: Verify that an index allocation exists. */
		if (!NInoIndexAllocPresent(dir_ni)) {
			ntfs_error(sb, "No index allocation attribute but index entry "
					"requires one. Directory inode 0x%lx is "
					"corrupt or driver bug.", dir_ni->mft_no);
			goto err_out;
		}
		/* Child node present, descend into it. */
		/* continue to check the subnode */
	}

	ntfs_debug("Entering Phase 2.");
	/* Phase 2:
	 * searching in Index_Allocation , accroding to the VCN */
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = ntfs_ie_get_subnode_pos(ie);
	/* The mapping of the directory is only for the INDEX_ALLOCATION */
	ia_mapping = VFS_I(dir_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record. Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(temp_search_ctx);
	unmap_mft_record(dir_ni);
	m = NULL;
	temp_search_ctx = NULL;
descend_into_child_node:
	ntfs_dump_index_entry(ie);
	ictx->parent_vcn[ictx->pindex] = old_vcn;
	if (ntfs_icx_parent_inc(ictx)) {
		goto err_out;
	}
	old_vcn = vcn;
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	ntfs_debug("Mapping page for VCN 0x%llx",vcn);
	page = ntfs_map_page(ia_mapping, ntfs_vcn_to_pos(vcn,dir_ni) >> PAGE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map directory index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + offset_in_page(ntfs_vcn_to_pos(vcn,dir_ni)));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug.", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)vcn, dir_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				dir_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + dir_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				dir_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	/* The first index entry. */
	ie = ntfs_ie_get_first(&ia->index);

	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = ntfs_ie_get_next(ie)) 
	{
		ntfs_dump_index_entry(ie);
		/* Bounds check. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end) {
			ntfs_error(sb, "Index entry out of bounds in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/*FIXME:Gzged set */
		ictx->is_in_root = false;
		ictx->ia = ia;
		ictx->entry = ie;
		ictx->actx = NULL;
		ictx->base_ni = NULL;
		ictx->page = page;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ntfs_ie_end(ie))
		{
			ntfs_debug("Walk till end but not found.");
		       	break;
		}
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		BUG_ON(!PageLocked(ictx->page));

		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) {
found_it2:
			set_index_context_with_result(ictx,ie);
			ictx->parent_vcn[ictx->pindex] = vcn;
			ntfs_debug("Done.");
			return PERFECT_MATCH;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it2;
	}
	/*
	 * We have finished with this index buffer without success. Check for
	 * the presence of a child node.
	 */
	if (ie->flags & INDEX_ENTRY_NODE) {
		if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
			ntfs_error(sb, "Index entry with child node found in "
					"a leaf node in directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/* Child node present, descend into it. */
		old_vcn = vcn;
		vcn = sle64_to_cpup((sle64*)((u8*)ie +
				le16_to_cpu(ie->length) - 8));
		if (vcn >= 0) {
			/* If vcn is in the same page cache page as old_vcn we
			 * recycle the mapped page. */
			if (old_vcn << vol->cluster_size_bits >>
					PAGE_SHIFT == vcn <<
					vol->cluster_size_bits >>
					PAGE_SHIFT)
				goto fast_descend_into_child_node;
			unlock_page(page);
			ntfs_unmap_page(page);
			goto descend_into_child_node;
		}
		ntfs_error(sb, "Negative child node vcn in directory inode "
				"0x%lx.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/*
	 * No child node present, return -ENOENT, unless we have got a matching
	 * name cached in name in which case return the mft reference
	 * associated with it.
	 */
	ntfs_debug("Entry not found.");
	err = -ENOENT;
	/* keep the page mapped and locked,
	 * but why ?
	 * TODO: make the lock requirment better to understand. **/
	return err;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (temp_search_ctx)
		ntfs_attr_put_search_ctx(temp_search_ctx);
	if (m)
		unmap_mft_record(dir_ni);
	ntfs_debug("done.");
	return err;
}
int ntfs_lookup_inode_by_filename (const FILE_NAME_ATTR *filename, 
		/* output */ ntfs_index_context *ictx)
{
	const ntfschar* uname = filename->file_name ;
	const int uname_len = filename->file_name_length;
/*	return _ntfs_index_lookup(uname,uname_len,ictx);*/
	return _ntfs_index_lookup_with_call_back(uname,uname_len,comparer_with_perfect_name,ictx);
}



/** 
 *  Find the median by going through all the entries
 */
static INDEX_ENTRY *ntfs_ie_get_median(INDEX_HEADER *ih)
{
	INDEX_ENTRY *ie, *ie_start;
	u8 *ie_end;
	int i = 0, median;
	
	ntfs_debug("Entering\n");
	
	ie = ie_start = ntfs_ie_get_first(ih);
	ie_end   = (u8 *)ntfs_ie_get_end(ih);
	
	while ((u8 *)ie < ie_end && !ntfs_ie_end(ie)) {
		ie = ntfs_ie_get_next(ie);
		i++;
	}
	/*
	 * NOTE: this could be also the entry at the half of the index block.
	 */
	median = i / 2 - 1;
	
	ntfs_debug("Total Index Entries of current Index_Header: %d  median: %d\n", i, median);
	
	for (i = 0, ie = ie_start; i <= median; i++)
		ie = ntfs_ie_get_next(ie);
	
	return ie;
}



/* Alloc and init the Index_Allocation
 * */
static INDEX_BLOCK *ntfs_ib_alloc(VCN ib_vcn, u32 ib_size, 
				  INDEX_HEADER_FLAGS node_type)
{
	INDEX_BLOCK *ib;
	int ih_size = sizeof(INDEX_HEADER);
	
	ntfs_debug("ib_vcn: %lld ib_size: %u\n", (long long)ib_vcn, ib_size);
	
	ib = kcalloc(1,ib_size,GFP_KERNEL );
	if (!ib)
		return NULL;
	
	ib->magic = magic_INDX;
	ib->usa_ofs = cpu_to_le16(sizeof(INDEX_BLOCK));
	ib->usa_count = cpu_to_le16(ib_size / NTFS_BLOCK_SIZE + 1);
	/* Set USN to 1 */
	*(le16 *)((char *)ib + le16_to_cpu(ib->usa_ofs)) = cpu_to_le16(1);
	ib->lsn = cpu_to_sle64(0);
	
	ib->index_block_vcn = cpu_to_sle64(ib_vcn);
	
	ib->index.entries_offset = cpu_to_le32((ih_size +
			le16_to_cpu(ib->usa_count) * 2 + 7) & ~7);
	ib->index.index_length = cpu_to_le32(0);
	ib->index.allocated_size = cpu_to_le32(ib_size - 
					       (sizeof(INDEX_BLOCK) - ih_size));
	ib->index.flags = node_type;
	
	return ib;
}	
/* Copy from [Median to end, including median]
 * To the new block, which will be allocated here.
 * */
static int ntfs_copy_context_tail(ntfs_index_context *icx, 
			     INDEX_ENTRY *median, VCN new_vcn)
{
	INDEX_ALLOCATION *src = icx->ia;
	u8 *ies_end;
	int tail_size, ret;
	INDEX_BLOCK *dst;
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
	
	ntfs_debug("Entering,copy to %lld\n",new_vcn);
	
	dst = ntfs_ib_alloc(new_vcn, bk_size, 
			    src->index.flags & NODE_MASK);
	if (!dst)
		return STATUS_ERROR;
	
	ies_end = (u8 *)ntfs_ie_get_end(&src->index);
	tail_size = ies_end - (u8 *)median;
	memcpy(ntfs_ie_get_first(&dst->index), median, tail_size);
	
	dst->index.index_length = cpu_to_le32(tail_size + 
					      le32_to_cpu(dst->index.entries_offset));
	/* dst includes the position and data of the new Index_Block ,
	other things we need, is the volume information*/ 
	if(!ntfs_prepare_directory_for_write(icx,dst)) /** allocate cluster on disk **/
	{
		ret = ntfs_directory_data_write(icx, dst);
	}
	else
	{
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "ntfs_prepare_directory_for_write failed");
	}
	kfree(dst);
	return ret;
}


#if 0
static int ntfs_ih_insert(INDEX_HEADER *ih, INDEX_ENTRY *orig_ie, VCN new_vcn, 
			  int pos)
{
	INDEX_ENTRY *ie_node, *ie;
	int ret = STATUS_ERROR;
	VCN old_vcn;
	
	ntfs_debug("Entering\n");
	
	ie = ntfs_ie_dup(orig_ie);
	if (!ie)
		return STATUS_ERROR;
	
	if (!(ie->flags & INDEX_ENTRY_NODE))
		if (ntfs_ie_add_vcn(&ie))
			goto out;

	ie_node = ntfs_ie_get_by_pos(ih, pos);
	old_vcn = ntfs_ie_get_vcn(ie_node);
	ntfs_ie_set_vcn(ie_node, new_vcn);
	
	ntfs_ie_insert(ih, ie, ie_node);
	ntfs_ie_set_vcn(ie_node, old_vcn);
	ret = STATUS_OK;
out:	
	kfree(ie);
	
	return ret;
}
#endif
#if 0 
static VCN ntfs_icx_parent_pos(ntfs_index_context *icx)
{
	        return icx->parent_pos[icx->pindex];
}
#endif

#if 0
static int ntfs_ir_insert_median(ntfs_index_context *icx, INDEX_ENTRY *median,
				 VCN new_vcn)
{
	u32 new_size;
	int ret;
	
	ntfs_debug("Entering\n");
	ntfs_dump_index_entry(median);
	
	/*
	icx->ir = ntfs_ir_lookup2(icx->idx_ni, icx->name, icx->name_len);
	if (!icx->ir)
		return STATUS_ERROR;
		*/

	new_size = le32_to_cpu(icx->ir->index.index_length) + 
			le16_to_cpu(median->length);
	if (!(median->flags & INDEX_ENTRY_NODE))
		new_size += sizeof(VCN);

	ret = ntfs_ir_make_space(icx, new_size);
	ntfs_debug("ret of ntfs_ir_make_space [%d]\n",ret);
	if (ret != STATUS_OK)
		return ret;
	
	/*
	icx->ir = ntfs_ir_lookup2(icx->ni, icx->name, icx->name_len);
	if (!icx->ir)
		return STATUS_ERROR;
		*/

	return ntfs_ih_insert(&icx->ir->index, median, new_vcn, 
			      ntfs_icx_parent_pos(icx));
}
#endif
#if 0
static VCN ntfs_icx_parent_vcn(ntfs_index_context *icx)
{
	        return icx->parent_vcn[icx->pindex];
}
#endif

/** 
 *  Find the last entry in the index block
 */
static INDEX_ENTRY *ntfs_ie_get_last(INDEX_ENTRY *ie, char *ies_end)
{
	ntfs_debug("Entering\n");
	
	while ((char *)ie < ies_end && !ntfs_ie_end(ie))
		ie = ntfs_ie_get_next(ie);
	
	return ie;
}

static int ntfs_cut_context_tail(ntfs_index_context *icx,
			    INDEX_ENTRY *ie,VCN new_vcn)
{
	/* The page of current ib is locked */
	INDEX_ALLOCATION *ib = icx->ia;
	char *ies_start, *ies_end;
	INDEX_ENTRY *ie_last;
	int ret = STATUS_ERROR;
	
	ntfs_debug("Entering\n");
	
	ies_start = (char *)ntfs_ie_get_first(&ib->index);
	ies_end   = (char *)ntfs_ie_get_end(&ib->index);
	
	ie_last   = ntfs_ie_get_last((INDEX_ENTRY *)ies_start, ies_end);

	memcpy(ie, ie_last, le16_to_cpu(ie_last->length));
	if (!(ie->flags & INDEX_ENTRY_NODE))
	{
		ie->flags |= INDEX_ENTRY_NODE;
		ie->length = cpu_to_le16(le16_to_cpu(ie->length) + sizeof(VCN));
	}
	ntfs_ie_set_vcn(ie, new_vcn);
	
	ib->index.index_length = cpu_to_le32(((char *)ie - ies_start) + 
		le16_to_cpu(ie->length) + le32_to_cpu(ib->index.entries_offset));

	ib->index.flags &= ~NODE_MASK;
	ib->index.flags |=  INDEX_NODE;


	/* Write to disk,no need to prepare*/
	ret = ntfs_directory_context_write(icx);
	if(!ret)
	{
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "ntfs_prepare_directory_for_write failed");
	}
	return ret;
}
/**
 * ntfs_ia_split - Split an INDEX_ALLOCATION
 * 
 * On success return STATUS_OK 
 */
int ntfs_split_current_index_allocation(ntfs_index_context *icx)
{			  
	INDEX_ALLOCATION *ia = icx->ia;
	INDEX_ENTRY *median;
	VCN new_vcn;
	int ret = STATUS_ERROR;

	median  = ntfs_ie_get_median(&ia->index);
	ntfs_dump_index_entry(median);
	new_vcn = ntfs_ibm_get_free(icx);
	if (new_vcn == -1)
		return -ENOSPC;
	/* Phase 1:
	 * * First of All, copy the Index_Entry in [median,end] 
	 * * to the new Index_Allocation block */ 
	if (ntfs_copy_context_tail(icx, median, new_vcn)) {
		/*TODO 
		 * ntfs_ibm_clear(icx, new_vcn);
		 * */
		return STATUS_ERROR;
	}
	else
	{
		ntfs_debug("Index Copy To tail finished well");
	}
	/* Phase 2: 
	 * * Clean up from the median to end
	 * * modify the median to point to the new block 
	 * * no need lock page of ia, because it is locked in lookup*/
	ret = ntfs_cut_context_tail(icx, median,new_vcn);
	if (ret != STATUS_OK) {
		/*TODO
		ntfs_ibm_clear(icx, new_vcn);
		*/
		ntfs_debug("Error will return %d",ret);
		return ret;
	}
	else
	{
		ntfs_debug("success will return %d",ret);
		return ret;
	}
}
