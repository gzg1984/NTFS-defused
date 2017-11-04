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

int ntfs_ir_make_space(ntfs_index_context *icx, int data_size);

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
				/*
			6	$Bitmap	 	包含卷的簇图（在用和空闲）
			7	$Boot	 	卷的引导记录
			8	$BadClus	 	列出在卷上的坏簇
			9	$Quota	NT	限额信息
			9	$Secure	2K	卷所用的安全描述符
			10	$UpCase	 	用于比较的大写字母表
			11	$Extend	2K	一个目录：$ObjId, $Quota, $Reparse, $UsnJrnl
			 	 	 	 
			12-15	<Unused>	 	标为在用但是空的
			16-23	<Unused>	 	标为未用
			 	 	 	 
			Any	$ObjId	2K	属于每一个文件的唯一标识部分
			Any	$Quota	2K	限额信息
			Any	$Reparse	2K	修复点信息
			Any	$UsnJrnl	2K	加密日志
			*/
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

	/*
		0x30	 	文件名 （$FILE_NAME）
		0x40	NT	卷版本 （$VOLUME_VERSION）
		0x40	2K	对象标识符 （$OBJECT_ID）
		0x50	 	安全描述符 （$SECURITY_DESCRIPTOR）
		0x60	 	卷名 （$VOLUME_NAME）
		0x70	 	卷信息 （$VOLUME_INFORMATION）
		0x80	 	数据 （$DATA）
		0x90	 	根索引 （$INDEX_ROOT）
		0xB0	 	位图 （$BITMAP）
		0xC0	NT	符号链接 （$SYMBOLIC_LINK）
		0xC0	2K	修复点 （$REPARSE_POINT）
		0xD0	 	$EA_INFORMATION
		0xE0	 	$EA
		0xF0	NT	所有权设置 （$PROPERTY_SET）
		0x100	2K	日志作用流 （$LOGGED_UTILITY_STREAM）
		*/
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
			if (ictx->base_ni)
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
int ntfs_lookup_inode_by_name_in_index_allocation(       ntfs_volume *vol,ntfs_attr_search_ctx *temp_search_ctx,
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
MFT_REF ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
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
	ntfs_debug("descend_into_child_node vcn %d\n",vcn);
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
	ntfs_debug("fast_descend_into_child_node vcn %d\n",vcn);
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
	rc =  ntfs_lookup_inode_by_name_in_index_allocation(vol,temp_search_ctx,
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

#if 0

// TODO: (AIA)
// The algorithm embedded in this code will be required for the time when we
// want to support adding of entries to directories, where we require correct
// collation of file names in order not to cause corruption of the filesystem.

/**
 * ntfs_lookup_inode_by_name - find an inode in a directory given its name
 * @dir_ni:	ntfs inode of the directory in which to search for the name
 * @uname:	Unicode name for which to search in the directory
 * @uname_len:	length of the name @uname in Unicode characters
 *
 * Look for an inode with name @uname in the directory with inode @dir_ni.
 * ntfs_lookup_inode_by_name() walks the contents of the directory looking for
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
 * Note, @uname_len does not include the (optional) terminating NULL character.
 */
u64 ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
		const int uname_len)
{
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	u64 mref;
	ntfs_attr_search_ctx *ctx;
	int err, rc;
	IGNORE_CASE_BOOL ic;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;

	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return ERR_MREF(PTR_ERR(m));
	}
	ctx = ntfs_attr_get_search_ctx(dir_ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL,
			0, ctx);
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
	ir = (INDEX_ROOT*)((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ctx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end)
			goto dir_err_out;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * If the current entry has a name type of POSIX, the name is
		 * case sensitive and not otherwise. This has the effect of us
		 * not being able to access any POSIX file names which collate
		 * after the non-POSIX one when they only differ in case, but
		 * anyone doing screwy stuff like that deserves to burn in
		 * hell... Doing that kind of stuff on NT4 actually causes
		 * corruption on the partition even when using SP6a and Linux
		 * is not involved at all.
		 */
		ic = ie->key.file_name.file_name_type ? IGNORE_CASE :
				CASE_SENSITIVE;
		/*
		 * If the names match perfectly, we are done and return the
		 * mft reference of the inode (i.e. the inode number together
		 * with the sequence number for consistency checking. We
		 * convert it to cpu format before returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, ic,
				vol->upcase, vol->upcase_len)) {
found_it:
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(dir_ni);
			return mref;
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
		goto found_it;
	}
	/*
	 * We have finished with this index without success. Check for the
	 * presence of a child node.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		/* No child node, return -ENOENT. */
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
	vcn = sle64_to_cpup((u8*)ie + le16_to_cpu(ie->length) - 8);
	ia_mapping = VFS_I(dir_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record. Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(dir_ni);
	m = NULL;
	ctx = NULL;
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
	ia = (INDEX_ALLOCATION*)(kaddr + ((vcn <<
			dir_ni->itype.index.vcn_size_bits) & ~PAGE_MASK));
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
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
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
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * If the current entry has a name type of POSIX, the name is
		 * case sensitive and not otherwise. This has the effect of us
		 * not being able to access any POSIX file names which collate
		 * after the non-POSIX one when they only differ in case, but
		 * anyone doing screwy stuff like that deserves to burn in
		 * hell... Doing that kind of stuff on NT4 actually causes
		 * corruption on the partition even when using SP6a and Linux
		 * is not involved at all.
		 */
		ic = ie->key.file_name.file_name_type ? IGNORE_CASE :
				CASE_SENSITIVE;
		/*
		 * If the names match perfectly, we are done and return the
		 * mft reference of the inode (i.e. the inode number together
		 * with the sequence number for consistency checking. We
		 * convert it to cpu format before returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, ic,
				vol->upcase, vol->upcase_len)) {
found_it2:
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			unlock_page(page);
			ntfs_unmap_page(page);
			return mref;
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
		vcn = sle64_to_cpup((u8*)ie + le16_to_cpu(ie->length) - 8);
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
	/* No child node, return -ENOENT. */
	ntfs_debug("Entry not found.");
	err = -ENOENT;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(dir_ni);
	return ERR_MREF(err);
dir_err_out:
	ntfs_error(sb, "Corrupt directory. Aborting lookup.");
	goto err_out;
}

#endif

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


static s64 ntfs_ibm_vcn_to_pos(ntfs_index_context *icx, VCN vcn)
{
        return ntfs_ib_vcn_to_pos(icx, vcn) / icx->idx_ni->itype.index.block_size;
}
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
	//int bit;
	s64 vcn;
        //s64 byte;
       	//s64 size;
        s64 bmp_allocated_size;
	struct inode *bmp_vi;
        //loff_t bvi_size;
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

	return vcn;
iput_err_out:
err_out:
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
	s64 written;
	struct inode *vi = VFS_I(idx_ni);

	struct address_space *mapping = VFS_I(idx_ni)->i_mapping;
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
			pgoff_t start_idx = pos >> PAGE_SHIFT;
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

void ntfs_ie_insert(INDEX_HEADER *ih, INDEX_ENTRY *ie, INDEX_ENTRY *pos);
/**
 *  *  Insert @ie index entry at @pos entry. Used @ih values should be ok already.
{
	int ie_size = le16_to_cpu(ie->length);

	ntfs_debug("Entering\n");

	ih->index_length = cpu_to_le32(le32_to_cpu(ih->index_length) + ie_size);
	memmove((u8 *)pos + ie_size, pos,
			le32_to_cpu(ih->index_length) - ((u8 *)pos - (u8 *)ih) - ie_size);
	memcpy(pos, ie, ie_size);
}
 *   */

/**
 * ntfs_ir_truncate - Truncate index root attribute
 * 
 * Returns STATUS_OK, STATUS_RESIDENT_ATTRIBUTE_FILLED_MFT or STATUS_ERROR.
 */
static int ntfs_ir_truncate(ntfs_index_context *icx, int data_size)
{			  
	/*
	   ntfs_attr *na;
	   */
	int ret;

	/* icx->actx is released now */
	/* We should locate the INDEX_ROOT again **/
	ntfs_inode* dir_ni = icx->idx_ni ;
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	ntfs_attr_search_ctx *temp_search_ctx;


	ntfs_debug("Entering");
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
		ret = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	ret = ntfs_search_attr_index_root(temp_search_ctx);
	if (unlikely(ret)) {
		if (ret == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
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

		icx->ir->index.allocated_size = cpu_to_le32(data_size);

	} else if (ret == -EPERM)
	{
		ntfs_debug("Failed to truncate INDEX_ROOT");
	}

	/**
	  ntfs_attr_close(na);
	  */
err_out:
	if (m)
		unmap_mft_record(dir_ni);
	ntfs_debug("Will return %d",ret);
	return ret;
}

/**
 * ntfs_ir_make_space - Make more space for the index root attribute
 * 
 * On success return STATUS_OK or STATUS_KEEP_SEARCHING.
 * On error return STATUS_ERROR.
 */
int ntfs_ir_make_space(ntfs_index_context *icx, int data_size)
{			  
	int ret;
	ntfs_debug("Entering");
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
			ret = ntfs_split_current_index_allocation(icx);
			if (ret )
			{
				ntfs_debug("ntfs_ib_split err ret %d",ret);
				goto err_out;
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
	ntfs_ie_insert(ih, ie, icx->entry);

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

static int ntfs_ih_numof_entries(INDEX_HEADER *ih)
{
	int n;
	INDEX_ENTRY *ie;
	u8 *end;
	
	ntfs_debug("Entering");
	
	end = ntfs_ie_get_end(ih);
	ie = ntfs_ie_get_first(ih);
	for (n = 0; !ntfs_ie_end(ie) && (u8 *)ie < end; n++)
		ie = ntfs_ie_get_next(ie);
	return n;
}


static void ntfs_ie_delete(INDEX_HEADER *ih, INDEX_ENTRY *ie)
{
	u32 new_size;
	ntfs_debug("Entering");
	new_size = le32_to_cpu(ih->index_length) - le16_to_cpu(ie->length);
	ih->index_length = cpu_to_le32(new_size);
	memmove(ie, (u8 *)ie + le16_to_cpu(ie->length), new_size - ((u8 *)ie - (u8 *)ih));
	ntfs_debug("Done");
}
/**
 * ntfs_index_rm - remove entry from the index
 * @icx:	index context describing entry to delete
 *
 * Delete entry described by @icx from the index. Index context is always 
 * reinitialized after use of this function, so it can be used for index 
 * lookup once again.
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
static int ntfs_index_rm(ntfs_index_context *icx)
{
	INDEX_HEADER *ih;
	int ret = STATUS_OK;

	ntfs_debug("Entering");
	
	if (!icx || (!icx->ia && !icx->ir) || ntfs_ie_end(icx->entry)) 
	{
		ntfs_debug("Invalid arguments.");
		ret = -EINVAL;
		goto err_out;
	}
	if (icx->is_in_root)
	{
		ih = &icx->ir->index;
	}
	else
	{
		ih = &icx->ia->index;
	}
	
	if (icx->entry->flags & INDEX_ENTRY_NODE) 
	{ 
		ntfs_debug("INDEX_ENTRY_NODE Not supported now.");
		/* TODO:
		ret = ntfs_index_rm_node(icx); 
		*/
		ret =  -EOPNOTSUPP ;
		goto err_out;
	} 
	else if (icx->is_in_root || !ntfs_ih_one_entry(ih)) 
	{
		ntfs_ie_delete(ih, icx->entry);
		
		if (icx->is_in_root) 
		{
			ret = ntfs_ir_truncate(icx, le32_to_cpu(ih->index_length));
			if (ret != STATUS_OK)
			{
				goto err_out;
			}
			ntfs_debug("icx->is_in_root:Before flush_dcache_mft_record_page ");
			flush_dcache_mft_record_page(icx->actx->ntfs_ino);

			ntfs_debug("icx->is_in_root:Before mark_mft_record_dirty ");
			mark_mft_record_dirty(icx->actx->ntfs_ino);
		} 
		else
		{
			/* shut by Gzged
			if (ntfs_icx_ib_write(icx))
			{
				goto err_out;
			}
			*/
			ntfs_index_entry_flush_dcache_page(icx);
			ntfs_index_entry_mark_dirty(icx);
		}
	} 
	else 
	{
		ret =  -EOPNOTSUPP ;
		goto err_out;
		/** not support yet
		if (ntfs_index_rm_leaf(icx))
		{
			goto err_out;
		}
		**/
	}


err_out:
	ntfs_debug("Done ");
	return ret;
}
/** 20091014 **/
int ntfs_index_remove(ntfs_inode *ni, const void *key, const int keylen)
{
	int ret = STATUS_ERROR;
	ntfs_index_context *icx;

	icx = ntfs_index_ctx_get(ni);
	if (!icx)
	{
		return -1;
	}

	while (1) 
	{
		if ( (ret = ntfs_lookup_inode_by_filename (key, icx) ) )
		{
			ntfs_debug("ntfs_lookup_inode_by_key faild ...");
			goto err_out;
		}

		ret = ntfs_index_rm(icx);
		if (ret == STATUS_OK)
		{
			ntfs_debug("ntfs_index_rm Done");
			break;
		}
		else 
		{
			ntfs_debug("ntfs_index_rm faild");
			goto err_out;
		}
		/*
		flush_dcache_mft_record_page(icx->actx->ntfs_ino);
		mark_mft_record_dirty(icx->actx->ntfs_ino);
		*/
		/*FIXME:Gzged change
		ntfs_inode_mark_dirty(icx->actx->ntfs_ino);
		ntfs_index_ctx_reinit(icx);
		***************/
		ntfs_index_ctx_put(icx);
		icx=ntfs_index_ctx_get(ni);
	}

	/*
	ntfs_debug("Before flush_dcache_mft_record_page ");
	flush_dcache_mft_record_page(icx->actx->ntfs_ino);
	ntfs_debug("Before mark_mft_record_dirty ");
	mark_mft_record_dirty(icx->actx->ntfs_ino);
	*/
	/*
	ntfs_debug("Before ntfs_index_entry_flush_dcache_page ");
	ntfs_index_entry_flush_dcache_page(icx);
	ntfs_debug("Before ntfs_index_entry_mark_dirty ");
	ntfs_index_entry_mark_dirty(icx);
	*/

err_out:
	ntfs_debug("Delete Done");
	if(icx)
	{
		ntfs_index_ctx_put(icx);
	}
	return ret;
}

