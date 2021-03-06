/*
 * index.h - Defines for NTFS kernel index handling.  Part of the Linux-NTFS
 *	     project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
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

#ifndef _LINUX_NTFS_INDEX_H
#define _LINUX_NTFS_INDEX_H

#include <linux/fs.h>

#include "ntfs.h"
#include "types.h"
#include "layout.h"
#include "attrib.h"
#include "mft.h"
#include "aops.h"

#define  VCN_INDEX_ROOT_PARENT  ((VCN)-2)
#define  MAX_PARENT_VCN         32
extern MFT_REF ntfs_lookup_inode_by_name(ntfs_inode *dir_ni,
		const ntfschar *uname, const int uname_len, ntfs_name **res);


/**
 * @idx_ni:	index inode containing the @entry described by this context
 * @entry:	index entry (points into @ir or @ia)
 * @data:	index entry data (points into @entry)
 * @data_len:	length in bytes of @data
 * @is_in_root:	'true' if @entry is in @ir and 'false' if it is in @ia
 * @ir:		index root if @is_in_root and NULL otherwise
 * @actx:	attribute search context if @is_in_root and NULL otherwise
 * @base_ni:	base inode if @is_in_root and NULL otherwise
 * @ia:		index block if @is_in_root is 'false' and NULL otherwise
 * @page:	page if @is_in_root is 'false' and NULL otherwise
 *
 * @idx_ni is the index inode this context belongs to.
 *
 * @entry is the index entry described by this context.  @data and @data_len
 * are the index entry data and its length in bytes, respectively.  @data
 * simply points into @entry.  This is probably what the user is interested in.
 *
 * If @is_in_root is 'true', @entry is in the index root attribute @ir described
 * by the attribute search context @actx and the base inode @base_ni.  @ia and
 * @page are NULL in this case.
 *
 * If @is_in_root is 'false', @entry is in the index allocation attribute and @ia
 * and @page point to the index allocation block and the mapped, locked page it
 * is in, respectively.  @ir, @actx and @base_ni are NULL in this case.
 *
 * To obtain a context call ntfs_index_ctx_get().
 *
 * We use this context to allow ntfs_index_lookup() to return the found index
 * @entry and its @data without having to allocate a buffer and copy the @entry
 * and/or its @data into it.
 *
 * When finished with the @entry and its @data, call ntfs_index_ctx_put() to
 * free the context and other associated resources.
 *
 * If the index entry was modified, call flush_dcache_index_entry_page()
 * immediately after the modification and either ntfs_index_entry_mark_dirty()
 * or ntfs_index_entry_write() before the call to ntfs_index_ctx_put() to
 * ensure that the changes are written to disk.
 */
typedef struct {
	/* For insert popurse */
	ntfs_inode * idx_ni;
	MFT_RECORD *m;/* map result of idx_ni */

	INDEX_ENTRY *entry;
	void *data;
	u16 data_len;
	bool is_in_root;
	INDEX_ROOT *ir;
	ntfs_attr_search_ctx *actx;
	ntfs_inode *base_ni;
	INDEX_ALLOCATION *ia;
	struct page *page;
	/* For perfect B tree split*/
	int parent_pos[MAX_PARENT_VCN];  /* parent entries' positions */
	VCN parent_vcn[MAX_PARENT_VCN]; /* entry's parent nodes */
	int pindex;          /* maximum it's the number of the parent nodes  */
	/* For lookup popurse 
	 * imperfect match name */
	ntfs_name* imperfect_match_name;
} ntfs_index_context;

extern ntfs_index_context *ntfs_index_ctx_get(ntfs_inode *idx_ni);
extern void ntfs_index_ctx_put(ntfs_index_context *ictx);
extern int _ntfs_ir_lookup_by_name(
		const ntfschar* uname,
		const int uname_len, 
		/* input */ ntfs_attr_search_ctx* temp_search_ctx,
		/* output */ INDEX_ENTRY** pie,
		/* output */ ntfs_index_context *ictx);
extern int ntfs_lookup_inode_by_index_entry (const INDEX_ENTRY *ie, ntfs_index_context *ictx);
extern int ntfs_lookup_inode_by_filename (const FILE_NAME_ATTR *filename, ntfs_index_context *ictx);
extern int ntfs_index_lookup(const void *key, const int key_len,
		ntfs_index_context *ictx);
extern int ntfs_search_attr_index_root( /* input & output */ntfs_attr_search_ctx *temp_search_ctx);

extern int _ntfs_index_lookup (const ntfschar* uname,const int uname_len,
		                /* output */ ntfs_index_context *ictx);

#ifdef NTFS_RW

extern int ntfs_split_current_index_allocation(ntfs_index_context *icx);

/**
 * ntfs_index_entry_flush_dcache_page - flush_dcache_page() for index entries
 * @ictx:	ntfs index context describing the index entry
 *
 * Call flush_dcache_page() for the page in which an index entry resides.
 *
 * This must be called every time an index entry is modified, just after the
 * modification.
 *
 * If the index entry is in the index root attribute, simply flush the page
 * containing the mft record containing the index root attribute.
 *
 * If the index entry is in an index block belonging to the index allocation
 * attribute, simply flush the page cache page containing the index block.
 */
static inline void ntfs_index_entry_flush_dcache_page(ntfs_index_context *ictx)
{
	if (ictx->is_in_root)
		flush_dcache_mft_record_page(ictx->actx->ntfs_ino);
	else
		flush_dcache_page(ictx->page);
}

/**
 * ntfs_index_entry_mark_dirty - mark an index entry dirty
 * @ictx:	ntfs index context describing the index entry
 *
 * Mark the index entry described by the index entry context @ictx dirty.
 *
 * If the index entry is in the index root attribute, simply mark the mft
 * record containing the index root attribute dirty.  This ensures the mft
 * record, and hence the index root attribute, will be written out to disk
 * later.
 *
 * If the index entry is in an index block belonging to the index allocation
 * attribute, mark the buffers belonging to the index record as well as the
 * page cache page the index block is in dirty.  This automatically marks the
 * VFS inode of the ntfs index inode to which the index entry belongs dirty,
 * too (I_DIRTY_PAGES) and this in turn ensures the page buffers, and hence the
 * dirty index block, will be written out to disk later.
 */
static inline void ntfs_index_entry_mark_dirty(ntfs_index_context *ictx)
{
	if (ictx->is_in_root)
		mark_mft_record_dirty(ictx->actx->ntfs_ino);
	else
		mark_ntfs_record_dirty(ictx->page,
				(u8*)ictx->ia - (u8*)page_address(ictx->page));
}

//extern int ntfs_ie_add(ntfs_index_context *icx, INDEX_ENTRY *ie);
extern int ntfs_ie_add(ntfs_inode *idx_ni, INDEX_ENTRY *ie);
extern VCN ntfs_ibm_get_free(ntfs_index_context *icx);

extern int ntfs_directory_context_write(ntfs_index_context *icx);
extern int ntfs_directory_data_write(ntfs_index_context *icx, INDEX_BLOCK *ib);

extern ssize_t ntfs_prepare_directory_for_write(ntfs_index_context *icx, INDEX_BLOCK *ib);
extern int ntfs_icx_parent_inc(ntfs_index_context *icx);
extern INDEX_ENTRY *ntfs_ie_dup(INDEX_ENTRY *ie);
extern int ntfs_ie_add_vcn(INDEX_ENTRY **ie);
extern void ntfs_ie_set_vcn(INDEX_ENTRY *ie, VCN vcn);
extern INDEX_ENTRY *ntfs_ie_get_by_pos(INDEX_HEADER *ih, int pos);
extern void ntfs_ie_insert(INDEX_HEADER *ih, INDEX_ENTRY *ie, INDEX_ENTRY *pos); 
extern VCN ntfs_ie_get_vcn(INDEX_ENTRY *ie);
//extern int ntfs_ir_make_space(ntfs_index_context *icx, int data_size);

void ntfs_dump_index_entry(INDEX_ENTRY* ie);






#endif /* NTFS_RW */
/**
 ** The little endian Unicode string $I30 as a global constant.
 **/
extern ntfschar I30[5];


/* INDEX_HEADER *ih
 */
#define ntfs_ie_get_first(ih) ((INDEX_ENTRY*)(((u8*)(ih)) + le32_to_cpu((ih)->entries_offset)))
#define ntfs_ie_get_end(ih) (((u8*)(ih)) + le32_to_cpu((ih)->index_length))

/* INDEX_ENTRY *ie
 */
#define ntfs_ie_end(ie) ((ie)->flags & INDEX_ENTRY_END || !(ie)->length)
#define ntfs_ie_get_next(ie) ((INDEX_ENTRY*)((char *)(ie) + le16_to_cpu((ie)->length)))
#define ntfs_ie_get_subnode_pos(ie) (sle64_to_cpup((sle64*)((u8*)(ie) + le16_to_cpu((ie)->length) - 8)))

/* ntfs_index_context *icx
 * s64 pos
 * */
#define ntfs_ib_pos_to_vcn(icx,pos) ( pos >> icx->idx_ni->itype.index.vcn_size_bits)
/* ntfs_index_context *icx
 * VCN vcn
 * */
#define ntfs_ib_vcn_to_pos(icx,vcn) ( vcn << icx->idx_ni->itype.index.vcn_size_bits)
/* size_t ntfs_vcn_to_pos(VCN vcn,ntfs_inode* ni) */
#define ntfs_vcn_to_pos(vcn,ni) ((vcn) << (ni)->itype.index.vcn_size_bits)

#define STATUS_OK	(0)
#define STATUS_ERROR	(-1)

extern void set_index_context_with_result(ntfs_index_context* ictx,INDEX_ENTRY* ie);
extern int ntfs_ir_truncate(ntfs_index_context *icx, int data_size);



#endif /* _LINUX_NTFS_INDEX_H */
