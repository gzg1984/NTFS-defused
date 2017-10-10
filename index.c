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
static VCN ntfs_ibm_get_free(ntfs_index_context *icx)
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

static int ntfs_ib_write(ntfs_index_context *icx, INDEX_BLOCK *ib)
{
	s64 ret;
	s64 status;
       	s64 vcn = sle64_to_cpu(ib->index_block_vcn);
	const s64 pos = ntfs_ib_vcn_to_pos(icx, vcn);
       	const s64 bk_cnt = 1;
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
       	void *src = ib;
	s64 written;
       	s64 i;
	struct address_space *mapping = VFS_I(idx_ni)->i_mapping;
	int err;
	struct page *pages[NTFS_MAX_PAGES_PER_CLUSTER];
	struct page *cached_page = NULL;

	ntfs_debug("vcn: %lld\n", (long long)vcn);
	ntfs_debug("Entering for inode 0x%llx, pos 0x%llx.\n", (unsigned long long)idx_ni->mft_no, 
			(long long)pos);
	if ( bk_size % NTFS_BLOCK_SIZE) 
	{
		return -EINVAL;
	}
	err = pre_write_mst_fixup((NTFS_RECORD*) ((u8*)src ), bk_size);
	if (err < 0) {
		/* Abort write at this position. */
		ntfs_error(VFS_I(icx->idx_ni)->i_sb, "%s #1", __FUNCTION__);
		if (!i)
			return err;
	}
	/***************************************/
	{
		pgoff_t start_idx = pos >> PAGE_SHIFT;

		/* Get and lock @do_pages starting at index @start_idx. */
		status = __ntfs_grab_cache_pages(mapping, start_idx, 1 /* only handle 1 page */,
				pages, &cached_page);
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
		unlock_page(pages[0]);
		put_page(pages[0]);
		if (unlikely(status < 0))
			return -EINVAL;
		cond_resched();
	}


	/*********************************************/

	/* Quickly deprotect the data again. */
	post_write_mst_fixup((NTFS_RECORD*)((u8*)src ));

	if (written != bk_size)
	{
		return STATUS_ERROR;
	}
	else
	{
		return STATUS_OK;
	}
}

static int ntfs_ib_copy_tail(ntfs_index_context *icx, INDEX_BLOCK *src,
			     INDEX_ENTRY *median, VCN new_vcn)
{
	u8 *ies_end;
	INDEX_ENTRY *ie_head;		/* first entry after the median */
	int tail_size, ret;
	INDEX_BLOCK *dst;
        ntfs_inode *idx_ni=icx->idx_ni;
       	const u32 bk_size  = idx_ni->itype.index.block_size;
	
	ntfs_debug("Entering\n");
	
	dst = ntfs_ib_alloc(new_vcn, bk_size, 
			    src->index.flags & NODE_MASK);
	if (!dst)
		return STATUS_ERROR;
	
	ie_head = ntfs_ie_get_next(median);
	
	ies_end = (u8 *)ntfs_ie_get_end(&src->index);
	tail_size = ies_end - (u8 *)ie_head;
	memcpy(ntfs_ie_get_first(&dst->index), ie_head, tail_size);
	
	dst->index.index_length = cpu_to_le32(tail_size + 
					      le32_to_cpu(dst->index.entries_offset));
	/* dst includes the position and data of the new Index_Block ,
	other things we need, is the volume information*/ 
	ret = ntfs_ib_write(icx, dst);

	kfree(dst);
	return ret;
}

/**
 * ntfs_ia_split - Split an INDEX_ALLOCATION
 * 
 * On success return STATUS_OK 
 */
static int ntfs_ia_split(ntfs_index_context *icx, INDEX_ALLOCATION *ib)
{			  
	INDEX_ENTRY *median;
	VCN new_vcn;
	int ret = STATUS_ERROR;

	ntfs_debug("Entering\n");
	
	/* First of All, copy the Index_Entry in [median,end] 
	 * to the new Index_Allocation block */ 
	median  = ntfs_ie_get_median(&ib->index);
	new_vcn = ntfs_ibm_get_free(icx);
	if (new_vcn == -1)
		return -ENOSPC;
	if (ntfs_ib_copy_tail(icx, ib, median, new_vcn)) {
		/*TODO 
		 * ntfs_ibm_clear(icx, new_vcn);
		 * */
		return STATUS_ERROR;
	}
/*
	
	if (ntfs_icx_parent_vcn(icx) == VCN_INDEX_ROOT_PARENT)
		ret = ntfs_ir_insert_median(icx, median, new_vcn);
	else
		ret = ntfs_ib_insert(icx, median, new_vcn);
	
	if (ret != STATUS_OK) {
		ntfs_ibm_clear(icx, new_vcn);
		return ret;
	}
	
	ret = ntfs_ib_cut_tail(icx, ib, median);
*/
	
	return ret;
}

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

	ntfs_debug("Entering");
	
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
	ret = ntfs_resident_attr_value_resize(icx->actx->mrec, icx->actx->attr, data_size + offsetof(INDEX_ROOT, index) );
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
	ntfs_debug("Done ");
	return ret;
}

/**
 *  Insert @ie index entry at @pos entry. Used @ih values should be ok already.
 */
static void ntfs_ie_insert(INDEX_HEADER *ih, INDEX_ENTRY *ie, INDEX_ENTRY *pos)
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
		ret = ntfs_lookup_inode_by_key(&ie->key, le16_to_cpu(ie->key_length), 
					 icx /*output*/ );
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
				ntfs_debug("ntfs_ir_make_space err ");
				goto err_out;
			}
			else
			{
				ntfs_debug("ntfs_ir_make_space done ");
			}
		} 
		else 
		{
			ret = ntfs_ia_split(icx, icx->ia);
			if (ret )
			{
				ntfs_debug("ntfs_ib_split err ");
				goto err_out;
			}
		}
		
		/*FIXME: Gzged mod
		ntfs_inode_mark_dirty(icx->actx->ntfs_ino);
		***/
		/*FIXME: Gzged will fix these in furture */
		flush_dcache_mft_record_page(icx->actx->ntfs_ino);
		mark_mft_record_dirty(icx->actx->ntfs_ino);

		/*FIXME: Gzged mod ntfs_index_ctx_reinit(icx); ***/
		ntfs_index_ctx_put(icx);
		ntfs_index_ctx_get(idx_ni);
	}
	
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
		if ( (ret = ntfs_lookup_inode_by_key (key, keylen, icx) ) )
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

