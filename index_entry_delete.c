/*
 * Index Entry Deleting code
 * Copyright (c) 2018 Gordon Zhigang Gao
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

#include <linux/dcache.h>
#include <linux/exportfs.h>
#include <linux/security.h>
#include <linux/slab.h>

#include "attrib.h"
#include "debug.h"
#include "dir.h"
#include "mft.h"
#include "ntfs.h"
#include "lcnalloc.h"
#include "index.h"




/*TODO:
  static int ntfs_index_rm_node(ntfs_index_context *icx)
  {
  int entry_pos, pindex;
  VCN vcn;
  INDEX_BLOCK *ib = NULL;
  INDEX_ENTRY *ie_succ, *ie, *entry = icx->entry;
  INDEX_HEADER *ih;
  u32 new_size;
  int delta, ret = STATUS_ERROR;

  ntfs_debug("Entering");

  if (!icx->ia_na) {
  icx->ia_na = ntfs_ia_open(icx, icx->ni);
  if (!icx->ia_na)
  return STATUS_ERROR;
  }

  ib = ntfs_malloc(icx->block_size);
  if (!ib)
  return STATUS_ERROR;

  ie_succ = ntfs_ie_get_next(icx->entry);
  entry_pos = icx->parent_pos[icx->pindex]++;
  pindex = icx->pindex;
descend:
vcn = ntfs_ie_get_vcn(ie_succ);
if (ntfs_ib_read(icx, vcn, ib))
goto out;

ie_succ = ntfs_ie_get_first(&ib->index);

if (ntfs_icx_parent_inc(icx))
goto out;

icx->parent_vcn[icx->pindex] = vcn;
icx->parent_pos[icx->pindex] = 0;

if ((ib->index.ih_flags & NODE_MASK) == INDEX_NODE)
goto descend;

if (ntfs_ih_zero_entry(&ib->index)) {
errno = EIO;
ntfs_log_perror("Empty index block");
goto out;
}

ie = ntfs_ie_dup(ie_succ);
if (!ie)
goto out;

if (ntfs_ie_add_vcn(&ie))
goto out2;

ntfs_ie_set_vcn(ie, ntfs_ie_get_vcn(icx->entry));

	if (icx->is_in_root)
		ih = &icx->ir->index;
	else
		ih = &icx->ib->index;

	delta = le16_to_cpu(ie->length) - le16_to_cpu(icx->entry->length);
	new_size = le32_to_cpu(ih->index_length) + delta;
	if (delta > 0) {
		if (icx->is_in_root) {
			ret = ntfs_ir_make_space(icx, new_size);
			if (ret != STATUS_OK)
				goto out2;
			
			ih = &icx->ir->index;
			entry = ntfs_ie_get_by_pos(ih, entry_pos);
			
		} else if (new_size > le32_to_cpu(ih->allocated_size)) {
			icx->pindex = pindex;
			ret = ntfs_ib_split(icx, icx->ib);
			if (ret == STATUS_OK)
				ret = STATUS_KEEP_SEARCHING;
			goto out2;
		}
	}

	ntfs_ie_delete(ih, entry);
	ntfs_ie_insert(ih, ie, entry);
	
	if (icx->is_in_root) {
		if (ntfs_ir_truncate(icx, new_size))
			goto out2;
	} else
		if (ntfs_icx_ib_write(icx))
			goto out2;
	
	ntfs_ie_delete(&ib->index, ie_succ);
	
	if (ntfs_ih_zero_entry(&ib->index)) {
		if (ntfs_index_rm_leaf(icx))
			goto out2;
	} else 
		if (ntfs_ib_write(icx, ib))
			goto out2;

	ret = STATUS_OK;
out2:
	free(ie);
out:
	free(ib);
	return ret;
}
*/

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
#define ntfs_ih_one_entry(ih) (ntfs_ih_numof_entries(ih) == 1)
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
/** 
 * 20091014 First line is writen
 * 2018.Oct.24 we found it will cause system hang
 * and try to fix it**/
static int ntfs_index_remove(ntfs_inode *ni, const void *key, const int keylen)
{
	int ret = STATUS_ERROR;
	ntfs_index_context *icx;

	if (!key)
	{
		ntfs_debug("Could not perform deleting via NULL key");
		return -1;
	}

	icx = ntfs_index_ctx_get(ni);
	if (!icx)
	{
		ntfs_debug("Creating temporary searching conetext fail...");
		return -1;
	}

	while (1) 
	{
		/* Try get the Entry for Key */
		if ( (ret = ntfs_lookup_inode_by_filename (key, icx) ) )
		{
			/* If there is no Entry*/
			ntfs_debug("ntfs_lookup_inode_by_key faild ...");
			goto err_out;
		}

		/*There is Entry in icx , remove it now*/
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

/**
 * ntfs_delete - remove NTFS inode of the target from the NTFS inode of the folder
 * @ni:	target of deleting
 * @dir_ni: folder of the target
 *
 * Return 0 on success or errno 
 * 
 * Gzged port from ntfs-3g
 */
static int ntfs_delete(ntfs_inode *ni, ntfs_inode *dir_ni )
{
	ntfs_attr_search_ctx *actx = NULL;
	MFT_RECORD* mrec;
	FILE_NAME_ATTR *fn = NULL;
	ntfs_volume* vol=ni->vol;
	int err = 0;

	ntfs_debug("Entering");
	BUG_ON(!ni);
	BUG_ON(!dir_ni);

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		mrec = NULL;
		goto err_out;
	}

	if ( (mrec->flags & MFT_RECORD_IS_DIRECTORY) )
	{
		ntfs_debug("Deleting Folder is not supported, cancelling.");
		err=  -EINVAL;
		goto err_out;
	}

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;
	if (dir_ni->nr_extents == -1)
		dir_ni = dir_ni->ext.base_ntfs_ino;

	/*
	 * Search for FILE_NAME attribute with such name. If it's in POSIX or
	 * WIN32_AND_DOS namespace, then simply remove it from index and inode.
	 *
	 * If filename in DOS or in WIN32 namespace, doesn't support now
	 * TODO: Port the DOS name support from ntfs-3g
	 */
	actx = ntfs_attr_get_search_ctx(ni, mrec);
	if (!actx)
	{
		ntfs_debug("ntfs_attr_get_search_ctx Failed.");
		goto err_out;
	}
	while (!ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, actx)) {

		fn = (FILE_NAME_ATTR*)((u8*)actx->attr +
				le16_to_cpu(actx->attr->data.resident.value_offset));
		
		/* Ignore hard links from other directories */
		if (dir_ni->mft_no != MREF_LE(fn->parent_directory)) {
			ntfs_debug("MFT record numbers don't match "
				       "(%llu != %llu)", 
				       (long long unsigned)dir_ni->mft_no, 
				       (long long unsigned)MREF_LE(fn->parent_directory));
			continue;
		}
		     
		break;
	}
	
	if ( (err = ntfs_index_remove(dir_ni, fn, 
		le32_to_cpu(actx->attr->data.resident.value_length)) ) )
	{
		ntfs_debug("ntfs_index_remove error.");
		goto err_out;
	}
	
	mrec->link_count = cpu_to_le16(le16_to_cpu( mrec->link_count) - 1);

	flush_dcache_mft_record_page(ni);
	mark_mft_record_dirty(ni);

	ntfs_attr_put_search_ctx(actx);

	actx = ntfs_attr_get_search_ctx(ni, mrec);
	
	err =  STATUS_OK ;
	while (!ntfs_attrs_walk(actx)) 
	{
		if (actx->attr->non_resident) 
		{
			err = __ntfs_cluster_free(ni, 0, -1, actx, false);
			if (unlikely(err < 0)) 
			{
				ntfs_error(vol->sb, "Failed to release cluster(s) (error code "
						"%lli).  Unmount and run chkdsk to recover "
						"the lost cluster(s).", (long long)err);
				NVolSetErrors(vol);
				err = 0;
			}
			flush_dcache_mft_record_page(actx->ntfs_ino);
			mark_mft_record_dirty(actx->ntfs_ino);
		}
	}
	if (err ) 
	{
		ntfs_debug("Attribute enumeration failed.  "
				"Probably leaving inconsistent metadata.\n");
	}
	/* All extents should be attached after attribute walk. */
	if (ni->nr_extents)
	{
		ntfs_error(vol->sb,"need use ntfs_extent_mft_record_free. not support now ");
	}

	if (ntfs_mft_record_free(ni->vol, ni,mrec)) 
	{
		err = -EIO;
		ntfs_debug("Failed to free base MFT record.  "
				"Leaving inconsistent metadata.\n");
	}

	flush_dcache_mft_record_page(ni);
	mark_mft_record_dirty(ni);

	unmap_mft_record(ni);
	ni = NULL;
	mrec=NULL;

err_out:
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (mrec)
		unmap_mft_record(ni);
	if (err) 
	{
		ntfs_debug("Could not delete file");
		return err;
	}
	else
	{
		ntfs_debug("Done.");
		return 0;
	}
}

/**
 * ntfs_unlink_inode - remove dentry from the inode
 * @pi:	folder inode
 * @pd:	dentry that to be removed
 *
 * Delete NTFS inode of pd->d_inode under folder inode
 * decrease the link count of pd->d_inode
 *
 * Return 0 on success or errno from ntfs_delete 
 */
extern int ntfs_unlink_vfs_inode(struct inode *pi,struct dentry *pd)
{
	int err ;

	ntfs_debug("Entering");

	err = ntfs_delete(NTFS_I(pd->d_inode),NTFS_I(pi));
	if(err)
	{
		ntfs_debug("Faile");
	}
	else
	{
		/** TODO: Set dirty after setting change time 
			if the file still exist ?**/
		pd->d_inode->i_ctime = pi->i_ctime;
		inode_dec_link_count(pi); 
		ntfs_debug("Done");
	}
	return err;
}
