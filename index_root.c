#include <linux/slab.h>
#include "ntfs.h"
#include "inode.h"
#include "index.h"

static int ntfs_inode_refresh_ir_snapshot(ntfs_inode* dir_ntfs_inode)
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
	/*TODO:lock ctx before copy done*/
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
	{
		/*TODO: gain the lock of ir snapshot*/
		int current_ir_lenth = le32_to_cpu(ctx->attr->data.resident.value_length);
		char* current_ir = (u8*)ctx->attr + le16_to_cpu(ctx->attr->data.resident.value_offset);
		/* use rc as data length */
		if(!dir_ntfs_inode->ir_snapshot)
		{
			dir_ntfs_inode->ir_snapshot = kmalloc(current_ir_lenth, GFP_NOFS);
			if (unlikely(!dir_ntfs_inode->ir_snapshot)) {
				rc = -ENOMEM;
				goto out;
			}
		}
		else if(dir_ntfs_inode->ir_snapshot && 
				dir_ntfs_inode->ir_snapshot_length < current_ir_lenth)
		{
			kfree(dir_ntfs_inode->ir_snapshot);
			dir_ntfs_inode->ir_snapshot = kmalloc(current_ir_lenth, GFP_NOFS);
			if (unlikely(!dir_ntfs_inode->ir_snapshot)) {
				rc = -ENOMEM;
				goto out;
			}
		}
		else 
		{
			memset(dir_ntfs_inode->ir_snapshot,0,dir_ntfs_inode->ir_snapshot_length);
		}

		/* Copy the index root value (it has been verified in read_inode). */
		memcpy(dir_ntfs_inode->ir_snapshot, current_ir , current_ir_lenth);
		/*TODO: unlock of ir snapshot*/
		/*TODO:unlock ctx after copy done*/
	}
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
int index_root_iterate(struct inode *vdir,loff_t* p_skip_pos,
		                ie_looper func,void* parameter)
{
	int err;
	ntfs_inode *ndir = NTFS_I(vdir);
	err = ntfs_inode_refresh_ir_snapshot(ndir); /* alloc ir **/
	if(err)
	{
		return err;
	}
	/* Get the offset into the index root attribute. */
	ntfs_debug("Starting Handling Index Root");
	err = ntfs_index_walk_entry_in_header(vdir,&(ndir->ir_snapshot->index),
			p_skip_pos,
			func,parameter);
	return err;
}
