#include <linux/slab.h>
#include "ntfs.h"
#include "inode.h"
#include "index.h"
static char* collation_rule_string(COLLATION_RULE rule)
{
	switch(rule)
	{
		case COLLATION_BINARY:
			return "COLLATION_BINARY";
		case COLLATION_FILE_NAME:
			return "COLLATION_FILE_NAME";
		case COLLATION_UNICODE_STRING:
			return "COLLATION_UNICODE_STRING";
		case COLLATION_NTOFS_ULONG:
			return "COLLATION_NTOFS_ULONG";
		case COLLATION_NTOFS_SID:
			return "COLLATION_NTOFS_SID";
		case COLLATION_NTOFS_SECURITY_HASH:
			return "COLLATION_NTOFS_SECURITY_HASH";
		case COLLATION_NTOFS_ULONGS:
			return "COLLATION_NTOFS_ULONGS";
		default:
			return "Unknown";
	}
	return "Error";
}
static void debug_show_ih(const char* const prefix,const INDEX_HEADER* const ih)
{
#ifdef DEBUG
	printk("%sINDEX_HEADER:\n",prefix);
	printk("%s\tOffset to first Index Entry:%d\n",prefix,ih->entries_offset);
	printk("%s\tTotal size of the Index Entries:%d\n",prefix,ih->index_length);
	printk("%s\tAllocated size of the Node:%d\n",prefix,ih->allocated_size);
	printk("%s\tNon-leaf node Flag:%X\n",prefix,ih->flags);
	/*TODO:show INDEX_HEADER_FLAGS */
#endif
}
static void debug_show_ir(const INDEX_ROOT* const ir)
{
#ifdef DEBUG
	printk("INDEX_ROOT\n");
	printk("\tAttribute Type:%X[%s]\n",ir->type,attr_type_string(ir->type));
	printk("\tCollation Rule:%X[%s]\n",ir->collation_rule,collation_rule_string(ir->collation_rule));
	printk("\tBytes per Index Record:%d\n",ir->index_block_size);
	printk("\tClusters per Index Record:%d\n",ir->clusters_per_index_block);
	printk("\tIndex Node Header:");
	debug_show_ih("\t",&(ir->index));
#endif
}
static int lock_refresh_ir_snapshot_from_attr(ntfs_inode* ni,ATTR_REC* ir_attr)
{

	/*TODO:lock ctx before copy done*/
	/*TODO: gain the lock of ir snapshot*/
	size_t current_ir_lenth = le32_to_cpu(ir_attr->data.resident.value_length);
	u8* current_ir = (u8*)ir_attr + le16_to_cpu(ir_attr->data.resident.value_offset);
	/* use rc as data length */
	if(!ni->ir_snapshot)
	{
		ni->ir_snapshot = kmalloc(current_ir_lenth, GFP_NOFS);
		if (unlikely(!ni->ir_snapshot)) {
			return  -ENOMEM;
		}
		ni->ir_snapshot_length = current_ir_lenth ;
	}
	else if(ni->ir_snapshot && 
			ni->ir_snapshot_length < current_ir_lenth)
	{
		kfree(ni->ir_snapshot);
		ni->ir_snapshot = kmalloc(current_ir_lenth, GFP_NOFS);
		if (unlikely(!ni->ir_snapshot)) {
			return -ENOMEM;
		}
		ni->ir_snapshot_length = current_ir_lenth ;
	}
	else 
	{
		memset(ni->ir_snapshot,0,ni->ir_snapshot_length);
	}

	/* Copy the index root value (it has been verified in read_inode). */
	memcpy(ni->ir_snapshot, current_ir , current_ir_lenth);
	debug_show_ir(ni->ir_snapshot);
	/*TODO: unlock of ir snapshot*/
	/*TODO:unlock ctx after copy done*/
	return  0 ;
}

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
	rc = lock_refresh_ir_snapshot_from_attr(dir_ntfs_inode,ctx->attr);
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
	ntfs_debug("Start iterating Index Root");
	err = ntfs_inode_refresh_ir_snapshot(ndir); /* alloc ir **/
	if(err)
	{
		return err;
	}
	/* Get the offset into the index root attribute. */
	err = ntfs_index_walk_entry_in_header(vdir,&(ndir->ir_snapshot->index),
			p_skip_pos,
			func,parameter);
	ntfs_debug("End iterating Index Root");
	return err;
}
