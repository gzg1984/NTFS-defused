#include <linux/slab.h>
#include "ntfs.h"
#include "inode.h"
#include "index.h"
static char* attr_type_string(ATTR_TYPE type)
{
	switch(type)
	{
		case AT_UNUSED:
			return "AT_UNUSED";
		case AT_STANDARD_INFORMATION:
			return "AT_STANDARD_INFORMATION";
		case AT_INDEX_ROOT:
			return "AT_INDEX_ROOT";
		case AT_INDEX_ALLOCATION:
			return "AT_INDEX_ALLOCATION";
		case AT_ATTRIBUTE_LIST:
			return "AT_ATTRIBUTE_LIST";
		case AT_FILE_NAME:
			return "AT_FILE_NAME";
		case AT_DATA:
			return "AT_DATA";
		default:
			return "Unknown";
	}
	return ":)";
	/*
					AT_OBJECT_ID                    = cpu_to_le32(      0x40),
					AT_SECURITY_DESCRIPTOR          = cpu_to_le32(      0x50),
					AT_VOLUME_NAME                  = cpu_to_le32(      0x60),
					AT_VOLUME_INFORMATION           = cpu_to_le32(      0x70),
					AT_BITMAP                       = cpu_to_le32(      0xb0),
					AT_REPARSE_POINT                = cpu_to_le32(      0xc0),
					AT_EA_INFORMATION               = cpu_to_le32(      0xd0),
					AT_EA                           = cpu_to_le32(      0xe0),
					AT_PROPERTY_SET                 = cpu_to_le32(      0xf0),
					AT_LOGGED_UTILITY_STREAM        = cpu_to_le32(     0x100),
					AT_FIRST_USER_DEFINED_ATTRIBUTE = cpu_to_le32(    0x1000),
					AT_END                          = cpu_to_le32(0xffffffff)
					*/

}
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
		default:
			return ":)";
	}
	return ":)";
	/*
	 *COLLATION_NTOFS_SID             = cpu_to_le32(0x11),
	 *COLLATION_NTOFS_SECURITY_HASH   = cpu_to_le32(0x12),
	 *COLLATION_NTOFS_ULONGS          = cpu_to_le32(0x13),
	 */
}
static void debug_show_ih(const char* const prefix,const INDEX_HEADER* const ih)
{
#ifdef DEBUG
	printk("%sINDEX_HEADER\n",prefix);
	printk("%s\t[......]\n",prefix);
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
