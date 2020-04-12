/*
 * Index Entry Creating process
 *
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

#include "dir.h"
#include "../mft.h"
#include "../ntfs.h"
#include "../lcnalloc.h"
#include "../index.h"
#include <linux/version.h>
/**
 * ntfs_create_index_entry - add filename to directory index
 * @ni:		ntfs inode describing directory to which index add filename
 * @fn:		FILE_NAME attribute to add
 * @mref:	reference of the inode which @fn describes
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
static int ntfs_create_index_entry(ntfs_inode *dir_ni, 
	FILE_NAME_ATTR *fn, MFT_REF mref)
{
	INDEX_ENTRY *ie;
	int ret = -1;

	ntfs_debug("Entering");
	
	if (!dir_ni || !fn) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"Invalid arguments.");
		return -EINVAL;
	}
	
	{/** create and set INDEX_entry **/
		int fn_size, ie_size;
		fn_size = (fn->file_name_length * sizeof(ntfschar)) + sizeof(FILE_NAME_ATTR);
		ie_size = (sizeof(INDEX_ENTRY_HEADER) + fn_size + 7) & ~7;
		
		ie = kcalloc(1,ie_size,GFP_KERNEL);
		if (!ie)
		{
			return -ENOMEM;
		}

		ie->data.dir.indexed_file = cpu_to_le64(mref);
		ie->length 	 		= cpu_to_le16(ie_size);
		ie->key_length 	 	= cpu_to_le16(fn_size);
		ie->flags 	 		= cpu_to_le16(0);
		memcpy(&(ie->key.file_name), fn, fn_size);
	}/**  END of create and set INDEX_entry **/
	
	/* Insert Index_Entry into
	 * Index_Root or Index_Allocation */
	ret = ntfs_ie_add(dir_ni, ie);
	if(ie)
	{
		kfree(ie);
	}
	ntfs_debug("ntfs_create_index_entry done");
	return ret;
}

/* 
 * STANDARD_INFORMATION start 
 * Create STANDARD_INFORMATION attribute. Write STANDARD_INFORMATION
 * version 1.2, windows will upgrade it to version 3 if needed.
 */
static int ntfs_create_attr_standard_infomation( MFT_RECORD* const mrec,
		int* const pnew_offset )
{
	STANDARD_INFORMATION *si = NULL;
	ATTR_REC attr_si;
	int si_len;
	int attr_si_len;
	int err;
	char* new_record=(char*)mrec;

	/*** $STANDARD_INFORMATION (0x10)  **/
	si_len = offsetof(STANDARD_INFORMATION, ver) + sizeof(si->ver.v1.reserved12);
	si = kcalloc(1,si_len,GFP_KERNEL );
	if (!si) 
	{
		err = -ENOMEM;
		goto err_out;
	}
#define NTFS_TIME_OFFSET ((s64)(369 * 365 + 89) * 24 * 3600 * 10000000)
	si->creation_time = NTFS_TIME_OFFSET ;
	si->last_data_change_time = NTFS_TIME_OFFSET ;
	si->last_mft_change_time = NTFS_TIME_OFFSET ;
	si->last_access_time = NTFS_TIME_OFFSET ;

	/** set attr **/
	attr_si_len = offsetof(ATTR_REC, data) + sizeof(attr_si.data.resident) ;
	attr_si= (ATTR_REC )
	{
		.type = AT_STANDARD_INFORMATION ,
			.length = attr_si_len +  si_len ,
			.non_resident = 0,
			.name_length = 0,
			.name_offset = 0,
			.flags =  0 ,
			.instance = (mrec->next_attr_instance) ++ ,
			.data=
			{
				.resident=
				{
					.value_length = si_len,
					.value_offset = attr_si_len  ,
					.flags = 0 ,
				}
			},
	};
	/*
	   attr_si.data.resident.value_length=si_len
	   attr_si.data.resident.flags = 0;
	   */

	/* Add STANDARD_INFORMATION to inode. */
	memcpy(&(new_record[*pnew_offset]),&attr_si, attr_si_len  );
	(*pnew_offset) += attr_si_len;
	memcpy(&(new_record[*pnew_offset]),  si,  si_len);
	(*pnew_offset) += si_len;

	ntfs_debug("new_temp_offset [%d]",*pnew_offset);

	kfree(si);
	si=NULL;
	/* End of STANDARD_INFORMATION */
	return 0;
err_out:
	if(si)
	{
		kfree(si);
		si=NULL;
	}
	return err;
}

static int ntfs_create_attr_file_name(
		ntfs_inode *dir_ni,
		ntfschar *name,
		u8 name_len,
	ntfs_inode *ni,
	MFT_RECORD* mrec,
	int* pnew_temp_offset, /* output*/
	FILE_NAME_ATTR **pfn /* output */)
{
	char* temp_new_record=(char*)mrec; 
	FILE_NAME_ATTR *fn=*pfn;
	int err = 0;
	ATTR_REC attr_fna;
	int fn_len;
	int attr_fna_len;
	/** create FILE_NAME_ATTR **/
	fn_len = sizeof(FILE_NAME_ATTR) + name_len * sizeof(ntfschar);
	fn = kcalloc(1,fn_len,GFP_KERNEL);
	if (!fn) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"kcalloc failed for fn_len [%d]",fn_len);
		err = -ENOMEM;
		goto err_fail_alloc;
	}
	fn->parent_directory = MK_LE_MREF(dir_ni->mft_no, le16_to_cpu(dir_ni->seq_no));
	fn->file_name_length = name_len;
	fn->file_name_type = FILE_NAME_POSIX;
	fn->creation_time = NTFS_TIME_OFFSET;
	fn->last_data_change_time = NTFS_TIME_OFFSET;
	fn->last_mft_change_time = NTFS_TIME_OFFSET;
	fn->last_access_time = NTFS_TIME_OFFSET;
	fn->data_size = cpu_to_sle64(ni->initialized_size);
	fn->allocated_size = cpu_to_sle64(ni->allocated_size);
	memcpy(fn->file_name, name, name_len * sizeof(ntfschar));

	/* Create FILE_NAME attribute. */
	attr_fna_len = offsetof(ATTR_REC, data) + sizeof(attr_fna.data.resident) ;
	attr_fna=(ATTR_REC) 
	{
		.type = AT_FILE_NAME ,
			.length = ( attr_fna_len + fn_len + 7 ) & ~7 ,
			.non_resident = 0,
			.name_length = 0,
			.name_offset = 0,
			.flags =  RESIDENT_ATTR_IS_INDEXED ,
			.instance = (mrec->next_attr_instance) ++ ,
			.data=
			{
				.resident=
				{
					.value_length = fn_len,
					.value_offset = attr_fna_len  ,
					.flags = 0 ,
				}
			},
	};

	/** insert FILE_NAME into new_file_record **/
	memcpy(&(temp_new_record[*pnew_temp_offset]) , &attr_fna,  attr_fna_len);
	memcpy(&(temp_new_record[*pnew_temp_offset + attr_fna_len]),fn,fn_len);
	*pnew_temp_offset += attr_fna.length;

	ntfs_debug("new_temp_offset [%d]",*pnew_temp_offset);
	*pfn=fn; /* setting the output FILE_NAME pointer */

err_fail_alloc:
	return err;
}
/* start of $END 
 * $AT_END              = cpu_to_le32(0xffffffff) */
static void ntfs_create_attr_end( MFT_RECORD* const mrec,
		int* const pnew_offset )
{
	char* new_record=(char*)mrec;
	ATTR_REC attr_end ;
	int attr_end_len= offsetof(ATTR_REC, data) + sizeof(attr_end.data.resident) ;
	attr_end=(ATTR_REC) 
	{
		.type = AT_END ,
			.length = attr_end_len ,
			.non_resident = 0,
			.name_length = 0,
			.name_offset = 0,
			.flags =  0 ,
			.instance = (mrec->next_attr_instance) ++ ,
			.data=
			{
				.resident=
				{
					.value_length = 0,
					.value_offset = attr_end_len  ,
					.flags = 0 ,
				}
			},
	};
	/** insert END into new_file_record **/
	memcpy(&(new_record[*pnew_offset]),&attr_end, attr_end_len);
	(*pnew_offset) += attr_end_len ;

	ntfs_debug("new_temp_offset [%d]",*pnew_offset);

} 
/* start of DATA 
 *   $DATA (0x80)  */
static void ntfs_create_attr_data( MFT_RECORD* const mrec,
		int* const pnew_offset )
{
	char* new_record=(char*)mrec;
	ATTR_REC attr_data;
	int attr_data_len= offsetof(ATTR_REC, data) + sizeof(attr_data.data.resident) ;
	attr_data=(ATTR_REC) 
	{
		.type = AT_DATA ,
		.length = attr_data_len,
		.non_resident = 0,
		.name_length = 0,
		.name_offset = 0,
		.flags =  0 ,
		.instance = (mrec->next_attr_instance) ++ ,
		.data=
		{
			.resident=
			{
				.value_length = 0,
				.value_offset = attr_data_len  ,
				.flags = 0 ,
			}
		},
	};
	debug_show_attr(&attr_data);
	/** insert DATA into new_file_record **/
	memcpy(&(new_record[*pnew_offset]),&attr_data, attr_data_len );
	(*pnew_offset) += attr_data_len ;
}
#define const_cpu_to_le16(x)    ((le16) __constant_cpu_to_le16(x))
#define const_cpu_to_le32(x)    ((le32) __constant_cpu_to_le32(x))

static void ntfs_create_attr_dir(ntfs_inode *new_dir_ntfs_inode,const ntfs_volume * const vol,MFT_RECORD* const mrec,
		int* const pnew_offset )
{
	char* new_record=(char*)mrec;
	const int attr_start = *pnew_offset;
	/* Create INDEX_ROOT attribute. */
	int index_len = sizeof(INDEX_HEADER) + sizeof(INDEX_ENTRY_HEADER);
	int ir_len = offsetof(INDEX_ROOT, index) + index_len;
	ntfschar NTFS_INDEX_I30[5] = { const_cpu_to_le16('$'), const_cpu_to_le16('I'),
		const_cpu_to_le16('3'), const_cpu_to_le16('0'),
		const_cpu_to_le16('\0') };
	int attr_ir_len= sizeof(ATTR_REC) + 
		((4/*name length*/ * sizeof(ntfschar) + 7) & ~7) + ((ir_len + 7) & ~7);
	ATTR_REC attr_index_root;

	/* Create INDEX_ROOT attribute. */
	/* 这里只是数据内容，不是完整的attr.
	 * 需要针对dir做一个完整的attr*/
	INDEX_ROOT ir = (INDEX_ROOT) 
	{
		.type = AT_FILE_NAME,
			.collation_rule = COLLATION_FILE_NAME,
		.index_block_size = cpu_to_le32(vol->index_record_size),
		.index=
		{
			.entries_offset = const_cpu_to_le32(sizeof(INDEX_HEADER)),
			.index_length = cpu_to_le32(index_len),
			.allocated_size = cpu_to_le32(index_len),
		}
	};
	if (vol->cluster_size <= vol->index_record_size)
		ir.clusters_per_index_block = vol->index_record_size >> vol->cluster_size_bits;
	else                    
		ir.clusters_per_index_block = vol->index_record_size >> NTFS_BLOCK_SIZE_BITS;

	attr_index_root=(ATTR_REC) 
	{
		.type = AT_INDEX_ROOT ,
			.length = attr_ir_len,
			.non_resident = 0,
			.name_length = 4,
			.name_offset = sizeof(ATTR_REC),
			.flags =  const_cpu_to_le16(0) ,
			.instance = (mrec->next_attr_instance) ++ ,
			.data=
			{
				.resident=
				{
					.value_length = cpu_to_le32(ir_len),
					.value_offset = cpu_to_le16(attr_ir_len - ((ir_len + 7) & ~7))  ,
					.flags = 0 ,
				}
			},
	};
	/** insert ATTR into new_file_record **/
	ntfs_debug("ATTR Header of Index Root:Overwrite offset from [%d] to [%d]", *pnew_offset , (*pnew_offset)+attr_ir_len-1);
	memcpy(&(new_record[*pnew_offset]),&attr_index_root, attr_ir_len );
	{
		int name_start = (*pnew_offset)+ le16_to_cpu(attr_index_root.name_offset);
		ntfs_debug("Attr Name: Overwrite offset from [%d] to [%lu]", name_start , name_start + (sizeof(ntfschar) * 4));
		memcpy(&(new_record[name_start]), NTFS_INDEX_I30, sizeof(ntfschar) * 4);
	}
	ntfs_dump_attr_name("After Copying name",&new_record[attr_start]);

	(*pnew_offset) += attr_ir_len ;


	/** insert INDEX ROOT into ATTR value **/
	{
		int ir_start=attr_start+le16_to_cpu(attr_index_root.data.resident.value_offset);
		ntfs_debug("Attr Value:Overwrite offset from [%d] to [%d]", ir_start , ir_start+ir_len-1 );
		memcpy(&(new_record[ir_start]),&ir, ir_len );
		(*pnew_offset) += attr_ir_len ;
		ntfs_dump_attr_name("After Copying INDEX ROOT into ATTR value",&new_record[attr_start]);
	}


	/* Creating First & Last IE */
	{
		INDEX_ENTRY ie = (INDEX_ENTRY) 
		{
			.length = const_cpu_to_le16(sizeof(INDEX_ENTRY_HEADER)),
			.key_length = const_cpu_to_le16(0),
			.flags = INDEX_ENTRY_END,
		};
		int ir_start=attr_start+le16_to_cpu(attr_index_root.data.resident.value_offset);
		int ie_start=ir_start+sizeof(INDEX_ROOT);

		/** insert DATA into new_file_record **/
		ntfs_debug("INDEX_ENTRY Overwrite offset from [%d] to [%lu]", ie_start , ie_start+sizeof(ie)-1);
		memcpy(&(new_record[ie_start]),&ie, sizeof(ie) );
	}
	ntfs_dump_attr_name("After Copying IE",&new_record[attr_start]);
	ntfs_debug("new_temp_offset [%d]",*pnew_offset);
//	new_dir_ntfs_inode->data_size = size;
	new_dir_ntfs_inode->allocated_size = (ir_len + 7) & ~7;
}

/* Start of SECURITY_DESCRIPTOR 
 * Create SECURITY_DESCRIPTOR attribute (everyone has full access). */
static int ntfs_create_attr_security_descriptor( MFT_RECORD* const mrec,
		int* const pnew_offset )
{
	int err = STATUS_OK;
	ACL *acl;
	ACCESS_ALLOWED_ACE *ace;
	SID *sid;
	ATTR_REC attr_sd;
	int sd_len, attr_sd_len;
	SECURITY_DESCRIPTOR_ATTR *sd =NULL;
	char* new_record=(char*)mrec;

	/*
	 * Calculate security descriptor length. We have 2 sub-authorities in
	 * owner and group SIDs, but structure SID contain only one, so add
	 * 4 bytes to every SID.
	 */
	sd_len = sizeof(SECURITY_DESCRIPTOR_ATTR) + 2 * (sizeof(SID) + 4) +
		sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE); 
	sd = kcalloc(1,sd_len,GFP_KERNEL);
	if (!sd) 
	{
		err = -ENOMEM;
		goto err_out;
	}

	sd->revision = 1;
	sd->control = SE_DACL_PRESENT | SE_SELF_RELATIVE;

	sid = (SID *)((u8 *)sd + sizeof(SECURITY_DESCRIPTOR_ATTR));
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->owner = cpu_to_le32((u8 *)sid - (u8 *)sd);

	sid = (SID *)((u8 *)sid + sizeof(SID) + 4); 
	sid->revision = 1;
	sid->sub_authority_count = 2;
	sid->sub_authority[0] = cpu_to_le32(SECURITY_BUILTIN_DOMAIN_RID);
	sid->sub_authority[1] = cpu_to_le32(DOMAIN_ALIAS_RID_ADMINS);
	sid->identifier_authority.value[5] = 5;
	sd->group = cpu_to_le32((u8 *)sid - (u8 *)sd);

	acl = (ACL *)((u8 *)sid + sizeof(SID) + 4);
	acl->revision = 2;
	acl->size = cpu_to_le16(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE));
	acl->ace_count = cpu_to_le16(1);
	sd->dacl = cpu_to_le32((u8 *)acl - (u8 *)sd);

	ace = (ACCESS_ALLOWED_ACE *)((u8 *)acl + sizeof(ACL));
	ace->type = ACCESS_ALLOWED_ACE_TYPE;
	ace->flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
	ace->size = cpu_to_le16(sizeof(ACCESS_ALLOWED_ACE));
	ace->mask = cpu_to_le32(0x1f01ff); /* FIXME */
	ace->sid.revision = 1;
	ace->sid.sub_authority_count = 1;
	ace->sid.sub_authority[0] = 0;
	ace->sid.identifier_authority.value[5] = 1;

	/* Create the attribute */
	attr_sd_len = offsetof(ATTR_REC, data) + sizeof(attr_sd.data.resident) ;
	attr_sd=(ATTR_REC) 
	{
		.type = AT_SECURITY_DESCRIPTOR  ,
			.length = ( attr_sd_len + sd_len + 7 ) & ~7 ,
			.non_resident = 0,
			.name_length = 0,
			.name_offset = 0,
			.flags =  0 ,
			.instance = (mrec->next_attr_instance) ++ ,
			.data=
			{
				.resident=
				{
					.value_length = sd_len,
					.value_offset = attr_sd_len  ,
					.flags = 0 ,
				}
			},
	};

	/** insert AT_SECURITY_DESCRIPTOR into new_file_record **/
	memcpy(&(new_record[*pnew_offset]) , &attr_sd,  attr_sd_len);
	memcpy(&(new_record[*pnew_offset + attr_sd_len]), sd ,sd_len);
	(*pnew_offset) += attr_sd.length;

	ntfs_debug("new_temp_offset [%d]",*pnew_offset);
err_out:
	if(sd)
	{
		kfree(sd);
		sd=NULL;
	}
	return err;
}

/**
 * __ntfs_create - create object on ntfs volume
 * @dir_ni:	ntfs inode for directory in which create new object
 * @name:	unicode name of new object
 * @name_len:	length of the name in unicode characters
 * @type:	type of the object to create
 *
 * Internal, use ntfs_create{,_device,_symlink} wrappers instead.
 *
 * @type can be:
 *	S_IFREG		to create regular file
 *
 * Return opened ntfs inode that describes created object on success 
 * or ERR_PTR(errno) on error 
 */
static ntfs_inode *__ntfs_create(ntfs_inode *dir_ni,
		ntfschar *name, u8 name_len, dev_t type )
{
	ntfs_inode *new_ntfs_inode =NULL;/** this is for new inode **/
	int err;

	MFT_RECORD* new_mft_record;
	int new_temp_offset ;
	char* temp_new_record;/* Wrapper of new_mft_record **/
	/* The only same attr cross the MFT and the Index Entry, is FILE_NAME **/
	FILE_NAME_ATTR *fn = NULL;

	ntfs_debug("Entering.");

	/* Sanity checks. */
	if (!dir_ni || !name || !name_len) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"Invalid arguments.");
		return ERR_PTR(-EINVAL);
	}

	/* TODO : not support REPARSE_POINT **/

	/** alloc new mft record for new file **/
	new_ntfs_inode = ntfs_mft_record_alloc(dir_ni->vol, type,NULL,&new_mft_record);
	if (IS_ERR(new_ntfs_inode))
	{
		ntfs_debug("ntfs_mft_record_alloc error [%ld]",PTR_ERR(new_ntfs_inode));
		return new_ntfs_inode;
	}
	else
	{
		new_temp_offset = new_mft_record->attrs_offset ;
		/** ntfs_mft_record_alloc{} had map new_ntfs_inode to new_mft_record */
		temp_new_record=(char*)new_mft_record;
		ntfs_debug("new $MFT File Record number [0x%x]",new_mft_record->mft_record_number);
	}
	ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);

	/*
	 * Create STANDARD_INFORMATION attribute
	 */
	err = ntfs_create_attr_standard_infomation(new_mft_record,&new_temp_offset);
	if(err)
	{
		goto err_out;
	}
	ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);
	/* Create FILE_NAME attribute  */
	err = ntfs_create_attr_file_name(dir_ni,name,name_len,
			new_ntfs_inode,
			new_mft_record,
			&new_temp_offset,/*output*/
			&fn/*output*/);
	if(err)
	{
		goto err_out;
	}
	ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);
	err = ntfs_create_attr_security_descriptor(new_mft_record,&new_temp_offset);
	if(err)
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"ntfs_create_attr_security_descriptor failed.");
		goto err_out;
	}
	ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);
	switch(type)
	{
		case S_IFREG:
			ntfs_create_attr_data(new_mft_record,&new_temp_offset);
			ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);
			break;
		case S_IFDIR:
			ntfs_create_attr_dir(new_ntfs_inode,dir_ni->vol,new_mft_record,&new_temp_offset);
			break;
		default:
			ntfs_error((VFS_I(dir_ni))->i_sb,"Creating Unsupported type %X.",type);
			goto err_out;

	}

#define FILE_ATTR_I30_INDEX_PRESENT      const_cpu_to_le32(0x10000000)
	if (S_ISDIR(type))
		fn->file_attributes = FILE_ATTR_I30_INDEX_PRESENT;

	/* Create END attribute  */
	ntfs_create_attr_end(new_mft_record,&new_temp_offset);
	ntfs_debug("new_temp_offset [%d]\n",new_temp_offset);
	/* new_temp_offset will NOT be changed in this function */

	/* Add FILE_NAME attribute to the Stream in a new Index Entry,
	 * Index Entry is in Index Record. */
	err = ntfs_create_index_entry(dir_ni, fn, MK_MREF(new_ntfs_inode->mft_no, le16_to_cpu(new_ntfs_inode->seq_no)));
	if(fn)/* free fn anyway*/
	{
		kfree(fn);
		fn=NULL;
	}
	if (err) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"Failed to add entry to the index");
		goto err_out;
	}


	/* Start flush the $MFT File Record */
	/**FIXME : it do not support hard link **/
	new_mft_record->link_count = cpu_to_le16(1);
	if (S_ISDIR(type))
		new_mft_record->flags |= MFT_RECORD_IS_DIRECTORY;

	/** MUST set this **/
	new_mft_record->bytes_in_use = new_temp_offset;
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off before flush_dcache_mft_record_page ");
	}
	else
	{
		ntfs_debug("in_atomic_preempt_off is on before flush_dcache_mft_record_page");
	}
	flush_dcache_mft_record_page(new_ntfs_inode);
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off before mark_mft_record_dirty ");
	}
	mark_mft_record_dirty(new_ntfs_inode);
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off before unmap_mft_record ");
	}
	unmap_mft_record(new_ntfs_inode);

	switch(type)
	{
		case S_IFREG:
			(VFS_I(new_ntfs_inode))->i_op = &ntfs_file_inode_ops;
			(VFS_I(new_ntfs_inode))->i_fop = &ntfs_file_ops;
			break;
		case S_IFDIR:
			{
				struct inode* new_vfs_inode=VFS_I(new_ntfs_inode);
				new_vfs_inode->i_op = &ntfs_dir_inode_ops;
				new_vfs_inode->i_fop = &ntfs_dir_ops;
			}
			break;
		default:
			ntfs_error((VFS_I(dir_ni))->i_sb,"Unsupport type %X, keep operation NULL",type);
			break;

	}

	if (NInoMstProtected(new_ntfs_inode))
	{
		(VFS_I(new_ntfs_inode))->i_mapping->a_ops = &ntfs_mst_aops;
	}
	else
	{
		(VFS_I(new_ntfs_inode))->i_mapping->a_ops = &ntfs_normal_aops;
	}

	(VFS_I(new_ntfs_inode))->i_blocks = new_ntfs_inode->allocated_size >> 9;
	if(in_atomic_preempt_off())
	{
		ntfs_debug("in_atomic_preempt_off is off before return ");
	}
	else
	{
		ntfs_debug("in_atomic_preempt_off is on before return");
	}


	ntfs_debug("Done.");
	return new_ntfs_inode;
err_out:
	ntfs_debug("Failed.");

	/* TODO : if new_ntfs_inode->nr_extents had been set  should been clear here **/

	if(new_mft_record)
	{
		if (ntfs_mft_record_free(new_ntfs_inode->vol, new_ntfs_inode,new_mft_record))
		{
			ntfs_debug("Failed to free MFT record.  "
					"Leaving inconsistent metadata. Run chkdsk.\n");
		}
		inode_dec_link_count(VFS_I(new_ntfs_inode)); 
		unmap_mft_record(new_ntfs_inode);
		atomic_dec(&(VFS_I(new_ntfs_inode))->i_count);
		new_mft_record=NULL;
	}
	return ERR_PTR(err);
}

/*
 * 2018. July 14
 * Add IFDIR case by Gordon
 */
static ntfs_inode *ntfs_create_ntfs_inode(ntfs_inode *dir_ni, ntfschar *name, u8 name_len,
		dev_t type)
{
	switch(type)
	{
		case S_IFREG:
		case S_IFDIR:
			return __ntfs_create(dir_ni, name, name_len, type);
		case S_IFIFO:
		case S_IFSOCK:
			ntfs_error((VFS_I(dir_ni))->i_sb,"Unsupported arguments.");
			return ERR_PTR(-EOPNOTSUPP);
		default:
			ntfs_error((VFS_I(dir_ni))->i_sb,"Invalid arguments [%X]. Only support [%X][%X]",
					type,S_IFREG,S_IFDIR);
			return ERR_PTR(-EINVAL);
	}
}
extern int ntfs_create_vfs_inode(struct inode *dir,
		struct dentry *dent,
		umode_t mode, 
		bool __unused )
{
	ntfschar *uname;
	int uname_len;
	ntfs_inode* ni ;

	/* Convert the name of the dentry to Unicode. */
	uname_len = ntfs_nlstoucs(NTFS_SB(dir->i_sb), dent->d_name.name, dent->d_name.len, &uname);
	if (uname_len < 0) 
	{
		if (uname_len != -ENAMETOOLONG)
		{
			ntfs_error(dir->i_sb, "Failed to convert name[%s] to Unicode.",
					dent->d_name.name);
		}
		return uname_len;
	}

	/* create file and inode */
	ni = ntfs_create_ntfs_inode(NTFS_I(dir), 
			uname,  /* Unicode Name */
			uname_len , /* Unicode Name length */
			mode & S_IFMT  );
	kmem_cache_free(ntfs_name_cache, uname);/* reclaim the memory that alloced in ntfs_nlstoucs */
	if(likely(!IS_ERR(ni)))
	{
		d_instantiate(dent,VFS_I(ni));
		/* TODO : modify    dir->i_mtime  to CURRENT_TIME */
		ntfs_debug("Done.");
		return 0;
	}
	else
	{
		ntfs_error(dir->i_sb, "ntfs_create error! dentry->d_name.name[%s]", dent->d_name.name);
		return  PTR_ERR(ni);
	}

}
extern int ntfs_mkdir(struct inode *dir,
		struct dentry *dent,
		umode_t mode)
{
	return ntfs_create_vfs_inode(dir,dent,mode|S_IFDIR,0/*unused*/);
}

