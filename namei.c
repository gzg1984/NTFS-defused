/*
 * namei.c - NTFS kernel directory inode operations. Part of the Linux-NTFS
 *	     project.
 *
 * Copyright (c) 2001-2006 Anton Altaparmakov
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

/**
 * ntfs_lookup - find the inode represented by a dentry in a directory inode
 * @dir_ino:	directory inode in which to look for the inode
 * @dent:	dentry representing the inode to look for
 * @flags:	lookup flags
 *
 * In short, ntfs_lookup() looks for the inode represented by the dentry @dent
 * in the directory inode @dir_ino and if found attaches the inode to the
 * dentry @dent.
 *
 * In more detail, the dentry @dent specifies which inode to look for by
 * supplying the name of the inode in @dent->d_name.name. ntfs_lookup()
 * converts the name to Unicode and walks the contents of the directory inode
 * @dir_ino looking for the converted Unicode name. If the name is found in the
 * directory, the corresponding inode is loaded by calling ntfs_iget() on its
 * inode number and the inode is associated with the dentry @dent via a call to
 * d_splice_alias().
 *
 * If the name is not found in the directory, a NULL inode is inserted into the
 * dentry @dent via a call to d_add(). The dentry is then termed a negative
 * dentry.
 *
 * Only if an actual error occurs, do we return an error via ERR_PTR().
 *
 * In order to handle the case insensitivity issues of NTFS with regards to the
 * dcache and the dcache requiring only one dentry per directory, we deal with
 * dentry aliases that only differ in case in ->ntfs_lookup() while maintaining
 * a case sensitive dcache. This means that we get the full benefit of dcache
 * speed when the file/directory is looked up with the same case as returned by
 * ->ntfs_readdir() but that a lookup for any other case (or for the short file
 * name) will not find anything in dcache and will enter ->ntfs_lookup()
 * instead, where we search the directory for a fully matching file name
 * (including case) and if that is not found, we search for a file name that
 * matches with different case and if that has non-POSIX semantics we return
 * that. We actually do only one search (case sensitive) and keep tabs on
 * whether we have found a case insensitive match in the process.
 *
 * To simplify matters for us, we do not treat the short vs long filenames as
 * two hard links but instead if the lookup matches a short filename, we
 * return the dentry for the corresponding long filename instead.
 *
 * There are three cases we need to distinguish here:
 *
 * 1) @dent perfectly matches (i.e. including case) a directory entry with a
 *    file name in the WIN32 or POSIX namespaces. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to NULL and we
 *    just d_splice_alias() @dent.
 * 2) @dent matches (not including case) a directory entry with a file name in
 *    the WIN32 namespace. In this case ntfs_lookup_inode_by_name() will return
 *    with name set to point to a kmalloc()ed ntfs_name structure containing
 *    the properly cased little endian Unicode name. We convert the name to the
 *    current NLS code page, search if a dentry with this name already exists
 *    and if so return that instead of @dent.  At this point things are
 *    complicated by the possibility of 'disconnected' dentries due to NFS
 *    which we deal with appropriately (see the code comments).  The VFS will
 *    then destroy the old @dent and use the one we returned.  If a dentry is
 *    not found, we allocate a new one, d_splice_alias() it, and return it as
 *    above.
 * 3) @dent matches either perfectly or not (i.e. we don't care about case) a
 *    directory entry with a file name in the DOS namespace. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to point to a
 *    kmalloc()ed ntfs_name structure containing the mft reference (cpu endian)
 *    of the inode. We use the mft reference to read the inode and to find the
 *    file name in the WIN32 namespace corresponding to the matched short file
 *    name. We then convert the name to the current NLS code page, and proceed
 *    searching for a dentry with this name, etc, as in case 2), above.
 *
 * Locking: Caller must hold i_mutex on the directory.
 */
static struct dentry *ntfs_lookup(struct inode *dir_ino, struct dentry *dent,
		unsigned int flags)
{
	ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct inode *dent_inode;
	ntfschar *uname;
	ntfs_name *name = NULL;
	MFT_REF mref;
	unsigned long dent_ino;
	int uname_len;

	ntfs_debug("Looking up %pd in directory inode 0x%lx.",
			dent, dir_ino->i_ino);
	/* Convert the name of the dentry to Unicode. */
	uname_len = ntfs_nlstoucs(vol, dent->d_name.name, dent->d_name.len,
			&uname);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(vol->sb, "Failed to convert name to "
					"Unicode.");
		return ERR_PTR(uname_len);
	}
	mref = ntfs_lookup_inode_by_name(NTFS_I(dir_ino), uname, uname_len,
			&name);
	kmem_cache_free(ntfs_name_cache, uname);
	if (!IS_ERR_MREF(mref)) {
		dent_ino = MREF(mref);
		ntfs_debug("Found inode 0x%lx. Calling ntfs_iget.", dent_ino);
		dent_inode = ntfs_iget(vol->sb, dent_ino);
		if (likely(!IS_ERR(dent_inode))) {
			/* Consistency check. */
			if (is_bad_inode(dent_inode) || MSEQNO(mref) ==
					NTFS_I(dent_inode)->seq_no ||
					dent_ino == FILE_MFT) {
				/* Perfect WIN32/POSIX match. -- Case 1. */
				if (!name) {
					ntfs_debug("Done.  (Case 1.)");
					return d_splice_alias(dent_inode, dent);
				}
				/*
				 * We are too indented.  Handle imperfect
				 * matches and short file names further below.
				 */
				goto handle_name;
			}
			ntfs_error(vol->sb, "Found stale reference to inode "
					"0x%lx (reference sequence number = "
					"0x%x, inode sequence number = 0x%x), "
					"returning -EIO. Run chkdsk.",
					dent_ino, MSEQNO(mref),
					NTFS_I(dent_inode)->seq_no);
			iput(dent_inode);
			dent_inode = ERR_PTR(-EIO);
		} else
			ntfs_error(vol->sb, "ntfs_iget(0x%lx) failed with "
					"error code %li.", dent_ino,
					PTR_ERR(dent_inode));
		kfree(name);
		/* Return the error code. */
		return ERR_CAST(dent_inode);
	}
	/* It is guaranteed that @name is no longer allocated at this point. */
	if (MREF_ERR(mref) == -ENOENT) {
		ntfs_debug("Entry was not found, adding negative dentry.");
		/* The dcache will handle negative entries. */
		d_add(dent, NULL);
		ntfs_debug("Done.");
		return NULL;
	}
	ntfs_error(vol->sb, "ntfs_lookup_ino_by_name() failed with error "
			"code %i.", -MREF_ERR(mref));
	return ERR_PTR(MREF_ERR(mref));
	// TODO: Consider moving this lot to a separate function! (AIA)
handle_name:
   {
	MFT_RECORD *m;
	ntfs_attr_search_ctx *ctx;
	ntfs_inode *ni = NTFS_I(dent_inode);
	int err;
	struct qstr nls_name;

	nls_name.name = NULL;
	if (name->type != FILE_NAME_DOS) {			/* Case 2. */
		ntfs_debug("Case 2.");
		nls_name.len = (unsigned)ntfs_ucstonls(vol,
				(ntfschar*)&name->name, name->len,
				(unsigned char**)&nls_name.name, 0);
		kfree(name);
	} else /* if (name->type == FILE_NAME_DOS) */ {		/* Case 3. */
		FILE_NAME_ATTR *fn;

		ntfs_debug("Case 3.");
		kfree(name);

		/* Find the WIN32 name corresponding to the matched DOS name. */
		ni = NTFS_I(dent_inode);
		m = map_mft_record(ni);
		if (IS_ERR(m)) {
			err = PTR_ERR(m);
			m = NULL;
			ctx = NULL;
			goto err_out;
		}
		ctx = ntfs_attr_get_search_ctx(ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			goto err_out;
		}
		do {
			ATTR_RECORD *a;
			u32 val_len;

			err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0,
					NULL, 0, ctx);
			if (unlikely(err)) {
				ntfs_error(vol->sb, "Inode corrupt: No WIN32 "
						"namespace counterpart to DOS "
						"file name. Run chkdsk.");
				if (err == -ENOENT)
					err = -EIO;
				goto err_out;
			}
			/* Consistency checks. */
			a = ctx->attr;
			if (a->non_resident || a->flags)
				goto eio_err_out;
			val_len = le32_to_cpu(a->data.resident.value_length);
			if (le16_to_cpu(a->data.resident.value_offset) +
					val_len > le32_to_cpu(a->length))
				goto eio_err_out;
			fn = (FILE_NAME_ATTR*)((u8*)ctx->attr + le16_to_cpu(
					ctx->attr->data.resident.value_offset));
			if ((u32)(fn->file_name_length * sizeof(ntfschar) +
					sizeof(FILE_NAME_ATTR)) > val_len)
				goto eio_err_out;
		} while (fn->file_name_type != FILE_NAME_WIN32);

		/* Convert the found WIN32 name to current NLS code page. */
		nls_name.len = (unsigned)ntfs_ucstonls(vol,
				(ntfschar*)&fn->file_name, fn->file_name_length,
				(unsigned char**)&nls_name.name, 0);

		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
	}
	m = NULL;
	ctx = NULL;

	/* Check if a conversion error occurred. */
	if ((signed)nls_name.len < 0) {
		err = (signed)nls_name.len;
		goto err_out;
	}
	nls_name.hash = full_name_hash(dent, nls_name.name, nls_name.len);

	dent = d_add_ci(dent, dent_inode, &nls_name);
	kfree(nls_name.name);
	return dent;

eio_err_out:
	ntfs_error(vol->sb, "Illegal file name attribute. Run chkdsk.");
	err = -EIO;
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(ni);
	iput(dent_inode);
	ntfs_error(vol->sb, "Failed, returning error code %i.", err);
	return ERR_PTR(err);
   }
}
void ntfs_index_ctx_put_I30(ntfs_index_context *ictx)
{
	ntfs_commit_inode(VFS_I(ictx->idx_ni));
	iput(VFS_I(ictx->idx_ni));
	ntfs_index_ctx_put(ictx);
}
#ifdef NTFS_RW
/**
 * ntfs_create_index_entry - add filename to directory index
 * @ni:		ntfs inode describing directory to which index add filename
 * @fn:		FILE_NAME attribute to add
 * @mref:	reference of the inode which @fn describes
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
static int ntfs_create_index_entry(ntfs_inode *dir_ni, FILE_NAME_ATTR *fn, MFT_REF mref)
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
out:
	if(ie)
	{
		kfree(ie);
	}
	ntfs_debug("done");
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
	/** insert DATA into new_file_record **/
	memcpy(&(new_record[*pnew_offset]),&attr_data, attr_data_len );
	(*pnew_offset) += attr_data_len ;
	ntfs_debug("new_temp_offset [%d]",*pnew_offset);
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

	/** insert FILE_NAME into new_file_record **/
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

	/* Begin from here , error must goto err_out */
	err = ntfs_create_attr_standard_infomation(new_mft_record,&new_temp_offset);
	if(err)
	{
		goto err_out;
	}
	err = ntfs_create_attr_security_descriptor(new_mft_record,&new_temp_offset);
	if(err)
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"ntfs_create_attr_security_descriptor failed.");
		goto err_out;
	}
	ntfs_create_attr_data(new_mft_record,&new_temp_offset);
	ntfs_create_attr_end(new_mft_record,&new_temp_offset);

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
	/** MUST set this **/
	new_mft_record->bytes_in_use = new_temp_offset;
	flush_dcache_mft_record_page(new_ntfs_inode);
	mark_mft_record_dirty(new_ntfs_inode);
	unmap_mft_record(new_ntfs_inode);

	(VFS_I(new_ntfs_inode))->i_op = &ntfs_file_inode_ops;
	(VFS_I(new_ntfs_inode))->i_fop = &ntfs_file_ops;

	if (NInoMstProtected(new_ntfs_inode))
	{
		(VFS_I(new_ntfs_inode))->i_mapping->a_ops = &ntfs_mst_aops;
	}
	else
	{
		(VFS_I(new_ntfs_inode))->i_mapping->a_ops = &ntfs_normal_aops;
	}

	(VFS_I(new_ntfs_inode))->i_blocks = new_ntfs_inode->allocated_size >> 9;


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

/**
 * Some wrappers around __ntfs_create() ...
 * Check the File type
 */
static ntfs_inode *ntfs_create_ntfs_inode(ntfs_inode *dir_ni, ntfschar *name, u8 name_len,
		dev_t type)
{
	/*TODO : type could be { S_IFREG S_IFDIR  S_IFIFO  S_IFSOCK } */
	if (type != S_IFREG ) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"Invalid arguments.");
		return ERR_PTR(-EOPNOTSUPP);
	}
	return __ntfs_create(dir_ni, name, name_len, type);
}

static int ntfs_create_vfs_inode(struct inode *dir,
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

/**
 * ntfs_get_parent - find the dentry of the parent of a given directory dentry
 * @child_dent:		dentry of the directory whose parent directory to find
 *
 * Find the dentry for the parent directory of the directory specified by the
 * dentry @child_dent.  This function is called from
 * fs/exportfs/expfs.c::find_exported_dentry() which in turn is called from the
 * default ->decode_fh() which is export_decode_fh() in the same file.
 *
 * The code is based on the ext3 ->get_parent() implementation found in
 * fs/ext3/namei.c::ext3_get_parent().
 *
 * Note: ntfs_get_parent() is called with @d_inode(child_dent)->i_mutex down.
 *
 * Return the dentry of the parent directory on success or the error code on
 * error (IS_ERR() is true).
 */
static struct dentry *ntfs_get_parent(struct dentry *child_dent)
{
	struct inode *vi = d_inode(child_dent);
	ntfs_inode *ni = NTFS_I(vi);
	MFT_RECORD *mrec;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *attr;
	FILE_NAME_ATTR *fn;
	unsigned long parent_ino;
	int err;

	ntfs_debug("Entering for inode 0x%lx.", vi->i_ino);
	/* Get the mft record of the inode belonging to the child dentry. */
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return (struct dentry *)mrec;
	/* Find the first file name attribute in the mft record. */
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (unlikely(!ctx)) {
		unmap_mft_record(ni);
		return ERR_PTR(-ENOMEM);
	}
try_next:
	err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
		if (err == -ENOENT)
			ntfs_error(vi->i_sb, "Inode 0x%lx does not have a "
					"file name attribute.  Run chkdsk.",
					vi->i_ino);
		return ERR_PTR(err);
	}
	attr = ctx->attr;
	if (unlikely(attr->non_resident))
		goto try_next;
	fn = (FILE_NAME_ATTR *)((u8 *)attr +
			le16_to_cpu(attr->data.resident.value_offset));
	if (unlikely((u8 *)fn + le32_to_cpu(attr->data.resident.value_length) >
			(u8*)attr + le32_to_cpu(attr->length)))
		goto try_next;
	/* Get the inode number of the parent directory. */
	parent_ino = MREF_LE(fn->parent_directory);
	/* Release the search context and the mft record of the child. */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);

	return d_obtain_alias(ntfs_iget(vi->i_sb, parent_ino));
}

static struct inode *ntfs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct inode *inode;

	inode = ntfs_iget(sb, ino);
	if (!IS_ERR(inode)) {
		if (is_bad_inode(inode) || inode->i_generation != generation) {
			iput(inode);
			inode = ERR_PTR(-ESTALE);
		}
	}

	return inode;
}

static struct dentry *ntfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

static struct dentry *ntfs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

/**
 * Export operations allowing NFS exporting of mounted NTFS partitions.
 *
 * We use the default ->encode_fh() for now.  Note that they
 * use 32 bits to store the inode number which is an unsigned long so on 64-bit
 * architectures is usually 64 bits so it would all fail horribly on huge
 * volumes.  I guess we need to define our own encode and decode fh functions
 * that store 64-bit inode numbers at some point but for now we will ignore the
 * problem...
 *
 * We also use the default ->get_name() helper (used by ->decode_fh() via
 * fs/exportfs/expfs.c::find_exported_dentry()) as that is completely fs
 * independent.
 *
 * The default ->get_parent() just returns -EACCES so we have to provide our
 * own and the default ->get_dentry() is incompatible with NTFS due to not
 * allowing the inode number 0 which is used in NTFS for the system file $MFT
 * and due to using iget() whereas NTFS needs ntfs_iget().
 */
const struct export_operations ntfs_export_ops = {
	.get_parent	= ntfs_get_parent,	/* Find the parent of a given
						   directory. */
	.fh_to_dentry	= ntfs_fh_to_dentry,
	.fh_to_parent	= ntfs_fh_to_parent,
};
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
static int ntfs_unlink_vfs_inode(struct inode *pi,struct dentry *pd)
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
#endif
/**
 * Inode operations for directories.
 */
const struct inode_operations ntfs_dir_inode_ops = {
	.lookup	= ntfs_lookup,	/* VFS: Lookup directory. */
#ifdef NTFS_RW
	.create = ntfs_create_vfs_inode, 
	.unlink = ntfs_unlink_vfs_inode,
#endif
};
