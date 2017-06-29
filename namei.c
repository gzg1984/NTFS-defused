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
#include <linux/security.h>

#include "attrib.h"
#include "debug.h"
#include "dir.h"
#include "mft.h"
#include "ntfs.h"

/**
 * ntfs_lookup - find the inode represented by a dentry in a directory inode
 * @dir_ino:	directory inode in which to look for the inode
 * @dent:	dentry representing the inode to look for
 * @nd:		lookup nameidata
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
		struct nameidata *nd)
{
	ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct inode *dent_inode;
	ntfschar *uname;
	ntfs_name *name = NULL;
	MFT_REF mref;
	unsigned long dent_ino;
	int uname_len;

	ntfs_debug("Looking up %s in directory inode 0x%lx.",
			dent->d_name.name, dir_ino->i_ino);
	/* Convert the name of the dentry to Unicode. */
	uname_len = ntfs_nlstoucs(vol, dent->d_name.name, dent->d_name.len,
			&uname);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(vol->sb, "Failed to convert name to " "Unicode.");
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
		return (struct dentry *)dent_inode;
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
	nls_name.hash = full_name_hash(nls_name.name, nls_name.len);

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

/**************************************Gzged porting from ntfs-3g *********/

#include "index.h"

#define STATUS_OK               (0)
#define STATUS_ERROR                (-1)

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


static int ntfs_ie_add(ntfs_index_context *icx, INDEX_ENTRY *ie)
{
	INDEX_HEADER *ih;
	int allocated_size, new_size;
	int ret = STATUS_ERROR;
	ntfs_inode *idx_ni = icx->idx_ni;
	ntfs_debug("Entering. ");
	while (1) 
	{
		/* ret = ntfs_index_lookup(&ie->key, le16_to_cpu(ie->key_length), icx) ; */
		ntfs_debug("new loop ");
		ret = ntfs_lookup_inode_by_key(&ie->key, le16_to_cpu(ie->key_length), icx) ;
		ntfs_debug("ntfs_lookup_inode_by_key ret[%d]",ret);
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
		/*
		ntfs_debug("here icx[%p] icx->is_in_root[%d]",icx,icx->is_in_root);
		*/
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
	
		ntfs_debug("index block sizes: allocated: %d  needed: %d", allocated_size, new_size);
		if (new_size <= allocated_size)
		{
			break;
		}
		/** else  it will make space for new index entry **/
		
		if (icx->is_in_root) 
		{
			if ( (ret = ntfs_ir_make_space(icx, new_size) ) )
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
/** Gzged add * */
			ntfs_debug("should run ntfs_ib_split ");
			ret = -ENOSPC;
			goto err_out;
/** Gzged add end * */

			/* Gzged shut
			if (ntfs_ib_split(icx, icx->ib) == STATUS_ERROR)
			{
				ntfs_debug("ntfs_ib_split err ");
				ret = -ENOMEM;
				goto err_out;
			}
			**/
		}
		
/** Gzged mod
		ntfs_inode_mark_dirty(icx->actx->ntfs_ino);
***/
/***TODO  fix these in furture
*****/
/* Gzged add  20091014 **/
		ntfs_debug("Before flush_dcache_mft_record_page ");/*****die here *****/
		flush_dcache_mft_record_page(icx->actx->ntfs_ino);

		ntfs_debug("Before mark_mft_record_dirty ");
		mark_mft_record_dirty(icx->actx->ntfs_ino);

		/** Gzged mod ntfs_index_ctx_reinit(icx); ***/
		ntfs_index_ctx_put(icx);
		ntfs_index_ctx_get(idx_ni);
	}
	
	ntfs_ie_insert(ih, ie, icx->entry);
	ntfs_index_entry_flush_dcache_page(icx);
	ntfs_index_entry_mark_dirty(icx);
	
	ret = STATUS_OK;
err_out:
	ntfs_debug("%s", ret ? "Failed" : "Done");
	return ret;
}
/**
 * ntfs_index_add_filename - add filename to directory index
 * @ni:		ntfs inode describing directory to which index add filename
 * @fn:		FILE_NAME attribute to add
 * @mref:	reference of the inode which @fn describes
 *
 * Return 0 on success or -1 on error with errno set to the error code.
 */
ntfs_index_context * ntfs_index_ctx_get_I30(ntfs_inode *idx_ni)
{
    static ntfschar I30[5] = { cpu_to_le16('$'),
	            cpu_to_le16('I'), 
	            cpu_to_le16('3'), 
	            cpu_to_le16('0'), 
				0 };

    struct inode * tmp_ino = ntfs_index_iget(VFS_I(idx_ni), I30, 4);
    if (IS_ERR(tmp_ino)) {
        ntfs_debug("Failed to load $I30 index.");
        return NULL;
    }

	return ntfs_index_ctx_get(NTFS_I(tmp_ino));
}
void ntfs_index_ctx_put_I30(ntfs_index_context *ictx)
{
	ntfs_commit_inode(VFS_I(ictx->idx_ni));
	iput(VFS_I(ictx->idx_ni));
	ntfs_index_ctx_put(ictx);
}
static int ntfs_index_add_filename(ntfs_inode *dir_ni, FILE_NAME_ATTR *fn, MFT_REF mref)
{
	INDEX_ENTRY *ie;
	ntfs_index_context *icx;
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
	
	icx =  ntfs_index_ctx_get(dir_ni);
	if (!icx)
	{
		ret = PTR_ERR(icx);
		goto out;
	}
	
	ret = ntfs_ie_add(icx, ie);
out:
	if(icx)
	{
		ntfs_index_ctx_put(icx);
	}
	if(ie)
	{
		kfree(ie);
	}
	ntfs_debug("done");
	return ret;
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
	ntfs_inode *ni =NULL;/** this is for new inode **/
	FILE_NAME_ATTR *fn = NULL;
	STANDARD_INFORMATION *si = NULL;
	SECURITY_DESCRIPTOR_ATTR *sd =NULL;
	int err;

/********Gzged new ********/
	MFT_RECORD* mrec;
	int new_temp_offset ;
	char* temp_new_record;

	ntfs_debug("Entering.");
	
	/* Sanity checks. */
	if (!dir_ni || !name || !name_len) 
	{
		ntfs_error((VFS_I(dir_ni))->i_sb,"Invalid arguments.");
		return ERR_PTR(-EINVAL);
	}

	/* TODO : not support REPARSE_POINT **/

	/** alloc new mft record for new file **/
	ni = ntfs_mft_record_alloc(dir_ni->vol, type,NULL,&mrec);
	if (IS_ERR(ni))
	{
		ntfs_debug("ntfs_mft_record_alloc error [%ld]",PTR_ERR(ni));
		return ni;
	}
	else
	{
		new_temp_offset = mrec->attrs_offset ;
		/** ntfs_mft_record_alloc{} had map ni to mrec */
		temp_new_record=(char*)mrec;
		ntfs_debug("mrec->mft_record_number [%d]",mrec->mft_record_number);
	}


/**************** Begin from here , error must goto err_out *****************/
	{ /************************ STANDARD_INFORMATION start ******************/
		/*
		 * Create STANDARD_INFORMATION attribute. Write STANDARD_INFORMATION
		 * version 1.2, windows will upgrade it to version 3 if needed.
		 */
		ATTR_REC attr_si;
		int si_len,attr_si_len;

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
		memcpy(&(temp_new_record[new_temp_offset]),&attr_si, attr_si_len  );
		new_temp_offset += attr_si_len;
		memcpy(&(temp_new_record[new_temp_offset]),  si,  si_len);
		new_temp_offset += si_len;

		ntfs_debug("new_temp_offset [%d]",new_temp_offset);

		kfree(si);
		si=NULL;
	} /****************************** end of STANDARD_INFORMATION *************/
	
	/*
	if (ntfs_sd_add_everyone(ni)) {
		err = errno;
		goto err_out;
	}
	rollback_sd = 1;
	*/



	{ /****************************** start of FILE_NAME *************/

		ATTR_REC attr_fna;
		int fn_len , attr_fna_len;
		/** create FILE_NAME_ATTR **/
		fn_len = sizeof(FILE_NAME_ATTR) + name_len * sizeof(ntfschar);
		fn = kcalloc(1,fn_len,GFP_KERNEL);
		if (!fn) 
		{
			err = -ENOMEM;
			goto err_out;
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
		memcpy(&(temp_new_record[new_temp_offset]) , &attr_fna,  attr_fna_len);
		memcpy(&(temp_new_record[new_temp_offset + attr_fna_len]),fn,fn_len);
		new_temp_offset += attr_fna.length;

		ntfs_debug("new_temp_offset [%d]",new_temp_offset);

/**********add to index ********************************************/
		/* Add FILE_NAME attribute to index. */
		if ((err = ntfs_index_add_filename(dir_ni, fn, MK_MREF(ni->mft_no, le16_to_cpu(ni->seq_no))) )) 
		{
			ntfs_error((VFS_I(dir_ni))->i_sb,"Failed to add entry to the index");
			goto err_out;
		}
/*********************************************************/

		kfree(fn);
		fn=NULL;
	} /****************************** end of FILE_NAME *************/

	{ /****************************** start of SECURITY_DESCRIPTOR *************/
		ACL *acl;
		ACCESS_ALLOWED_ACE *ace;
		SID *sid;
		ATTR_REC attr_sd;
		int sd_len, attr_sd_len;

		/* Create SECURITY_DESCRIPTOR attribute (everyone has full access). */
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
		memcpy(&(temp_new_record[new_temp_offset]) , &attr_sd,  attr_sd_len);
		memcpy(&(temp_new_record[new_temp_offset + attr_sd_len]), sd ,sd_len);
		new_temp_offset += attr_sd.length;
		ntfs_debug("new_temp_offset [%d]",new_temp_offset);
/************************/

		kfree(sd);
		sd=NULL;
	} /****************************** end of SECURITY_DESCRIPTOR *************/

	{ /****************************** start of DATA *************/
		/***  $DATA (0x80)   **/
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
		memcpy(&(temp_new_record[new_temp_offset]),&attr_data, attr_data_len );
		new_temp_offset += attr_data_len ;
		ntfs_debug("new_temp_offset [%d]",new_temp_offset);

	} /****************************** end of DATA *************/

	{ /****************************** start of $END *************/
		/***  $AT_END              = cpu_to_le32(0xffffffff) */
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
		memcpy(&(temp_new_record[new_temp_offset]),&attr_end, attr_end_len);
		new_temp_offset += attr_end_len ;
		ntfs_debug("new_temp_offset [%d]",new_temp_offset);

	} /****************************** end of $END *************/


	/**FIXME : it do not support hard link **/
	mrec->link_count = cpu_to_le16(1);
	/** MUST set this **/
	mrec->bytes_in_use = new_temp_offset;

	flush_dcache_mft_record_page(ni);
	mark_mft_record_dirty(ni);  /**ntfs_inode_mark_dirty(ni); int ntfs-3g**/
	unmap_mft_record(ni);

	(VFS_I(ni))->i_op = &ntfs_file_inode_ops;
	(VFS_I(ni))->i_fop = &ntfs_file_ops;

	if (NInoMstProtected(ni))
	{
		(VFS_I(ni))->i_mapping->a_ops = &ntfs_mst_aops;
	}
	else
	{
		(VFS_I(ni))->i_mapping->a_ops = &ntfs_aops;
	}

	(VFS_I(ni))->i_blocks = ni->allocated_size >> 9;


	ntfs_debug("Done.");
	return ni;
err_out:
	ntfs_debug("Failed.");

	/* TODO : if ni->nr_extents had been set  should been clear here **/

	if(fn)
	{
		kfree(fn);
		fn=NULL;
	}
	if(si)
	{
		kfree(si);
		si=NULL;
	}
	if(sd)
	{
		kfree(sd);
		sd=NULL;
	}

	if(mrec)
	{
		if (ntfs_mft_record_free(ni->vol, ni,mrec))
		{
			ntfs_debug("Failed to free MFT record.  "
					"Leaving inconsistent metadata. Run chkdsk.\n");
		}
		(VFS_I(ni))->i_nlink--;
		unmap_mft_record(ni);
		atomic_dec(&(VFS_I(ni))->i_count);
		mrec=NULL;
	}
	return ERR_PTR(err);
}

/**
 * Some wrappers around __ntfs_create() ...
 */
ntfs_inode *ntfs_create(ntfs_inode *dir_ni, ntfschar *name, u8 name_len,
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
/**************************************Gzged porting from ntfs-3g *********/

static int gzged_ntfs_create(struct inode *dir, 
		struct dentry *dent, 
		int mode, 
		bool __b  __attribute__((unused)) )
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
			ntfs_error(dir->i_sb, "Failed to convert name to Unicode.");
		}
		return uname_len;
	}


	/* create file and inode */
	ni = ntfs_create(NTFS_I(dir), uname, uname_len , mode & S_IFMT  );
	kmem_cache_free(ntfs_name_cache, uname);
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

/************************* unlink support **********/

/*
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

static int ntfs_ie_end(INDEX_ENTRY *ie)
{
    return ie->flags & INDEX_ENTRY_END || !ie->length;
}

static INDEX_ENTRY *ntfs_ie_get_first(INDEX_HEADER *ih)
{
    return (INDEX_ENTRY *)((u8 *)ih + le32_to_cpu(ih->entries_offset));
}
static INDEX_ENTRY *ntfs_ie_get_next(INDEX_ENTRY *ie)
{
    return (INDEX_ENTRY *)((char *)ie + le16_to_cpu(ie->length));
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



static u8 *ntfs_ie_get_end(INDEX_HEADER *ih)
{
	/* FIXME: check if it isn't overflowing the index block size */
	return (u8 *)ih + le32_to_cpu(ih->index_length);
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

static int ntfs_ih_one_entry(INDEX_HEADER *ih)
{
	return (ntfs_ih_numof_entries(ih) == 1);
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
	/* not support
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
			ntfs_debug("Before flush_dcache_mft_record_page ");
			flush_dcache_mft_record_page(icx->actx->ntfs_ino);

			ntfs_debug("Before mark_mft_record_dirty ");
			mark_mft_record_dirty(icx->actx->ntfs_ino);
/******* **********/
		} 
		else
		{
			/* shut by Gzged
			if (ntfs_icx_ib_write(icx))
			{
				goto err_out;
			}
			*/
			ntfs_debug("Before ntfs_index_entry_flush_dcache_page ");
			ntfs_index_entry_flush_dcache_page(icx);
			ntfs_debug("Before ntfs_index_entry_mark_dirty ");
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
		/** use my func
		if (ntfs_index_lookup(key, keylen, icx))
		*/
		if ( (ret = ntfs_lookup_inode_by_key (key, keylen, icx) ) )
		{
			ntfs_debug("ntfs_lookup_inode_by_key faild ...");
			goto err_out;
		}
/*********debug print
	{
			struct qstr nls_name;
			nls_name.name = NULL;
			nls_name.len = (unsigned)ntfs_ucstonls(ni->vol,
			                ((FILE_NAME_ATTR *)icx->data)->file_name , icx->data_len,
							                (unsigned char**)&nls_name.name, 0);
			ntfs_debug("icx data name=[%s]",nls_name.name);
			kfree(nls_name.name);
	}

		if (((FILE_NAME_ATTR *)icx->data)->file_attributes & FILE_ATTR_REPARSE_POINT) 
		{
			ntfs_debug("not support faild ");
			ret = -EOPNOTSUPP;
			goto err_out;
		} ********/
/*********debug print ********/

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
/***********Gzged change
		ntfs_inode_mark_dirty(icx->actx->ntfs_ino);
		ntfs_index_ctx_reinit(icx);
***************/
        ntfs_index_ctx_put(icx);
		ntfs_index_ctx_get(ni);
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

static __inline__ int ntfs_attrs_walk(ntfs_attr_search_ctx *ctx)
{
	/** case all attr **/
    return ntfs_attr_lookup(0, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, ctx);
}


//static const char *es = "  Leaving inconsistent metadata.  Unmount and run chkdsk.";
typedef bool BOOL;
#include "lcnalloc.h"
int ntfs_delete(ntfs_inode *ni, ntfs_inode *dir_ni )
{
	ntfs_attr_search_ctx *actx = NULL;
	MFT_RECORD* mrec;
	FILE_NAME_ATTR *fn = NULL;
	ntfs_volume* vol=ni->vol;
	/*
	BOOL looking_for_dos_name = FALSE, looking_for_win32_name = FALSE;
	BOOL case_sensitive_match = TRUE;
	*/
	int err = 0;

	ntfs_debug("Entering");

	mrec = map_mft_record(ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		mrec = NULL;
		goto err_out;
	}

    if ( (mrec->flags & MFT_RECORD_IS_DIRECTORY) )
	{
		ntfs_debug("Invalid arguments.");
		err=  -EINVAL;
		goto err_out;
	}
	
	if (!ni || !dir_ni ) 
	{
		ntfs_debug("Invalid arguments.");
		err=  -EINVAL;
		goto err_out;
	}

	if (ni->nr_extents == -1)
		ni = ni->ext.base_ntfs_ino;
	if (dir_ni->nr_extents == -1)
		dir_ni = dir_ni->ext.base_ntfs_ino;


/******************************************* get fn ******************/
	/*
	 * Search for FILE_NAME attribute with such name. If it's in POSIX or
	 * WIN32_AND_DOS namespace, then simply remove it from index and inode.
	 * If filename in DOS or in WIN32 namespace, then remove DOS name first,
	 * only then remove WIN32 name.
	 */
	actx = ntfs_attr_get_search_ctx(ni, mrec);
	if (!actx)
	{
		goto err_out;
	}
	while (!ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE,
			0, NULL, 0, actx)) {
/*debuger need...
		char *s;
		**/
		BOOL case_sensitive = IGNORE_CASE;

		fn = (FILE_NAME_ATTR*)((u8*)actx->attr +
				le16_to_cpu(actx->attr->data.resident.value_offset));
/*debuger need...
		s = ntfs_attr_name_get(fn->file_name, fn->file_name_length);
		ntfs_debug("name: '%s'  type: %d  dos: %d  win32: %d  "
			       "case: %d\n", s, fn->file_name_type,
			       looking_for_dos_name, looking_for_win32_name,
			       case_sensitive_match);
		ntfs_attr_name_free(&s);
		*/
/** all ways use posix name
		if (looking_for_dos_name) {
			if (fn->file_name_type == FILE_NAME_DOS)
				break;
			else
				continue;
		}
		if (looking_for_win32_name) {
			if  (fn->file_name_type == FILE_NAME_WIN32)
				break;
			else
				continue;
		}
		**/
		
		/* Ignore hard links from other directories */
		if (dir_ni->mft_no != MREF_LE(fn->parent_directory)) {
			ntfs_debug("MFT record numbers don't match "
				       "(%llu != %llu)", 
				       (long long unsigned)dir_ni->mft_no, 
				       (long long unsigned)MREF_LE(fn->parent_directory));
			continue;
		}
		     
/****all ways use posix case
		if (fn->file_name_type == FILE_NAME_POSIX || case_sensitive_match)
		*/
			case_sensitive = CASE_SENSITIVE;
		
		/** all ways think name is equal 
		if (ntfs_names_are_equal(fn->file_name, fn->file_name_length,
					 name, name_len, case_sensitive, 
					 ni->vol->upcase, ni->vol->upcase_len))*/ {
			
			/**  all ways think it`s posix name...
			if (fn->file_name_type == FILE_NAME_WIN32) {
				looking_for_dos_name = TRUE;
				ntfs_attr_reinit_search_ctx(actx);
				continue;
			}
			if (fn->file_name_type == FILE_NAME_DOS)
				looking_for_dos_name = TRUE;
				*/
			break;
		}
	}
/******************************************* get fn ******************/
	
/*********** cut the entry down *****************/
	if ( (err = ntfs_index_remove(dir_ni, fn, le32_to_cpu(actx->attr->data.resident.value_length)) ) )
	{
		ntfs_debug("ntfs_index_remove error.");
		goto err_out;
	}
	
	mrec->link_count = cpu_to_le16(le16_to_cpu( mrec->link_count) - 1);
/*********** cut the entry down *****************/


/********************flush ***************/
	flush_dcache_mft_record_page(ni);
	mark_mft_record_dirty(ni);
/********************flush end ***************/

/********************cut down all run list ***************/
	ntfs_attr_put_search_ctx(actx);
	actx = ntfs_attr_get_search_ctx(ni, mrec);
	
	err=  STATUS_OK ;
	ntfs_debug("Before while ");
	while (!ntfs_attrs_walk(actx)) 
	{
		ntfs_debug("new loop ");
		if (actx->attr->non_resident) 
		{
			ntfs_debug("Inner case ");
			/*
			runlist *rl;
			rl = ntfs_mapping_pairs_decompress(ni->vol, actx->attr,
					NULL);
			if (!rl) {
				err = -EOPNOTSUPP ;
				ntfs_debug("Failed to decompress runlist.  "
						"Leaving inconsistent metadata.\n");
				continue;
			}
			if (ntfs_cluster_free_from_rl(ni->vol, rl)) {
				err = -EOPNOTSUPP ;
				ntfs_debug("Failed to free clusters.  "
						"Leaving inconsistent metadata.\n");
				continue;
			}
			free(rl);
			*/

			/* alloc_change < 0 */
			/* Free the clusters. 
			err = ntfs_cluster_free(ni, 0, -1, actx);*/
			
			ntfs_debug("before __ntfs_cluster_free ");
			err = __ntfs_cluster_free(ni, 0, -1, actx, false);
			if (unlikely(err < 0)) 
			{
				ntfs_error(vol->sb, "Failed to release cluster(s) (error code "
						"%lli).  Unmount and run chkdsk to recover "
						"the lost cluster(s).", (long long)err);
				NVolSetErrors(vol);
				err = 0;
			}
			/* Truncate the runlist.  NO NEED
			err = ntfs_rl_truncate_nolock(vol, &ni->runlist, 0);
			if (unlikely(err || IS_ERR(actx->mrec))) 
			{
				ntfs_error(vol->sb, "Failed to %s (error code %li).%s",
						IS_ERR(actx->mrec) ?
						"restore attribute search context" :
						"truncate attribute runlist",
						IS_ERR(actx->mrec) ? PTR_ERR(actx->mrec) : err, es);
				err = -EIO;
				goto err_out;
			}*/
			ntfs_debug("before flush_dcache_mft_record_page actx->ntfs_ino[%p]",actx->ntfs_ino);
			flush_dcache_mft_record_page(actx->ntfs_ino);
			ntfs_debug("before mark_mft_record_dirty actx->ntfs_ino[%p]",actx->ntfs_ino);
			mark_mft_record_dirty(actx->ntfs_ino);
		}
	}
	if (err ) 
	{
		ntfs_debug("Attribute enumeration failed.  "
				"Probably leaving inconsistent metadata.\n");
	}
	/* All extents should be attached after attribute walk. */
	while (ni->nr_extents)
	{
		ntfs_error(vol->sb,"need use ntfs_extent_mft_record_free. not support now ");
		/**FIXME
		if ( ( err = ntfs_mft_record_free(ni->vol, *(ni->extent_nis) ))) 
		{
			ntfs_debug("Failed to free extent MFT record.  "
					"Leaving inconsistent metadata.\n");
		}
		**/
	}

	if (ntfs_mft_record_free(ni->vol, ni,mrec)) 
	{
		err = -EIO;
		ntfs_debug("Failed to free base MFT record.  "
				"Leaving inconsistent metadata.\n");
	}
	/* FIXME */

	flush_dcache_mft_record_page(ni);
	mark_mft_record_dirty(ni);
/*************Gzged add *********/
	ntfs_debug("before unmap_mft_record.");
	unmap_mft_record(ni);
	ni = NULL;
	mrec=NULL;


	/** Gzged shut now
	ntfs_inode_update_times(dir_ni, NTFS_UPDATE_MCTIME);
	*/
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

static int gzged_ntfs_unlink(struct inode *pi,struct dentry *pd)
{
	ntfs_inode* ni = NTFS_I(pd->d_inode);
	int err = -ENOENT;

	ntfs_debug("Entering");
	BUG_ON(!ni);

	err =   ntfs_delete(ni,NTFS_I(pi));
	if(err)
	{
		ntfs_debug("Faile");
		return err;
	}
	else
	{
		(VFS_I(ni))->i_ctime = pi->i_ctime;
		(VFS_I(ni))->i_nlink--;
		ntfs_debug("Done");
		return  err;
	}
}

/**
 * Inode operations for directories.
 */
const struct inode_operations ntfs_dir_inode_ops = {
	.lookup	= ntfs_lookup,	/* VFS: Lookup directory. */
	.create = gzged_ntfs_create,
	.unlink = gzged_ntfs_unlink,
};

