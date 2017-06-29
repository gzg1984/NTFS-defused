#include "ntfs_g.h"
#include <linux/security.h>



/*
static void update_page_reclaim_stat(struct zone *zone, struct page *page,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &zone->reclaim_stat;
	struct zone_reclaim_stat *memcg_reclaim_stat;

	memcg_reclaim_stat = mem_cgroup_get_reclaim_stat_from_page(page);

	reclaim_stat->recent_scanned[file]++;
	if (rotated)
		reclaim_stat->recent_rotated[file]++;

	if (!memcg_reclaim_stat)
		return;

	memcg_reclaim_stat->recent_scanned[file]++;
	if (rotated)
		memcg_reclaim_stat->recent_rotated[file]++;
}
*/

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 */
/* Gzged shut
void ____pagevec_lru_add(struct pagevec *pvec, enum lru_list lru)
{
	int i;
	struct zone *zone = NULL;

	VM_BUG_ON(is_unevictable_lru(lru));

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		struct zone *pagezone = page_zone(page);
		int file;
		int active;

		if (pagezone != zone) {
			if (zone)
				spin_unlock_irq(&zone->lru_lock);
			zone = pagezone;
			spin_lock_irq(&zone->lru_lock);
		}
		VM_BUG_ON(PageActive(page));
		VM_BUG_ON(PageUnevictable(page));
		VM_BUG_ON(PageLRU(page));
		SetPageLRU(page);
		active = is_active_lru(lru);
		file = is_file_lru(lru);
		if (active)
			SetPageActive(page);
		update_page_reclaim_stat(zone, page, file, active);
		add_page_to_lru_list(zone, page, lru);
	}
	if (zone)
		spin_unlock_irq(&zone->lru_lock);
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	pagevec_reinit(pvec);
}

EXPORT_SYMBOL(____pagevec_lru_add);
*/


int cap_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}
EXPORT_SYMBOL(cap_inode_need_killpriv);

int cap_inode_killpriv(struct dentry *dentry)
{
	return 0;
}
EXPORT_SYMBOL(cap_inode_killpriv);


static int __remove_suid(struct dentry *dentry, int kill)
{
	struct iattr newattrs;

	newattrs.ia_valid = ATTR_FORCE | kill;
	return notify_change(dentry, &newattrs);
}




/*
 * The logic we want is
 *
 *	if suid or (sgid and xgrp)
 *		remove privs
 */
int should_remove_suid(struct dentry *dentry)
{
	mode_t mode = dentry->d_inode->i_mode;
	int kill = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && !capable(CAP_FSETID) && S_ISREG(mode)))
		return kill;

	return 0;
}
EXPORT_SYMBOL(should_remove_suid);


/*
 * Performs necessary checks before doing a write
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @count:	number of bytes to write
 * @access_flags: type of access: %VERIFY_READ or %VERIFY_WRITE
 *
 * Adjust number of segments and amount of bytes to write (nr_segs should be
 * properly initialized first). Returns appropriate error code that caller
 * should return or zero in case that write should be allowed.
 */
int generic_segment_checks(const struct iovec *iov,
			unsigned long *nr_segs, size_t *count, int access_flags)
{
	unsigned long   seg;
	size_t cnt = 0;
	for (seg = 0; seg < *nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		cnt += iv->iov_len;
		if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(access_flags, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		*nr_segs = seg;
		cnt -= iv->iov_len;	/* This segment is no good */
		break;
	}
	*count = cnt;
	return 0;
}
EXPORT_SYMBOL(generic_segment_checks);


int file_remove_suid(struct file *file)
{
    struct dentry *dentry = file->f_dentry;
    int killsuid = should_remove_suid(dentry);
    int killpriv = security_inode_need_killpriv(dentry);
    int error = 0;

    if (killpriv < 0)
        return killpriv;
    if (killpriv)
        error = security_inode_killpriv(dentry);
    if (!error && killsuid)
        error = __remove_suid(dentry, killsuid);

    return error;
}
EXPORT_SYMBOL(file_remove_suid);




/**
 * mnt_want_write - get write access to a mount
 * @mnt: the mount on which to take a write
 *
 * This tells the low-level filesystem that a write is
 * about to be performed to it, and makes sure that
 * writes are allowed before returning success.  When
 * the write operation is finished, mnt_drop_write()
 * must be called.  This is effectively a refcount.
 */
/*
int mnt_want_write(struct vfsmount *mnt)
{
	int ret = 0;
	struct mnt_writer *cpu_writer;

	cpu_writer = &get_cpu_var(mnt_writers);
	spin_lock(&cpu_writer->lock);
	if (__mnt_is_readonly(mnt)) {
		ret = -EROFS;
		goto out;
	}
	use_cpu_writer_for_mount(cpu_writer, mnt);
	cpu_writer->count++;
out:
	spin_unlock(&cpu_writer->lock);
	put_cpu_var(mnt_writers);
	return ret;
}
EXPORT_SYMBOL_GPL(mnt_want_write);
*/




void file_update_time(struct file *file)
{
	struct inode *inode = file->f_dentry->d_inode;
	struct timespec now;
	int sync_it = 0;
	//int err;

	if (IS_NOCMTIME(inode))
		return;

	/*
	err = mnt_want_write(file->f_vfsmnt);
	if (err)
	*/
		return;

	now = current_fs_time(inode->i_sb);
	if (!timespec_equal(&inode->i_mtime, &now)) {
		inode->i_mtime = now;
		sync_it = 1;
	}

	if (!timespec_equal(&inode->i_ctime, &now)) {
		inode->i_ctime = now;
		sync_it = 1;
	}

	if (IS_I_VERSION(inode)) {
		inode_inc_iversion(inode);
		sync_it = 1;
	}

	if (sync_it)
		mark_inode_dirty_sync(inode);
	/* Gzged shut
	mnt_drop_write(file->f_vfsmnt);
	*/
}
EXPORT_SYMBOL(file_update_time);

int sb_has_dirty_inodes(struct super_block *sb)
{
	/*Gzged shut
    return !list_empty(&sb->s_dirty) ||
           !list_empty(&sb->s_io) ||
           !list_empty(&sb->s_more_io);
		   */
    return !list_empty(&sb->s_dirty) || !list_empty(&sb->s_io) ;
}
EXPORT_SYMBOL(sb_has_dirty_inodes);


/** for namei.o **/


/* the caller must hold dcache_lock */
static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (inode)
		list_add(&dentry->d_alias, &inode->i_dentry);
	dentry->d_inode = inode;
	fsnotify_d_instantiate(dentry, inode);
}
/*
 * inotify_d_instantiate - instantiate dcache entry for inode
 */
void inotify_d_instantiate(struct dentry *entry, struct inode *inode)
{
	return ;
}
EXPORT_SYMBOL(inotify_d_instantiate);




/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On hash failure or on lookup failure NULL is returned.
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	struct dentry *dentry = NULL;

	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		if (dir->d_op->d_hash(dir, name) < 0)
			goto out;
	}
	dentry = d_lookup(dir, name);
out:
	return dentry;
}



/**
 * d_add_ci - lookup or allocate new dentry with case-exact name
 * @inode:  the inode case-insensitive lookup has found
 * @dentry: the negative dentry that was passed to the parent's lookup func
 * @name:   the case-exact name to be associated with the returned dentry
 *
 * This is to avoid filling the dcache with case-insensitive names to the
 * same inode, only the actual correct case is stored in the dcache for
 * case-insensitive filesystems.
 *
 * For a case-insensitive lookup match and if the the case-exact dentry
 * already exists in in the dcache, use it and return it.
 *
 * If no entry exists with the exact case name, allocate new dentry with
 * the exact case, and return the spliced entry.
 */
struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
			struct qstr *name)
{
	int error;
	struct dentry *found;
	struct dentry *new;

	/*
	 * First check if a dentry matching the name already exists,
	 * if not go ahead and create it now.
	 */
	found = d_hash_and_lookup(dentry->d_parent, name);
	if (!found) {
		new = d_alloc(dentry->d_parent, name);
		if (!new) {
			error = -ENOMEM;
			goto err_out;
		}

		found = d_splice_alias(inode, new);
		if (found) {
			dput(new);
			return found;
		}
		return new;
	}

	/*
	 * If a matching dentry exists, and it's not negative use it.
	 *
	 * Decrement the reference count to balance the iget() done
	 * earlier on.
	 */
	if (found->d_inode) {
		if (unlikely(found->d_inode != inode)) {
			/* This can't happen because bad inodes are unhashed. */
			BUG_ON(!is_bad_inode(inode));
			BUG_ON(!is_bad_inode(found->d_inode));
		}
		iput(inode);
		return found;
	}

	/*
	 * Negative dentry: instantiate it unless the inode is a directory and
	 * already has a dentry.
	 */
	spin_lock(&dcache_lock);
	if (!S_ISDIR(inode->i_mode) || list_empty(&inode->i_dentry)) {
		__d_instantiate(found, inode);
		spin_unlock(&dcache_lock);
		security_d_instantiate(found, inode);
		return found;
	}

	/*
	 * In case a directory already has a (disconnected) entry grab a
	 * reference to it, move it in place and use it.
	 */
	new = list_entry(inode->i_dentry.next, struct dentry, d_alias);
	dget_locked(new);
	spin_unlock(&dcache_lock);
	security_d_instantiate(found, inode);
	d_move(new, found);
	iput(inode);
	dput(found);
	return new;

err_out:
	iput(inode);
	return ERR_PTR(error);
}
EXPORT_SYMBOL(d_add_ci);
