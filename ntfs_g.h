#ifndef __NTFS_G_H__
#define __NTFS_G_H__

#define DCACHE_BUG
#define kmem_cache kmem_cache_s

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/module.h>
//#include <linux/config.h>

#include <linux/mm.h>
#ifdef CONFIG_DEBUG_VM
#define VM_BUG_ON(cond) BUG_ON(cond)
#else
#define VM_BUG_ON(cond) do { } while (0)
#endif

#include <linux/backing-dev.h>


//#include <asm/semaphore.h>
#define DEFINE_MUTEX(m) DECLARE_MUTEX(m)
#define mutex_init(m) init_MUTEX(m)
#define mutex_destroy(m) do { } while (0)
#define mutex_lock(m) down(m)
#define mutex_unlock(m) up(m)
#define mutex_trylock(lock)         (down_trylock(lock) ? 0 : 1)
#define mutex semaphore

#ifndef HAVE_I_MUTEX
#ifndef mutex_destroy
/* Some RHEL kernels include a backported mutex.h, which lacks mutex_destroy */
#define mutex_destroy(m) do { } while (0)
#endif
#define i_mutex i_sem	/* Hack for struct inode */
#endif /** HAVE_I_MUTEX **/



/**
 * __mutex_fastpath_trylock - try to acquire the mutex, without waiting
 *
 *  @count: pointer of type atomic_t
 *  @fail_fn: fallback function
 *
 * Change the count from 1 to a value lower than 1, and return 0 (failure)
 * if it wasn't 1 originally, or return 1 (success) otherwise. This function
 * MUST leave the value lower than 1 even when the "1" assertion wasn't true.
 * Additionally, if the value was < 0 originally, this function must not leave
 * it to 0 on failure.
 */
static inline int __mutex_fastpath_trylock(atomic_t *count,
					   int (*fail_fn)(atomic_t *))
{
	/*
	 * We have two variants here. The cmpxchg based one is the best one
	 * because it never induce a false contention state.  It is included
	 * here because architectures using the inc/dec algorithms over the
	 * xchg ones are much more likely to support cmpxchg natively.
	 *
	 * If not we fall back to the spinlock based variant - that is
	 * just as efficient (and simpler) as a 'destructive' probing of
	 * the mutex state would be.
	 */
#ifdef __HAVE_ARCH_CMPXCHG
	if (likely(atomic_cmpxchg(count, 1, 0) == 1))
		return 1;
	return 0;
#else
	return fail_fn(count);
#endif
}


/** 2.6.13 -> 2.6.19 */
#define clear_nlink(inode) (inode)->i_nlink = 0
#define inc_nlink(inode) (inode)->i_nlink++

#ifndef HAVE_CONFIG_BLOCK
#define CONFIG_BLOCK
#endif
#ifndef FS_HAS_SUBTYPE
#define FS_HAS_SUBTYPE 0
#endif
#ifndef FS_SAFE
#define FS_SAFE 0
#endif

#define current_uid()       (current->uid)
#define current_gid()       (current->gid)
#define current_fsuid()       (current->fsuid)

typedef enum{false = 0, true} bool;


#include "lockdep.h"


static inline int is_vmalloc_addr(const void *x)
{
#ifdef CONFIG_MMU
    unsigned long addr = (unsigned long)x;

    return addr >= VMALLOC_START && addr < VMALLOC_END;
#else
    return 0;
#endif
}


#include <linux/pagemap.h>
static inline struct page *read_mapping_page(struct address_space *mapping,
                         pgoff_t index, void *data)
{
    filler_t *filler = (filler_t *)mapping->a_ops->readpage;
    return read_cache_page(mapping, index, filler, data);
}

static inline void zero_user_segments(struct page *page,
    unsigned start1, unsigned end1,
    unsigned start2, unsigned end2)
{
    void *kaddr = kmap_atomic(page, KM_USER0);

    BUG_ON(end1 > PAGE_SIZE || end2 > PAGE_SIZE);

    if (end1 > start1)
        memset(kaddr + start1, 0, end1 - start1);

    if (end2 > start2)
        memset(kaddr + start2, 0, end2 - start2);

    kunmap_atomic(kaddr, KM_USER0);
    flush_dcache_page(page);
}

static inline void zero_user(struct page *page,
		unsigned start, unsigned size)
{
	zero_user_segments(page, start, start + size, 0, 0);
}
static inline void zero_user_segment(struct page *page,
		unsigned start, unsigned end)
{
	zero_user_segments(page, start, end, 0, 0);
}





static __always_inline int
test_and_set_bit_lock(int nr, volatile unsigned long *addr)
{                      
    return test_and_set_bit(nr, addr);
}  

#include <linux/buffer_head.h>
static inline int trylock_buffer(struct buffer_head *bh)
{
    return likely(!test_and_set_bit_lock(BH_Lock, &bh->b_state));
}


/*
#define f_dentry    f_path.dentry
#define f_vfsmnt    f_path.mnt
*/

/*
#include <linux/pagevec.h>
*/


/*
 * We do arithmetic on the LRU lists in various places in the code,
 * so it is important to keep the active lists LRU_ACTIVE higher in
 * the array than the corresponding inactive lists, and to keep
 * the *_FILE lists LRU_FILE higher than the corresponding _ANON lists.
 *
 * This has to be kept in sync with the statistics in zone_stat_item
 * above and the descriptions in vmstat_text in mm/vmstat.c
 */
#define LRU_BASE 0
#define LRU_ACTIVE 1
#define LRU_FILE 2

enum lru_list {
	LRU_INACTIVE_ANON = LRU_BASE,
	LRU_ACTIVE_ANON = LRU_BASE + LRU_ACTIVE,
	LRU_INACTIVE_FILE = LRU_BASE + LRU_FILE,
	LRU_ACTIVE_FILE = LRU_BASE + LRU_FILE + LRU_ACTIVE,
#ifdef CONFIG_UNEVICTABLE_LRU
	LRU_UNEVICTABLE,
#else
	LRU_UNEVICTABLE = LRU_ACTIVE_FILE, /* avoid compiler errors in dead code */
#endif
	NR_LRU_LISTS
};

/*
static inline void add_page_to_lru_list(struct zone *zone, struct page *page, enum lru_list l)
{
	list_add(&page->lru, &zone->lru[l].list);
	__inc_zone_state(zone, NR_LRU_BASE + l);
	mem_cgroup_add_lru_list(page, l);
}

static inline int is_file_lru(enum lru_list l)
{
	return (l == LRU_INACTIVE_FILE || l == LRU_ACTIVE_FILE);
}
static inline int is_active_lru(enum lru_list l)
{
	return (l == LRU_ACTIVE_ANON || l == LRU_ACTIVE_FILE);
}

void ____pagevec_lru_add(struct pagevec *pvec, enum lru_list lru);
static inline void __pagevec_lru_add_file(struct pagevec *pvec)
{
	____pagevec_lru_add(pvec, LRU_INACTIVE_FILE);
}
static inline void pagevec_lru_add_file(struct pagevec *pvec)
{
	if (pagevec_count(pvec))
		__pagevec_lru_add_file(pvec);
}
*/

int generic_segment_checks(const struct iovec *iov,
		unsigned long *nr_segs, size_t *count, int access_flags);


int file_remove_suid(struct file *file);

void file_update_time(struct file *file);





/** for super.c **/
int sb_has_dirty_inodes(struct super_block *sb);




/*for fs/ntfs/upcase.o */
static inline void le16_add_cpu(__le16 *var, u16 val)
{
	*var = cpu_to_le16(le16_to_cpu(*var) + val);
}


/* for ntfs_g.o */
int cap_inode_need_killpriv(struct dentry *dentry);
int cap_inode_killpriv(struct dentry *dentry);
static inline int security_inode_need_killpriv(struct dentry *dentry)
{
	return cap_inode_need_killpriv(dentry);
}

static inline int security_inode_killpriv(struct dentry *dentry)
{
	return cap_inode_killpriv(dentry);
}

/*shut
 * include/linux/security.h have it
static inline int security_inode_getsecurity(const struct inode *inode, const char *name, void **buffer, bool alloc)
{
	return -EOPNOTSUPP;
}

static inline int security_inode_setsecurity(struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
	return -EOPNOTSUPP;
}
*/



#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))
#define IS_I_VERSION(inode)   __IS_FLG(inode, MS_I_VERSION)
#define MS_I_VERSION    (1<<23) /* Update inode I_version field */

/**
 *  * inode_inc_iversion - increments i_version
 *   * @inode: inode that need to be updated
 *    *
 *     * Every time the inode is modified, the i_version field will be incremented.
 *      * The filesystem has to be mounted with i_version flag
 *       */

static inline void inode_inc_iversion(struct inode *inode)
{
       spin_lock(&inode->i_lock);
       inode->i_version++;
       spin_unlock(&inode->i_lock);
}


/** for namei.o */
struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
            struct qstr *name);
/*
 *  * fsnotify_d_instantiate - instantiate a dentry for inode
 *   * Called with dcache_lock held.
 *    */
void inotify_d_instantiate(struct dentry *entry, struct inode *inode);
static inline void fsnotify_d_instantiate(struct dentry *entry,
		struct inode *inode)
{
	inotify_d_instantiate(entry, inode);
}



#endif

