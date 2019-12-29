#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct ext4_attr {
	struct attribute attr;
	short attr_id;
	short attr_ptr;
	union {
		int offset;
		void *explicit_ptr;
	} u;
};


typedef enum {
	attr_noop,
	attr_delayed_allocation_blocks,
	attr_session_write_kbytes,
	attr_lifetime_write_kbytes,
	attr_reserved_clusters,
	attr_inode_readahead,
	attr_trigger_test_error,
	attr_feature,
	attr_pointer_ui,
	attr_pointer_atomic,
} attr_id_t;


#define EXT4_ATTR(_name,_mode,_id)                                      \
	static struct ext4_attr ext4_attr_##_name = {                           \
		        .attr = {.name = __stringify(_name), .mode = _mode },           \
		        .attr_id = attr_##_id,                                          \
	}

#define EXT4_ATTR_FUNC(_name,_mode)  EXT4_ATTR(_name,_mode,_name)

EXT4_ATTR_FUNC(delayed_allocation_blocks, 0444);

#define ATTR_LIST(name) &ext4_attr_##name.attr


static struct attribute *ntfs_attrs[] = {
	ATTR_LIST(delayed_allocation_blocks),
	NULL,
};


static ssize_t ntfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "supported\n");
	return 0;
}

static ssize_t ntfs_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	return 0;
}

static void ntfs_sb_release(struct kobject *kobj)
{
	/*
	struct ext4_sb_info *sbi = container_of(kobj, struct ext4_sb_info,
						s_kobj);
	complete(&sbi->s_kobj_unregister);
	*/
}

static const struct sysfs_ops ntfs_attr_ops = {
	.show   = ntfs_attr_show,
	.store  = ntfs_attr_store,
};

static struct kobj_type ntfs_sb_ktype = {
	.default_attrs  = ntfs_attrs,
	.sysfs_ops      = &ntfs_attr_ops,
	.release        = ntfs_sb_release,
};

static struct kobj_type ntfs_ktype = {
	.sysfs_ops      = &ntfs_attr_ops,
};

static struct kset ntfs_kset = {
	.kobj   = {.ktype = &ntfs_ktype},
};


#define EXT4_ATTR_FEATURE(_name)   EXT4_ATTR(_name, 0444, feature)
EXT4_ATTR_FEATURE(lazy_itable_init);


static struct attribute *ntfs_feat_attrs[] = {
	ATTR_LIST(lazy_itable_init),
	NULL,
};



static struct kobj_type ntfs_feat_ktype = {
	        .default_attrs  = ntfs_feat_attrs,
		        .sysfs_ops      = &ntfs_attr_ops,
};

static struct kobject ntfs_feat = {
	        .kset   = &ntfs_kset,
};

extern int next_g_sysfs_init(void)
{
	int ret;
	kobject_set_name(&ntfs_kset.kobj, "ntfs");
	ntfs_kset.kobj.parent = fs_kobj;

	ret = kset_register(&ntfs_kset);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&ntfs_feat, &ntfs_feat_ktype,
			NULL, "features");
	if (ret)
	{
		kset_unregister(&ntfs_kset);
		return -1;
	}
	else
	{
		return 0;
	}
}

extern void next_g_sysfs_exit(void)
{
	kobject_put(&ntfs_feat);
	kset_unregister(&ntfs_kset);
	return;
}


