#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "../debug.h"
#include "sysfs.h"
#include "../ntfs.h"


static ssize_t ntfs_show_feature_attr(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	if (!strcmp(attr->name,"debug_enabled"))
	{
		return snprintf(buf, PAGE_SIZE, "%d\n",debug_msgs);
	}
	if (!strcmp(attr->name,"mount_type"))
	{
		return snprintf(buf, PAGE_SIZE, "%s",FS_NAME);
	}
	return 0;
}

static ssize_t ntfs_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	if (!strcmp(attr->name,"debug_enabled"))
	{
		if (len >=1)
		{
			switch(buf[0])
			{
				case '0':
					debug_msgs=0;
					break;
				case '1':
					debug_msgs=1;
					break;
				default:
					break;
			}
		}	
	}

	return 0;
}

static const struct sysfs_ops ntfs_attr_ops = {
	.show   = ntfs_show_feature_attr,
	.store  = ntfs_attr_store,
};

#define INIT_ATTR_FEATURE(_name)   NTFS_ATTR(_name, 0444, feature)
INIT_ATTR_FEATURE(debug_enabled);
INIT_ATTR_FEATURE(mount_type);



#define FEATURE_LIST(name) &ntfs_attr_##name.attr
static struct attribute *ntfs_feat_attrs[] = {
	FEATURE_LIST(debug_enabled),
	FEATURE_LIST(mount_type),
	NULL,
};

static struct kobj_type ntfs_feat_ktype = {
	.default_attrs  = ntfs_feat_attrs,
	.sysfs_ops      = &ntfs_attr_ops,
};

static struct kobj_type _no_attr_at_top={};

struct kset ntfs_top = {
	.kobj   = {.ktype = &_no_attr_at_top },
};

static struct kobject ntfs_feat = {
	.kset   = &ntfs_top,
};

extern int next_g_sysfs_init(void)
{
	int ret;
	kobject_set_name(&ntfs_top.kobj, "ntfs");
	ntfs_top.kobj.parent = fs_kobj;

	ret = kset_register(&ntfs_top);
	if (ret)
		return ret;

	ret = kobject_init_and_add(&ntfs_feat, &ntfs_feat_ktype,
			NULL, "features");
	if (ret)
	{
		kset_unregister(&ntfs_top);
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
	kset_unregister(&ntfs_top);
	return;
}


