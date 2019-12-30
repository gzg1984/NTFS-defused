#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "sysfs.h"
#include "../volume.h"


#define EXT4_ATTR_FUNC(_name,_mode)  NTFS_ATTR(_name,_mode,_name)

EXT4_ATTR_FUNC(map_ino, 0444);

#define ATTR_LIST(name) &ntfs_attr_##name.attr


static struct attribute *ntfs_attrs[] = {
	ATTR_LIST(map_ino),
	NULL,
};


static ssize_t ntfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	ntfs_volume *nv = container_of(kobj,  ntfs_volume,v_kobj);
    struct ntfs_attr *a = container_of(attr, struct ntfs_attr, attr);

	return snprintf(buf, PAGE_SIZE, "%s+%s+%ld+%ld\n",
		kobj->name,attr->name,nv->mftbmp_ino->i_ino,nv->mft_ino->i_ino);
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

int ntfs_register_volume_sysfs(ntfs_volume *nv)
{       
	int err;

	struct kobject* p=&(nv->v_kobj);

	p->kset = &ntfs_top;
	if (nv && nv->sb && nv->sb->s_id)
	{
		err = kobject_init_and_add(p, &ntfs_sb_ktype, NULL,
			"%s", nv->sb->s_id);
	}
	else
	{
		
		err = kobject_init_and_add(p, &ntfs_sb_ktype, NULL,
			"unknown");
	
	}
	

	if (err)
		return err;

	return 0;
}

void ntfs_unregister_volume_sysfs(ntfs_volume *nv)
{
	struct kobject* p=&nv->v_kobj;

	kobject_del(p);
}

