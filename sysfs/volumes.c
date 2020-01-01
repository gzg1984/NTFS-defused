#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "sysfs.h"
#include "../volume.h"
#include "../ntfs_inode.h"

#define NTFS_ATTR_FUNC(_name,_mode)  NTFS_ATTR(_name,_mode,_name)
#define ATTR_LIST(name) &ntfs_attr_##name.attr

typedef enum {
	e_attr_volume_mft = 1 ,
	e_attr_volume_mftbmp,
	e_attr_volume_lcnbmp,
	e_attr_volume_root,
	e_attr_volume_superblock,
	e_attr_major_ver ,
	e_attr_minor_ver,
} volume_attr_id_t;

NTFS_ATTR_FUNC(volume_mft, 0444);
NTFS_ATTR_FUNC(volume_mftbmp, 0444);
NTFS_ATTR_FUNC(volume_lcnbmp, 0444);
NTFS_ATTR_FUNC(volume_root, 0444);
NTFS_ATTR_FUNC(volume_superblock, 0444);
NTFS_ATTR_FUNC(major_ver, 0444);
NTFS_ATTR_FUNC(minor_ver, 0444);

static struct attribute *ntfs_attrs[] = {
	ATTR_LIST(volume_mft),
	ATTR_LIST(volume_mftbmp),
	ATTR_LIST(volume_lcnbmp),
	ATTR_LIST(volume_root),
	ATTR_LIST(volume_superblock),
	ATTR_LIST(major_ver),
	ATTR_LIST(minor_ver),
	NULL,
};
static ssize_t ntfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct kset* ns=container_of(kobj, struct kset,kobj);
	ntfs_volume *nv = container_of(ns,  ntfs_volume,v_kset);
    struct ntfs_attr *a = container_of(attr, struct ntfs_attr, attr);

	if(!strcmp(attr->name,"volume_mft"))
	{
		struct inode* vi=nv->mft_ino;
		ntfs_inode* ni=NTFS_I(vi);
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
	}
	else if(!strcmp(attr->name,"volume_mftbmp"))
	{
		struct inode* vi=nv->mftbmp_ino;
		ntfs_inode* ni=NTFS_I(vi);
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
	}
	else if(!strcmp(attr->name,"volume_lcnbmp"))
	{
		struct inode* vi=nv->lcnbmp_ino;
		ntfs_inode* ni=NTFS_I(vi);
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
	}
	else if(!strcmp(attr->name,"volume_root"))
	{
		struct inode* vi=nv->root_ino;
		ntfs_inode* ni=NTFS_I(vi);
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
	}
	else if(!strcmp(attr->name,"volume_superblock"))
	{
		struct inode* vi=nv->vol_ino;
		ntfs_inode* ni=NTFS_I(nv->vol_ino);
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
	}
	else if(!strcmp(attr->name,"major_ver"))
	{
		return snprintf(buf, PAGE_SIZE,
			"major_ver=%u\n",
			nv->major_ver);
	}
	else if(!strcmp(attr->name,"minor_ver"))
	{
		return snprintf(buf, PAGE_SIZE,
			"minor_ver=%u\n",
			nv->minor_ver);
	}
	else
	{
		return snprintf(buf, PAGE_SIZE,
			"Unexpected Attr %s",attr->name);
	}
	/*Unexpected */
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

int ntfs_register_volume_sysfs(ntfs_volume *nv)
{       
	int err;
	struct kset* pk=&(nv->v_kset);

	pk->kobj.kset = &ntfs_top; /* mount the volume folder to the /sys/fs/ntfs/ */
	pk->kobj.ktype = &ntfs_sb_ktype; /* mount the volume folder to the /sys/fs/ntfs/ */
	kobject_set_name(&(pk->kobj), nv->sb->s_id);
	pk->kobj.parent = &ntfs_top.kobj;
	err = kset_register(pk);
	if (err)
	{
		return err;
	}
	return 0;
}

void ntfs_unregister_volume_sysfs(ntfs_volume *nv)
{
	struct kset* pk=&(nv->v_kset);
	kset_unregister(pk);
}

