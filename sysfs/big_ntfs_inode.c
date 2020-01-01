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
	e_attr_number = 1 ,
} mft_attr_id_t;

NTFS_ATTR_FUNC(number, 0444);

static struct attribute *ntfs_attrs[] = {
	ATTR_LIST(number),
	NULL,
};
static ssize_t ntfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{

    typedef struct {
	ntfs_inode ntfs_inode;
	struct kobject bni_kobj;
	struct inode vfs_inode;		/* The vfs inode structure. */
} big_ntfs_inode;


	big_ntfs_inode* bni=container_of(kobj, big_ntfs_inode,bni_kobj);
	ntfs_inode *ni = &(bni->ntfs_inode);
	struct inode *vi = &(bni->vfs_inode);


	if(!strcmp(attr->name,"number"))
	{
		return snprintf(buf, PAGE_SIZE,
			"i_ino=%ld\nmft_no=%ld\n",
			vi->i_ino,ni->mft_no);
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


static const struct sysfs_ops ntfs_attr_ops = {
	.show   = ntfs_attr_show,
	.store  = ntfs_attr_store,
};

static struct kobj_type ntfs_mft_ktype = {
	.default_attrs  = ntfs_attrs,
	.sysfs_ops      = &ntfs_attr_ops,
};



int ntfs_register_ntfs_inode_sysfs(struct inode *vi)
{       
	int err;
    ntfs_inode* ni=NTFS_I(vi);
    big_ntfs_inode* bni=(big_ntfs_inode*)ni;
	struct kobject* p=&(bni->bni_kobj);
    ntfs_volume* nv=ni->vol;
    struct kset* top=&(nv->v_kset);

	p->kset = top;

    err = kobject_init_and_add(p, &ntfs_mft_ktype, NULL,
			"%ld", ni->mft_no);

	if (err)
		return err;

	return 0;
}

void ntfs_unregister_ntfs_inode_sysfs(struct inode *vi)
{
    ntfs_inode* ni=NTFS_I(vi);
    big_ntfs_inode* bni=(big_ntfs_inode*)ni;
	struct kobject* p=&(bni->bni_kobj);
	kobject_del(p);
}
