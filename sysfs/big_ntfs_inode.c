#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "sysfs.h"
#include "../volume.h"
#include "../ntfs_inode.h"
#include "../attrib.h"
#include "../mft.h"
#include "../index.h"

#define NTFS_ATTR_FUNC(_name,_mode)  NTFS_ATTR(_name,_mode,_name)
#define ATTR_LIST(name) &ntfs_attr_##name.attr

typedef enum {
	e_attr_type,
	e_attr_count,
	e_attr_AT_INDEX_ROOT = AT_INDEX_ROOT ,
} mft_attr_id_t;

NTFS_ATTR_FUNC(type, 0444);
NTFS_ATTR_FUNC(count, 0444);
NTFS_ATTR_FUNC(AT_INDEX_ROOT, 0444);

static struct attribute *ntfs_attrs[] = {
	ATTR_LIST(type),
	ATTR_LIST(count),
	ATTR_LIST(AT_INDEX_ROOT),
	NULL,
};

ntfs_attr_search_ctx *get_index_root_attr(ntfs_inode* ni)
{
	MFT_RECORD * m = NULL;
	ntfs_attr_search_ctx *ctx=NULL;
	int rc = 0 ;

	/* Get hold of the mft record for the directory. */
	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		rc = PTR_ERR(m);
		m = NULL;
		goto out;
	}
	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (unlikely(!ctx)) {
		rc = -ENOMEM;
		goto out;
	}
	/* Find the index root attribute in the mft record. */
	rc = ntfs_search_attr_index_root(ctx);
	if (unlikely(rc)) 
	{
		ntfs_error(VFS_I(ni)->i_sb , 
				"Index root attribute missing in directory "
				"inode 0x%lx.", VFS_I(ni)->i_ino);
		/* keep rc as error code */
		goto out;
	}
	return ctx;
out:
	if (ctx)
	{
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
	}
	if (m)
	{
		unmap_mft_record(ni);
		m = NULL;
	}
	return NULL;
}


inline static void sysfs_show_mft_attr_dump_attr_name(char *buf,const char* prompt,
		/*const ATTR_RECORD* */const void* _a)
{
	const ATTR_RECORD* a = (ATTR_RECORD*) _a;
	int i = 0;
	char temp_name[500];
	ntfschar* name_start = (ntfschar*)(((char*)a) + a->name_offset);
	snprintf(temp_name,400,"%c ", (char)(name_start[i]));
	for(i = 1 ; i < a->name_length ; i++ )
	{                                               
		snprintf(temp_name,400,"%s%c ",temp_name,(char)(name_start[i]));
	}                                                                               
	snprintf(buf, PAGE_SIZE,"%s %s:[%s]",buf,prompt, temp_name);
}

static void sysfs_show_mft_attr(char *buf,const ATTR_REC* const attr)
{
	snprintf(buf, PAGE_SIZE,"ATTR_RECORD\n");
	snprintf(buf, PAGE_SIZE,"%s\tAttribute Type:%X[%s]\n",
		buf,attr->type,attr_type_string(attr->type));
	snprintf(buf, PAGE_SIZE,"%s\tLength:%d\n",
		buf,attr->length);
	snprintf(buf, PAGE_SIZE,"%s\tNon-resident flag:%d[%s]\n",
		buf,attr->non_resident,attr->non_resident?"non-resident":"resident");
	snprintf(buf, PAGE_SIZE,"%s\tName length:%d\n",
		buf,attr->name_length);
	snprintf(buf, PAGE_SIZE,"%s\tOffset to the Name:%d\n",
		buf,attr->name_offset);
	if(attr->name_length)
		sysfs_show_mft_attr_dump_attr_name(buf,"ATTR name:",attr);
	snprintf(buf, PAGE_SIZE,"%s\tFlags:%X\n",
		buf,attr->flags);
	snprintf(buf, PAGE_SIZE,"%s\tAttribute Id:%d\n",
		buf,attr->instance);
	if(!attr->non_resident)
	{
		snprintf(buf, PAGE_SIZE,"%s\tRESIDENT\n",buf);
		snprintf(buf, PAGE_SIZE,"%s\t\tLength of the Attribute:%d\n",
			buf,attr->data.resident.value_length);
		snprintf(buf, PAGE_SIZE,"%s\t\tOffset to the Attribute:%d\n",
			buf,attr->data.resident.value_offset);
		snprintf(buf, PAGE_SIZE,"%s\t\tIndexed flag:%d\n",
			buf,attr->data.resident.flags);
	}
}

static ssize_t ntfs_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{

	big_ntfs_inode* bni=container_of(kobj, big_ntfs_inode,bni_kobj);
	ntfs_inode *ni = &(bni->ntfs_inode);
	//struct inode *vi = &(bni->vfs_inode);


	if(!strcmp(attr->name,"AT_INDEX_ROOT"))
	{
		ntfs_attr_search_ctx *ctx=get_index_root_attr(ni);
		if(ctx)
		{
			sysfs_show_mft_attr(buf,ctx->attr);
			//debug_show_ir(ni->ir_snapshot);
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(ni);
		}

		return snprintf(buf, PAGE_SIZE,"%s\n",buf);
	}
	else if(!strcmp(attr->name,"type"))
	{
		return snprintf(buf, PAGE_SIZE,"%s\n",attr_type_string(ni->type));
	}
	else if(!strcmp(attr->name,"count"))
	{
		return snprintf(buf, PAGE_SIZE,"%d\n",atomic_read(&ni->count));
	}
	else
	{
		return snprintf(buf, PAGE_SIZE,
			"Unexpected Attr %s",attr->name);
	}
	/*Unexpected */
	return 0;
}

static ssize_t _nopermison(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t len)
{
	return -EPERM;
}


static const struct sysfs_ops ntfs_attr_ops = {
	.show   = ntfs_attr_show,
	.store  = _nopermison,
};

static struct kobj_type ntfs_mft_ktype = {
	.default_attrs  = ntfs_attrs,
	.sysfs_ops      = &ntfs_attr_ops,
};



int ntfs_register_ntfs_inode_sysfs(struct inode *vi)
{       
	int err = -1;
	ntfs_inode* ni = NULL;
	big_ntfs_inode* bni = NULL;
	struct kobject* p = NULL;
	ntfs_volume* nv = NULL;
	struct kset* top = NULL;

	if(!vi)
		return -EINVAL;

	/* init all of the var */
    ni=NTFS_I(vi);
    bni=(big_ntfs_inode*)ni;
	p=&(bni->bni_kobj);
    nv=ni->vol;
    top=&(nv->v_kset);

	p->kset = top;

    err = kobject_init_and_add(p, &ntfs_mft_ktype, NULL,
			"%ld", ni->mft_no);

	if (err)
		return err;

	return 0;
}
static inline struct kobject* vfs_inode_to_kobj(struct inode *vi)
{
	ntfs_inode* ni=NTFS_I(vi);
    big_ntfs_inode* bni=(big_ntfs_inode*)ni;
	struct kobject* p=&(bni->bni_kobj);
	return p;
}
void ntfs_unregister_ntfs_inode_sysfs(struct inode *vi)
{
	struct kobject* p = NULL;
	if(!vi)
		return;

	p=vfs_inode_to_kobj(vi);
	kobject_del(p);
}
