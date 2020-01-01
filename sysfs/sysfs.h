#ifndef __SYSFS_H__
#define __SYSFS_H__
#include "../ntfs_inode.h"

struct ntfs_attr {
	struct attribute attr;
	short attr_id;
	short attr_ptr;
	union {
		int offset;
		void *explicit_ptr;
	} u;
};

#define NTFS_ATTR(_name,_mode,_id)                                      \
	static struct ntfs_attr ntfs_attr_##_name = {                           \
		.attr = {.name = __stringify(_name), .mode = _mode },           \
		.attr_id = e_attr_##_id,                                          \
	}


typedef enum {
	attr_noop,
	e_attr_feature,
} feature_attr_id_t;

extern int ntfs_register_ntfs_inode_sysfs(struct inode *vi);
extern void ntfs_unregister_ntfs_inode_sysfs(struct inode *vi);


extern struct kset ntfs_top;
#endif
