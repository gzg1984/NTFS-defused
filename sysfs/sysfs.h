#ifndef __SYSFS_H__
#define __SYSFS_H__
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



typedef enum {
	e_attr_map_ino = 1 ,
	e_attr_ino,
} volume_attr_id_t;


extern struct kset ntfs_top;
#endif
