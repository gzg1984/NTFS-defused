/*
 * attrib.h - Defines for attribute handling in NTFS Linux kernel driver.
 *	      Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2005 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LINUX_NTFS_ATTRIB_H
#define _LINUX_NTFS_ATTRIB_H

#include "endian.h"
#include "types.h"
#include "layout.h"
#include "inode.h"
#include "runlist.h"
#include "volume.h"
/**
 * ntfs_attr_search_ctx - used in attribute search functions
 * @mrec:	buffer containing mft record to search
 * @attr:	attribute record in @mrec where to begin/continue search
 * @is_first:	if true ntfs_attr_lookup() begins search with @attr, else after
 *
 * Structure must be initialized to zero before the first call to one of the
 * attribute search functions. Initialize @mrec to point to the mft record to
 * search, and @attr to point to the first attribute within @mrec (not necessary
 * if calling the _first() functions), and set @is_first to 'true' (not necessary
 * if calling the _first() functions).
 *
 * If @is_first is 'true', the search begins with @attr. If @is_first is 'false',
 * the search begins after @attr. This is so that, after the first call to one
 * of the search attribute functions, we can call the function again, without
 * any modification of the search context, to automagically get the next
 * matching attribute.
 */
typedef struct {
	MFT_RECORD *mrec;
	ATTR_RECORD *attr;
	bool is_first;
	ntfs_inode *ntfs_ino;
	ATTR_LIST_ENTRY *al_entry;
	ntfs_inode *base_ntfs_ino;
	MFT_RECORD *base_mrec;
	ATTR_RECORD *base_attr;
} ntfs_attr_search_ctx;


extern int ntfs_map_runlist_nolock(ntfs_inode *ni, VCN vcn,
		ntfs_attr_search_ctx *ctx);
extern int ntfs_map_runlist(ntfs_inode *ni, VCN vcn);

extern LCN ntfs_attr_vcn_to_lcn_nolock(ntfs_inode *ni, const VCN vcn,
		const bool write_locked);

extern runlist_element *ntfs_attr_find_vcn_nolock(ntfs_inode *ni,
		const VCN vcn, ntfs_attr_search_ctx *ctx);

int ntfs_attr_lookup(const ATTR_TYPE type, const ntfschar *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const VCN lowest_vcn, const u8 *val, const u32 val_len,
		ntfs_attr_search_ctx *ctx);

extern int load_attribute_list(ntfs_volume *vol, runlist *rl, u8 *al_start,
		const s64 size, const s64 initialized_size);

static __inline__ int ntfs_attrs_walk(ntfs_attr_search_ctx *ctx)
{
    return ntfs_attr_lookup(0, NULL, 0, CASE_SENSITIVE, 0, NULL, 0, ctx);
}
static inline s64 ntfs_attr_size(const ATTR_RECORD *a)
{
	if (!a->non_resident)
		return (s64)le32_to_cpu(a->data.resident.value_length);
	return sle64_to_cpu(a->data.non_resident.data_size);
}

extern void ntfs_attr_reinit_search_ctx(ntfs_attr_search_ctx *ctx);
extern ntfs_attr_search_ctx *ntfs_attr_get_search_ctx(ntfs_inode *ni,
		MFT_RECORD *mrec);
extern void ntfs_attr_put_search_ctx(ntfs_attr_search_ctx *ctx);

#ifdef NTFS_RW

extern int ntfs_attr_size_bounds_check(const ntfs_volume *vol,
		const ATTR_TYPE type, const s64 size);
extern int ntfs_attr_can_be_non_resident(const ntfs_volume *vol,
		const ATTR_TYPE type);
extern int ntfs_attr_can_be_resident(const ntfs_volume *vol,
		const ATTR_TYPE type);

extern int ntfs_attr_record_resize(MFT_RECORD *m, ATTR_RECORD *a, u32 new_size);
extern int ntfs_resident_attr_value_resize(MFT_RECORD *m, ATTR_RECORD *a,
		const u32 new_size);

extern int ntfs_attr_make_non_resident(ntfs_inode *ni, const u32 data_size);

extern s64 ntfs_attr_extend_allocation(ntfs_inode *ni, s64 new_alloc_size,
		const s64 new_data_size, const s64 data_start);

extern int ntfs_attr_set(ntfs_inode *ni, const s64 ofs, const s64 cnt,
		const u8 val);

#endif /* NTFS_RW */

static inline char* attr_type_string(ATTR_TYPE type)
{
	switch(type)
	{
		case AT_UNUSED:
			return "AT_UNUSED";
		case AT_STANDARD_INFORMATION:
			return "AT_STANDARD_INFORMATION";
		case AT_INDEX_ROOT:
			return "AT_INDEX_ROOT";
		case AT_INDEX_ALLOCATION:
			return "AT_INDEX_ALLOCATION";
		case AT_ATTRIBUTE_LIST:
			return "AT_ATTRIBUTE_LIST";
		case AT_FILE_NAME:
			return "AT_FILE_NAME";
		case AT_DATA:
			return "AT_DATA";
		case AT_END:
			return "AT_END";
		case AT_BITMAP:
			return "AT_BITMAP";
		case AT_VOLUME_NAME:
			return "AT_VOLUME_NAME";
		case AT_VOLUME_INFORMATION:
			return "AT_VOLUME_INFORMATION";
		case AT_SECURITY_DESCRIPTOR:
			return "AT_SECURITY_DESCRIPTOR";
		default:
			return "Unknown";
	}
	return ":)";
	/*
					AT_OBJECT_ID                    = cpu_to_le32(      0x40),
					AT_REPARSE_POINT                = cpu_to_le32(      0xc0),
					AT_EA_INFORMATION               = cpu_to_le32(      0xd0),
					AT_EA                           = cpu_to_le32(      0xe0),
					AT_PROPERTY_SET                 = cpu_to_le32(      0xf0),
					AT_LOGGED_UTILITY_STREAM        = cpu_to_le32(     0x100),
					AT_FIRST_USER_DEFINED_ATTRIBUTE = cpu_to_le32(    0x1000),
					*/

}
inline static void ntfs_dump_attr_name(const char* prompt,const ATTR_RECORD* a)
{
#ifdef DEBUG
	int i = 0;
	char temp_name[500];
	ntfschar* name_start = (char*)a + a->name_offset;
	snprintf(temp_name,400,"%c ", (char)(name_start[i]));
	for(i = 1 ; i < a->name_length ; i++ )
	{                                               
		snprintf(temp_name,400,"%s%c ",temp_name,(char)(name_start[i]));
	}                                                                               
	ntfs_debug("%s:[%s]",prompt, temp_name);
#endif
}


inline static void debug_show_attr(const ATTR_REC* const attr)
{
#ifdef DEBUG
	printk("ATTR_RECORD\n");
	printk("\tAttribute Type:%X[%s]\n",attr->type,attr_type_string(attr->type));
	printk("\tLength:%d\n",attr->length);
	printk("\tNon-resident flag:%d[%s]\n",attr->non_resident,attr->non_resident?"non-resident":"resident");
	printk("\tName length:%d\n",attr->name_length);
	printk("\tOffset to the Name:%d\n",attr->name_offset);
	if(attr->name_length)
		ntfs_dump_attr_name("ATTR name:",attr);
	printk("\tFlags:%X\n",attr->flags);
	printk("\tAttribute Id:%d\n",attr->instance);
	if(!attr->non_resident)
	{
		printk("\tRESIDENT\n");
		printk("\t\tLength of the Attribute:%d\n",attr->data.resident.value_length);
		printk("\t\tOffset to the Attribute:%d\n",attr->data.resident.value_offset);
		printk("\t\tIndexed flag:%d\n",attr->data.resident.flags);
	}
#endif
}
#endif /* _LINUX_NTFS_ATTRIB_H */
