/*
 * dir.h - Defines for directory handling in NTFS Linux kernel driver. Part of
 *	   the Linux-NTFS project.
 *
 * Copyright (c) 2002-2004 Anton Altaparmakov
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

#ifndef _LINUX_NTFS_DIR_H
#define _LINUX_NTFS_DIR_H

#include "layout.h"
#include "types.h"
#include "inode.h"

/*
 * int inline is_actor_exceed_root(const struct dir_context* actor, const ntfs_volume* vol)
 **/
#define is_actor_exceed_root(actor,vol) (actor->pos >= vol->mft_record_size) 
/*
 * void inline mark_actor_exceed_root(/--output--/struct  dir_context* actor,const ntfs_volume* vol)
 */
#define mark_actor_exceed_root(actor,vol)	(actor->pos = vol->mft_record_size)
/*
 * loff_t inline offset_actor_exceed_root(const struct dir_context* actor,const ntfs_volume* vol)
 */
#define offset_actor_exceed_root(actor,vol) (actor->pos - vol->mft_record_size) 

#endif /* _LINUX_NTFS_FS_DIR_H */
