/**
 *  @file
 *  Defines the public interface for the filesystem fc list object.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef SEFS_FILESYSTEM_H
#define SEFS_FILESYSTEM_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>

#include "fclist.h"

#include <apol/vector.h>

	typedef struct sefs_filesystem sefs_filesystem_t;

/**
 * Allocate and return a new sefs filesystem structure representing the
 * filesystem rooted at directory \a root.
 * @param root Directory to use as the root of the filesystem.
 * @param msg_callback Callback to invoke as errors/warnings are generated.
 * If NULL, write messages to standard error.
 * @param varg Value to be passed as the first parameter to the 
 * callback function.
 * @return An initialized sefs_fclist_t with data of type SEFS_TYPE_FILESYSTEM,
 * or NULL on error. The caller is responsible for calling
 * sefs_fclist_destroy() to free all memory associated with the returned list.
 */
	sefs_fclist_t *sefs_filesystem_create(const char *root, sefs_callback_fn_t msg_callback, void * varg);

/**
 * Get the root directory of a sefs filesystem structure.
 * @param fs Filesystem structure from which to get the root.
 * @return The root directory of the filesystem or NULL on error.
 */
	const char *sefs_filesystem_get_root(sefs_filesystem_t *fs);

/**
 * Get a list of mount points within a sefs filesystem.
 * @param fs Filesystem structure from which to get the mount points.
 * @return A vector of paths (char *) to all mount points in the
 * filesystem. The caller should not destroy the returned vector.
 */
	const apol_vector_t *sefs_filesystem_get_mount_points(sefs_filesystem_t *fs);

#ifdef __cplusplus
}
#endif

#endif /* SEFS_FILESYSTEM_H */

