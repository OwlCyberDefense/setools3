/**
 *  @file
 *  Defines the public interface for the database fc list object.
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

#ifndef SEFS_DB_H
#define SEFS_DB_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>

#include "fclist.h"

#include <apol/vector.h>

	typedef struct sefs_filesystem sefs_filesystem_t;

/**
 * Allocate and return a new sefs database from the filesystem \a fs.
 * @param fs Sefs filesystem from which to create the database.
 * @param msg_callback Callback to invoke as errors/warnings are generated.
 * If NULL, write messages to standard error.
 * @param varg Value to be passed as the first parameter to the 
 * callback function.
 * @return An initialized sefs_fclist_t with data of type SEFS_TYPE_DB,
 * or NULL on error. The caller is responsible for calling
 * sefs_fclist_destroy() to free all memory associated with the returned list.
 */
	sefs_fclist_t *sefs_db_create_from_filesystem(const sefs_filesystem_t * fs, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs database, loading the entries from
 * the saved database \a path.
 * @param path Path of a sefs database from which to load.
 * @param msg_callback Callback to invoke as errors/warnings are generated.
 * If NULL, write messages to standard error.
 * @param varg Value to be passed as the first parameter to the 
 * callback function.
 * @return An initialized sefs_fclist_t with data of type SEFS_TYPE_DB,
 * or NULL on error. The caller is responsible for calling
 * sefs_fclist_destroy() to free all memory associated with the returned list.
 */
	sefs_fclist_t *sefs_db_create_from_file(const char *path, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Get the creation time of a sefs database.
 * @param db Database from which to get the creation time.
 * @return Creation time of the database, or 0 on error.
 */
	time_t sefs_db_get_ctime(sefs_db_t * db);

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_DB_H */
