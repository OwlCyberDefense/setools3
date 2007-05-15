/**
 *  @file
 *  Defines the public interface for file context entries.
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

#ifndef SEFS_ENTRY_H
#define SEFS_ENTRY_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <config.h>

#include <sys/types.h>

#include <apol/context-query.h>
#include <apol/vector.h>

	typedef struct sefs_entry sefs_entry_t;

/**
 * Get the context from a sefs entry.
 * @param ent Entry from which to get the context.
 * @return A pointer to the context, or NULL on error.
 */
	const apol_context_t *sefs_entry_get_context(const sefs_entry_t * ent);

/**
 * Get the inode number associated with a sefs entry.
 * @param ent Entry from which to get the inode number.
 * @return Inode number associated with the entry or 0 on error.
 */
	ino64_t sefs_entry_get_inode(const sefs_entry_t * ent);

/**
 * Get the device number associated with a sefs entry.
 * @param ent Entry from which to get the device number.
 * @return Device number associated with the entry or 0 on error.
 */
	dev64_t sefs_entry_get_dev(const sefs_entry_t * ent);

/**
 * Get the object class associated with a sefs entry.
 * @param ent Entry from which to get the object class.
 * @return Name of the object class or NULL on error.
 */
	const char *sefs_entry_get_object_class(const sefs_entry_t * ent);

/**
 * Get the list of paths associated with a sefs entry.
 * @param ent Entry from which to get the list of paths.
 * @return Vector of path strings (char *) representing the
 * paths for the entry or NULL on error. The caller <b>should not</b>
 * destroy the vector or the strings it returns. If the entry comes
 * from a file_contexts file the paths will be regular expressions
 * rather than literal paths.
 */
	const apol_vector_t *sefs_entry_get_paths(const sefs_entry_t * ent);

/**
 * Get the origin of a sefs entry.
 * This function is only meaningful when entries are returned
 * from a query on a modular file context file.
 * @param ent Entry from which to get the origin.
 * @return The path of the module providing the entry or NULL
 * if the entry is not from a module.
 */
	const char *sefs_entry_get_origin(const sefs_entry_t * ent);

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_ENTRY_H */
