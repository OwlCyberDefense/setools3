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

#include <sys/types.h>
#include <apol/context-query.h>
#include <apol/vector.h>

#ifdef __cplusplus
}

class sefs_fclist;
class sefs_db;
class sefs_fcfile;
class sefs_filesystem;

/**
 * This class represents an individual entry within a list an fcfile object.
 */
class sefs_entry
{
	friend class sefs_db;
	friend class sefs_fcfile;
	friend class sefs_filesystem;

      public:

	/**
	 * Get the context from a sefs entry.
	 * @return A pointer to the context, or NULL on error.  The
	 * caller should not modify or destroy the returned context.
	 */
	const apol_context_t *context() const;

	/**
	 * Get the inode number associated with a sefs entry.
	 * @return Inode number associated with the entry or 0 on
	 * error.
	 */
	ino64_t inode() const;

	/**
	 * Get the device number associated with a sefs entry.
	 * @return Device number associated with the entry or 0 on
	 * error.
	 */
	dev_t dev() const;

	/**
	 * Get the object class associated with a sefs entry.  If this
	 * returns an empty string ("") then the entry is associated
	 * with all object classes.
	 * @return Name of the object class or NULL on error.  Do not
	 * free() this pointer.
	 */
	const char *objectClass() const;

	/**
	 * Get the list of paths associated with a sefs entry.
	 * @return Vector of path strings (char *) representing the
	 * paths for the entry or NULL on error.  The caller <b>should
	 * not</b> destroy the vector or the strings it returns.  If
	 * the entry came from a file_contexts object the paths will
	 * be regular expressions rather than literal paths.
	 */
	const apol_vector_t *paths() const;

	/**
	 * Get the file from which a sefs entry originated.
	 * This function is only meaningful when entries are returned
	 * from a query on a modular file context file.
	 * @return The path of the file (policy package or source
	 * file) providing the entry or NULL if the entry is not from
	 * a module.  Do not free() this pointer.
	 */
	const char *origin() const;

      private:
	/**
         * Create a blank entry.  The entity creating this entry is
         * responsible for setting additional values as needed.
         * @param list Associate the new entry with this list.
         * @param context A string representing the file entry's
         * context.  It will be converted into an apol_context_t
         * struct.
         * @param objectClass Object class for the entry, or an empty
         * string to mean any class.
         * @param path Path to this entry.         
         */
	sefs_entry(sefs_fclist * fclist, const char *context, const char *objectClass, const char *path);

	// note that entry owns the context; all others are assumed to
	// be shallow pointers
	apol_context_t *_context;
	ino64_t _inode;
	dev_t _dev;
	char *_objectClass;
	apol_vector_t *_paths;
	char *_origin;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_entry sefs_entry_t;

/**
 * Get the context from a sefs entry.
 * @see sefs_entry::context()
 */
	const apol_context_t *sefs_entry_get_context(const sefs_entry_t * ent);

/**
 * Get the inode number associated with a sefs entry.
 * @see sefs_entry::inode()
 */
	ino64_t sefs_entry_get_inode(const sefs_entry_t * ent);

/**
 * Get the device number associated with a sefs entry.
 * @see sefs_entry::dev()
 */
	dev_t sefs_entry_get_dev(const sefs_entry_t * ent);

/**
 * Get the object class associated with a sefs entry.
 * @see sefs_entry::objectClass()
 */
	const char *sefs_entry_get_object_class(const sefs_entry_t * ent);

/**
 * Get the list of paths associated with a sefs entry.
 * @see sefs_entry::paths()
 */
	const apol_vector_t *sefs_entry_get_paths(const sefs_entry_t * ent);

/**
 * Get the file from which a sefs entry originated.
 * @see sefs_entry::origin()
 */
	const char *sefs_entry_get_origin(const sefs_entry_t * ent);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_ENTRY_H */
