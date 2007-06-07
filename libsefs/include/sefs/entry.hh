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

#include <stdexcept>

class sefs_fclist;
struct sefs_context_node;

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
	 * Perform a deep copy of an entry object.
	 */
	 sefs_entry(const sefs_entry * e) throw(std::bad_alloc);

	~sefs_entry();

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
	 * Get the object class associated with a sefs entry.  The
	 * returned value will be one of one of QPOL_CLASS_ALL,
	 * QPOL_CLASS_FILE, etc., as defined in
	 * <qpol/genfscon_query.h>.  If this returns QPOL_CLASS_ALL
	 * then the entry is associated with all object classes.
	 * @return Entry's object class.  Upon error return
	 * QPOL_CLASS_ALL.
	 * @see apol_objclass_to_str() to convert the value to a
	 * string.
	 */
	uint32_t objectClass() const;

	/**
	 * Get the list of paths associated with a sefs entry.
	 * @return Vector of path strings (char *) representing the
	 * paths for the entry or NULL on error.  The caller <b>should
	 * not</b> destroy or otherwise modify the vector or the
	 * strings within it.  If the entry came from a file_contexts
	 * object the paths will be regular expressions rather than
	 * literal paths.
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

	/**
	 * Return a string representation of this entry.  The string
	 * is suitable for printing to the screen or to a
	 * file_contexts file.
	 * @return An allocated string representation.  The caller is
	 * responsibily for free()ing the string afterwards.
	 * @exception std::bad_alloc Out of memory.
	 */
	char *toString() const throw(std::bad_alloc);

      private:
	/**
	 * Create a blank entry.  The entity creating this entry is
	 * responsible for setting additional values as needed.
	 * @param fclist List that will contain this entry.  This
	 * constructor will not add itself to the fclist.
	 * @param context Context node containing the SELinux context.
	 * @param objectClass Object class for the entry.
	 * @param path Path to this entry.  The entry will share this
	 * pointer.
	 * @param origin Name of file_contexts file from which this
	 * entry originated.  The entry will share this pointer.
	 * @exception std::bad_alloc Out of memory.
	 */
	 sefs_entry(class sefs_fclist * fclist, const struct sefs_context_node *context, uint32_t objectClass, const char *path,
		    const char *origin = NULL) throw(std::bad_alloc);

	// note that entry does not own any of these pointers; they
	// are shallow copies into the fclist's BST
	class sefs_fclist *_fclist;
	const struct sefs_context_node *_context;
	ino64_t _inode;
	dev_t _dev;
	uint32_t _objectClass;
	const char *_origin;

	apol_vector_t *_paths;
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
	extern const apol_context_t *sefs_entry_get_context(const sefs_entry_t * ent);

/**
 * Get the inode number associated with a sefs entry.
 * @see sefs_entry::inode()
 */
	extern ino64_t sefs_entry_get_inode(const sefs_entry_t * ent);

/**
 * Get the device number associated with a sefs entry.
 * @see sefs_entry::dev()
 */
	extern dev_t sefs_entry_get_dev(const sefs_entry_t * ent);

/**
 * Get the object class associated with a sefs entry.
 * @see sefs_entry::objectClass()
 */
	extern uint32_t sefs_entry_get_object_class(const sefs_entry_t * ent);

/**
 * Get the list of paths associated with a sefs entry.
 * @see sefs_entry::paths()
 */
	extern const apol_vector_t *sefs_entry_get_paths(const sefs_entry_t * ent);

/**
 * Get the file from which a sefs entry originated.
 * @see sefs_entry::origin()
 */
	extern const char *sefs_entry_get_origin(const sefs_entry_t * ent);

/**
 * Return a string representation of this entry.
 * @see sefs_entry::toString()
 */
	extern char *sefs_entry_to_string(const sefs_entry_t * ent);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_ENTRY_H */
