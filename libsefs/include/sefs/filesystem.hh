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

#include <sefs/fclist.hh>

#include <apol/vector.h>

#ifdef __cplusplus
}

#include <stdexcept>

/**
 * This class represents the SELinux file contexts on a local on-disk
 * filesystem.
 */
class sefs_filesystem:public sefs_fclist
{
      public:

	/**
	 * Allocate and return a new sefs filesystem structure
	 * representing the filesystem rooted at directory \a root.
	 * <b>Be aware that the constructor is not thread-safe.</b>
	 * @param root Directory to use as the root of the filesystem.
	 * @param rw If true, then this filesystem object only
	 * represents files (and directories) on filesystems that are
	 * mounted read/write.  Otherwise it represents all files.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 * @exception bad_alloc Out of memory.
	 * @exception invalid_argument Root directory must exist.
	 * @exception runtime_error Could not open root directory or
	 * /etc/mtab.
	 */
	sefs_filesystem(const char *root, bool rw, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc,
												      std::invalid_argument,
												      std::runtime_error);

	~sefs_filesystem();

	/**
	 * Perform a sefs query on this filesystem object, and then invoke
	 * a callback upon each matching entry.  Mapping occurs in the
	 * order of entries as given by ftw().
	 * @param query Query object containing search parameters.  If
	 * NULL, invoke the callback on all entries.
	 * @param fn Function to invoke upon matching entries.  This
	 * function will be called with three parameters: a pointer to
	 * this filesystem, pointer to a matching entry, and an
	 * arbitrary data pointer.  It should return a non-negative
	 * value upon success, negative value upon error and to abort
	 * the mapping.
	 * @param data Arbitrary pointer to be passed into \fn as a
	 * third parameter.
	 * @return Last value returned by fn() (i.e., >= on success, <
	 * 0 on failure).  If the filesystem has no entries then
	 * return 0.
	 * @exception std::runtime_error Error while reading contexts
	 * from the filesystem.
	 */
	int runQueryMap(sefs_query * query, sefs_fclist_map_fn_t fn, void *data) throw(std::runtime_error);

	/**
	 * Determine if the contexts stored in this filesystem contain
	 * MLS fields.
	 * @return \a true if MLS fields are present, \a false if not
	 * or undeterminable.
	 */
	bool isMLS() const;

	/**
	 * Get the root directory of a sefs filesystem structure.
	 * @return The root directory of the filesystem or NULL on
	 * error.  Do not free() this string.
	 */
	const char *root() const;

      private:
	char *_root;
	bool _rw, _mls;
	apol_vector_t *_mounts;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_filesystem sefs_filesystem_t;

/**
 * Allocate and return a new sefs filesystem structure representing
 * the filesystem rooted at directory \a root.
 * @see sefs_filesystem::sefs_filesystem()
 */
	extern sefs_filesystem_t *sefs_filesystem_create(const char *root, bool rw, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Get the root directory of a sefs filesystem structure.
 * @see sefs_filesystem::root()
 */
	extern const char *sefs_filesystem_get_root(const sefs_filesystem_t * fs);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_FILESYSTEM_H */
