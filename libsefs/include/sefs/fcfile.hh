/**
 *  @file
 *  Defines the public interface for the file_context set fc list object.
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

#ifndef SEFS_FCFILE_H
#define SEFS_FCFILE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>

#include <apol/vector.h>

#ifdef __cplusplus
}

#include <sefs/fclist.hh>
#include <stdexcept>

/**
 * This class represents file contexts entry as read from a file,
 * typically name file_contexts.
 */
class sefs_fcfile:public sefs_fclist
{
      public:

	/**
	 * Allocate and return a new (and empty) sefs file_context set
	 * structure.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 */
	sefs_fcfile(sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc);

	/**
	 * Allocate and return a new sefs file_context set structure
	 * from a single file_contexts file.
	 * @param file File contexts file to read.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 */
	 sefs_fcfile(const char *file, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc);

	/**
	 * Allocate and return a new sefs file_context set structure
	 * from a list of file_context files.
	 * @param files Vector of file contexts filenames (of type
	 * char *) to read.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 */
	 sefs_fcfile(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc);

	~sefs_fcfile();

	/**
	 * Append a file_contexts file to a sefs file contexts file
	 * set.
	 * @param file File containing entries to append.
	 * @return 0 on success or < 0 on failure; if the call fails,
	 * the fcfile will be unchanged.
	 */
	int appendFile(const char *file);

	/**
	 * Append a list of file_context files to a sefs file contexts
	 * file set.
	 * @param files Vector of filenames (type char *) to append;
	 * these files will be appended in the order they appear in
	 * the vector.
	 * @return The number of files successfully appended. If the
	 * value returned is less than the size of the vector, then
	 * file at index (returned value) failed.  If append fails for
	 * any file, the operation stops at that file; it is safe to
	 * attempt to append the files remaining after the
	 * unsuccessful file.
	 */
	size_t appendFileList(const apol_vector_t * files);

	/**
	 * Get a list of all files contributing to the entries in a
	 * sefs file_contexts set.
	 * @return Vector of file paths (char *) of all files
	 * contributing to the set; the caller should not destroy or
	 * otherwise modify the returned vector.
	 */
	const apol_vector_t *fileList() const;

      private:
	 bool isMLS() const;
	int parse(const char *file);
	apol_vector_t *_files, *_entries;
};

extern "C"
{
#endif

//we do not want to wrap two copies of everything so have SWIG ignore
//the compatibility section.
#ifndef SWIG

	typedef struct sefs_fcfile sefs_fcfile_t;

/**
 * Allocate and return a new sefs file_context set structure.
 * @see sefs_fcfile::sefs_fcfile(sefs_callback_fn_t msg_callback, void *varg)
 */
	sefs_fclist_t *sefs_fcfile_create(sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs file_context set structure from a
 * single file_contexts file.
 * @see sefs_fcfile::sefs_fcfile(const char *file, sefs_callback_fn_t msg_callback, void *varg)
 */
	sefs_fclist_t *sefs_fcfile_create_from_file(const char *file, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs file_context set structure from a
 * list of file_context files.
 * @see sefs_fcfile::sefs_fcfile(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg)
 */
	sefs_fclist_t *sefs_fcfile_create_from_file_list(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Append a file_contexts file to a sefs file contexts file set.
 * @see sefs_fcfile::appendFile()
 */
	int sefs_fcfile_append_file(sefs_fcfile_t * fcfile, const char *file);

/**
 * Append a list of file_context files to a sefs file contexts file
 * set.
 * @see sefs_fcfile::appendFileList()
 */
	size_t sefs_fcfile_append_file_list(sefs_fcfile_t * fcfile, const apol_vector_t * files);

/**
 * Get a list of all files contributing to the entries in a sefs
 * file_contexts set.
 * @see sefs_fcfile::fileList()
 */
	const apol_vector_t *sefs_fcfile_get_file_list(sefs_fcfile_t * fcfile);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_FCFILE_H */
