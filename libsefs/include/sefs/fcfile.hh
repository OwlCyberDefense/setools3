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
	 * @exception std::bad_alloc if out of memory
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
	 * @exception std::bad_alloc if out of memory
	 * @exception std::invalid_argument if the vector is NULL
	 * @exception std::runtime_error if the give file could not be
	 * read or is the wrong format
	 */
	 sefs_fcfile(const char *file, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc, std::invalid_argument,
											  std::runtime_error);

	/**
	 * Allocate and return a new sefs file_context set structure
	 * from a list of file_context files.
	 * @param files Vector of file contexts filenames (of type
	 * char *) to read.
	 * @param msg_callback Callback to invoke as errors/warnings
	 * are generated.  If NULL, write messages to standard error.
	 * @param varg Value to be passed as the first parameter to
	 * the callback function.
	 * @exception std::bad_alloc if out of memory
	 * @exception std::invalid_argument if the vector is NULL
	 * @exception std::runtime_error if a given file could not
	 * be read or is the wrong format
	 */
	 sefs_fcfile(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg) throw(std::bad_alloc,
												     std::invalid_argument,
												     std::runtime_error);

	~sefs_fcfile();

	/**
	 * Perform a sefs query on this fcfile object, and then invoke
	 * a callback upon each matching entry.  Mapping occurs in the
	 * order of entries as given by the file_contexts, and in the
	 * order that file_contexts were appended (via appendFile())
	 * to this object.
	 * @param query Query object containing search parameters.  If
	 * NULL, invoke the callback on all entries.
	 * @param fn Function to invoke upon matching entries.  This
	 * function will be called with three parameters: a pointer to
	 * this fclist, pointer to a matching entry, and an arbitrary
	 * data pointer.  It should return a non-negative value upon
	 * success, negative value upon error and to abort the
	 * mapping.
	 * @param data Arbitrary pointer to be passed into \fn as a
	 * third parameter.
	 * @return Last value returned by fn() (i.e., >= on success, <
	 * 0 on failure).  If the fcfile has no entries then return 0.
	 * @exception std::runtime_error Error while reading contexts
	 * from the fclist.
	 */
	int runQueryMap(sefs_query * query, sefs_fclist_map_fn_t fn, void *data) throw(std::runtime_error);

	/**
	 * Determine if the contexts in the fcfile contain MLS fields.
	 * @return \a true if MLS fields are present, \a false if not
	 * or undeterminable.
	 */
	bool isMLS() const;

	/**
	 * Append a file_contexts file to a sefs file contexts file
	 * set.  If the fcfile already has a non-MLS file, subsequent
	 * appends must also be to non-MLS files.  Likewise, if the
	 * fcfile already has an MLS file the file to be append must
	 * also be MLS.
	 * @param file File containing entries to append.
	 * @return 0 on success or < 0 on failure; if the call fails,
	 * the fcfile will be unchanged.
	 * @exception std::bad_alloc if out of memory
	 * @exception std::invalid_argument if the file name is NULL
	 * @exception std::runtime_error if a given file could not
	 * be read or is the wrong format
	 */
	int appendFile(const char *file) throw(std::bad_alloc, std::invalid_argument, std::runtime_error);

	/**
	 * Append a list of file_context files to a sefs file contexts
	 * file set.  If the fcfile already has a non-MLS file,
	 * subsequent appends must also be to non-MLS files.
	 * Likewise, if the fcfile already has an MLS file the file to
	 * be append must also be MLS.
	 * @param files Vector of filenames (type char *) to append;
	 * these files will be appended in the order they appear in
	 * the vector.
	 * @return The number of files successfully appended.  If the
	 * value returned is less than the size of the vector, then
	 * file at index (returned value) failed.  If append fails for
	 * any file, the operation stops at that file; it is safe to
	 * attempt to append the files remaining after the
	 * unsuccessful file.
	 * @exception std::bad_alloc if out of memory
	 * @exception std::invalid_argument if the vector is NULL
	 * @exception std::runtime_error if a given file could not
	 * be read or is the wrong format
	 */
	size_t appendFileList(const apol_vector_t * files) throw(std::bad_alloc, std::invalid_argument, std::runtime_error);

	/**
	 * Get a list of all files contributing to the entries in a
	 * sefs file_contexts set.
	 * @return Vector of file paths (char *) of all files
	 * contributing to the set; the caller should not destroy or
	 * otherwise modify the returned vector.
	 */
	const apol_vector_t *fileList() const;

      private:

	/**
	 * Parse a single line from a file_contexts file (or from any
	 * other source of file contexts information), and then add
	 * the resulting sefs_entry into the vector of entries.
	 * @param origin File from which this line originated.
	 * @param line File contexts line to parse.
	 * @param line_regex Compiled regular expression pattern for
	 * an entire line.
	 * @param context_regex Compiled regular expression pattern
	 * for the SELinux portion of a line.
	 * @exception std::bad_alloc if out of memory
	 * @exception std::runtime_error if the give file could not be
	 * read or is the wrong format
	 */
	void parse_line(const char *origin, const char *line, regex_t * line_regex, regex_t * context_regex) throw(std::bad_alloc,
														   std::
														   runtime_error);

	apol_vector_t *_files, *_entries;
	bool _mls, _mls_set;
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
	extern sefs_fclist_t *sefs_fcfile_create(sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs file_context set structure from a
 * single file_contexts file.
 * @see sefs_fcfile::sefs_fcfile(const char *file, sefs_callback_fn_t msg_callback, void *varg)
 */
	extern sefs_fclist_t *sefs_fcfile_create_from_file(const char *file, sefs_callback_fn_t msg_callback, void *varg);

/**
 * Allocate and return a new sefs file_context set structure from a
 * list of file_context files.
 * @see sefs_fcfile::sefs_fcfile(const apol_vector_t * files, sefs_callback_fn_t msg_callback, void *varg)
 */
	extern sefs_fclist_t *sefs_fcfile_create_from_file_list(const apol_vector_t * files, sefs_callback_fn_t msg_callback,
								void *varg);

/**
 * Append a file_contexts file to a sefs file contexts file set.
 * @return 0 on success or < 0 on failure; if the call fails, the
 * fcfile will be unchanged.
 * @see sefs_fcfile::appendFile()
 */
	extern int sefs_fcfile_append_file(sefs_fcfile_t * fcfile, const char *file);

/**
 * Append a list of file_context files to a sefs file contexts file
 * set.
 * @see sefs_fcfile::appendFileList()
 */
	extern size_t sefs_fcfile_append_file_list(sefs_fcfile_t * fcfile, const apol_vector_t * files);

/**
 * Get a list of all files contributing to the entries in a sefs
 * file_contexts set.
 * @see sefs_fcfile::fileList()
 */
	extern const apol_vector_t *sefs_fcfile_get_file_list(const sefs_fcfile_t * fcfile);

#endif				       /* SWIG */

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_FCFILE_H */
