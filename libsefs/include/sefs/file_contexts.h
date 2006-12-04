/**
 *  @file file_contexts.h
 *  Defines the public interface for manipulating a file_contexts
 *  file.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#ifndef SEFS_FILE_CONTEXTS_H
#define SEFS_FILE_CONTEXTS_H

#ifdef	__cplusplus
extern "C"
{
#endif

/* libapol */
#include <apol/policy.h>
#include <apol/vector.h>

/* libqpol */
#include <qpol/policy_query.h>

/* file type IDs, used by sefs_fc_entry::filetype */
#define SEFS_FILETYPE_NONE 0	       /* none */
/* the following values must correspond to libsepol flask.h */
#define SEFS_FILETYPE_REG  6	       /* Regular file */
#define SEFS_FILETYPE_DIR  7	       /* Directory */
#define SEFS_FILETYPE_LNK  9	       /* Symbolic link */
#define SEFS_FILETYPE_CHR  10	       /* Character device */
#define SEFS_FILETYPE_BLK  11	       /* Block device */
#define SEFS_FILETYPE_SOCK 12	       /* Socket */
#define SEFS_FILETYPE_FIFO 13	       /* FIFO */
#define SEFS_FILETYPE_ANY  14	       /* any type */

/* general file contexts structure */
	typedef struct sefs_security_context
	{
		char *user;
		char *role;
		char *type;
		char *range;
	} sefs_security_con_t;

	typedef struct sefs_fc_entry
	{
	/** path for genfs_context or a regexp for file_context */
		char *path;
		/* type of file, block, char, etc.  See SEFS_FILETYPE_* defines. */
		int filetype;
		sefs_security_con_t *context;
	} sefs_fc_entry_t;

/**
 * Given the path to a file_contexts file, open and parse the file.
 * Return a vector of sefs_fc_t objects corresponding to each entry
 * within the file.
 *
 * @param policy Error handler.
 * @param fc_path Path to the file_contexts.
 * @param contexts Reference to a vector of sefs_fc_t objects.  Upon
 * error this will be set to NULL.  The caller is responsible for
 * calling apol_vector_destroy(), passing in sefs_fc_entry free() as
 * the second parameter.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int sefs_fc_entry_parse_file_contexts(apol_policy_t * policy, const char *fc_path, apol_vector_t ** contexts);

/**
 * Free all space associated with a file context entry, including the
 * pointer itself.  If the pointer is NULL then do nothing.
 *
 * @param fc fc_entry to free.
 */
	extern void sefs_fc_entry_free(void *fc);

/**
 * Write to the referenced string the pathname of the file_contexts
 * for the currently running SELinux system.  If the system is not
 * running SELinux than NULL will be written to the path.
 *
 * @param path Reference to where to right the file_contexts path.
 * The caller is responsible for free()ing the returned value.
 *
 * @return 0 if a valid path was written.  On error, < 0 will be
 * returned and *path will be set to NULL.
 */
	extern int sefs_fc_find_default_file_contexts(char **path);

#ifdef	__cplusplus
}
#endif

#endif				       /* SEFS_FILE_CONTEXTS_H */
