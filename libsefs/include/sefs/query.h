/**
 *  @file
 *  Defines the public interface for file context queries.
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

#ifndef SEFS_QUERY_H
#define SEFS_QUERY_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/types.h>
#include <stdbool.h>

#include <apol/context-query.h>
#include <apol/mls-query.h>
#include <apol/policy-query.h>
#include <apol/vector.h>

#include "fclist.h"

	typedef struct sefs_query sefs_query_t;

/**
 * Allocate and return a new sefs query structure. 
 * All fields are initialized, such that running this blank query results in
 * returning all entries within a fclist.  The caller must call
 * sefs_query_destroy() upon the return value afterwords.
 * @return An initialized sefs query structure or NULL on error.
 */
	sefs_query_t *sefs_query_create();

/**
 * Deallocate all memory associated with the referenced sefs query, and then
 * set it to NULL.  This function does nothing if the query is already NULL.
 * @param query Reference to a sefs query structure to destroy.
 */
	void sefs_query_destroy(sefs_query_t ** query);

/**
 * Set a sefs query to match only entries with contexts with the user \a name.
 * @param query Query for which to set the user.
 * @param name Limit query to only contexts with this user.
 */
	void sefs_query_set_user(sefs_query_t * query, const char *name);

/**
 * Set a sefs query to match only entries with contexts with the role \a name.
 * @param query Query for which to set the role.
 * @param name Limit query to only contexts with this role.
 */
	void sefs_query_set_role(sefs_query_t * query, const char *name);

/**
 * Set a sefs query to match only entries with contexts with the type \a name.
 * @param query Query for which to set the type.
 * @param name Limit query to only contexts with this type.
 * @param indirect If the fclist queried has access to a policy, also match
 * contexts with types in attribute \a name or types which are an alias for \a
 * name. If a policy is not available, this field is ignored, and exact string
 * matching is used instead. 
 */
	void sefs_query_set_type(sefs_query_t * query, const char *name, bool indirect);

/**
 * Set a sefs query to match only entries with contexts with a range of \a range.
 * @param query Query for which to set the range.
 * @param range Limit query to only contexts matching this string representing
 * the MLS range.
 * @param match If non-zero and the fclist queried has access to a policy,
 * match the range using the specified semantics; this should be one of
 * APOL_QUERY_SUB, APOL_QUERY_SUPER, or APOL_QUERY_EXACT. If a policy is not
 * available or \a match is zero, exact string matching is used instead.
 * Note, if a policy is available the regex flag is ignored if \a match
 * is non-zero.
 * @see sefs_fclist_associate_policy() to associate a policy with a fclist.
 */
	void sefs_query_set_range(sefs_query_t * query, const char *range, int match);

/**
 * Set a sefs query to match only entries with object class \a name.
 * @param query Query for which to set the object class.
 * @param name Limit query to only entries with this object class.
 */
	void sefs_query_set_object_class(sefs_query_t * query, const char *name);

/**
 * Set a sefs query to match only entries with path \a path.
 * @param query Query for which to set the path.
 * @param path Limit query to only entries with this path.
 */
	void sefs_query_set_path(sefs_query_t * query, const char *path);

/**
 * Set a sefs query to match only entries with a given inode number.
 * @param query Query for which to set the inode number.
 * @param inode Limit query to only entries with this inode number.
 */
	void sefs_query_set_inode(sefs_query_t * query, ino64_t inode);

/**
 * Set a sefs query to match only entries with a given device number.
 * @param query Query for which to set the device number.
 * @param dev Limit query to only entries with this device number.
 */
	void sefs_query_set_dev(sefs_query_t * query, dev64_t dev);

/**
 * Set a sefs query to use regular expression matching for string fields.
 * @param query Query to set to use regular expression matching.
 * @param regex If non-zero use regular expression matching, if zero,
 * use only exact string matching.
 */
	void sefs_query_set_regex(sefs_query_t * query, bool regex);

/**
 * Set a sefs query to operate starting at directory \a root.
 * @param query Query for which to set the root directory.
 * @param root Directory from which to begin the query. This field is
 * not affected by the sefs_query_set_regex() option.
 * @param recursive If non-zero operate recursively on all sub-directories
 * of \a root, if zero, only operate on \a root not its sub-directories.
 */
	void sefs_query_set_root_dir(sefs_query_t * query, const char *root, bool recursive);

/**
 * Perform a sefs query on the given file context list object.
 * @param query Query to run.
 * @param fclist File context list on which to run the query.
 * @return A newly allocated vector (of type sefs_entry_t*) containing all
 * entries matching the query, or NULL on error. The caller is responsible for
 * calling apol_vector_destroy() on the returned vector.
 */
	apol_vector_t *sefs_query_do(sefs_query_t * query, sefs_fclist_t * fclist);

#ifdef __cplusplus
}
#endif

#endif				       /* SEFS_QUERY_H */
