/**
 *  @file
 *  Additional declarations for use solely by libsefs.
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

#ifndef SEFS_INTERNAL_HH
#define SEFS_INTERNAL_HH

#include <apol/bst.h>
#include <sefs/fclist.hh>
#include <regex.h>

/**
 * Given a policy containing types, generate and return a vector of
 * names (char *) that match the given criteria.
 *
 * @param policy Policy associated with types.
 * @param str Type name to find.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use.
 * @param regex_flag If true, use the compiled regular expression
 * instead of str.
 * @param indirect If true, do indirect type matching.
 *
 * @return Vector of strings.  The caller is responsible for calling
 * apol_vector_destroy() upon the returned value afterwards.
 */
apol_vector_t *query_create_candidate_type(apol_policy_t * policy, const char *str, const regex_t * regex, const bool regex_flag,
					   const bool indirect);

/**
 * Determines if a string matches a target symbol name.  If \a
 * regex_flag is true, use the compiled regular expression instead of
 * \a str.  Otherwise do a straight string comparison between \a str
 * and \a target.  If \a str is NULL and/or empty then the comparison
 * always succeeds regardless of \a regex and \a target.  Next, if \a
 * target is NULL or empty then comparison fails.
 *
 * @param target Name of target symbol to compare.
 * @param str Source string from which to compare.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use.
 * @param regex_flag If true, use the compiled regular expression
 * instead.
 *
 * @return true if comparison succeeds, false if not.
 */
bool query_str_compare(const char *target, const char *str, const regex_t * regex, const bool regex_flag);

// rather than having each sefs_entry having its own apol_context_t
// object, build a cache of nodes to save space
struct sefs_context_node
{
	apol_context_t *context;       // each node owns its apol context
	const char *user, *role, *type, *range;	// these are pointers into fclists's BSTs
	char *context_str;	       // each node owns the string
};

#endif
