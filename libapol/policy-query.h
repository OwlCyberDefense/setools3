/**
 * @file policy-query.h
 *
 * Routines to query parts of a policy.  For each component and rule
 * there is a query structure to specify the details of the query.
 * The reason for all of the modifier functions on the query
 * structures is to ease the creation of swig wrappers to libapol.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#ifndef APOL_POLICY_QUERY_H
#define APOL_POLICY_QUERY_H

#include <regex.h>
#include <stdlib.h>
#include <qpol/policy_query.h>

#include "type-query.h"
#include "class-perm-query.h"
#include "role-query.h"
#include "user-query.h"
#include "bool-query.h"
#include "isid-query.h"
#include "mls-query.h"
#include "netcon-query.h"
#include "fscon-query.h"
#include "context-query.h"

#include "avrule-query.h"

/** Every query allows the treatment of strings as regular expressions
 *  instead.  Within the query structure are flags; if the first bit
 *  is set then use regex matching instead. */
#define APOL_QUERY_REGEX 0x01

#define APOL_QUERY_SUB	 0x02	  /* query is subset of rule range */
#define APOL_QUERY_SUPER 0x04	  /* query is superset of rule range */
#define APOL_QUERY_EXACT (APOL_QUERY_SUB|APOL_QUERY_SUPER)
#define APOL_QUERY_INTERSECT 0x08 /* query overlaps any part of rule range */
#define APOL_QUERY_FLAGS \
	(APOL_QUERY_SUB | APOL_QUERY_SUPER | APOL_QUERY_EXACT | \
	 APOL_QUERY_INTERSECT)

/******************** private functions ********************/

/**
 * Destroy a compiled regular expression, setting it to NULL
 * afterwards.	Does nothing if the reference is NULL.
 * @param regex Regular expression to destroy.
 */
void apol_regex_destroy(regex_t **regex);

/**
 * Sets a string field within a query, clearing its old contents and
 * cached regex first.	The search name will be duplicated.
 *
 * @param p Policy handler.
 * @param search_name Reference to where to store duplicated name.
 * @param regex Reference to cached regex; this will be cleared by the
 * function.
 * @param name New name to set, or NULL to just clear the field.
 *
 * @return 0 on success, < 0 on error.
 */
int apol_query_set(apol_policy_t *p, char **query_name, regex_t **regex,
		   const char *name);

/**
 * Sets an arbitrary flag for a query structure.
 *
 * @param p Policy handler.
 * @param flags Reference to a flag bitmap.
 * @param is_flag If non-zero, set flag. Otherwise unset it.
 * @param flag_value Flag value to set.
 *
 * @return Always returns 0.
 */
int apol_query_set_flag(apol_policy_t *p, unsigned int *flags,
			const int is_regex, int flag_value);

/**
 * Sets the regular expression flag for a query structure.
 *
 * @param p Policy handler.
 * @param flags Reference to the regular expression flag.
 * @param is_regex If non-zero, set regex flag.	 Otherwise unset it.
 *
 * @return Always returns 0.
 */
int apol_query_set_regex(apol_policy_t *p, unsigned int *flags,
			 const int is_regex);

/**
 * Determines if a name matches a target symbol name.  If flags has
 * the APOL_QUERY_REGEX bit set, then (1) compile the regular
 * expression if NULL, and (2) apply it to target.  Otherwise do a
 * string comparison between name and target.  If name is NULL and/or
 * empty then the comparison always succeeds regardless of flags and
 * regex.
 *
 * @param p Policy handler.
 * @param target Name of target symbol to compare.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare(apol_policy_t *p, const char *target, const char *name,
		 unsigned int flags, regex_t **regex);

/**
 * Given an iterator of strings, checks if name matches any element
 * within it.  If there is a match, either literally or by regular
 * expression, then return 1.  If there are no matches then return 0.
 *
 * @param p Policy handler.
 * @param iter Iterator of strings to match.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare_iter(apol_policy_t *p, qpol_iterator_t *iter, const char *name,
		      unsigned int flags, regex_t **regex);

/**
 * Determines if a (partial) type query matches a qpol_type_t,
 * either the type name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param type Type datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare_type(apol_policy_t *p,
		      qpol_type_t *type, const char *name,
		      unsigned int flags, regex_t **type_regex);

/**
 * Determines if a level query matches a qpol_level_t, either
 * the sensitivity name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param level level datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare_level(apol_policy_t *p,
		       qpol_level_t *level, const char *name,
		       unsigned int flags, regex_t **level_regex);

/**
 * Determines if a category query matches a qpol_cat_t, either
 * the category name or any of its aliases.
 *
 * @param p Policy within which to look up types.
 * @param cat category datum to compare against.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare_cat(apol_policy_t *p,
		     qpol_cat_t *cat, const char *name,
		     unsigned int flags, regex_t **cat_regex);

/**
 * Convenience function that compares a qpol_context_t to a
 * apol_context_t, based upon the MLS range match given by flags.  If
 * search is NULL then the comparison always succeeds.
 *
 * @param p Policy within which to look up types.
 * @param target Target context to compare.
 * @param name Source context from which to compare.
 * @param flags Gives how to match MLS ranges within the contexts.
 *
 * @return 1 If comparison succeeds, 0 if not; < 0 on error.
 */
int apol_compare_context(apol_policy_t *p, qpol_context_t *target,
			 apol_context_t *search, unsigned int flags);

#endif
