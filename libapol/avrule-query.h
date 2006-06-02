/**
 * @file avrule-query.h
 *
 * Routines to query access vector rules of a policy.  These are
 * allow, neverallow, auditallow, and dontaudit rules.
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

#ifndef APOL_AVRULE_QUERY_H
#define APOL_AVRULE_QUERY_H

#include "policy.h"
#include "vector.h"

typedef struct apol_avrule_query apol_avrule_query_t;

/**
 * Execute a query against all access vector rules within the policy.
 *
 * @param p Policy within which to look up avrules.
 * @param a Structure containing parameters for query.	If this is
 * NULL then return all avrules.
 * @param v Reference to a vector of qpol_avrule_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_avrule_by_query(apol_policy_t *p,
				    apol_avrule_query_t *a,
				    apol_vector_t **v);

/**
 * Allocate and return a new avrule query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all avrules within the policy.  The caller must call
 * apol_avrule_query_destroy() upon the return value afterwards.
 *
 * @return An initialized avrule query structure, or NULL upon error.
 */
extern apol_avrule_query_t *apol_avrule_query_create(void);

/**
 * Deallocate all memory associated with the referenced avrule query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param t Reference to a avrule query structure to destroy.
 */
extern void apol_avrule_query_destroy(apol_avrule_query_t **a);

/**
 * Set an avrule query to search only certain access vector rules
 * within the policy.  This is a bitmap; use the constants in
 * libqpol/avrule_query.h (QPOL_RULE_ALLOW, etc.) to give the rule
 * selections.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param rules Bitmap to indicate which rules to search, or 0 to
 * search all rules.
 *
 * @return Always 0.
 */
extern int apol_avrule_query_set_rules(apol_policy_t *p,
				       apol_avrule_query_t *a, unsigned int rules);

/**
 * Set an avrule query to return rules whose source symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * source, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_avrule_query_set_source(apol_policy_t *p,
					apol_avrule_query_t *a,
					const char *symbol,
					int is_indirect);

/**
 * Set an avrule query to return rules whose target symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * target, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_avrule_query_set_target(apol_policy_t *p,
					apol_avrule_query_t *a,
					const char *symbol,
					int is_indirect);

/**
 * Set an avrule query to return rules with this object (non-common)
 * class.  If more than one class are appended to the query, the
 * rule's class must be one of those appended.  (I.e., the rule's
 * class must be a member of the query's classes.)
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param class Name of object class to add to search set.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_avrule_query_append_class(apol_policy_t *p,
					  apol_avrule_query_t *a,
					  const char *obj_class);

/**
 * Set an avrule query to return rules with this permission.  If more
 * than one permission are appended to the query, at least one of the
 * rule's permissions must be one of those appended.  (I.e., the
 * intersection of query's and rule's permissions must be non-empty.)
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param perm Name of permission to add to search set.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_avrule_query_append_perm(apol_policy_t *p,
					 apol_avrule_query_t *a,
					 const char *perm);

/**
 * Set an avrule query to treat the source symbol as any.  That is,
 * use the same symbol for the target, and for type rules the default.
 * This flag does nothing if the source symbol is not set.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_enabled Non-zero to search only enabled rules, 0 to
 * search all rules.
 *
 * @return Always 0.
 */
extern int apol_avrule_query_set_enabled(apol_policy_t *p,
					 apol_avrule_query_t *a, int is_enabled);

/**
 * Set an avrule query to search only enabled rules within the policy.
 * These include rules that are unconditional and those within enabled
 * conditionals.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_any Non-zero to use source symbol for any field, 0 to
 * keep source as only source.
 *
 * @return Always 0.
 */
extern int apol_avrule_query_set_source_any(apol_policy_t *p,
					    apol_avrule_query_t *a, int is_any);

/**
 * Set an avrule query to use regular expression searching for source
 * and target types/attributes.  Strings will be treated as regexes
 * instead of literals.  Matching will occur against the type name or
 * any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param a AV rule query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_avrule_query_set_regex(apol_policy_t *p,
				       apol_avrule_query_t *a, int is_regex);

#endif
