/**
 * @file rangetrans-query.h
 *
 * Routines to query range transition rules of a policy.
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

#ifndef APOL_RANGETRANS_QUERY_H
#define APOL_RANGETRANS_QUERY_H

#include "policy.h"
#include "vector.h"

typedef struct apol_range_trans_query apol_range_trans_query_t;

/**
 * Execute a query against all range transition rules within the
 * policy.
 *
 * @param p Policy within which to look up terules.
 * @param r Structure containing parameters for query.  If this is
 * NULL then return all range transitions.
 * @param v Reference to a vector of qpol_range_trans_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_range_trans_by_query(apol_policy_t *p,
					 apol_range_trans_query_t *r,
					 apol_vector_t **v);

/**
 * Allocate and return a new range trans query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all range transitions within the policy.  The caller must
 * call apol_range_trans_query_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized range trans structure, or NULL upon error.
 */
extern apol_range_trans_query_t *apol_range_trans_query_create(void);

/**
 * Deallocate all memory associated with the referenced range trans
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param r Reference to a range trans query structure to destroy.
 */
extern void apol_range_trans_query_destroy(apol_range_trans_query_t **r);

/**
 * Set a range trans query to return rules whose source symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param r Range trans rule query to set.
 * @param symbol Limit query to rules with this symbol as their
 * source, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_range_trans_query_set_source(apol_policy_t *p,
					     apol_range_trans_query_t *r,
					     const char *symbol,
					     int is_indirect);

/**
 * Set a range trans query to return rules whose target symbol matches
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.  If
 * is_indirect is non-zero then the search will be done indirectly.
 * If the symbol is a type, then the query matches rules with one of
 * the type's attributes.  If the symbol is an attribute, then it
 * matches rule with any of the attribute's types.
 *
 * @param p Policy handler, to report errors.
 * @param r Range trans query to set.
 * @param symbol Limit query to rules with this symbol as their
 * target, or NULL to unset this field.
 * @param is_indirect If non-zero, perform indirect matching.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_range_trans_query_set_target(apol_policy_t *p,
					     apol_range_trans_query_t *r,
					     const char *symbol,
					     int is_indirect);

/**
 * Set a range trans query to return only users matching a MLS range.
 * This function takes ownership of the range, such that the caller
 * must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param r Range trans query to set.
 * @param range Limit query to only rules matching this range, or NULL
 * to unset this field.
 * @param range_match Specifies how to match a rules to a range.  This
 * must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if range is NULL.
 *
 * @return Always returns 0.
 */
extern int apol_range_trans_query_set_range(apol_policy_t *p,
					    apol_range_trans_query_t *r,
					    apol_mls_range_t *range,
					    unsigned int range_match);

/**
 * Set a range trans query to treat the source symbol as any.  That
 * is, use the same symbol for either source or target of a rule.
 * This flag does nothing if the source symbol is not set.
 *
 * @param p Policy handler, to report errors.
 * @param r Range trans rule query to set.
 * @param is_any Non-zero to use source symbol for any field, 0 to
 * keep source as only source.
 *
 * @return Always 0.
 */
extern int apol_range_trans_query_set_source_any(apol_policy_t *p,
						 apol_range_trans_query_t *r,
						 int is_any);

/**
 * Set a range trans query to use regular expression searching for
 * source and target types/attributes.  Strings will be treated as
 * regexes instead of literals.  Matching will occur against the type
 * name or any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param r Range trans rule query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_range_trans_query_set_regex(apol_policy_t *p,
					    apol_range_trans_query_t *t,
					    int is_regex);

/**
 *  Render a range transition to a string.
 *
 *  @param policy Policy handler, to report errors.
 *  @param rule The rule to render.
 *
 *  @return a newly malloc()'d string representation of the rule, or NULL on
 *  failure; if the call fails, errno will be set. The caller is responsible
 *  for calling free() on the returned string.
 */
extern char *apol_range_trans_render(apol_policy_t *policy,
				     qpol_range_trans_t *rule);

#endif
