/**
 * @file rbacrule-query.h
 *
 * Routines to query (role) allow and role_transition rules of a
 * policy.  This does not include access vector's allow rules, which
 * are found in avrule-query.h.
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

#ifndef APOL_RBACRULE_QUERY_H
#define APOL_RBACRULE_QUERY_H

#include "policy.h"
#include "vector.h"

typedef struct apol_role_allow_query apol_role_allow_query_t;
typedef struct apol_role_trans_query apol_role_trans_query_t;

/******************** (role) allow queries ********************/

/**
 * Execute a query against all (role) allow rules within the policy.
 *
 * @param p Policy within which to look up allow rules.
 * @param r Structure containing parameters for query.	If this is
 * NULL then return all allow rules.
 * @param v Reference to a vector of qpol_role_allow_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_role_allow_by_query(apol_policy_t *p,
					apol_role_allow_query_t *r,
					apol_vector_t **v);

/**
 * Allocate and return a new role allow query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all (role) allows within the policy.  The caller must
 * call apol_role_allow_query_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized role allow query structure, or NULL upon
 * error.
 */
extern apol_role_allow_query_t *apol_role_allow_query_create(void);

/**
 * Deallocate all memory associated with the referenced role allow
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param r Reference to a role allow query structure to destroy.
 */
extern void apol_role_allow_query_destroy(apol_role_allow_query_t **r);

/**
 * Set a role allow query to return rules with a particular source
 * role.
 *
 * @param p Policy handler, to report errors.
 * @param r Role allow query to set.
 * @param role Limit query to rules with this role as their source, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_allow_query_set_source(apol_policy_t *p,
					    apol_role_allow_query_t *r,
					    const char *role);

/**
 * Set a role allow query to return rules with a particular target
 * role.  This field is ignored if
 * apol_role_allow_query_set_source_any() is set to non-zero.
 *
 * @param p Policy handler, to report errors.
 * @param r Role allow query to set.
 * @param role Limit query to rules with this role as their target, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_allow_query_set_target(apol_policy_t *p,
					    apol_role_allow_query_t *r,
					    const char *role);

/**
 * Set a role allow query to treat the source role as any.  That is,
 * use the same symbol for either source or target of a (role) allow
 * rule.  This flag does nothing if the source role is not set.
 *
 * @param p Policy handler, to report errors.
 * @param r Role allow query to set.
 * @param is_any Non-zero to use source symbol for any field, 0 to
 * keep source as only source.
 *
 * @return Always 0.
 */
extern int apol_role_allow_query_set_source_any(apol_policy_t *p,
                                                apol_role_allow_query_t *r,
                                                int is_any);

/******************** role_transition queries ********************/

/**
 * Execute a query against all role_transition rules within the
 * policy.
 *
 * @param p Policy within which to look up role_transition rules.
 * @param r Structure containing parameters for query.	If this is
 * NULL then return all role_transition rules.
 * @param v Reference to a vector of qpol_role_trans_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_role_trans_by_query(apol_policy_t *p,
					apol_role_trans_query_t *r,
					apol_vector_t **v);

/**
 * Allocate and return a new role trans query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all role_transitions within the policy.  The caller must
 * call apol_role_trans_query_destroy() upon the return value
 * afterwards.
 *
 * @return An initialized role trans query structure, or NULL upon
 * error.
 */
extern apol_role_trans_query_t *apol_role_trans_query_create(void);

/**
 * Deallocate all memory associated with the referenced role trans
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param r Reference to a role trans query structure to destroy.
 */
extern void apol_role_trans_query_destroy(apol_role_trans_query_t **r);

/**
 * Set a role trans query to return rules with a particular source
 * role.
 *
 * @param p Policy handler, to report errors.
 * @param r Role trans query to set.
 * @param role Limit query to rules with this role as their source, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_trans_query_set_source(apol_policy_t *p,
					    apol_role_trans_query_t *r,
					    const char *role);

/**
 * Set a role trans query to return rules with a particular target
 * symbol.  Symbol may be a type or attribute; if it is an alias then
 * the query will convert it to its primary prior to searching.
 *
 * @param p Policy handler, to report errors.
 * @param r Role trans query to set.
 * @param symbol Limit query to rules with this type or attribute as
 * their target, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_trans_query_set_target(apol_policy_t *p,
					    apol_role_trans_query_t *r,
					    const char *symbol);

/**
 * Set a role trans query to return rules with a particular default
 * role.  This field is ignored if
 * apol_role_trans_query_set_source_any() is set to non-zero.
 *
 * @param p Policy handler, to report errors.
 * @param r Role trans query to set.
 * @param role Limit query to rules with this role as their default, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_trans_query_set_default(apol_policy_t *p,
					     apol_role_trans_query_t *r,
					     const char *role);

/**
 * Set a role trans query to treat the source role as any.  That is,
 * use the same symbol for either source or default of a
 * role_transition rule.  This flag does nothing if the source role is
 * not set.  Note that a role_transition's target is a type, so thus
 * this flag does not affect its searching.
 *
 * @param p Policy handler, to report errors.
 * @param r Role allow query to set.
 * @param is_any Non-zero to use source symbol for source or default
 * field, 0 to keep source as only source.
 *
 * @return Always 0.
 */
extern int apol_role_trans_query_set_source_any(apol_policy_t *p,
                                                apol_role_trans_query_t *r,
                                                int is_any);

#endif
