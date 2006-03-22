/**
 * @file component-query.h
 *
 * Routines to query individual components of a policy.	 For each
 * component there is a query structure to specify the details of the
 * query.  The reason for all of the modifier functions on the query
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

#ifndef _APOL_COMPONENT_QUERY_H_
#define _APOL_COMPONENT_QUERY_H_

#include <stdlib.h>
#include <sepol/policydb_query.h>

#include "context-query.h"
#include "mls-query.h"
#include "policy.h"
#include "vector.h"

typedef struct apol_type_query apol_type_query_t;
typedef struct apol_attr_query apol_attr_query_t;
typedef struct apol_class_query apol_class_query_t;
typedef struct apol_common_query apol_common_query_t;
typedef struct apol_perm_query apol_perm_query_t;
typedef struct apol_role_query apol_role_query_t;
typedef struct apol_user_query apol_user_query_t;
typedef struct apol_bool_query apol_bool_query_t;
typedef struct apol_level_query apol_level_query_t;
typedef struct apol_cat_query apol_cat_query_t;
typedef struct apol_portcon_query apol_portcon_query_t;
typedef struct apol_netifcon_query apol_netifcon_query_t;

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

/******************** type queries ********************/

/**
 * Execute a query against all types within the policy.	 The results
 * will only contain types, not aliases nor attributes.
 *
 * @param p Policy within which to look up types.
 * @param t Structure containing parameters for query.	If this is
 * NULL then return all types.
 * @param v Reference to a vector of sepol_type_datum_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_type_by_query(apol_policy_t *p,
				  apol_type_query_t *t,
				  apol_vector_t **v);

/**
 * Allocate and return a new type query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all types within the policy.  The caller must call
 * apol_type_query_destroy() upon the return value afterwards.
 *
 * @return An initialized type query structure, or NULL upon error.
 */
extern apol_type_query_t *apol_type_query_create(void);

/**
 * Deallocate all memory associated with the referenced type query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param t Reference to a type query structure to destroy.
 */
extern void apol_type_query_destroy(apol_type_query_t **t);

/**
 * Set a type query to return only types that match this name.	The
 * name may be either a type or one of its aliases.  This function
 * duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param t Type query to set.
 * @param name Limit query to only types or aliases with this name, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_type_query_set_type(apol_policy_t *p,
				    apol_type_query_t *t, const char *name);

/**
 * Set a type query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 * Matching will occur against the type name or any of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param t Type query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_type_query_set_regex(apol_policy_t *p,
				     apol_type_query_t *t, int is_regex);


/******************** attribute queries ********************/

/**
 * Execute a query against all attributes within the policy.  The
 * results will only contain attributes, not types nor aliases.
 *
 * @param p Policy within which to look up attributes.
 * @param a Structure containing parameters for query.	If this is
 * NULL then return all attributes.
 * @param v Reference to a vector of sepol_type_datum_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_attr_by_query(apol_policy_t *p,
				  apol_attr_query_t *a,
				  apol_vector_t **v);

/**
 * Allocate and return a new attribute query structure.	 All fields
 * are initialized, such that running this blank query results in
 * returning all attributes within the policy.	The caller must call
 * apol_attr_query_destroy() upon the return value afterwards.
 *
 * @return An initialized attribute query structure, or NULL upon error.
 */
extern apol_attr_query_t *apol_attr_query_create(void);

/**
 * Deallocate all memory associated with the referenced attribute
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param a Reference to an attribute query structure to destroy.
 */
extern void apol_attr_query_destroy(apol_attr_query_t **a);

/**
 * Set an attribute query to return only attributes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param a Attribute query to set.
 * @param name Limit query to only attributes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_attr_query_set_attr(apol_policy_t *p,
				    apol_attr_query_t *a, const char *name);

/**
 * Set an attribute query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param a Attribute query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_attr_query_set_regex(apol_policy_t *p,
				     apol_attr_query_t *a, int is_regex);


/******************** class queries ********************/

/**
 * Execute a query against all classes within the policy.  The results
 * will only contain object classes, not common classes.
 *
 * @param p Policy within which to look up classes.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all object classes.
 * @param v Reference to a vector of sepol_class_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_class_by_query(apol_policy_t *p,
				   apol_class_query_t *c,
				   apol_vector_t **v);

/**
 * Allocate and return a new class query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all object classes within the policy.  The caller must
 * call apol_class_query_destroy() upon the return value afterwards.
 *
 * @return An initialized class query structure, or NULL upon error.
 */
extern apol_class_query_t *apol_class_query_create(void);

/**
 * Deallocate all memory associated with the referenced class query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param c Reference to a class query structure to destroy.
 */
extern void apol_class_query_destroy(apol_class_query_t **c);

/**
 * Set a class query to return only object classes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param name Limit query to only classes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_class_query_set_class(apol_policy_t *p,
				      apol_class_query_t *c, const char *name);

/**
 * Set a class query to return only object classes that inherit from a
 * particular common class.  Queries will not match classes without
 * commons if this option is set.  This function duplicates the
 * incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param name Limit query to only classes that inherit from this
 * common class, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_class_query_set_common(apol_policy_t *p,
				       apol_class_query_t *c, const char *name);
/**
 * Set a class query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_class_query_set_regex(apol_policy_t *p,
				      apol_class_query_t *c, int is_regex);


/******************** common class queries ********************/

/**
 * Execute a query against all common classes within the policy.  The
 * results will only contain common classes, not object classes.
 *
 * @param p Policy within which to look up common classes.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all common classes.
 * @param v Reference to a vector of sepol_common_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_common_by_query(apol_policy_t *p,
				    apol_common_query_t *c,
				    apol_vector_t **v);

/**
 * Allocate and return a new common query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all common classes within the policy.  The caller must
 * call apol_common_query_destroy() upon the return value afterwards.
 *
 * @return An initialized common query structure, or NULL upon error.
 */
extern apol_common_query_t *apol_common_query_create(void);

/**
 * Deallocate all memory associated with the referenced common query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param c Reference to a common query structure to destroy.
 */
extern void apol_common_query_destroy(apol_common_query_t **c);

/**
 * Set a common query to return only common classes that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Common query to set.
 * @param name Limit query to only commons with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_common_query_set_common(apol_policy_t *p,
					apol_common_query_t *c, const char *name);

/**
 * Set a common query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_common_query_set_regex(apol_policy_t *p,
				       apol_common_query_t *c, int is_regex);


/******************** permission queries ********************/

/**
 * Execute a query against all permissions within the policy.  The
 * results will contain char pointers to permission names.
 *
 * @param p Policy within which to look up permissions.
 * @param pq Structure containing parameters for query.	 If this is
 * NULL then return all permissions.
 * @param v Reference to a vector of character pointers.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_perm_by_query(apol_policy_t *p,
				  apol_perm_query_t *pq,
				  apol_vector_t **v);

/**
 * Allocate and return a new permission query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all permissions within the policy.	 The caller must call
 * apol_perm_query_destroy() upon the return value afterwards.
 *
 * @return An initialized permission query structure, or NULL upon
 * error.
 */
extern apol_perm_query_t *apol_perm_query_create(void);

/**
 * Deallocate all memory associated with the referenced permission
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param pq Reference to a permission query structure to destroy.
 */
extern void apol_perm_query_destroy(apol_perm_query_t **pq);

/**
 * Set a permission query to return only permissions that match this
 * name.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param pq Permission query to set.
 * @param name Limit query to only permissions with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_perm_query_set_perm(apol_policy_t *p,
				    apol_perm_query_t *pq, const char *name);

/**
 * Set a permission query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param pq Permission query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_perm_query_set_regex(apol_policy_t *p,
				     apol_perm_query_t *pq, int is_regex);


/******************** role queries ********************/

/**
 * Execute a query against all roles within the policy.
 *
 * @param p Policy within which to look up roles.
 * @param r Structure containing parameters for query.	If this is
 * NULL then return all roles.
 * @param v Reference to a vector of sepol_role_datum_t.  The vector
 * will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_role_by_query(apol_policy_t *p,
				  apol_role_query_t *r,
				  apol_vector_t **v);

/**
 * Allocate and return a new role query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all roles within the policy.  The caller must call
 * apol_role_query_destroy() upon the return value afterwards.
 *
 * @return An initialized role query structure, or NULL upon error.
 */
extern apol_role_query_t *apol_role_query_create(void);

/**
 * Deallocate all memory associated with the referenced role query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param r Reference to a role query structure to destroy.
 */
extern void apol_role_query_destroy(apol_role_query_t **r);

/**
 * Set a role query to return only roles that match this name.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param name Limit query to only roles with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_query_set_role(apol_policy_t *p,
				    apol_role_query_t *r, const char *name);

/**
 * Set a role query to return only roles containing this type or one
 * of its aliases.  This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param name Limit query to only roles with this type, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_query_set_type(apol_policy_t *p,
				    apol_role_query_t *r, const char *name);

/**
 * Set a role query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param p Policy handler, to report errors.
 * @param r Role query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_role_query_set_regex(apol_policy_t *p,
				     apol_role_query_t *r, int is_regex);


/******************** user queries ********************/

/**
 * Execute a query against all users within the policy.
 *
 * @param p Policy within which to look up users.
 * @param u Structure containing parameters for query.	If this is
 * NULL then return all users.
 * @param v Reference to a vector of sepol_user_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_user_by_query(apol_policy_t *p,
				  apol_user_query_t *u,
				  apol_vector_t **v);

/**
 * Allocate and return a new user query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all users within the policy.  The caller must call
 * apol_user_query_destroy() upon the return value afterwards.
 *
 * @return An initialized user query structure, or NULL upon error.
 */
extern apol_user_query_t *apol_user_query_create(void);

/**
 * Deallocate all memory associated with the referenced user query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param u Reference to a user query structure to destroy.
 */
extern void apol_user_query_destroy(apol_user_query_t **u);

/**
 * Set a user query to return only users that match this name.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param name Limit query to only users this name, or NULL to unset
 * this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_user(apol_policy_t *p,
				    apol_user_query_t *u, const char *name);

/**
 * Set a user query to return only users containing this role.	This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param role Limit query to only users with this role, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_role(apol_policy_t *p,
				    apol_user_query_t *u, const char *role);

/**
 * Set a user query to return only users containing this default
 * level.  This function takes ownership of the level, such that the
 * caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to which set.
 * @param level Limit query to only users with this level as their
 * default, or NULL to unset this field.
 *
 * @return Always returns 0.
 */
extern int apol_user_query_set_default_level(apol_policy_t *p,
					     apol_user_query_t *u,
					     apol_mls_level_t *level);

/**
 * Set a user query to return only users matching a MLS range.	This
 * function takes ownership of the range, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param range Limit query to only users matching this range, or NULL
 * to unset this field.
 * @param range_match Specifies how to match a user to a range.	 This
 * must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if range is NULL.
 *
 * @return Always returns 0.
 */
extern int apol_user_query_set_range(apol_policy_t *p,
				     apol_user_query_t *u,
				     apol_mls_range_t *range,
				     unsigned int range_match);

/**
 * Set a user query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param p Policy handler, to report errors.
 * @param u User query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_user_query_set_regex(apol_policy_t *p,
				     apol_user_query_t *u, int is_regex);


/******************** booleans queries ********************/

/**
 * Execute a query against all booleans within the policy.
 *
 * @param p Policy within which to look up booleans.
 * @param b Structure containing parameters for query.	If this is
 * NULL then return all booleans.
 * @param v Reference to a vector of sepol_bool_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_bool_by_query(apol_policy_t *p,
				  apol_bool_query_t *b,
				  apol_vector_t **v);

/**
 * Allocate and return a new boolean query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all booleans within the policy.  The caller must call
 * apol_bool_query_destroy() upon the return value afterwards.
 *
 * @return An initialized boolean query structure, or NULL upon error.
 */
extern apol_bool_query_t *apol_bool_query_create(void);

/**
 * Deallocate all memory associated with the referenced boolean query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param b Reference to a boolean query structure to destroy.
 */
extern void apol_bool_query_destroy(apol_bool_query_t **b);

/**
 * Set a boolean query to return only booleans that match this name.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param b Boolean query to set.
 * @param name Limit query to only booleans with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_bool_query_set_bool(apol_policy_t *p,
				    apol_bool_query_t *b, const char *name);

/**
 * Set a boolean query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.
 *
 * @param p Policy handler, to report errors.
 * @param b Boolean query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_bool_query_set_regex(apol_policy_t *p,
				     apol_bool_query_t *b, int is_regex);


/******************** level queries ********************/

/**
 * Execute a query against all levels within the policy.  The results
 * will only contain levels, not sensitivity aliases.  The returned
 * levels will be unordered.
 *
 * @param p Policy within which to look up levels.
 * @param l Structure containing parameters for query.	If this is
 * NULL then return all levels.
 * @param v Reference to a vector of sepol_level_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_level_by_query(apol_policy_t *p,
				   apol_level_query_t *l,
				   apol_vector_t **v);

/**
 * Allocate and return a new level query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all levels within the policy.  The caller must call
 * apol_level_query_destroy() upon the return value afterwards.
 *
 * @return An initialized level query structure, or NULL upon error.
 */
extern apol_level_query_t *apol_level_query_create(void);

/**
 * Deallocate all memory associated with the referenced level query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param l Reference to a level query structure to destroy.
 */
extern void apol_level_query_destroy(apol_level_query_t **l);

/**
 * Set a level query to return only levels that match this name.  The
 * name may be either a sensitivity or one of its aliases.  This
 * function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param name Limit query to only sensitivities or aliases with this
 * name, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_level_query_set_sens(apol_policy_t *p,
				     apol_level_query_t *l, const char *name);

/**
 * Set a level query to return only levels contain a particular
 * category.  The name may be either a category or one of its aliases.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param name Limit query to levels containing this category or
 * alias, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_level_query_set_cat(apol_policy_t *p,
				    apol_level_query_t *l, const char *name);

/**
 * Set a level query to use regular expression searching for all of
 * its fields.	Strings will be treated as regexes instead of
 * literals.  Matching will occur against the sensitivity name or any
 * of its aliases.
 *
 * @param p Policy handler, to report errors.
 * @param l Level query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_level_query_set_regex(apol_policy_t *p,
				      apol_level_query_t *l, int is_regex);


/******************** category queries ********************/

/**
 * Execute a query against all categories within the policy.  The
 * results will only contain categories, not aliases.  The returned
 * categories will be unordered.
 *
 * @param p Policy within which to look up categories.
 * @param c Structure containing parameters for query.	If this is
 * NULL then return all categories.
 * @param v Reference to a vector of sepol_cat_datum_t.  The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.  This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_cat_by_query(apol_policy_t *p,
				 apol_cat_query_t *c,
				 apol_vector_t **v);

/**
 * Allocate and return a new category query structure.	All fields are
 * initialized, such that running this blank query results in
 * returning all categories within the policy.	The caller must call
 * apol_cat_query_destroy() upon the return value afterwards.
 *
 * @return An initialized category query structure, or NULL upon
 * error.
 */
extern apol_cat_query_t *apol_cat_query_create(void);

/**
 * Deallocate all memory associated with the referenced category
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param c Reference to a category query structure to destroy.
 */
extern void apol_cat_query_destroy(apol_cat_query_t **c);

/**
 * Set a category query to return only categories that match this
 * name.  The name may be either a category or one of its aliases.
 * This function duplicates the incoming name.
 *
 * @param p Policy handler, to report errors.
 * @param c Category query to set.
 * @param name Limit query to only categories or aliases with this
 * name, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_cat_query_set_cat(apol_policy_t *p,
				  apol_cat_query_t *c, const char *name);

/**
 * Set a category query to use regular expression searching for all of
 * its fields. Strings will be treated as regexes instead of literals.
 * Matching will occur against the category name or any of its
 * aliases.
 *
 * @param p Policy handler, to report errors.
 * @param c Category query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_cat_query_set_regex(apol_policy_t *p,
				    apol_cat_query_t *c, int is_regex);

/******************** portcon queries ********************/

/**
 * Execute a query against all portcons within the policy.  The
 * returned portcons will be unordered.
 *
 * @param p Policy within which to look up portcons.
 * @param po Structure containing parameters for query.	 If this is
 * NULL then return all portcons.
 * @param v Reference to a vector of sepol_portcon_t.  The vector will
 * be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.	This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_portcon_by_query(apol_policy_t *p,
				     apol_portcon_query_t *po,
				     apol_vector_t **v);

/**
 * Allocate and return a new portcon query structure. All fields are
 * initialized, such that running this blank query results in
 * returning all portcons within the policy. The caller must call
 * apol_portcon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized portcon query structure, or NULL upon error.
 */
extern apol_portcon_query_t *apol_portcon_query_create(void);

/**
 * Deallocate all memory associated with the referenced portcon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param po Reference to a portcon query structure to destroy.
 */
extern void apol_portcon_query_destroy(apol_portcon_query_t **po);

/**
 * Set a portcon query to return only portcons that use this protocol.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param proto Limit query to only portcons with this protocol, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
extern int apol_portcon_query_set_proto(apol_policy_t *p,
					apol_portcon_query_t *po, int proto);

/**
 * Set a portcon query to return only portcons with this as their low
 * port.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param low Limit query to only portcons with this low port, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
extern int apol_portcon_query_set_low(apol_policy_t *p,
				      apol_portcon_query_t *po, int low);

/**
 * Set a portcon query to return only portcons with this as their high
 * port.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param high Limit query to only portcons with this high port, or
 * negative to unset this field.
 *
 * @return Always 0.
 */
extern int apol_portcon_query_set_high(apol_policy_t *p,
				       apol_portcon_query_t *po, int high);

/**
 * Set a portcon query to return only portcons matching a
 * context. This function takes ownership of the context, such that
 * the caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param po Portcon query to set.
 * @param context Limit query to only portcons matching this context,
 * or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
extern int apol_portcon_query_set_context(apol_policy_t *p,
					  apol_portcon_query_t *po,
					  apol_context_t *context,
					  unsigned int range_match);

/******************** netifcon queries ********************/

/**
 * Execute a query against all netifcons within the policy.  The
 * returned netifcons will be unordered.
 *
 * @param p Policy within which to look up netifcons.
 * @param n Structure containing parameters for query.	If this is
 * NULL then return all netifcons.
 * @param v Reference to a vector of sepol_netifcon_t.	The vector
 * will be allocated by this function. The caller must call
 * apol_vector_destroy() afterwards, but <b>must not</b> free the
 * elements within it.	This will be set to NULL upon no results or
 * upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_netifcon_by_query(apol_policy_t *p,
				      apol_netifcon_query_t *n,
				      apol_vector_t **v);

/**
 * Allocate and return a new netifcon query structure.	All fields are
 * initialized, such that running this blank query results in
 * returning all netifcons within the policy.  The caller must call
 * apol_netifcon_query_destroy() upon the return value afterwards.
 *
 * @return An initialized netifcon query structure, or NULL upon
 * error.
 */
extern apol_netifcon_query_t *apol_netifcon_query_create(void);

/**
 * Deallocate all memory associated with the referenced netifcon
 * query, and then set it to NULL.  This function does nothing if the
 * query is already NULL.
 *
 * @param n Reference to a netifcon query structure to destroy.
 */
extern void apol_netifcon_query_destroy(apol_netifcon_query_t **n);

/**
 * Set a netifcon query to return only netifcons that use this device.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param dev Limit query to only netifcons that use this device, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_netifcon_query_set_device(apol_policy_t *p,
					  apol_netifcon_query_t *n, const char *dev);

/**
 * Set a netifcon query to return only netifcons matching this context
 * for its interface.  This function takes ownership of the context,
 * such that the caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param context Limit query to only netifcon matching this context
 * for its interface, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
extern int apol_netifcon_query_set_if_context(apol_policy_t *p,
					      apol_netifcon_query_t *n,
					      apol_context_t *context,
					      unsigned int range_match);

/**
 * Set a netifcon query to return only netifcons matching this context
 * for its messages.  This function takes ownership of the context,
 * such that the caller must not modify nor destroy it afterwards.
 *
 * @param p Policy handler, to report errors.
 * @param n Netifcon query to set.
 * @param context Limit query to only netifcon matching this context
 * for its messages, or NULL to unset this field.
 * @param range_match Specifies how to match the MLS range within the
 * context.  This must be one of APOL_QUERY_SUB, APOL_QUERY_SUPER, or
 * APOL_QUERY_EXACT.  This parameter is ignored if context is NULL.
 *
 * @return Always returns 0.
 */
extern int apol_netifcon_query_set_msg_context(apol_policy_t *p,
					       apol_netifcon_query_t *n,
					       apol_context_t *context,
					       unsigned int range_match);

#endif
