/**
 * @file component-query.h
 *
 * Routines to query individual components of a policy.  For each 
 * component there is a query structure to specify the details of the query. 
 * The reason for all of the modifier functions on the query structures 
 * is to ease the creation of swig wrappers to libapol.
 *
 * @author Jason Tang  jtang@tresys.com
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
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

struct apol_mls_level {
        char *sens;
        char **cats;
        size_t num_cats;
};
typedef struct apol_mls_level apol_mls_level_t;

struct apol_mls_range {
        apol_mls_level_t *low, *high;
};
typedef struct apol_mls_range apol_mls_range_t;

#define APOL_MLS_RANGE_SUB   0x08 /* query range is subset of rule range */
#define APOL_MLS_RANGE_SUPER 0x10 /* query range is superset of rule range */
#define APOL_MLS_RANGE_EXACT (AP_MLS_RANGE_SUB|AP_MLS_RANGE_SUPER)

/** Every query allows the treatment of strings as regular expressions
 *  instead.  Within the query structure are flags; if the first bit
 *  is set then use regex matching instead. */
#define APOL_QUERY_REGEX 0x01

struct apol_type_query {
        char *type_name;
        unsigned int flags;
};

struct apol_attr_query {
        char *attr_name;
        unsigned int flags;
};

struct apol_class_query {
        char *class_name;
        unsigned int flags;
};

struct apol_common_query {
        char *common_name;
        unsigned int flags;
};

struct apol_perm_query {
        char *perm_name;
        unsigned int flags;
};

struct apol_role_query {
        char *role_name;
        char *type_name;
        unsigned int flags;
};

struct apol_user_query {
        char *user_name;
        char *role_name;
        apol_mls_level_t *default_level;
        apol_mls_range_t *range;
        unsigned int flags;
};

struct apol_bool_query {
        char *bool_name;
        unsigned int flags;
};

struct apol_sens_query {
        char *sens_name;
        unsigned int flags;
};

struct apol_cats_query {
        char *cats_name;
        unsigned int flags;
};

typedef struct apol_type_query apol_type_query_t;
typedef struct apol_attr_query apol_type_query_t;
typedef struct apol_class_query apol_class_query_t;
typedef struct apol_common_query apol_common_query_t;
typedef struct apol_perm_query apol_perm_query_t;
typedef struct apol_role_query apol_role_query_t;
typedef struct apol_user_query apol_user_query_t;
typedef struct apol_bool_query apol_bool_query_t;
typedef struct apol_sens_query apol_sens_query_t;
typedef struct apol_cats_query apol_cats_query_t;


/******************** type queries ********************/

/**
 * Execute a query against all types within the policy.  The results
 * will only contain types, not aliases nor attributes.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up types.
 * @param t Structure containing parameters for query.  If this is
 * NULL then return all types.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_type_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                  apol_type_query_t *t,
                                  sepol_type_datum_t ***results,
                                  size_t *num_results);

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
 * Set a type query to return only types that match this name.  The
 * name may be either a type or one of its aliases.  This function
 * duplicates the incoming name.
 *
 * @param t Type query to set.
 * @param name Limit query to only types or aliases with this name, or
 * NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_type_query_set_type(apol_type_query_t *t, char *name);

/**
 * Set a type query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param t Type query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_type_query_set_regex(apol_type_query_t *t, int is_regex);


/******************** attribute queries ********************/

/**
 * Execute a query against all attributes within the policy.  The
 * results will only contain attributes, not types nor aliases.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up types.
 * @param a Structure containing parameters for query.  If this is
 * NULL then return all attributes.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This
 * will be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_attr_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                    apol_attr_query_t *t,
                                    sepol_type_datum_t ***results,
                                    size_t *num_results);

/**
 * Allocate and return a new attribute query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all attributes within the policy.  The caller must call
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
 * @param a Attribute query to set.
 * @param name Limit query to only attributes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_attr_query_set_type(apol_attr_query_t *a, char *name);

/**
 * Set an attribute query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param a Attribute query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_attr_query_set_regex(apol_attr_query_t *a, int is_regex);


/******************** class queries ********************/

/**
 * Execute a query against all classes within the policy.  The results
 * will only contain object classes, not common classes.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up classes.
 * @param c Structure containing parameters for query.  If this is
 * NULL then return all object classes.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_class_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                   apol_class_query_t *c,
                                   sepol_class_datum_t ***results,
                                   size_t *num_results);

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
 * @param c Class query to set.
 * @param name Limit query to only classes with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_class_query_set_class(apol_class_query_t *c, char *name);

/**
 * Set a class query to use regular expression searching for all of
 * its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_class_query_set_regex(apol_class_query_t *c, int is_regex);


/******************** common class queries ********************/

/**
 * Execute a query against all common classes within the policy.  The
 * results will only contain common classes, not object classes.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up classes.
 * @param c Structure containing parameters for query.  If this is
 * NULL then return all common classes.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_common_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                    apol_common_query_t *c,
                                    sepol_common_datum_t ***results,
                                    size_t *num_results);

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
 * @param c Common query to set.
 * @param name Limit query to only commons with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_common_query_set_common(apol_common_query_t *c, char *name);

/**
 * Set a common query to use regular expression searching for all of
 * its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param c Class query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_common_query_set_regex(apol_common_query_t *c, int is_regex);


/******************** permission queries ********************/

/**
 * Execute a query against all permissions within the policy.  The
 * results will contain char pointers to permission names.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up classes.
 * @param pq Structure containing parameters for query.  If this is
 * NULL then return all permission.
 * @param results Reference to a list of results for permissions.  The
 * list will be allocated by this function.  The caller must free this
 * list afterwards, but <b>must not</b> free the elements within it.
 * This will be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_common_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                    apol_perm_query_t *pq,
                                    char ***results,
                                    size_t *num_results);

/**
 * Allocate and return a new permission query structure.  All fields
 * are initialized, such that running this blank query results in
 * returning all permissions within the policy.  The caller must call
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
 * @param pq Permission query to set.
 * @param name Limit query to only permissions with this name, or NULL
 * to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_perm_query_set_perm(apol_perm_query_t *pq, char *name);

/**
 * Set a permission query to use regular expression searching for all
 * of its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param pq Permission query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_perm_query_set_regex(apol_perm_query_t *pq, int is_regex);


/******************** role queries ********************/

/**
 * Execute a query against all roles within the policy.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up roles.
 * @param r Structure containing parameters for query.  If this is
 * NULL then return all roles.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_role_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                  apol_role_query_t *r,
                                  sepol_role_datum_t ***results,
                                  size_t *num_results);

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
 * Set a role query to return only roles that match this name.  This
 * function duplicates the incoming name.
 *
 * @param r Role query to set.
 * @param name Limit query to only roles with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_query_set_role(apol_role_query_t *r, char *name);

/**
 * Set a role query to return only roles containing this type.  This
 * function duplicates the incoming name.
 *
 * @param r Role query to set.
 * @param name Limit query to only roles with this type, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_role_query_set_type(apol_role_query_t *r, char *name);

/**
 * Set a role query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param r Role query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_role_query_set_regex(apol_role_query_t *r, int is_regex);


/******************** user queries ********************/

/**
 * Execute a query against all users within the policy.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up users.
 * @param u Structure containing parameters for query.  If this is
 * NULL then return all users.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_user_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                  apol_user_query_t *u,
                                  sepol_user_datum_t ***results,
                                  size_t *num_results);

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
 * Set a user query to return only users that match this name.  This
 * function duplicates the incoming name.
 *
 * @param u User query to set.
 * @param name Limit query to only users this name, or NULL to unset
 * this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_user(apol_user_query_t *u, char *name);

/**
 * Set a user query to return only users containing this role.  This
 * function duplicates the incoming name.
 *
 * @param u User query to set.
 * @param role Limit query to only users with this role, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_role(apol_user_query_t *u, char *role);

/**
 * Set a user query to return only users containing this default
 * level.  This function takes ownership of the level, such that the
 * caller must not modify nor destroy it afterwards.
 *
 * @param u User query to which set.
 * @param level Limit query to only users with this level as their
 * default, or NULL to unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_default_level(apol_user_query_t *u,
                                             apol_mls_level_t *level);

/**
 * Set a user query to return only users matching a MLS range.  This
 * function takes ownership of the range, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param u User query to set.
 * @param range Limit query to only users matching this range, or NULL
 * to unset this field.
 * @param range_match Specifies how to match a user to a range.  This
 * must be one of APOL_MLS_RANGE_SUB, APOL_MLS_RANGE_SUPER, or
 * APOL_MLS_RANGE_EXACT.  This is ignored if range is NULL.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_user_query_set_range(apol_user_query_t *u,
                                     apol_mls_range_t *range,
                                     unsigned int range_match);

/**
 * Set a user query to use regular expression searching for all of its
 * fields.  Strings will be treated as regexes instead of literals.
 *
 * @param u User query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_user_query_set_regex(apol_user_query_t *u, int is_regex);


/******************** booleans queries ********************/

/**
 * Execute a query against all booleans within the policy.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up roles.
 * @param b Structure containing parameters for query.  If this is
 * NULL then return all booleans.
 * @param results Reference to a list of results.  The list will be
 * allocated by this function.  The caller must free this list
 * afterwards, but <b>must not</b> free the elements within it.  This will
 * be set to NULL upon no results or upon error.
 * @param num_results Reference to number of results, or 0 upon no
 * results or error.
 *
 * @return 0 on success (including none found), negative on error.
 */
extern int apol_get_bool_by_query(sepol_handle_t *h, sepol_policydb_t *p,
                                  apol_bool_query_t *b,
                                  sepol_bool_datum_t ***results,
                                  size_t *num_results);

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
 * @param b Boolean query to set.
 * @param name Limit query to only booleans with this name, or NULL to
 * unset this field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_bool_query_set_role(apol_bool_query_t *b, char *name);

/**
 * Set a boolean query to use regular expression searching for all of
 * its fields.  Strings will be treated as regexes instead of
 * literals.
 *
 * @param b Boolean query to set.
 * @param is_regex Non-zero to enable regex searching, 0 to disable.
 *
 * @return Always 0.
 */
extern int apol_bool_query_set_regex(apol_bool_query_t *b, int is_regex);

/******************** MLS queries ********************/


/**
 * Allocate and return a new MLS level structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_level_destroy() upon the return value afterwards, assuming
 * that the caller maintains ownership.
 *
 * @return An initialized MLS level structure, or NULL upon error.
 */
extern apol_mls_level_t *apol_mls_level_create(void);

/**
 * Take a MLS level string (e.g., <t>S0:C0.C127</t>) and parse it.
 * Fill in a newly allocated apol_mls_level_t and return it.  This
 * function needs a policy to resolve dots within categories.  If the
 * string represents an illegal level then return NULL.  The caller
 * must call apol_mls_level_destroy() upon the return value
 * afterwards, assuming that the caller maintains ownership.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to validate mls_level_string.
 * @param mls_level_string Pointer to a string representing a valid
 * MLS level.  Caller is responsible for memory management of this
 * string.
 *
 * @return A filled in MLS level structure, or NULL upon error.
 */
extern apol_mls_level_t *apol_mls_level_create_from_string(sepol_handle_t *h, sepol_policydb_t *p, char *mls_level_string);

/**
 * Deallocate all memory associated with a MLS level structure and
 * then set it to NULL.  This function does nothing if the level is
 * already NULL.
 *
 * @param level Reference to a MLS level structure to destroy.
 */
extern void apol_mls_level_destroy(apol_mls_level_t **level);

/**
 * Set the sensitivity component of an MLS level structure.  This
 * function duplicates the incoming string.
 *
 * @param level MLS level to modify.
 * @param sens New sensitivity component to set.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_mls_level_set_sens(apol_mls_level_t *level, char *sens);

/**
 * Add a category component of an MLS level structure.  This function
 * duplicates the incoming string.
 *
 * @param level MLS level to modify.
 * @param cats New category component to append.
 */
extern int apol_mls_level_append_cats(apol_mls_level_t *level, char *cats);

/**
 * Allocate and return a new MLS range structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_range_destroy() upon the return value afterwards, assuming
 * that the caller maintains ownership.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
extern apol_mls_range_t *apol_mls_range_create(void);

/**
 * Deallocate all memory associated with a MLS range structure and
 * then set it to NULL.  This function does nothing if the range is
 * already NULL.
 *
 * @param level Reference to a MLS level structure to destroy.
 */
extern void apol_mls_range_set_destroy(apol_mls_range_t **range);

/**
 * Set the low level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param range MLS range to modify.
 * @param level New low level for range.
 *
 * @return Always 0.
 */
extern int apol_mls_range_set_low(apol_mls_range_t *range, apol_mls_level_t *level);

/**
 * Set the high level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param range MLS range to modify.
 * @param level New high level for range.
 *
 * @return Always 0.
 */
extern int apol_mls_range_set_high(apol_mls_range_t *range, apol_mls_level_t *level);

#endif
