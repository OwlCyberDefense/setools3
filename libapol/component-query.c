/**
 * @file component-query.c
 *
 * Provides a way for setools to make queries about different
 * components of a policy.  The caller obtains a query object, fills
 * in its parameters, and then runs the query; it obtains a vector of
 * results.  Searches are conjunctive -- all fields of the search
 * query must match for a datum to be added to the results query.
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

#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sepol/policydb-query.h>

#include "component-query.h"
#include "mls-query.h"

struct apol_type_query {
	char *type_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_attr_query {
	char *attr_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_class_query {
	char *class_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_common_query {
	char *common_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_perm_query {
	char *perm_name;
	unsigned int flags;
	regex_t *regex;
};

struct apol_role_query {
	char *role_name, *type_name;
	unsigned int flags;
	regex_t *role_regex, *type_regex;
};

struct apol_user_query {
	char *user_name, *role_name;
	apol_mls_level_t *default_level;
	apol_mls_range_t *range;
	unsigned int flags;
	regex_t *user_regex, *role_regex;
};

struct apol_bool_query {
	char *bool_name;
	unsigned int flags;
	regex_t *regex;
};

/** Every query allows the treatment of strings as regular expressions
 *  instead.  Within the query structure are flags; if the first bit
 *  is set then use regex matching instead. */
#define APOL_QUERY_REGEX 0x01

#define APOL_QUERY_SUB	 0x02	  /* query is subset of rule range */
#define APOL_QUERY_SUPER 0x04	  /* query is superset of rule range */
#define APOL_QUERY_EXACT (AP_MLS_RANGE_SUB|AP_MLS_RANGE_SUPER)
#define APOL_QUERY_INTERSECT 0x08 /* query overlaps any part of rule range */

/******************** misc helpers ********************/

/**
 * Equivalent to the non-ANSI strdup() function.
 * @param s String to duplicate.
 * @return Pointer to newly allocated string, or NULL on error.
 */
static char *apol_strdup(const char *s)
{
	char *t;
	if ((t = malloc(strlen(s) + 1)) == NULL) {
		return NULL;
	}
	return strcpy(t, s);
}

/**
 * Determines if a name matches a target symbol name.  If flags has
 * the APOL_QUERY_REGEX bit set, then (1) compile the regular
 * expression if NULL, and (2) apply it to target.  Otherwise do a
 * string comparison between name and target.  If name is NULL and/or
 * empty then the comparison always succeeds regardless of flags and
 * regex.
 *
 * @param target Name of target symbol to compare.
 * @param name Source target from which to compare.
 * @param flags If APOL_QUERY_REGEX bit is set, treat name as a
 * regular expression.
 * @param regex If using regexp comparison, the compiled regular
 * expression to use; the pointer will be allocated space if regexp is
 * legal.  If NULL, then compile the regexp pattern given by name and
 * cache it here.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
static int apol_compare(const char *target, const char *name, unsigned int flags, regex_t **regex)
{
	if (name == NULL || *name == '\0') {
		return 1;
	}
	if (flags & APOL_QUERY_REGEX) {
		if (*regex == NULL) {
			if ((*regex = malloc(sizeof(**regex))) == NULL ||
			    regcomp(*regex, name, REG_EXTENDED | REG_NOSUB)) {
				free(*regex);
				*regex = NULL;
				return -1;
			}
		}
		if (regexec(*regex, target, 0, NULL, 0) == 0) {
			return 1;
		}
		return 0;
	}
	else {
		if (strcmp(target, name) == 0) {
			return 1;
		}
		return 0;
	}
}

/**
 * Determines if a (partial) type query matches a sepol_type_datum_t,
 * either the type name or any of its aliases.
 *
 * @param h Error reporting handler.
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
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
static int apol_compare_type(sepol_handle_t *h, sepol_policydb_t *p,
			     sepol_type_datum_t *type, const char *name,
			     unsigned int flags, regex_t **type_regex)
{
	char *type_name;
	int compval;
	sepol_iterator_t *alias_iter = NULL;
	if (sepol_type_datum_get_name(h, p, type, &type_name) < 0) {
		return -1;
	}
	compval = apol_compare(type_name, name, flags, type_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the type's
	   aliases */
	if (sepol_type_datum_get_alias_iter(h, p, type, &alias_iter) < 0) {
		return -1;
	}
	for ( ; !sepol_iterator_end(alias_iter); sepol_iterator_next(alias_iter)) {
		char *alias_name;
		if (sepol_iterator_get_item(alias_iter, (void **) &alias_name) < 0) {
			sepol_iterator_destroy(&alias_iter);
			return -1;
		}
		compval = apol_compare(alias_name, name, flags, type_regex);
		if (compval != 0) {
			/* matched at least one of the aliases, or error */
			sepol_iterator_destroy(&alias_iter);
			return compval;
		}
	}
	sepol_iterator_destroy(&alias_iter);
	/* did not match any of the aliases */
	return 0;
}

/******************** types ********************/

int apol_get_type_by_query(sepol_handle_t *h, sepol_policydb_t *p,
			   apol_type_query_t *t,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_type_iter(h, p, &iter) < 0) {
		return -1;
	}
	*v = apol_vector_create();
	for( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_type_datum_t *type;
		unsigned char isattr, isalias;
		if (sepol_iterator_get_item(iter, (void **) &type) < 0) {
			goto cleanup;
		}
		if (sepol_type_datum_get_isattr(h, p, type, &isattr) < 0 ||
		    sepol_type_datum_get_isalias(h, p, type, &isalias) < 0) {
			goto cleanup;
		}
		if (isattr || isalias) {
			continue;
		}
		if (t != NULL) {
			int compval = apol_compare_type(h, p,
							type, t->type_name,
							t->flags, &(t->regex));
			if (compval == -1) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, type)) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_type_query_t *apol_type_query_create(void)
{
	return calloc(1, sizeof(apol_type_query_t));
}

void apol_type_query_destroy(apol_type_query_t **t)
{
	if (*t != NULL) {
		free((*t)->type_name);
		if ((*t)->regex != NULL) {
			regfree((*t)->regex);
			free((*t)->regex);
		}
		*t = NULL;
	}
}

int apol_type_query_set_type(apol_type_query_t *t, const char *name)
{
	free(t->type_name);
	t->type_name = NULL;
	if (name != NULL && (t->type_name = apol_strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_type_query_set_regex(apol_type_query_t *t, int is_regex)
{
	if (is_regex) {
		t->flags |= APOL_QUERY_REGEX;
	}
	else {
		t->flags &= ~APOL_QUERY_REGEX;
	}
	return 0;
}

/******************** attribute queries ********************/

int apol_get_attr_by_query(sepol_handle_t *h, sepol_policydb_t *p,
			   apol_attr_query_t *a,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_type_iter(h, p, &iter) < 0) {
		return -1;
	}
	*v = apol_vector_create();
	for( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_type_datum_t *type;
		unsigned char isattr, isalias;
		if (sepol_iterator_get_item(iter, (void **) &type) < 0) {
			goto cleanup;
		}
		if (sepol_type_datum_get_isattr(h, p, type, &isattr) < 0 ||
		    sepol_type_datum_get_isalias(h, p, type, &isalias) < 0) {
			goto cleanup;
		}
		if (!isattr || isalias) {
			continue;
		}
		if (a != NULL) {
			char *attr_name;
			if (sepol_type_datum_get_name(h, p, type, &attr_name) < 0) {
				return -1;
			}
			int compval = apol_compare(attr_name, a->attr_name,
						   a->flags, &(a->regex));
			if (compval == -1) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, type)) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_attr_query_t *apol_attr_query_create(void)
{
	return calloc(1, sizeof(apol_attr_query_t));
}

void apol_attr_query_destroy(apol_attr_query_t **a)
{
	if (*a != NULL) {
		free((*a)->attr_name);
		if ((*a)->regex != NULL) {
			regfree((*a)->regex);
			free((*a)->regex);
		}
		*a = NULL;
	}
}

int apol_attr_query_set_attr(apol_attr_query_t *a, const char *name)
{
	free(a->attr_name);
	a->attr_name = NULL;
	if (name != NULL && (a->attr_name = apol_strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_attr_query_set_regex(apol_attr_query_t *a, int is_regex)
{
	if (is_regex) {
		a->flags |= APOL_QUERY_REGEX;
	}
	else {
		a->flags &= ~APOL_QUERY_REGEX;
	}
	return 0;
}


/******************** role queries ********************/

int apol_get_role_by_query(sepol_handle_t *h, sepol_policydb_t *p,
			   apol_role_query_t *r,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *type_iter = NULL;
	int retval = -1, append_role;
	*v = NULL;
	if (sepol_policydb_get_role_iter(h, p, &iter) < 0) {
		return -1;
	}
	*v = apol_vector_create();
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_role_datum_t *role;
		if (sepol_iterator_get_item(iter, (void **) &role) < 0) {
			goto cleanup;
		}
		append_role = 1;
		if (r != NULL) {
			char *role_name;
			int compval;
			if (sepol_role_datum_get_name(h, p, role, &role_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(role_name, r->role_name,
					       r->flags, &(r->role_regex));
			if (compval == -1) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_role_datum_get_type_iter(h, p, role, &type_iter) < 0) {
				goto cleanup;
			}
			append_role = 0;
			for ( ; !sepol_iterator_end(type_iter); sepol_iterator_next(type_iter)) {
				sepol_type_datum_t *type;
				if (sepol_iterator_get_item(type_iter, (void **) &type) < 0) {
					goto cleanup;
				}
				compval = apol_compare_type(h, p,
							    type, r->type_name,
							    r->flags, &(r->type_regex));
				if (compval == -1) {
					goto cleanup;
				}
				else if (compval == 1) {
					append_role = 1;
					break;
				}
			}
			sepol_iterator_destroy(&type_iter);
		}
		if (append_role && apol_vector_append(*v, role)) {
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	sepol_iterator_destroy(&type_iter);
	return retval;
}

apol_role_query_t *apol_role_query_create(void)
{
	return calloc(1, sizeof(apol_role_query_t));
}

void apol_role_query_destroy(apol_role_query_t **r)
{
	if (*r != NULL) {
		free((*r)->role_name);
		free((*r)->type_name);
		if ((*r)->role_regex) {
			regfree((*r)->role_regex);
			free((*r)->role_regex);
		}
		if ((*r)->type_regex) {
			regfree((*r)->type_regex);
			free((*r)->type_regex);
		}
		*r = NULL;
	}
}

int apol_role_query_set_role(apol_role_query_t *r, const char *name)
{
	free(r->role_name);
	r->role_name = NULL;
	if (name != NULL && (r->role_name = apol_strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_role_query_set_type(apol_role_query_t *r, const char *name)
{
	free(r->type_name);
	r->type_name = NULL;
	if (name != NULL && (r->type_name = apol_strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_role_query_set_regex(apol_role_query_t *r, int is_regex)
{
	if (is_regex) {
		r->flags |= APOL_QUERY_REGEX;
	}
	else {
		r->flags &= ~APOL_QUERY_REGEX;
	}
	return 0;
}


/******************** user queries ********************/

int apol_get_user_by_query(sepol_handle_t *h, sepol_policydb_t *p,
			   apol_user_query_t *u,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *role_iter = NULL;
        apol_mls_level_t *default_level = NULL;
	int retval = -1, append_user;
	*v = NULL;
	if (sepol_policydb_get_user_iter(h, p, &iter) < 0) {
		return -1;
	}
	*v = apol_vector_create();
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_user_datum_t *user;
		if (sepol_iterator_get_item(iter, (void **) &user) < 0) {
			goto cleanup;
		}
		append_user = 1;
		if (u != NULL) {
			char *user_name;
			int compval;
                        sepol_mls_level_t *mls_default_level;
			if (sepol_user_datum_get_name(h, p, user, &user_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(user_name, u->user_name,
					       u->flags, &(u->user_regex));
			if (compval == -1) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_user_datum_get_role_iter(h, p, user, &role_iter) < 0) {
				goto cleanup;
			}
			append_user = 0;
			for ( ; !sepol_iterator_end(role_iter); sepol_iterator_next(role_iter)) {
				sepol_role_datum_t *role;
				char *role_name;
				if (sepol_iterator_get_item(role_iter, (void **) &role) < 0 ||
				    sepol_role_datum_get_name(h, p, role, &role_name) < 0) {
					goto cleanup;
				}
				compval = apol_compare(role_name, u->role_name,
						       u->flags, &(u->role_regex));
				if (compval == -1) {
					goto cleanup;
				}
				else if (compval == 1) {
					append_user = 1;
					break;
				}
			}
			sepol_iterator_destroy(&role_iter);
			if (!append_user) {
				continue;
			}
                        if (sepol_user_datum_get_dfltlevel(h, p, user, &mls_default_level) < 0 ||
                            (default_level = apol_mls_level_create_from_sepol_mls_level(h, p, mls_default_level)) == NULL) {
                                goto cleanup;
                        }
                        compval = apol_mls_compare_level(h, p, default_level,
                                                         u->default_level);
                        apol_mls_level_destroy(&default_level);
                        if (compval == 0) {
                                continue;
                        }
		}
		if (append_user && apol_vector_append(*v, user)) {
			goto cleanup;
		}
	}
	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	sepol_iterator_destroy(&role_iter);
        apol_mls_level_destroy(&default_level);
	return retval;
}

apol_user_query_t *apol_user_query_create(void)
{
	return calloc(1, sizeof(apol_user_query_t));
}

void apol_user_query_destroy(apol_user_query_t **u)
{
	if (*u != NULL) {
		free((*u)->user_name);
		free((*u)->role_name);
		apol_mls_level_destroy(&((*u)->default_level));
		apol_mls_range_destroy(&((*u)->range));
		if ((*u)->user_regex != NULL) {
			regfree((*u)->user_regex);
			free((*u)->user_regex);
		}
		if ((*u)->role_regex != NULL) {
			regfree((*u)->role_regex);
			free((*u)->role_regex);
		}
		*u = NULL;
	}
}

int apol_user_query_set_user(apol_user_query_t *u, const char *name)
{
	free(u->user_name);
	u->user_name = NULL;
	if (name != NULL && (u->user_name = apol_strdup(name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_user_query_set_role(apol_user_query_t *u, const char *role)
{
	free(u->role_name);
	u->role_name = NULL;
	if (role != NULL && (u->role_name = apol_strdup(role)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_user_query_set_default_level(apol_user_query_t *u,
				      apol_mls_level_t *level)
{
	u->default_level = level;
	return 0;
}

int apol_user_query_set_range(apol_user_query_t *u,
			      apol_mls_range_t *range,
			      unsigned int range_match)
{
	u->range = range;
	u->flags |= range_match;
	return 0;
}

int apol_user_query_set_regex(apol_user_query_t *u, int is_regex)
{
	if (is_regex) {
		u->flags |= APOL_QUERY_REGEX;
	}
	else {
		u->flags &= ~APOL_QUERY_REGEX;
	}
	return 0;
}
