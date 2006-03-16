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
	char *class_name, *common_name;
	unsigned int flags;
	regex_t *class_regex, *common_regex;
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

struct apol_level_query {
	char *sens_name, *cat_name;
	unsigned int flags;
	regex_t *sens_regex, *cat_regex;
};

struct apol_cat_query {
	char *cat_name;
	unsigned int flags;
	regex_t *regex;
};

/******************** misc helpers ********************/

/**
 * Equivalent to the non-ANSI strdup() function.
 * @param p Policy handler.
 * @param s String to duplicate.
 * @return Pointer to newly allocated string, or NULL on error.
 */
static char *apol_strdup(apol_policy_t *p, const char *s)
{
	char *t;
	if ((t = malloc(strlen(s) + 1)) == NULL) {
		ERR(p, "Out of memory!");
		return NULL;
	}
	return strcpy(t, s);
}

/**
 * Destroy a compiled regular expression, setting it to NULL
 * afterwards.	Does nothing if the reference is NULL.
 * @param regex Regular expression to destroy.
 */
static void apol_regex_destroy(regex_t **regex)
{
	if (*regex != NULL) {
		regfree(*regex);
		free(*regex);
		*regex = NULL;
	}
}

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
static int apol_query_set(apol_policy_t *p, char **query_name, regex_t **regex, const char *name)
{
	apol_regex_destroy(regex);
	free(*query_name);
	*query_name = NULL;
	if (name != NULL && ((*query_name) = apol_strdup(p, name)) == NULL) {
		return -1;
	}
	return 0;
}

/**
 * Call strcmp(), to be used by apol_vector_append_unique().
 */
static int apol_strcmp(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const char *s = (const char *) a;
	const char *t = (const char *) b;
	return strcmp(s, t);
}

/**
 * Sets the regular expression flag for a query structure.
 *
 * @param p Policy handler.
 * @param flags Reference to the regular expression flag.
 * @param is_regex If non-zero, set regex flag.	 Otherwise unset it.
 *
 * @return Always returns 0.
 */
static int apol_query_set_regex(apol_policy_t *p __attribute__ ((unused)),
				unsigned int *flags, const int is_regex)
{
	if (is_regex) {
		*flags |= APOL_QUERY_REGEX;
	}
	else {
		*flags &= ~APOL_QUERY_REGEX;
	}
	return 0;
}

/********************* comparison helpers *********************/

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
static int apol_compare(apol_policy_t *p, const char *target, const char *name, unsigned int flags, regex_t **regex)
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
				ERR(p, "Out of memory!");
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
static int apol_compare_iter(apol_policy_t *p, sepol_iterator_t *iter,
			     const char *name,
			     unsigned int flags, regex_t **regex)
{
	int compval;
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		char *iter_name;
		if (sepol_iterator_get_item(iter, (void **) &iter_name) < 0) {
			return -1;
		}
		compval = apol_compare(p, iter_name, name, flags, regex);
		if (compval != 0) {
			/* matched at least one name, or error */
			return compval;
		}
	}
	/* no matches */
	return 0;
}

/**
 * Determines if a (partial) type query matches a sepol_type_datum_t,
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
static int apol_compare_type(apol_policy_t *p,
			     sepol_type_datum_t *type, const char *name,
			     unsigned int flags, regex_t **type_regex)
{
	char *type_name;
	int compval;
	sepol_iterator_t *alias_iter = NULL;
	if (sepol_type_datum_get_name(p->sh, p->p, type, &type_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, type_name, name, flags, type_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the type's
	   aliases */
	if (sepol_type_datum_get_alias_iter(p->sh, p->p, type, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, type_regex);
	sepol_iterator_destroy(&alias_iter);
	return compval;
}

/**
 * Determines if a level query matches a sepol_level_datum_t, either
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
static int apol_compare_level(apol_policy_t *p,
			      sepol_level_datum_t *level, const char *name,
			      unsigned int flags, regex_t **level_regex)
{
	char *level_name;
	int compval;
	sepol_iterator_t *alias_iter = NULL;
	if (sepol_level_datum_get_name(p->sh, p->p, level, &level_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, level_name, name, flags, level_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the sensitivity's
	   aliases */
	if (sepol_level_datum_get_alias_iter(p->sh, p->p, level, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, level_regex);
	sepol_iterator_destroy(&alias_iter);
	return compval;
}

/**
 * Determines if a category query matches a sepol_cat_datum_t, either
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
static int apol_compare_cat(apol_policy_t *p,
			    sepol_cat_datum_t *cat, const char *name,
			    unsigned int flags, regex_t **cat_regex)
{
	char *cat_name;
	int compval;
	sepol_iterator_t *alias_iter = NULL;
	if (sepol_cat_datum_get_name(p->sh, p->p, cat, &cat_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, cat_name, name, flags, cat_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the category's
	   aliases */
	if (sepol_cat_datum_get_alias_iter(p->sh, p->p, cat, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, cat_regex);
	sepol_iterator_destroy(&alias_iter);
	return compval;
}

/******************** types ********************/

int apol_get_type_by_query(apol_policy_t *p,
			   apol_type_query_t *t,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_type_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_type_datum_t *type;
		unsigned char isattr, isalias;
		if (sepol_iterator_get_item(iter, (void **) &type) < 0) {
			goto cleanup;
		}
		if (sepol_type_datum_get_isattr(p->sh, p->p, type, &isattr) < 0 ||
		    sepol_type_datum_get_isalias(p->sh, p->p, type, &isalias) < 0) {
			goto cleanup;
		}
		if (isattr || isalias) {
			continue;
		}
		if (t != NULL) {
			int compval = apol_compare_type(p,
							type, t->type_name,
							t->flags, &(t->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, type)) {
			ERR(p, "Out of memory!");
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
		apol_regex_destroy(&(*t)->regex);
		free(*t);
		*t = NULL;
	}
}

int apol_type_query_set_type(apol_policy_t *p, apol_type_query_t *t, const char *name)
{
	return apol_query_set(p, &t->type_name, &t->regex, name);
}

int apol_type_query_set_regex(apol_policy_t *p, apol_type_query_t *t, int is_regex)
{
	return apol_query_set_regex(p, &t->flags, is_regex);
}

/******************** attribute queries ********************/

int apol_get_attr_by_query(apol_policy_t *p,
			   apol_attr_query_t *a,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_type_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_type_datum_t *type;
		unsigned char isattr, isalias;
		if (sepol_iterator_get_item(iter, (void **) &type) < 0) {
			goto cleanup;
		}
		if (sepol_type_datum_get_isattr(p->sh, p->p, type, &isattr) < 0 ||
		    sepol_type_datum_get_isalias(p->sh, p->p, type, &isalias) < 0) {
			goto cleanup;
		}
		if (!isattr || isalias) {
			continue;
		}
		if (a != NULL) {
			char *attr_name;
			int compval;
			if (sepol_type_datum_get_name(p->sh, p->p, type, &attr_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, attr_name, a->attr_name,
					       a->flags, &(a->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, type)) {
			ERR(p, "Out of memory!");
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
		apol_regex_destroy(&(*a)->regex);
		free(*a);
		*a = NULL;
	}
}

int apol_attr_query_set_attr(apol_policy_t *p, apol_attr_query_t *a, const char *name)
{
	return apol_query_set(p, &a->attr_name, &a->regex, name);
}

int apol_attr_query_set_regex(apol_policy_t *p, apol_attr_query_t *a, int is_regex)
{
	return apol_query_set_regex(p, &a->flags, is_regex);
}


/******************** class queries ********************/

int apol_get_class_by_query(apol_policy_t *p,
			    apol_class_query_t *c,
			    apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *perm_iter = NULL;
	int retval = -1, append_class;
	*v = NULL;
	if (sepol_policydb_get_class_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_class_datum_t *class_datum;
		if (sepol_iterator_get_item(iter, (void **) &class_datum) < 0) {
			goto cleanup;
		}
		append_class = 1;
		if (c != NULL) {
			char *class_name, *common_name = NULL;
			sepol_common_datum_t *common_datum;
			int compval;
			if (sepol_class_datum_get_name(p->sh, p->p, class_datum, &class_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, class_name, c->class_name,
					       c->flags, &(c->class_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_class_datum_get_common(p->sh, p->p,
							 class_datum, &common_datum) < 0) {
				goto cleanup;
			}
			if (common_datum == NULL) {
				if (c->common_name != NULL && c->common_name[0] != '\0') {
					continue;
				}
			}
			else {
				if (sepol_common_datum_get_name(p->sh, p->p,
								common_datum, &common_name) < 0) {
					goto cleanup;
				}
				compval = apol_compare(p, common_name, c->common_name,
						       c->flags, &(c->common_regex));
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 0) {
					continue;
				}
			}
		}
		if (append_class && apol_vector_append(*v, class_datum)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	sepol_iterator_destroy(&perm_iter);
	return retval;
}

apol_class_query_t *apol_class_query_create(void)
{
	return calloc(1, sizeof(apol_class_query_t));
}

void apol_class_query_destroy(apol_class_query_t **c)
{
	if (*c != NULL) {
		free((*c)->class_name);
		free((*c)->common_name);
		apol_regex_destroy(&(*c)->class_regex);
		apol_regex_destroy(&(*c)->common_regex);
		free(*c);
		*c = NULL;
	}
}

int apol_class_query_set_class(apol_policy_t *p, apol_class_query_t *c, const char *name)
{
	return apol_query_set(p, &c->class_name, &c->class_regex, name);
}

int apol_class_query_set_common(apol_policy_t *p, apol_class_query_t *c, const char *name)
{
	return apol_query_set(p, &c->common_name, &c->common_regex, name);
}

int apol_class_query_set_regex(apol_policy_t *p, apol_class_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}


/******************** common queries ********************/

int apol_get_common_by_query(apol_policy_t *p,
			     apol_common_query_t *c,
			     apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_common_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_common_datum_t *common_datum;
		if (sepol_iterator_get_item(iter, (void **) &common_datum) < 0) {
			goto cleanup;
		}
		if (c != NULL) {
			char *common_name = NULL;
			int compval;
			if (sepol_common_datum_get_name(p->sh, p->p, common_datum, &common_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, common_name, c->common_name,
					       c->flags, &(c->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, common_datum)) {
			ERR(p, "Out of memory!");
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

apol_common_query_t *apol_common_query_create(void)
{
	return calloc(1, sizeof(apol_common_query_t));
}

void apol_common_query_destroy(apol_common_query_t **c)
{
	if (*c != NULL) {
		free((*c)->common_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_common_query_set_common(apol_policy_t *p, apol_common_query_t *c, const char *name)
{
	return apol_query_set(p, &c->common_name, &c->regex, name);
}

int apol_common_query_set_regex(apol_policy_t *p, apol_common_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}


/******************** permission queries ********************/

int apol_get_perm_by_query(apol_policy_t *p,
			   apol_perm_query_t *pq,
			   apol_vector_t **v)
{
	sepol_iterator_t *class_iter = NULL, *common_iter = NULL, *perm_iter = NULL;
	int retval = -1, compval;
	char *perm_name;
	*v = NULL;
	if (sepol_policydb_get_class_iter(p->sh, p->p, &class_iter) < 0 ||
	    sepol_policydb_get_common_iter(p->sh, p->p, &common_iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(class_iter); sepol_iterator_next(class_iter)) {
		sepol_class_datum_t *class_datum;
		if (sepol_iterator_get_item(class_iter, (void **) &class_datum) < 0 ||
		    sepol_class_datum_get_perm_iter(p->sh, p->p, class_datum, &perm_iter) < 0) {
			goto cleanup;
		}
		for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
			if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
				goto cleanup;
			}
			if (pq == NULL) {
				compval = 1;
			}
			else {
				compval = apol_compare(p, perm_name, pq->perm_name,
						       pq->flags, &(pq->regex));
			}
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 1 &&
				 apol_vector_append_unique(*v, perm_name, apol_strcmp, NULL) < 0) {
				ERR(p, "Out of memory!");
				goto cleanup;
			}
		}
		sepol_iterator_destroy(&perm_iter);
	}

	for ( ; !sepol_iterator_end(common_iter); sepol_iterator_next(common_iter)) {
		sepol_common_datum_t *common_datum;
		if (sepol_iterator_get_item(common_iter, (void **) &common_datum) < 0 ||
		    sepol_common_datum_get_perm_iter(p->sh, p->p, common_datum, &perm_iter) < 0) {
			goto cleanup;
		}
		for ( ; !sepol_iterator_end(perm_iter); sepol_iterator_next(perm_iter)) {
			if (sepol_iterator_get_item(perm_iter, (void **) &perm_name) < 0) {
				goto cleanup;
			}
			if (pq == NULL) {
				compval = 1;
			}
			else {
				compval = apol_compare(p, perm_name, pq->perm_name,
						       pq->flags, &(pq->regex));
			}
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 1 &&
				 apol_vector_append_unique(*v, perm_name, apol_strcmp, NULL) < 0) {
				ERR(p, "Out of memory!");
				goto cleanup;
			}
		}
		sepol_iterator_destroy(&perm_iter);
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&class_iter);
	sepol_iterator_destroy(&common_iter);
	sepol_iterator_destroy(&perm_iter);
	return retval;
}

apol_perm_query_t *apol_perm_query_create(void)
{
	return calloc(1, sizeof(apol_perm_query_t));
}

void apol_perm_query_destroy(apol_perm_query_t **pq)
{
	if (*pq != NULL) {
		free((*pq)->perm_name);
		apol_regex_destroy(&(*pq)->regex);
		free(*pq);
		*pq = NULL;
	}
}

int apol_perm_query_set_perm(apol_policy_t *p, apol_perm_query_t *pq, const char *name)
{
	return apol_query_set(p, &pq->perm_name, &pq->regex, name);
}

int apol_perm_query_set_regex(apol_policy_t *p, apol_perm_query_t *pq, int is_regex)
{
	return apol_query_set_regex(p, &pq->flags, is_regex);
}


/******************** role queries ********************/

int apol_get_role_by_query(apol_policy_t *p,
			   apol_role_query_t *r,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *type_iter = NULL;
	int retval = -1, append_role;
	*v = NULL;
	if (sepol_policydb_get_role_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_role_datum_t *role;
		if (sepol_iterator_get_item(iter, (void **) &role) < 0) {
			goto cleanup;
		}
		append_role = 1;
		if (r != NULL) {
			char *role_name;
			int compval;
			if (sepol_role_datum_get_name(p->sh, p->p, role, &role_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, role_name, r->role_name,
					       r->flags, &(r->role_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_role_datum_get_type_iter(p->sh, p->p, role, &type_iter) < 0) {
				goto cleanup;
			}
			append_role = 0;
			for ( ; !sepol_iterator_end(type_iter); sepol_iterator_next(type_iter)) {
				sepol_type_datum_t *type;
				if (sepol_iterator_get_item(type_iter, (void **) &type) < 0) {
					goto cleanup;
				}
				compval = apol_compare_type(p,
							    type, r->type_name,
							    r->flags, &(r->type_regex));
				if (compval < 0) {
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
			ERR(p, "Out of memory!");
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
		apol_regex_destroy(&(*r)->role_regex);
		apol_regex_destroy(&(*r)->type_regex);
		free(*r);
		*r = NULL;
	}
}

int apol_role_query_set_role(apol_policy_t *p, apol_role_query_t *r, const char *name)
{
	return apol_query_set(p, &r->role_name, &r->role_regex, name);
}

int apol_role_query_set_type(apol_policy_t *p, apol_role_query_t *r, const char *name)
{
	return apol_query_set(p, &r->type_name, &r->type_regex, name);
}

int apol_role_query_set_regex(apol_policy_t *p, apol_role_query_t *r, int is_regex)
{
	return apol_query_set_regex(p, &r->flags, is_regex);
}


/******************** user queries ********************/

int apol_get_user_by_query(apol_policy_t *p,
			   apol_user_query_t *u,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *role_iter = NULL;
	apol_mls_level_t *default_level = NULL;
	apol_mls_range_t *range = NULL;
	int retval = -1, append_user;
	*v = NULL;
	if (sepol_policydb_get_user_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
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
			sepol_mls_range_t *mls_range;

			sepol_iterator_destroy(&role_iter);
			apol_mls_level_destroy(&default_level);
			apol_mls_range_destroy(&range);

			if (sepol_user_datum_get_name(p->sh, p->p, user, &user_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, user_name, u->user_name,
					       u->flags, &(u->user_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_user_datum_get_role_iter(p->sh, p->p, user, &role_iter) < 0) {
				goto cleanup;
			}
			append_user = 0;
			for ( ; !sepol_iterator_end(role_iter); sepol_iterator_next(role_iter)) {
				sepol_role_datum_t *role;
				char *role_name;
				if (sepol_iterator_get_item(role_iter, (void **) &role) < 0 ||
				    sepol_role_datum_get_name(p->sh, p->p, role, &role_name) < 0) {
					goto cleanup;
				}
				compval = apol_compare(p, role_name, u->role_name,
						       u->flags, &(u->role_regex));
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 1) {
					append_user = 1;
					break;
				}
			}
			if (!append_user) {
				continue;
			}
			if (apol_policy_is_mls(p)) {
				if (sepol_user_datum_get_dfltlevel(p->sh, p->p, user, &mls_default_level) < 0 ||
				    (default_level = apol_mls_level_create_from_sepol_mls_level(p, mls_default_level)) == NULL) {
					goto cleanup;
				}
				compval = apol_mls_level_compare(p, default_level,
								 u->default_level);
				apol_mls_level_destroy(&default_level);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval != APOL_MLS_EQ) {
					continue;
				}

				if (sepol_user_datum_get_range(p->sh, p->p, user, &mls_range) < 0 ||
				    (range = apol_mls_range_create_from_sepol_mls_range(p, mls_range)) == NULL) {
					goto cleanup;
				}
				compval = apol_mls_range_compare(p,
								 range, u->range,
								 u->flags);
				apol_mls_range_destroy(&range);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 0) {
					continue;
				}
			}
		}
		if (append_user && apol_vector_append(*v, user)) {
			ERR(p, "Out of memory!");
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
	apol_mls_range_destroy(&range);
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
		apol_regex_destroy(&(*u)->user_regex);
		apol_regex_destroy(&(*u)->role_regex);
		free(*u);
		*u = NULL;
	}
}

int apol_user_query_set_user(apol_policy_t *p, apol_user_query_t *u, const char *name)
{
	return apol_query_set(p, &u->user_name, &u->user_regex, name);
}

int apol_user_query_set_role(apol_policy_t *p, apol_user_query_t *u, const char *role)
{
	return apol_query_set(p, &u->role_name, &u->role_regex, role);
}

int apol_user_query_set_default_level(apol_policy_t *p __attribute__ ((unused)),
				      apol_user_query_t *u,
				      apol_mls_level_t *level)
{
	u->default_level = level;
	return 0;
}

int apol_user_query_set_range(apol_policy_t *p __attribute__ ((unused)),
			      apol_user_query_t *u,
			      apol_mls_range_t *range,
			      unsigned int range_match)
{
	u->range = range;
	u->flags |= range_match;
	return 0;
}

int apol_user_query_set_regex(apol_policy_t *p, apol_user_query_t *u, int is_regex)
{
	return apol_query_set_regex(p, &u->flags, is_regex);
}

/******************** booleans queries ********************/

int apol_get_bool_by_query(apol_policy_t *p,
			   apol_bool_query_t *b,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_bool_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_bool_datum_t *bool;
		if (sepol_iterator_get_item(iter, (void **) &bool) < 0) {
			goto cleanup;
		}
		if (b != NULL) {
			char *bool_name;
			int compval;
			if (sepol_bool_datum_get_name(p->sh, p->p, bool, &bool_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, bool_name, b->bool_name,
					       b->flags, &(b->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, bool)) {
			ERR(p, "Out of memory!");
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

apol_bool_query_t *apol_bool_query_create(void)
{
	return calloc(1, sizeof(apol_bool_query_t));
}

void apol_bool_query_destroy(apol_bool_query_t **b)
{
	if (*b != NULL) {
		free((*b)->bool_name);
		apol_regex_destroy(&(*b)->regex);
		free(*b);
		*b = NULL;
	}
}

int apol_bool_query_set_bool(apol_policy_t *p, apol_bool_query_t *b, const char *name)
{
	return apol_query_set(p, &b->bool_name, &b->regex, name);
}

int apol_bool_query_set_regex(apol_policy_t *p, apol_bool_query_t *b, int is_regex)
{
	return apol_query_set_regex(p, &b->flags, is_regex);
}

/******************** level queries ********************/

int apol_get_level_by_query(apol_policy_t *p,
			    apol_level_query_t *l,
			    apol_vector_t **v)
{
	sepol_iterator_t *iter, *cat_iter = NULL;
	int retval = -1, append_level;
	*v = NULL;
	if (sepol_policydb_get_level_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create ()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_level_datum_t *level;
		unsigned char isalias;
		if (sepol_iterator_get_item(iter, (void **) &level) < 0 ||
		    sepol_level_datum_get_isalias(p->sh, p->p, level, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		append_level = 1;
		if (l != NULL) {
			int compval = apol_compare_level(p,
							 level, l->sens_name,
							 l->flags, &(l->sens_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_level_datum_get_cat_iter(p->sh, p->p, level, &cat_iter) < 0) {
				goto cleanup;
			}
			append_level = 0;
			for ( ; !sepol_iterator_end(cat_iter); sepol_iterator_next(cat_iter)) {
				sepol_cat_datum_t *cat;
				if (sepol_iterator_get_item(cat_iter, (void **) &cat) < 0) {
					goto cleanup;
				}
				compval = apol_compare_cat(p,
							   cat, l->cat_name,
							   l->flags, &(l->cat_regex));
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 1) {
					append_level = 1;
					break;
				}
			}
			sepol_iterator_destroy(&cat_iter);
		}
		if (append_level && apol_vector_append(*v, level)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	sepol_iterator_destroy(&cat_iter);
	return retval;
}

apol_level_query_t *apol_level_query_create(void)
{
	return calloc(1, sizeof(apol_level_query_t));
}

void apol_level_query_destroy(apol_level_query_t **l)
{
	if (*l != NULL) {
		free((*l)->sens_name);
		free((*l)->cat_name);
		apol_regex_destroy(&(*l)->sens_regex);
		apol_regex_destroy(&(*l)->cat_regex);
		free(*l);
		*l = NULL;
	}
}

int apol_level_query_set_sens(apol_policy_t *p, apol_level_query_t *l, const char *name)
{
	return apol_query_set(p, &l->sens_name, &l->sens_regex, name);
}

int apol_level_query_set_cat(apol_policy_t *p, apol_level_query_t *l, const char *name)
{
	return apol_query_set(p, &l->cat_name, &l->cat_regex, name);
}

int apol_level_query_set_regex(apol_policy_t *p, apol_level_query_t *l, int is_regex)
{
	return apol_query_set_regex(p, &l->flags, is_regex);
}

/******************** category queries ********************/

int apol_get_cat_by_query(apol_policy_t *p,
			  apol_cat_query_t *c,
			  apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_cat_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create ()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_cat_datum_t *cat;
		unsigned char isalias;
		if (sepol_iterator_get_item(iter, (void **) &cat) < 0 ||
		    sepol_cat_datum_get_isalias(p->sh, p->p, cat, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		if (c != NULL) {
			int compval = apol_compare_cat(p,
						       cat, c->cat_name,
						       c->flags, &(c->regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cat)) {
			ERR(p, "Out of memory!");
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

apol_cat_query_t *apol_cat_query_create(void)
{
	return calloc(1, sizeof(apol_cat_query_t));
}

void apol_cat_query_destroy(apol_cat_query_t **c)
{
	if (*c != NULL) {
		free((*c)->cat_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cat_query_set_cat(apol_policy_t *p, apol_cat_query_t *c, const char *name)
{
	return apol_query_set(p, &c->cat_name, &c->regex, name);
}

int apol_cat_query_set_regex(apol_policy_t *p, apol_cat_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}
