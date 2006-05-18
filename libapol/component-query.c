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

#include <qpol/policy_query.h>

#include "component-query.h"

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

void apol_regex_destroy(regex_t **regex)
{
	if (*regex != NULL) {
		regfree(*regex);
		free(*regex);
		*regex = NULL;
	}
}

int apol_query_set(apol_policy_t *p, char **query_name, regex_t **regex, const char *name)
{
	if (regex != NULL) {
		apol_regex_destroy(regex);
	}
	free(*query_name);
	*query_name = NULL;
	if (name != NULL && ((*query_name) = apol_strdup(p, name)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_query_set_regex(apol_policy_t *p __attribute__ ((unused)),
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

int apol_compare(apol_policy_t *p, const char *target, const char *name,
		 unsigned int flags, regex_t **regex)
{
	if (name == NULL || *name == '\0') {
		return 1;
	}
	if ((flags & APOL_QUERY_REGEX) && regex != NULL) {
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

int apol_compare_iter(apol_policy_t *p, qpol_iterator_t *iter,
		      const char *name,
		      unsigned int flags, regex_t **regex)
{
	int compval;
	if (name == NULL || *name == '\0') {
		return 1;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *iter_name;
		if (qpol_iterator_get_item(iter, (void **) &iter_name) < 0) {
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

int apol_compare_type(apol_policy_t *p,
		      qpol_type_t *type, const char *name,
		      unsigned int flags, regex_t **type_regex)
{
	char *type_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_type_get_name(p->sh, p->p, type, &type_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, type_name, name, flags, type_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the type's
	   aliases */
	if (qpol_type_get_alias_iter(p->sh, p->p, type, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, type_regex);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_level(apol_policy_t *p,
		       qpol_level_t *level, const char *name,
		       unsigned int flags, regex_t **level_regex)
{
	char *level_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_level_get_name(p->sh, p->p, level, &level_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, level_name, name, flags, level_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the sensitivity's
	   aliases */
	if (qpol_level_get_alias_iter(p->sh, p->p, level, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, level_regex);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_cat(apol_policy_t *p,
		     qpol_cat_t *cat, const char *name,
		     unsigned int flags, regex_t **cat_regex)
{
	char *cat_name;
	int compval;
	qpol_iterator_t *alias_iter = NULL;
	if (qpol_cat_get_name(p->sh, p->p, cat, &cat_name) < 0) {
		return -1;
	}
	compval = apol_compare(p, cat_name, name, flags, cat_regex);
	if (compval != 0) {
		return compval;
	}
	/* also check if the matches against one of the category's
	   aliases */
	if (qpol_cat_get_alias_iter(p->sh, p->p, cat, &alias_iter) < 0) {
		return -1;
	}
	compval = apol_compare_iter(p, alias_iter, name, flags, cat_regex);
	qpol_iterator_destroy(&alias_iter);
	return compval;
}

int apol_compare_context(apol_policy_t *p, qpol_context_t *target,
			 apol_context_t *search, unsigned int flags)
{
	apol_context_t *apol_context;
	int retval;
	if (search == NULL) {
		return 1;
	}
	apol_context = apol_context_create_from_qpol_context(p, target);
	retval = apol_context_compare(p, apol_context, search, flags);
	apol_context_destroy(&apol_context);
	return retval;
}
