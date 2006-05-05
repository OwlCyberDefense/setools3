/**
 * @file bool-query.c
 *
 * Provides a way for setools to make queries about conditional
 * booleans within a policy.  The caller obtains a query object, fills
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

#include "component-query.h"

struct apol_bool_query {
	char *bool_name;
	unsigned int flags;
	regex_t *regex;
};

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
