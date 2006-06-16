/**
 * @file condrule-query.c
 *
 * Provides a way for setools to make queries about conditional
 * expressions rules within a policy.  The caller obtains a query
 * object, fills in its parameters, and then runs the query; it
 * obtains a vector of results.  Searches are conjunctive -- all
 * fields of the search query must match for a datum to be added to
 * the results query.
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

#include "policy-query.h"
#include <errno.h>

struct apol_cond_query {
	char *bool_name;
	unsigned int flags;
	regex_t *regex;
};

int apol_get_cond_by_query(apol_policy_t *p,
			   apol_cond_query_t *c,
			   apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	int retval = -1;
	*v = NULL;

	if (qpol_policy_get_cond_iter(p->qh, p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cond_t *cond;
		if (qpol_iterator_get_item(iter, (void **) &cond) < 0) {
			goto cleanup;
		}
		if (c != NULL) {
			int keep_cond = apol_compare_cond_expr(p, cond, c->bool_name, c->flags, &c->regex);
			if (keep_cond < 0) {
				goto cleanup;
			}
			else if (keep_cond == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cond)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_cond_query_t *apol_cond_query_create(void)
{
	return calloc(1, sizeof(apol_cond_query_t));
}

void apol_cond_query_destroy(apol_cond_query_t **c)
{
	if (*c != NULL) {
		free((*c)->bool_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cond_query_set_bool(apol_policy_t *p,
			     apol_cond_query_t *c, const char *name)
{
	return apol_query_set(p, &c->bool_name, &c->regex, name);
}

int apol_cond_query_set_regex(apol_policy_t *p, apol_cond_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}

char *apol_cond_expr_render(apol_policy_t *p, qpol_iterator_t *iter)
{
	return NULL;
}
