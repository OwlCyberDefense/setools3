/**
 * @file
 *
 * Provides a way for setools to make queries about policy capabilities 
 * within a policy.  The caller obtains a query object,
 * fills in its parameters, and then runs the query; it obtains a
 * vector of results.  Searches are conjunctive -- all fields of the
 * search query must match for a datum to be added to the results
 * query.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include "policy-query-internal.h"

#include <errno.h>

struct apol_default_object_query
{
	char *name;
};

int apol_default_object_get_by_query(const apol_policy_t * p, apol_default_object_query_t * q, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;

	*v = NULL;
	if (qpol_policy_get_default_object_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_default_object_t *default_object;
		if (qpol_iterator_get_item(iter, (void **)&default_object) < 0) {
			goto cleanup;
		}
		if (q != NULL) {
			if (apol_vector_append(*v, (void *)default_object)) {
				ERR(p, "%s", strerror(ENOMEM));
				goto cleanup;
			}
		}
	}

	retval = 0;
cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_default_object_query_t *apol_default_object_query_create(void)
{
	return calloc(1, sizeof(apol_default_object_query_t));
}

void apol_default_object_query_destroy(apol_default_object_query_t ** q)
{
	if (*q != NULL) {
		free((*q)->name);
		free(*q);
		*q = NULL;
	}
}

