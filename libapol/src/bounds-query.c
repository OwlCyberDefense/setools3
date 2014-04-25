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

			/************ TYPEBOUNDS *************/
struct apol_typebounds_query
{
	char *name;
	unsigned int flags;
	regex_t *regex;
};

int apol_typebounds_get_by_query(const apol_policy_t * p, apol_typebounds_query_t * q, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;

	*v = NULL;
	if (qpol_policy_get_typebounds_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_typebounds_t *typebounds;
		if (qpol_iterator_get_item(iter, (void **)&typebounds) < 0) {
			goto cleanup;
		}
		if (q != NULL) {
			if (apol_compare_typebounds(p, typebounds, q->name,
						q->flags, &(q->regex)) == 1) {
				if (apol_vector_append(*v, (void *)typebounds)) {
					ERR(p, "%s", strerror(ENOMEM));
					goto cleanup;
				}
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

apol_typebounds_query_t *apol_typebounds_query_create(void)
{
	return calloc(1, sizeof(apol_typebounds_query_t));
}

void apol_typebounds_query_destroy(apol_typebounds_query_t ** q)
{
	if (*q != NULL) {
		free((*q)->name);
		apol_regex_destroy(&(*q)->regex);
		free(*q);
		*q = NULL;
	}
}

int apol_typebounds_query_set_name(const apol_policy_t * p, apol_typebounds_query_t * q, const char *name)
{
	return apol_query_set(p, &q->name, &q->regex, name);
}

int apol_typebounds_query_set_regex(const apol_policy_t * p, apol_typebounds_query_t * q, int is_regex)
{
	return apol_query_set_regex(p, &q->flags, is_regex);
}


			/************ ROLEBOUNDS *************/
struct apol_rolebounds_query
{
	char *name;
};

int apol_rolebounds_get_by_query(const apol_policy_t * p, apol_rolebounds_query_t * q, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;

	*v = NULL;
	if (qpol_policy_get_rolebounds_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_rolebounds_t *rolebounds;
		if (qpol_iterator_get_item(iter, (void **)&rolebounds) < 0) {
			goto cleanup;
		}
		if (q != NULL) {
			if (apol_vector_append(*v, (void *)rolebounds)) {
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

apol_rolebounds_query_t *apol_rolebounds_query_create(void)
{
	return calloc(1, sizeof(apol_rolebounds_query_t));
}

void apol_rolebounds_query_destroy(apol_rolebounds_query_t ** q)
{
	if (*q != NULL) {
		free((*q)->name);
		free(*q);
		*q = NULL;
	}
}


			/************ USERBOUNDS *************/
struct apol_userbounds_query
{
	char *name;
};

int apol_userbounds_get_by_query(const apol_policy_t * p, apol_userbounds_query_t * q, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;

	*v = NULL;
	if (qpol_policy_get_userbounds_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		const qpol_userbounds_t *userbounds;
		if (qpol_iterator_get_item(iter, (void **)&userbounds) < 0) {
			goto cleanup;
		}
		if (q != NULL) {
			if (apol_vector_append(*v, (void *)userbounds)) {
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

apol_userbounds_query_t *apol_userbounds_query_create(void)
{
	return calloc(1, sizeof(apol_userbounds_query_t));
}

void apol_userbounds_query_destroy(apol_userbounds_query_t ** q)
{
	if (*q != NULL) {
		free((*q)->name);
		free(*q);
		*q = NULL;
	}
}

