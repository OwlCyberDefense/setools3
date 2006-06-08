/**
 * @file rbacrule-query.c
 *
 * Provides a way for setools to make queries about type enforcement
 * rules within a policy.  The caller obtains a query object, fills in
 * its parameters, and then runs the query; it obtains a vector of
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

#include "policy-query.h"

struct apol_role_allow_query {
	char *source, *target;
	unsigned int flags;
};

struct apol_role_trans_query {
	char *source, *target, *default_role;
	unsigned int flags;
};

/******************** (role) allow queries ********************/

int apol_get_role_allow_by_query(apol_policy_t *p,
                                 apol_role_allow_query_t *r,
                                 apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	char *target = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	if (r != NULL) {
		if ((source_as_any = r->flags & APOL_QUERY_SOURCE_AS_ANY)) {
			target = r->source;
		}
		else {
			target = r->target;
		}
	}
	if (qpol_policy_get_role_allow_iter(p->qh, p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_role_allow_t *rule;
		int match_source = 0, match_target = 0;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}

		if (r == NULL) {
			match_source = 1;
		}
		else {
			qpol_role_t *source_role;
			char *source_name;
			if (qpol_role_allow_get_source_role(p->qh, p->p, rule, &source_role) < 0 ||
			    qpol_role_get_name(p->qh, p->p, source_role, &source_name) < 0) {
				goto cleanup;
			}
			match_source = apol_compare(p, source_name, r->source, 0, NULL);
			if (match_source < 0) {
				goto cleanup;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target has been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (r == NULL || (source_as_any && match_source)) {
			match_target = 1;
		}
		else {
			qpol_role_t *target_role;
			char *target_name;
			if (qpol_role_allow_get_target_role(p->qh, p->p, rule, &target_role) < 0 ||
			    qpol_role_get_name(p->qh, p->p, target_role, &target_name) < 0) {
				goto cleanup;
			}
			match_target = apol_compare(p, target_name, target, 0, NULL);
			if (match_target < 0) {
				goto cleanup;
			}
		}
		if (!match_target) {
			continue;
		}

		if (apol_vector_append(*v, rule)) {
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

apol_role_allow_query_t *apol_role_allow_query_create(void)
{
	return calloc(1, sizeof(apol_role_allow_query_t));
}

void apol_role_allow_query_destroy(apol_role_allow_query_t **r)
{
	if (*r != NULL) {
		free((*r)->source);
		free((*r)->target);
		free(*r);
		*r = NULL;
	}
}

int apol_role_allow_query_set_source(apol_policy_t *p,
				     apol_role_allow_query_t *r,
				     const char *role)
{
	return apol_query_set(p, &r->source, NULL, role);
}

int apol_role_allow_query_set_target(apol_policy_t *p,
				     apol_role_allow_query_t *r,
				     const char *role)
{
	return apol_query_set(p, &r->target, NULL, role);
}

int apol_role_allow_query_set_source_any(apol_policy_t *p,
					 apol_role_allow_query_t *r,
					 int is_any)
{
	return apol_query_set_flag(p, &r->flags, is_any,
				   APOL_QUERY_SOURCE_AS_ANY);
}

/******************** role_transition queries ********************/

int apol_get_role_trans_by_query(apol_policy_t *p,
                                 apol_role_trans_query_t *r,
                                 apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	char *q_default_role = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	if (r != NULL) {
		if ((source_as_any = r->flags & APOL_QUERY_SOURCE_AS_ANY)) {
			q_default_role = r->source;
		}
		else {
			q_default_role = r->default_role;
		}
	}
	if (qpol_policy_get_role_trans_iter(p->qh, p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_role_trans_t *rule;
		int match_source = 0, match_target = 0, match_default = 0;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}

		if (r == NULL) {
			match_source = 1;
		}
		else {
			qpol_role_t *source_role;
			char *source_name;
			if (qpol_role_trans_get_source_role(p->qh, p->p, rule, &source_role) < 0 ||
			    qpol_role_get_name(p->qh, p->p, source_role, &source_name) < 0) {
				goto cleanup;
			}
			match_source = apol_compare(p, source_name, r->source, 0, NULL);
			if (match_source < 0) {
				goto cleanup;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target and default have been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (r == NULL) {
			match_target = 1;
		}
		else {
			qpol_type_t *target_type;
			char *target_name;
			if (qpol_role_trans_get_target_type(p->qh, p->p, rule, &target_type) < 0 ||
			    qpol_type_get_name(p->qh, p->p, target_type, &target_name) < 0) {
				goto cleanup;
			}
			match_target = apol_compare(p, target_name, r->target, 0, NULL);
			if (match_target < 0) {
				goto cleanup;
			}
		}
		if (!match_target) {
			continue;
		}

		if (r == NULL || (source_as_any && match_source)) {
			match_default = 1;
		}
		else {
			qpol_role_t *default_role;
			char *default_name;
			if (qpol_role_trans_get_default_role(p->qh, p->p, rule, &default_role) < 0 ||
			    qpol_role_get_name(p->qh, p->p, default_role, &default_name) < 0) {
				goto cleanup;
			}
			match_default = apol_compare(p, default_name, q_default_role, 0, NULL);
			if (match_default < 0) {
				goto cleanup;
			}
		}
		if (!match_default) {
			continue;
		}

		if (apol_vector_append(*v, rule)) {
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

apol_role_trans_query_t *apol_role_trans_query_create(void)
{
	return calloc(1, sizeof(apol_role_trans_query_t));
}

void apol_role_trans_query_destroy(apol_role_trans_query_t **r)
{
	if (*r != NULL) {
		free((*r)->source);
		free((*r)->target);
		free((*r)->default_role);
		free(*r);
		*r = NULL;
	}
}

int apol_role_trans_query_set_source(apol_policy_t *p,
				     apol_role_trans_query_t *r,
				     const char *role)
{
	return apol_query_set(p, &r->source, NULL, role);
}

int apol_role_trans_query_set_target(apol_policy_t *p,
				     apol_role_trans_query_t *r,
				     const char *type)
{
	return apol_query_set(p, &r->target, NULL, type);
}

int apol_role_trans_query_set_default(apol_policy_t *p,
				      apol_role_trans_query_t *r,
				      const char *role)
{
	return apol_query_set(p, &r->default_role, NULL, role);
}

int apol_role_trans_query_set_source_any(apol_policy_t *p,
					 apol_role_trans_query_t *r,
					 int is_any)
{
	return apol_query_set_flag(p, &r->flags, is_any,
				   APOL_QUERY_SOURCE_AS_ANY);
}
