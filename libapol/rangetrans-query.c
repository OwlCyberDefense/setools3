/**
 * @file rangetrans-query.c
 *
 * Provides a way for setools to make queries about range transition
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
#include "util.h"

#include <errno.h>

struct apol_range_trans_query {
	char *source, *target;
        apol_mls_range_t *range;
	unsigned int flags;
};

int apol_get_range_trans_by_query(apol_policy_t *p,
				  apol_range_trans_query_t *r,
				  apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL;
	apol_mls_range_t *range = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	if (r != NULL) {
		if (r->source != NULL &&
		    (source_list = apol_query_create_candidate_type_list(p, r->source, r->flags & APOL_QUERY_REGEX, r->flags & APOL_QUERY_SOURCE_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if ((r->flags & APOL_QUERY_SOURCE_AS_ANY) && r->source != NULL) {
			target_list = source_list;
			source_as_any = 1;
		}
		else if (r->target != NULL &&
			 (target_list = apol_query_create_candidate_type_list(p, r->target, r->flags & APOL_QUERY_REGEX, r->flags & APOL_QUERY_TARGET_INDIRECT)) == NULL) {
			goto cleanup;
		}
	}

	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	if (qpol_policy_get_range_trans_iter(p->qh, p->p, &iter) < 0) {
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_range_trans_t *rule;
		qpol_mls_range_t *mls_range;
		int match_source = 0, match_target = 0, compval;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}
		if (source_list == NULL) {
			match_source = 1;
		}
		else {
			qpol_type_t *source_type;
			if (qpol_range_trans_get_source_type(p->qh, p->p, rule, &source_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_type, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target has been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL || (source_as_any && match_source)) {
			match_target = 1;
		}
		else {
			qpol_type_t *target_type;
			if (qpol_range_trans_get_target_type(p->qh, p->p, rule, &target_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_type, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}

		if (!match_target) {
			continue;
		}

		if (qpol_range_trans_get_range(p->qh, p->p, rule, &mls_range) < 0 ||
		    (range = apol_mls_range_create_from_qpol_mls_range(p, mls_range)) == NULL) {
			goto cleanup;
		}
		compval = apol_mls_range_compare(p, range, r->range, r->flags);
		apol_mls_range_destroy(&range);
		if (compval < 0) {
			goto cleanup;
		}
		else if (compval == 0) {
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
	apol_vector_destroy(&source_list, NULL);
	if (!source_as_any) {
		apol_vector_destroy(&target_list, NULL);
	}
	qpol_iterator_destroy(&iter);
	apol_mls_range_destroy(&range);
	return retval;
}

apol_range_trans_query_t *apol_range_trans_query_create(void)
{
	return calloc(1, sizeof(apol_range_trans_query_t));
}

void apol_range_trans_query_destroy(apol_range_trans_query_t **r)
{
	if (*r != NULL) {
		free((*r)->source);
		free((*r)->target);
		apol_mls_range_destroy(&((*r)->range));
		free(*r);
		*r = NULL;
	}
}

int apol_range_trans_query_set_source(apol_policy_t *p,
				      apol_range_trans_query_t *r,
				      const char *symbol,
				      int is_indirect)
{
	apol_query_set_flag(p, &r->flags, is_indirect,
			    APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &r->source, NULL, symbol);
}

int apol_range_trans_query_set_target(apol_policy_t *p,
				      apol_range_trans_query_t *r,
				      const char *symbol,
				      int is_indirect)
{
	apol_query_set_flag(p, &r->flags, is_indirect,
			    APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &r->target, NULL, symbol);
}

int apol_range_trans_query_set_range(apol_policy_t *p __attribute__ ((unused)),
				     apol_range_trans_query_t *r,
				     apol_mls_range_t *range,
				     unsigned int range_match)
{
	if (r->range != NULL) {
		apol_mls_range_destroy(&r->range);
	}
	r->range = range;
	r->flags = (r->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

int apol_range_trans_query_set_enabled(apol_policy_t *p,
				       apol_range_trans_query_t *r,
				       int is_enabled)
{
	return apol_query_set_flag(p, &r->flags, is_enabled,
				   APOL_QUERY_ONLY_ENABLED);
}

int apol_range_trans_query_set_source_any(apol_policy_t *p,
					  apol_range_trans_query_t *r,
					  int is_any)
{
	return apol_query_set_flag(p, &r->flags, is_any,
				   APOL_QUERY_SOURCE_AS_ANY);
}

int apol_range_trans_query_set_regex(apol_policy_t *p,
				     apol_range_trans_query_t *r,
				     int is_regex)
{
	return apol_query_set_regex(p, &r->flags, is_regex);
}

char *apol_range_trans_render(apol_policy_t *policy, qpol_range_trans_t *rule)
{
	char *tmp = NULL, *tmp_name = NULL;
	int error = 0;
	size_t tmp_sz = 0;
	qpol_type_t *type = NULL;
	qpol_mls_range_t *range = NULL;
	apol_mls_range_t *arange = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* range_transition */
	if (apol_str_append(&tmp, &tmp_sz, "range_transition ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* source type */
	if (qpol_range_trans_get_source_type(policy->qh, policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->qh, policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* target type */
	if (qpol_range_trans_get_target_type(policy->qh, policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->qh, policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* range */
	if (qpol_range_trans_get_range(policy->qh, policy->p, rule, &range)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (!(arange = apol_mls_range_create_from_qpol_mls_range(policy, range))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (!(tmp_name = apol_mls_range_render(policy, arange))) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	apol_mls_range_destroy(&arange);
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	return tmp;

err:
	apol_mls_range_destroy(&arange);
	free(tmp);
	errno = error;
	return NULL;
}
