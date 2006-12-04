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

#include "policy-query-internal.h"

#include <errno.h>
#include <string.h>

struct apol_role_allow_query
{
	char *source, *target;
	unsigned int flags;
};

struct apol_role_trans_query
{
	char *source, *target, *default_role;
	unsigned int flags;
};

/******************** (role) allow queries ********************/

int apol_get_role_allow_by_query(apol_policy_t * p, apol_role_allow_query_t * r, apol_vector_t ** v)
{
	return apol_role_allow_get_by_query(p, r, v);
}

int apol_role_allow_get_by_query(apol_policy_t * p, apol_role_allow_query_t * r, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	if (r != NULL) {
		if (r->source != NULL &&
		    (source_list = apol_query_create_candidate_role_list(p, r->source, r->flags & APOL_QUERY_REGEX)) == NULL) {
			goto cleanup;
		}
		if ((r->flags & APOL_QUERY_SOURCE_AS_ANY) && r->source != NULL) {
			target_list = source_list;
			source_as_any = 1;
		} else if (r->target != NULL &&
			   (target_list =
			    apol_query_create_candidate_role_list(p, r->target, r->flags & APOL_QUERY_REGEX)) == NULL) {
			goto cleanup;
		}
	}
	if (qpol_policy_get_role_allow_iter(p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_role_allow_t *rule;
		int match_source = 0, match_target = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0) {
			goto cleanup;
		}

		if (source_list == NULL) {
			match_source = 1;
		} else {
			qpol_role_t *source_role;
			if (qpol_role_allow_get_source_role(p->p, rule, &source_role) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_role, NULL, NULL, &i) == 0) {
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
		} else {
			qpol_role_t *target_role;
			if (qpol_role_allow_get_target_role(p->p, rule, &target_role) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_role, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}
		if (!match_target) {
			continue;
		}

		if (apol_vector_append(*v, rule)) {
			ERR(p, "%s", strerror(ENOMEM));
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
	return retval;
}

apol_role_allow_query_t *apol_role_allow_query_create(void)
{
	return calloc(1, sizeof(apol_role_allow_query_t));
}

void apol_role_allow_query_destroy(apol_role_allow_query_t ** r)
{
	if (*r != NULL) {
		free((*r)->source);
		free((*r)->target);
		free(*r);
		*r = NULL;
	}
}

int apol_role_allow_query_set_source(apol_policy_t * p, apol_role_allow_query_t * r, const char *role)
{
	return apol_query_set(p, &r->source, NULL, role);
}

int apol_role_allow_query_set_target(apol_policy_t * p, apol_role_allow_query_t * r, const char *role)
{
	return apol_query_set(p, &r->target, NULL, role);
}

int apol_role_allow_query_set_source_any(apol_policy_t * p, apol_role_allow_query_t * r, int is_any)
{
	return apol_query_set_flag(p, &r->flags, is_any, APOL_QUERY_SOURCE_AS_ANY);
}

int apol_role_allow_query_set_regex(apol_policy_t * p, apol_role_allow_query_t * r, int is_regex)
{
	return apol_query_set_regex(p, &r->flags, is_regex);
}

char *apol_role_allow_render(apol_policy_t * policy, qpol_role_allow_t * rule)
{
	char *tmp = NULL, *tmp_name = NULL;
	int error = 0;
	size_t tmp_sz = 0;
	qpol_role_t *role = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* allow */
	if (apol_str_append(&tmp, &tmp_sz, "allow ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* source role */
	if (qpol_role_allow_get_source_role(policy->p, rule, &role)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_role_get_name(policy->p, role, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* target role */
	if (qpol_role_allow_get_target_role(policy->p, rule, &role)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_role_get_name(policy->p, role, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	return tmp;

      err:
	free(tmp);
	errno = error;
	return NULL;
}

/******************** role_transition queries ********************/

int apol_get_role_trans_by_query(apol_policy_t * p, apol_role_trans_query_t * r, apol_vector_t ** v)
{
	return apol_role_trans_get_by_query(p, r, v);
}

int apol_role_trans_get_by_query(apol_policy_t * p, apol_role_trans_query_t * r, apol_vector_t ** v)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL, *default_list = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	if (r != NULL) {
		if (r->source != NULL &&
		    (source_list = apol_query_create_candidate_role_list(p, r->source, r->flags & APOL_QUERY_REGEX)) == NULL) {
			goto cleanup;
		}
		if (r->target != NULL &&
		    (target_list =
		     apol_query_create_candidate_type_list(p, r->target, r->flags & APOL_QUERY_REGEX,
							   r->flags & APOL_QUERY_TARGET_INDIRECT,
							   APOL_QUERY_SYMBOL_IS_BOTH)) == NULL) {
			goto cleanup;
		}
		if ((r->flags & APOL_QUERY_SOURCE_AS_ANY) && r->source != NULL) {
			default_list = source_list;
			source_as_any = 1;
		} else if (r->default_role != NULL &&
			   (default_list =
			    apol_query_create_candidate_role_list(p, r->default_role, r->flags & APOL_QUERY_REGEX)) == NULL) {
			goto cleanup;
		}
	}
	if (qpol_policy_get_role_trans_iter(p->p, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_role_trans_t *rule;
		int match_source = 0, match_target = 0, match_default = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **)&rule) < 0) {
			goto cleanup;
		}

		if (source_list == NULL) {
			match_source = 1;
		} else {
			qpol_role_t *source_role;
			if (qpol_role_trans_get_source_role(p->p, rule, &source_role) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_role, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target and default have been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL) {
			match_target = 1;
		} else {
			qpol_type_t *target_type;
			if (qpol_role_trans_get_target_type(p->p, rule, &target_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_type, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}
		if (!match_target) {
			continue;
		}

		if (default_list == NULL || (source_as_any && match_source)) {
			match_default = 1;
		} else {
			qpol_role_t *default_role;
			if (qpol_role_trans_get_default_role(p->p, rule, &default_role) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(default_list, default_role, NULL, NULL, &i) == 0) {
				match_default = 1;
			}
		}
		if (!match_default) {
			continue;
		}

		if (apol_vector_append(*v, rule)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	apol_vector_destroy(&source_list, NULL);
	apol_vector_destroy(&target_list, NULL);
	if (!source_as_any) {
		apol_vector_destroy(&default_list, NULL);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_role_trans_query_t *apol_role_trans_query_create(void)
{
	return calloc(1, sizeof(apol_role_trans_query_t));
}

void apol_role_trans_query_destroy(apol_role_trans_query_t ** r)
{
	if (*r != NULL) {
		free((*r)->source);
		free((*r)->target);
		free((*r)->default_role);
		free(*r);
		*r = NULL;
	}
}

int apol_role_trans_query_set_source(apol_policy_t * p, apol_role_trans_query_t * r, const char *role)
{
	return apol_query_set(p, &r->source, NULL, role);
}

int apol_role_trans_query_set_target(apol_policy_t * p, apol_role_trans_query_t * r, const char *type, int is_indirect)
{
	apol_query_set_flag(p, &r->flags, is_indirect, APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &r->target, NULL, type);
}

int apol_role_trans_query_set_default(apol_policy_t * p, apol_role_trans_query_t * r, const char *role)
{
	return apol_query_set(p, &r->default_role, NULL, role);
}

int apol_role_trans_query_set_source_any(apol_policy_t * p, apol_role_trans_query_t * r, int is_any)
{
	return apol_query_set_flag(p, &r->flags, is_any, APOL_QUERY_SOURCE_AS_ANY);
}

int apol_role_trans_query_set_regex(apol_policy_t * p, apol_role_trans_query_t * r, int is_regex)
{
	return apol_query_set_regex(p, &r->flags, is_regex);
}

char *apol_role_trans_render(apol_policy_t * policy, qpol_role_trans_t * rule)
{
	char *tmp = NULL, *tmp_name = NULL;
	int error = 0;
	size_t tmp_sz = 0;
	qpol_role_t *role = NULL;
	qpol_type_t *type = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* role_transition */
	if (apol_str_append(&tmp, &tmp_sz, "role_transition ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* source role */
	if (qpol_role_trans_get_source_role(policy->p, rule, &role)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_role_get_name(policy->p, role, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* target type */
	if (qpol_role_trans_get_target_type(policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	/* default role */
	if (qpol_role_trans_get_default_role(policy->p, rule, &role)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_role_get_name(policy->p, role, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	if (apol_str_append(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}

	return tmp;

      err:
	free(tmp);
	errno = error;
	return NULL;
}
