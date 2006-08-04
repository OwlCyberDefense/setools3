/**
 * @file avrule-query.c
 *
 * Provides a way for setools to make queries about access vector
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


struct apol_avrule_query {
	char *source, *target, *bool_name;
	apol_vector_t *classes, *perms;
	unsigned int rules;
	unsigned int flags;
};

int apol_get_avrule_by_query(apol_policy_t *p,
			     apol_avrule_query_t *a,
			     apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL, *perm_iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL,
		*class_list = NULL, *perm_list = NULL;
	int retval = -1, source_as_any = 0, only_enabled = 0, is_regex = 0;
	char *bool_name = NULL;
	regex_t *bool_regex = NULL;
	*v = NULL;

	uint32_t rule_type = QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW |
			     QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;
	if (a != NULL) {
		if (a->rules != 0) {
			rule_type &= a->rules;
		}
		only_enabled = a->flags & APOL_QUERY_ONLY_ENABLED;
		is_regex = a->flags & APOL_QUERY_REGEX;
		bool_name = a->bool_name;
		if (a->source != NULL &&
		    (source_list = apol_query_create_candidate_type_list(p, a->source, is_regex, a->flags & APOL_QUERY_SOURCE_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if ((a->flags & APOL_QUERY_SOURCE_AS_ANY) && a->source != NULL) {
			target_list = source_list;
			source_as_any = 1;
		}
		else if (a->target != NULL &&
			 (target_list = apol_query_create_candidate_type_list(p, a->target, is_regex, a->flags & APOL_QUERY_TARGET_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if (a->classes != NULL &&
		    apol_vector_get_size(a->classes) > 0 &&
		    (class_list = apol_query_create_candidate_class_list(p, a->classes)) == NULL) {
			goto cleanup;
		}
		if (a->perms != NULL &&
		    apol_vector_get_size(a->perms) > 0) {
			perm_list = a->perms;
		}
	}

	if (qpol_policy_get_avrule_iter(p->qh, p->p, rule_type, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "%s", strerror(ENOMEM));
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_avrule_t *rule;
		uint32_t is_enabled;
		qpol_cond_t *cond = NULL;
		int match_source = 0, match_target = 0, match_perm = 0,
                        match_bool = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}

		if (qpol_avrule_get_is_enabled(p->qh, p->p, rule, &is_enabled) < 0) {
			goto cleanup;
		}
		if (!is_enabled && only_enabled) {
			continue;
		}

		if (bool_name != NULL) {
			if (qpol_avrule_get_cond(p->qh, p->p, rule, &cond) < 0) {
				goto cleanup;
			}
			if (cond == NULL) {
				continue;	  /* skip unconditional rule */
			}
			match_bool = apol_compare_cond_expr(p, cond, bool_name, is_regex, &bool_regex);
			if (match_bool < 0) {
				goto cleanup;
			}
			else if (match_bool == 0) {
				continue;
			}
		}

		if (source_list == NULL) {
			match_source = 1;
		}
		else {
			qpol_type_t *source_type;
			if (qpol_avrule_get_source_type(p->qh, p->p, rule, &source_type) < 0) {
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
			if (qpol_avrule_get_target_type(p->qh, p->p, rule, &target_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(target_list, target_type, NULL, NULL, &i) == 0) {
				match_target = 1;
			}
		}

		if (!match_target) {
			continue;
		}

		if (class_list != NULL) {
			qpol_class_t *obj_class;
			if (qpol_avrule_get_object_class(p->qh, p->p, rule, &obj_class) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(class_list, obj_class, NULL, NULL, &i) < 0) {
				continue;
			}
		}

		if (perm_list != NULL) {
			for (i = 0; i < apol_vector_get_size(perm_list) && match_perm == 0; i++) {
				char *perm = (char *) apol_vector_get_element(perm_list, i);
				if (qpol_avrule_get_perm_iter(p->qh, p->p, rule, &perm_iter) < 0) {
					goto cleanup;
				}
				match_perm = apol_compare_iter(p, perm_iter, perm, 0, NULL);
				if (match_perm < 0) {
					goto cleanup;
				}
				qpol_iterator_destroy(&perm_iter);
			}
		}
		else {
			match_perm = 1;
		}
		if (!match_perm) {
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
	apol_vector_destroy(&class_list, NULL);
        /* don't destroy perm_list - it points to query's permission list */
	apol_regex_destroy(&bool_regex);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&perm_iter);
	return retval;
}

apol_avrule_query_t *apol_avrule_query_create(void)
{
	apol_avrule_query_t *a = calloc(1, sizeof(apol_avrule_query_t));
	if (a != NULL) {
		a->rules = ~0U;
	}
	return a;
}

void apol_avrule_query_destroy(apol_avrule_query_t **a)
{
	if (*a != NULL) {
		free((*a)->source);
		free((*a)->target);
		free((*a)->bool_name);
		apol_vector_destroy(&(*a)->classes, free);
		apol_vector_destroy(&(*a)->perms, free);
		free(*a);
		*a = NULL;
	}
}

int apol_avrule_query_set_rules(apol_policy_t *p __attribute__((unused)),
				apol_avrule_query_t *a, unsigned int rules)
{
	if (rules != 0) {
		a->rules = rules;
	}
	else {
		a->rules = ~0U;
	}
	return 0;
}

int apol_avrule_query_set_source(apol_policy_t *p,
				 apol_avrule_query_t *a,
				 const char *symbol,
				 int is_indirect)
{
	apol_query_set_flag(p, &a->flags, is_indirect,
			    APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &a->source, NULL, symbol);
}

int apol_avrule_query_set_target(apol_policy_t *p,
				 apol_avrule_query_t *a,
				 const char *symbol,
				 int is_indirect)
{
	apol_query_set_flag(p, &a->flags, is_indirect,
			    APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &a->target, NULL, symbol);
}

int apol_avrule_query_append_class(apol_policy_t *p,
				   apol_avrule_query_t *a,
				   const char *obj_class)
{
	char *s;
	if (obj_class == NULL) {
		apol_vector_destroy(&a->classes, free);
	}
	else if ((s = strdup(obj_class)) == NULL ||
	    (a->classes == NULL && (a->classes = apol_vector_create()) == NULL) ||
	    apol_vector_append(a->classes, s) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

int apol_avrule_query_append_perm(apol_policy_t *p,
				  apol_avrule_query_t *a,
				  const char *perm)
{
	char *s;
	if (perm == NULL) {
		apol_vector_destroy(&a->perms, free);
	}
	else if ((s = strdup(perm)) == NULL ||
	    (a->perms == NULL && (a->perms = apol_vector_create()) == NULL) ||
	    apol_vector_append(a->perms, s) < 0) {
		ERR(p, "%s", strerror(ENOMEM));
		return -1;
	}
	return 0;
}

int apol_avrule_query_set_bool(apol_policy_t *p,
				    apol_avrule_query_t *a,
				    const char *bool_name)
{
	return apol_query_set(p, &a->bool_name, NULL, bool_name);
}

int apol_avrule_query_set_enabled(apol_policy_t *p,
				  apol_avrule_query_t *a, int is_enabled)
{
	return apol_query_set_flag(p, &a->flags, is_enabled,
				   APOL_QUERY_ONLY_ENABLED);
}

int apol_avrule_query_set_source_any(apol_policy_t *p,
				     apol_avrule_query_t *a, int is_any)
{
	return apol_query_set_flag(p, &a->flags, is_any,
				   APOL_QUERY_SOURCE_AS_ANY);
}

int apol_avrule_query_set_regex(apol_policy_t *p, apol_avrule_query_t *a, int is_regex)
{
	return apol_query_set_regex(p, &a->flags, is_regex);
}

char *apol_avrule_render(apol_policy_t *policy, qpol_avrule_t *rule)
{
	char *tmp = NULL, *tmp_name = NULL;
	int error = 0;
	uint32_t rule_type = 0;
	qpol_type_t *type = NULL;
	qpol_class_t *obj_class = NULL;
	qpol_iterator_t *iter = NULL;
	size_t tmp_sz = 0, num_perms = 0;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* rule type */
	if (qpol_avrule_get_rule_type(policy->qh, policy->p, rule, &rule_type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_ALLOW|QPOL_RULE_NEVERALLOW|QPOL_RULE_AUDITALLOW|QPOL_RULE_DONTAUDIT))) {
		ERR(policy, "%s", "Invalid av rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(tmp_name = (char*)apol_rule_type_to_str(rule_type))) {
		ERR(policy, "%s", "Av rule has multiple rule types?");
		errno = EINVAL;
		return NULL;
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

	/* source type */
	if (qpol_avrule_get_source_type(policy->qh, policy->p, rule, &type)) {
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
	if (qpol_avrule_get_target_type(policy->qh, policy->p, rule, &type)) {
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
	if (apol_str_append(&tmp, &tmp_sz, " : ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* object class */
	if (qpol_avrule_get_object_class(policy->qh, policy->p, rule, &obj_class)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_class_get_name(policy->qh, policy->p, obj_class, &tmp_name)) {
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

	/* perms */
	if (qpol_avrule_get_perm_iter(policy->qh, policy->p, rule, &iter)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_iterator_get_size(iter, &num_perms)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (num_perms > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "{ ")) {
			ERR(policy, "%s", strerror(ENOMEM));
			error = ENOMEM;
			goto err;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void**)&tmp_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto err;
		}
		if (apol_str_append(&tmp, &tmp_sz, tmp_name)) {
			ERR(policy, "%s", strerror(ENOMEM));
			error = ENOMEM;
			goto err;
		}
		free(tmp_name);
		tmp_name = NULL;
		if (apol_str_append(&tmp, &tmp_sz, " ")) {
			ERR(policy, "%s", strerror(ENOMEM));
			error = ENOMEM;
			goto err;
		}
	}
	if (num_perms > 1) {
		if (apol_str_append(&tmp, &tmp_sz, "}")) {
			ERR(policy, "%s", strerror(ENOMEM));
			error = ENOMEM;
			goto err;
		}
	}

	if (apol_str_append(&tmp, &tmp_sz, ";")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	qpol_iterator_destroy(&iter);
	return tmp;

err:
	free(tmp);
	qpol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}
