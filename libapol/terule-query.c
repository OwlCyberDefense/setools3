/**
 * @file terule-query.c
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
#include <errno.h>

struct apol_terule_query {
	char *source, *target, *default_type;
	apol_vector_t *classes;
	unsigned int rules;
	unsigned int flags;
};

int apol_get_terule_by_query(apol_policy_t *p,
			     apol_terule_query_t *t,
			     apol_vector_t **v)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *source_list = NULL, *target_list = NULL,
		*class_list = NULL, *default_list = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	uint32_t rule_type = QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_MEMBER |
			     QPOL_RULE_TYPE_CHANGE;
	if (t != NULL) {
		if (t->rules != 0) {
			rule_type &= t->rules;
		}
		if (t->source != NULL &&
		    (source_list = apol_query_create_candidate_type_list(p, t->source, t->flags & APOL_QUERY_REGEX, t->flags & APOL_QUERY_SOURCE_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if ((t->flags & APOL_QUERY_SOURCE_AS_ANY) && t->source != NULL) {
			default_list = target_list = source_list;
			source_as_any = 1;
		}
		else {
			if (t->target != NULL &&
			    (target_list = apol_query_create_candidate_type_list(p, t->target, t->flags & APOL_QUERY_REGEX, t->flags & APOL_QUERY_TARGET_INDIRECT)) == NULL) {
				goto cleanup;
			}
			if (t->default_type != NULL &&
			    (default_list = apol_query_create_candidate_type_list(p, t->default_type, t->flags & APOL_QUERY_REGEX, 0)) == NULL) {
				goto cleanup;
			}
		}
		if (t->classes != NULL &&
		    apol_vector_get_size(t->classes) > 0 &&
		    (class_list = apol_query_create_candidate_class_list(p, t->classes)) == NULL) {
			goto cleanup;
		}
	}

	if (qpol_policy_get_terule_iter(p->qh, p->p, rule_type, &iter) < 0) {
		goto cleanup;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_terule_t *rule;
		int match_source = 0, match_target = 0, match_default = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}
		if (source_list == NULL) {
			match_source = 1;
		}
		else {
			qpol_type_t *source_type;
			if (qpol_terule_get_source_type(p->qh, p->p, rule, &source_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(source_list, source_type, NULL, NULL, &i) == 0) {
				match_source = 1;
			}
		}

		/* if source did not match, but treating source symbol
		 * as any field, then delay rejecting this rule until
		 * the target and default have been checked */
		if (!source_as_any && !match_source) {
			continue;
		}

		if (target_list == NULL || (source_as_any && match_source)) {
			match_target = 1;
		}
		else {
			qpol_type_t *target_type;
			if (qpol_terule_get_target_type(p->qh, p->p, rule, &target_type) < 0) {
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
		}
		else {
			qpol_type_t *default_type;
			if (qpol_terule_get_default_type(p->qh, p->p, rule, &default_type) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(default_list, default_type, NULL, NULL, &i) == 0) {
				match_default = 1;
			}
		}

		if (!match_default) {
			continue;
		}

		if (class_list != NULL) {
			qpol_class_t *obj_class;
			if (qpol_terule_get_object_class(p->qh, p->p, rule, &obj_class) < 0) {
				goto cleanup;
			}
			if (apol_vector_get_index(class_list, obj_class, NULL, NULL, &i) < 0) {
				continue;
			}
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
		apol_vector_destroy(&default_list, NULL);
	}
	apol_vector_destroy(&class_list, NULL);
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_terule_query_t *apol_terule_query_create(void)
{
	apol_terule_query_t *t = calloc(1, sizeof(apol_terule_query_t));
	if (t != NULL) {
		t->rules = ~0U;
	}
	return t;
}

void apol_terule_query_destroy(apol_terule_query_t **t)
{
	if (*t != NULL) {
		free((*t)->source);
		free((*t)->target);
		free((*t)->default_type);
		apol_vector_destroy(&(*t)->classes, free);
		free(*t);
		*t = NULL;
	}
}

int apol_terule_query_set_rules(apol_policy_t *p __attribute__((unused)),
				apol_terule_query_t *t, unsigned int rules)
{
	if (rules != 0) {
		t->rules = rules;
	}
	else {
		t->rules = ~0U;
	}
	return 0;
}

int apol_terule_query_set_source(apol_policy_t *p,
				 apol_terule_query_t *t,
				 const char *symbol,
				 int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect,
			    APOL_QUERY_SOURCE_INDIRECT);
	return apol_query_set(p, &t->source, NULL, symbol);
}

int apol_terule_query_set_target(apol_policy_t *p,
				 apol_terule_query_t *t,
				 const char *symbol,
				 int is_indirect)
{
	apol_query_set_flag(p, &t->flags, is_indirect,
			    APOL_QUERY_TARGET_INDIRECT);
	return apol_query_set(p, &t->target, NULL, symbol);
}

int apol_terule_query_set_default(apol_policy_t *p,
				  apol_terule_query_t *t,
				  const char *symbol)
{
	return apol_query_set(p, &t->default_type, NULL, symbol);
}

int apol_terule_query_append_class(apol_policy_t *p,
				   apol_terule_query_t *t,
				   const char *obj_class)
{
	char *s;
	if (obj_class == NULL) {
		apol_vector_destroy(&t->classes, free);
	}
	else if ((s = strdup(obj_class)) == NULL ||
	    (t->classes == NULL && (t->classes = apol_vector_create()) == NULL) ||
	    apol_vector_append(t->classes, s) < 0) {
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
}

int apol_terule_query_set_enabled(apol_policy_t *p,
				  apol_terule_query_t *t, int is_enabled)
{
	return apol_query_set_flag(p, &t->flags, is_enabled,
				   APOL_QUERY_ONLY_ENABLED);
}

int apol_terule_query_set_source_any(apol_policy_t *p,
				     apol_terule_query_t *t, int is_any)
{
	return apol_query_set_flag(p, &t->flags, is_any,
				   APOL_QUERY_SOURCE_AS_ANY);
}

int apol_terule_query_set_regex(apol_policy_t *p, apol_terule_query_t *t, int is_regex)
{
	return apol_query_set_regex(p, &t->flags, is_regex);
}

char *apol_terule_render(apol_policy_t *policy, qpol_terule_t *rule)
{
	char *tmp = NULL, *tmp_name = NULL;
	int tmp_sz = 0, error = 0;
	uint32_t rule_type = 0;
	qpol_type_t *type = NULL;
	qpol_class_t *obj_class = NULL;

	if (!policy || !rule) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	/* rule type */
	if (qpol_terule_get_rule_type(policy->qh, policy->p, rule, &rule_type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if (!(rule_type &= (QPOL_RULE_TYPE_TRANS|QPOL_RULE_TYPE_CHANGE|QPOL_RULE_TYPE_MEMBER))) {
		ERR(policy, "Invalid type rule type");
		errno = EINVAL;
		return NULL;
	}
	if (!(tmp_name = (char*)apol_rule_type_to_str(rule_type))) {
		ERR(policy, "Type rule has multiple rule types?");
		errno = EINVAL;
		return NULL;
	}
	if (append_str(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* source type */
	if (qpol_terule_get_source_type(policy->qh, policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->qh, policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* target type */
	if (qpol_terule_get_target_type(policy->qh, policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->qh, policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, " : ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* object class */
	if (qpol_terule_get_object_class(policy->qh, policy->p, rule, &obj_class)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_class_get_name(policy->qh, policy->p, obj_class, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, " ")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	/* default type */
	if (qpol_terule_get_default_type(policy->qh, policy->p, rule, &type)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (qpol_type_get_name(policy->qh, policy->p, type, &tmp_name)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto err;
	}
	if (append_str(&tmp, &tmp_sz, tmp_name)) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	if (append_str(&tmp, &tmp_sz, ";")) {
		ERR(policy, "%s", strerror(ENOMEM));
		error = ENOMEM;
		goto err;
	}

	return tmp;

err:
	free(tmp);
	errno = error;
	return NULL;
}
