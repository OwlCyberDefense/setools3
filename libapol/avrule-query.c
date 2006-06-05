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

#include "policy-query.h"

struct apol_avrule_query {
	char *source, *target;
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
	int retval = -1, source_as_any = 0;
	*v = NULL;

	uint32_t rule_type = QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW |
			     QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;
	if (a != NULL) {
		if (a->rules != 0) {
			rule_type &= a->rules;
		}
		if (a->source != NULL &&
		    (source_list = apol_query_create_candidate_type_list(p, a->source, a->flags & APOL_QUERY_REGEX, a->flags & APOL_QUERY_SOURCE_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if (a->flags & APOL_QUERY_SOURCE_AS_ANY) {
			target_list = source_list;
			source_as_any = 1;
		}
		else if (a->target != NULL &&
			 (target_list = apol_query_create_candidate_type_list(p, a->target, a->flags & APOL_QUERY_REGEX, a->flags & APOL_QUERY_TARGET_INDIRECT)) == NULL) {
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
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_avrule_t *rule;
		int match_source = 0, match_target = 0, match_perm = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
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
	apol_vector_destroy(&class_list, NULL);
        /* don't destroy perm_list - it points to query's permission list */
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
		ERR(p, "Out of memory!");
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
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
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
