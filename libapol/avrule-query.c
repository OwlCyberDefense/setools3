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
	unsigned int rules;
	unsigned int flags;
};

#define APOL_QUERY_ONLY_ENABLED 0x02
#define APOL_QUERY_SOURCE_AS_ANY 0x04
#define APOL_QUERY_SOURCE_INDIRECT 0x08
#define APOL_QUERY_TARGET_INDIRECT 0x10

/**
 * Append a non-aliased type to a vector.  If the passed in type is an
 * alias, find its primary type and append that instead.
 *
 * @param p Policy in which to look up types.
 * @param v Vector in which append the non-aliased type.
 * @param type Type or attribute to append.  If this is an alias,
 * append its primary.
 *
 * @return 0 on success, < 0 on error.
 */
static int append_type(apol_policy_t *p, apol_vector_t *v, qpol_type_t *type) {
	unsigned char isalias;
	qpol_type_t *real_type = type;
	if (qpol_type_get_isattr(p->qh, p->p, type, &isalias) < 0) {
		return -1;
	}
	if (isalias) {
		char *primary_name;
		if (qpol_type_get_name(p->qh, p->p, type, &primary_name) < 0 ||
		    qpol_policy_get_type_by_name(p->qh, p->p, primary_name, &real_type) < 0) {
			return -1;
		}
	}
	if (apol_vector_append(v, real_type) < 0) {
		ERR(p, "Out of memory!");
		return -1;
	}
	return 0;
}

/**
 * Given a symbol name (a type, attribute, alias, or a regular
 * expression string), determine all types/attributes it matches.
 * Return a vector of qpol_type_t that match.  If regex is enabled,
 * include all types/attributes that match the expression.  If
 * indirect is enabled, expand the candidiates within the vector (all
 * attributes for a type, all types for an attribute), and then
 * uniquify the vector.
 *
 * @param p Policy in which to look up types.
 * @param symbol A string describing one or more type/attribute to
 * which match.
 * @param search flags; only regex and indirect are used here.
 * @param indirect_flag Bit value for indirect flag.
 *
 * @return Vector of unique qpol_type_t pointers (relative to policy
 * within p), or NULL upon error.
 */
static apol_vector_t *build_candidate_type_list(apol_policy_t *p, char *symbol, int flags, int indirect_flag)
{
	apol_vector_t *list = apol_vector_create();
	qpol_type_t *type;
	regex_t *regex = NULL;
	qpol_iterator_t *iter = NULL;
	int retval = -1;

	if (list == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}

	if (qpol_policy_get_type_by_name(p->qh, p->p, symbol, &type) == 0) {
		if (append_type(p, list, type) < 0) {
			goto cleanup;
		}
	}

	if (flags & APOL_QUERY_REGEX) {
		if (qpol_policy_get_type_iter(p->qh, p->p, &iter) < 0) {
			goto cleanup;
		}
		for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			char *type_name;
			int compval;
			if (qpol_iterator_get_item(iter, (void **) &type) < 0 ||
			    qpol_type_get_name(p->qh, p->p, type, &type_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, type_name, symbol, flags, &regex);
			if (compval < 0) {
				goto cleanup;
			}
			if (compval && append_type(p, list, type)) {
				goto cleanup;
			}
		}
		qpol_iterator_destroy(&iter);
	}

	if (flags & indirect_flag) {
		size_t i, orig_vector_size = apol_vector_get_size(list);
		for (i = 0; i < orig_vector_size; i++) {
			unsigned char isalias, isattr;
			type = (qpol_type_t *) apol_vector_get_element(list, i);
			if (qpol_type_get_isalias(p->qh, p->p, type, &isalias) < 0 ||
			    qpol_type_get_isattr(p->qh, p->p, type, &isattr) < 0) {
				goto cleanup;
			}
			if (isalias) {
				continue;
			}
			if ((isattr &&
			     qpol_type_get_type_iter(p->qh, p->p, type, &iter) < 0) ||
			    (!isattr &&
			     qpol_type_get_attr_iter(p->qh, p->p, type, &iter) < 0)) {
				goto cleanup;
			}
			for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **) &type) < 0) {
					goto cleanup;
				}
				if (append_type(p, list, type)) {
					goto cleanup;
				}
			}
			qpol_iterator_destroy(&iter);
		}
	}

	apol_vector_sort_uniquify(list, NULL, NULL, NULL);
	retval = 0;
 cleanup:
	if (regex != NULL) {
		regfree(regex);
		free(regex);
	}
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&list, NULL);
		list = NULL;
	}
	return list;
}

int apol_get_avrule_by_query(apol_policy_t *p,
			     apol_avrule_query_t *a,
			     apol_vector_t **v)
{
	qpol_iterator_t *iter;
	apol_vector_t *source_list = NULL, *target_list = NULL;
	int retval = -1, source_as_any = 0;
	*v = NULL;

	uint32_t rule_type = QPOL_RULE_ALLOW | QPOL_RULE_NEVERALLOW |
			     QPOL_RULE_AUDITALLOW | QPOL_RULE_DONTAUDIT;
	if (a != NULL) {
		if (a->rules != 0) {
			rule_type &= a->rules;
		}
		if (a->source != NULL &&
		    (source_list = build_candidate_type_list(p, a->source, a->flags, APOL_QUERY_SOURCE_INDIRECT)) == NULL) {
			goto cleanup;
		}
		if (a->flags & APOL_QUERY_SOURCE_AS_ANY) {
			target_list = source_list;
			source_as_any = 1;
		}
		else if (a->target != NULL &&
			 (target_list = build_candidate_type_list(p, a->target, a->flags, APOL_QUERY_TARGET_INDIRECT)) == NULL) {
			goto cleanup;
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
		qpol_type_t *source_type, *target_type;
		int match_source = 0, match_target = 0;
		size_t i;
		if (qpol_iterator_get_item(iter, (void **) &rule) < 0) {
			goto cleanup;
		}
		if (source_list == NULL) {
			match_source = 1;
		}
		else {
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
