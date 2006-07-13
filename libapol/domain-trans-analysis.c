/**
 * @file domain-trans-analysis.c
 *
 * Routines to perform a domain transition analysis.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include "policy.h"
#include "policy-query.h"
#include "domain-trans-analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* private data structure definitions */
typedef struct apol_domain_trans_rule {
	/* relavant type :
	 * for domain nodes either the transition target or the entrypoint type (target)
	 * for exec nodes either the entered or calling domain (source) */
	qpol_type_t	*type;
	qpol_type_t	*dflt;		/* only for type_transition rules */
	void		*rule;		/* qpol_avrule_t or qpol_terule_t */
	bool_t		used;		/* not used for setexec rules */
	bool_t		has_no_trans;	/* for exec_rules domain also has execute_no_trans permission */
} apol_domain_trans_rule_t;

typedef struct apol_domain_trans_dom_node {
	apol_vector_t	*proc_trans_rules;	/* of type apol_domain_trans_rule_t w/ qpol_avrule_t */
	apol_vector_t	*ep_rules;		/* of type apol_domain_trans_rule_t w/ qpol_avrule_t */
	apol_vector_t	*setexec_rules;		/* of type apol_domain_trans_rule_t w/ qpol_avrule_t */
	apol_vector_t	*type_trans_rules;	/* of type apol_domain_trans_rule_t w/ qpol_terule_t */
} apol_domain_trans_dom_node_t;

typedef struct apol_domain_trans_exec_node {
	apol_vector_t	*exec_rules;	/* of type apol_domain_trans_rule_t w/ qpol_avrule_t */
	apol_vector_t	*ep_rules;	/* of type apol_domain_trans_rule_t w/ qpol_avrule_t */
} apol_domain_trans_exec_node_t;

typedef struct apol_domain_trans {
	qpol_type_t	*start_type;
	qpol_type_t	*ep_type;
	qpol_type_t	*end_type;
	qpol_avrule_t	*proc_trans_rule;
	qpol_avrule_t	*ep_rule;
	qpol_avrule_t	*exec_rule;
	qpol_avrule_t	*setexec_rule;
	qpol_terule_t	*type_trans_rule;
	bool_t		valid;
	apol_vector_t	*access_rules;	/* used for access filtering, this is only populated on demand */
	struct apol_domain_trans *next;
} apol_domain_trans_t;

/* public data structure definitions */
struct apol_domain_trans_analysis {
	unsigned char	direction;
	unsigned char	valid;
	char		*start_type;
	char		*result;
	apol_vector_t	*access_types;
	apol_vector_t	*access_class_perms;
	regex_t		*result_regex;
};

struct apol_domain_trans_result {
	qpol_type_t	*start_type;
	qpol_type_t	*ep_type;
	qpol_type_t	*end_type;
	qpol_avrule_t	*proc_trans_rule;
	qpol_avrule_t	*ep_rule;
	qpol_avrule_t	*exec_rule;
	qpol_avrule_t	*setexec_rule;
	qpol_terule_t	*type_trans_rule;
	bool_t		valid;
	/* if access filters used list of rules that satisfy
	 * the filter criteria (of type qpol_avrule_t) */
	apol_vector_t	*access_rules;
};

struct apol_domain_trans_table {
	size_t				size;		/* size == number of types in policy (including attributes) */
	apol_domain_trans_dom_node_t	*dom_list;	/* these two arrays are indexed by type value -1 */
	apol_domain_trans_exec_node_t	*exec_list;	/* there will be holes for attributes (which are expanded) */
};

/* private functions */
static apol_domain_trans_table_t *apol_domain_trans_table_new(apol_policy_t *policy)
{
	apol_domain_trans_table_t *new_table = NULL;
	apol_vector_t *v = NULL;
	size_t size = 0, i;
	int error;

	if (!policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	new_table = (apol_domain_trans_table_t*)calloc(1, sizeof(apol_domain_trans_table_t));
	if (!new_table) {
		ERR(policy, "Out of memory!");
		error = ENOMEM;
		goto cleanup;
	}

	apol_get_type_by_query(policy, NULL, &v);
	size += apol_vector_get_size(v);
	apol_vector_destroy(&v, NULL);
	apol_get_attr_by_query(policy, NULL, &v);
	size += apol_vector_get_size(v);
	apol_vector_destroy(&v, NULL);

	new_table->size = size;

	new_table->dom_list = (apol_domain_trans_dom_node_t*)calloc(new_table->size, sizeof(apol_domain_trans_dom_node_t));
	if (!new_table->dom_list) {
		ERR(policy, "Out of memory!");
		error = ENOMEM;
		goto cleanup;
	}
	new_table->exec_list = (apol_domain_trans_exec_node_t*)calloc(new_table->size, sizeof(apol_domain_trans_exec_node_t));
	if (!new_table->exec_list) {
		ERR(policy, "Out of memory!");
		error = ENOMEM;
		goto cleanup;
	}

	for (i = 0; i < new_table->size; i++) {
		/* create all the vectors for each side of the table, return error if any fails */
		if (!(new_table->dom_list[i].proc_trans_rules = apol_vector_create()) ||
			!(new_table->dom_list[i].ep_rules = apol_vector_create()) ||
			!(new_table->dom_list[i].setexec_rules = apol_vector_create()) ||
			!(new_table->dom_list[i].type_trans_rules = apol_vector_create()) ||
			!(new_table->exec_list[i].exec_rules = apol_vector_create()) ||
			!(new_table->exec_list[i].ep_rules = apol_vector_create())) {
			 ERR(policy, "Out of memory!");
			 error = ENOMEM;
			 goto cleanup;
		}
	}

	return new_table;
 cleanup:
	apol_domain_trans_table_destroy(&new_table);
	errno = error;
	return NULL;
}

static apol_domain_trans_t *apol_domain_trans_new()
{
	apol_domain_trans_t *new_trans = NULL;
	int error;

	new_trans = (apol_domain_trans_t*)calloc(1, sizeof(apol_domain_trans_t));
	if (!new_trans) {
		return NULL;
	}

	new_trans->access_rules = apol_vector_create();
	if (!new_trans->access_rules){
		error = errno;
		free(new_trans);
		errno = error;
		return NULL;
	}

	return new_trans;
}

static void apol_domain_trans_dom_node_free(apol_domain_trans_dom_node_t *node)
{
	if (!node)
		return;

	apol_vector_destroy(&node->proc_trans_rules, free);
	apol_vector_destroy(&node->ep_rules, free);
	apol_vector_destroy(&node->setexec_rules, free);
	apol_vector_destroy(&node->type_trans_rules, free);
}

static void apol_domain_trans_exec_node_free(apol_domain_trans_exec_node_t *node)
{
	if (!node)
		return;

	apol_vector_destroy(&node->exec_rules, free);
	apol_vector_destroy(&node->ep_rules, free);
}

static void apol_domain_trans_destroy(apol_domain_trans_t **trans)
{
	apol_domain_trans_t *trx = NULL, *next = NULL;

	if (!trans || !(*trans))
		return;

	for (trx = *trans; trx; trx = next) {
		apol_vector_destroy(&trx->access_rules, NULL);
		next = trx->next;
		free(trx);
	}

	*trans = NULL;
}

static int apol_domain_trans_find_rule_for_type(apol_policy_t *policy, apol_vector_t *rule_list, qpol_type_t *type)
{
	int list_sz = apol_vector_get_size(rule_list);
	int left = 0, right = list_sz - 1;
	int i = list_sz / 2;
	apol_domain_trans_rule_t *rule = NULL;
	uint32_t type_val, rule_type_val;
	unsigned char isattr = 0;

	if (!type) {
		errno = EINVAL;
		return -1;
	}

	/* can only fail on NULL pointer which has been checked so any non-null value is fine */
	qpol_type_get_isattr(policy->qh, policy->p, type, &isattr);
	if (isattr) {
		errno = EINVAL;
		return -1;
	}

	if (!rule_list || list_sz == 0)
		return -1; /* empty list, not necessarily an error */

	/* can only fail on NULL pointer which has been checked so any non-null value is fine */
	qpol_type_get_value(policy->qh, policy->p, type, &type_val);

	/* potentially a lot of entries but list is sorted so
	 * we can do a binary search */
	do {
		rule = apol_vector_get_element(rule_list, i);
		/* can only fail on NULL pointer which has been checked so any non-null value is fine */
		qpol_type_get_value(policy->qh, policy->p, rule->type, &rule_type_val);
		if (rule_type_val == type_val) {
			return i;
		} else if (rule_type_val < type_val) {
			left = i+1;
			i += ((right - i)/2 + (right - i)%2);
		} else {
			right = i-1;
			i -= ((i - left)/2 + (i - left)%2);
		}
	} while (right >= left);

	return -1;
}

static int apol_domain_trans_find_rule_for_dflt(apol_policy_t *policy, apol_vector_t *rule_list, qpol_type_t *dflt)
{
	size_t list_sz = apol_vector_get_size(rule_list), i;
	apol_domain_trans_rule_t *rule = NULL;
	uint32_t dflt_val, rule_type_val;
	unsigned char isattr = 0;

	if (!dflt) {
		errno = EINVAL;
		return -1;
	}

	/* can only fail on NULL pointer which has been checked so any non-null value is fine */
	qpol_type_get_isattr(policy->qh, policy->p, dflt, &isattr);
	if (isattr) {
		errno = EINVAL;
		return -1;
	}

	if (!rule_list)
		return -1; /* empty list, not necessarily an error */

	/* can only fail on NULL pointer which has been checked so any non-null value is fine */
	qpol_type_get_value(policy->qh, policy->p, dflt, &dflt_val);

	/* potentially a lot of entries but list is sorted so
	 * we can do a binary search */
	for (i = 0; i < list_sz; i++) {
		dflt_val = 0;
		rule = apol_vector_get_element(rule_list, i);
		if (rule->dflt)
			qpol_type_get_value(policy->qh, policy->p, rule->dflt, &rule_type_val);
		if (rule_type_val == dflt_val) {
			return i;
		}
	}

	return -1;
}

static int apol_domain_trans_rule_compare(const void *a, const void *b, void *unused __attribute__ ((unused)))
{
	const apol_domain_trans_rule_t *rule_a = (const apol_domain_trans_rule_t*)a;
	const apol_domain_trans_rule_t *rule_b = (const apol_domain_trans_rule_t*)b;

	/* only care if pointer value is the same */
	return (int)((void*)(rule_a->type) - (void*)(rule_b->type));
}

static int apol_domain_trans_add_rule_to_list(apol_policy_t *policy, apol_vector_t *rule_list, qpol_type_t *type, qpol_type_t *dflt, void *rule, bool_t has_no_trans)
{
	int retv;
	apol_domain_trans_rule_t *tmp_rule = NULL;
	unsigned char isattr = 0;

	if (!rule_list || !type || !rule) {
		errno = EINVAL;
		return -1;
	}

	/* can only fail on NULL pointer which has been checked so any non-null value is fine */
	qpol_type_get_isattr(policy->qh, policy->p, type, &isattr);
	if (isattr) {
		errno = EINVAL;
		return -1;
	}

	/* if rule with same key already exists do nothing */
	retv = apol_domain_trans_find_rule_for_type(policy, rule_list, type);
	if (retv >= 0) {
		return 0;
	}

	tmp_rule = calloc(1, sizeof(apol_domain_trans_rule_t));
	if (!tmp_rule)
		return -1;

	tmp_rule->type = type;
	tmp_rule->dflt = dflt;
	tmp_rule->rule = rule;
	tmp_rule->has_no_trans = (has_no_trans? TRUE : FALSE);

	if (apol_vector_append(rule_list, (void*)tmp_rule)) {
		free(tmp_rule);
		errno = ENOMEM;
		return -1;
	}

	apol_vector_sort(rule_list, apol_domain_trans_rule_compare, NULL);

	return 0;
}

static int apol_domain_trans_table_add_rule(apol_policy_t *policy, unsigned char rule_type, void *rule)
{
	int retv, error = 0;
	apol_domain_trans_table_t *table = NULL;
	qpol_terule_t *terule = NULL;
	qpol_avrule_t *avrule = NULL;
	qpol_type_t *src = NULL, *tgt = NULL, *dflt = NULL;
	uint32_t src_val = 0, tgt_val = 0;
	unsigned char isattr = 0;
	apol_vector_t *src_types = NULL, *tgt_types = NULL;
	qpol_iterator_t *iter = NULL;
	size_t i, j;

	if (!policy || !policy->domain_trans_table || !rule_type || !rule) {
		errno = EINVAL;
		return -1;
	}

	table = policy->domain_trans_table;

	if (rule_type & APOL_DOMAIN_TRANS_RULE_TYPE_TRANS) {
		terule = rule;
		qpol_terule_get_source_type(policy->qh, policy->p, terule, &src);
		qpol_terule_get_target_type(policy->qh, policy->p, terule, &tgt);
		qpol_terule_get_default_type(policy->qh, policy->p, terule, &dflt);
	} else {
		avrule = rule;
		qpol_avrule_get_source_type(policy->qh, policy->p, avrule, &src);
		qpol_avrule_get_target_type(policy->qh, policy->p, avrule, &tgt);
	}

	/* handle any attributes*/
	qpol_type_get_isattr(policy->qh, policy->p, src, &isattr);
	if (isattr) {
		if (qpol_type_get_type_iter(policy->qh, policy->p, src, &iter))
			goto err;
		if (!(src_types = apol_vector_create_from_iter(iter))) {
			ERR(policy, "Out of memory!");
			qpol_iterator_destroy(&iter);
			goto err;
		}
		qpol_iterator_destroy(&iter);
	} else {
		if (!(src_types = apol_vector_create()) ||
		    apol_vector_append(src_types, src)) {
			ERR(policy, "Out of memory!");
			goto err;
		}
	}

	qpol_type_get_isattr(policy->qh, policy->p, tgt, &isattr);
	if (isattr) {
		if (qpol_type_get_type_iter(policy->qh, policy->p, tgt, &iter))
			goto err;
		if (!(tgt_types = apol_vector_create_from_iter(iter))) {
			ERR(policy, "Out of memory!");
			qpol_iterator_destroy(&iter);
			goto err;
		}
		qpol_iterator_destroy(&iter);
	} else {
		if (!(tgt_types = apol_vector_create()))
			goto err;
		if (apol_vector_append(tgt_types, tgt)) {
			ERR(policy, "Out of memory!");
			goto err;
		}
	}


	if (rule_type & APOL_DOMAIN_TRANS_RULE_PROC_TRANS) {
		for (j = 0; j < apol_vector_get_size(src_types); j++) {
			src = apol_vector_get_element(src_types, j);
			qpol_type_get_value(policy->qh, policy->p, src, &src_val);
			for (i = 0; i < apol_vector_get_size(tgt_types); i++) {
				tgt = apol_vector_get_element(tgt_types, i);
				retv = apol_domain_trans_add_rule_to_list(policy, table->dom_list[src_val - 1].proc_trans_rules,
						tgt, NULL, rule, 0);
				if (retv)
					goto err;
			}
		}
	}
	if (rule_type & APOL_DOMAIN_TRANS_RULE_EXEC) {
		for (j = 0; j < apol_vector_get_size(tgt_types); j++) {
			tgt = apol_vector_get_element(tgt_types, j);
			qpol_type_get_value(policy->qh, policy->p, tgt, &tgt_val);
			for (i = 0; i < apol_vector_get_size(src_types); i++) {
				src = apol_vector_get_element(src_types, i);
				retv = apol_domain_trans_add_rule_to_list(policy, table->exec_list[tgt_val - 1].exec_rules,
						src, NULL, rule, (rule_type & APOL_DOMAIN_TRANS_RULE_EXEC_NO_TRANS));
				if (retv)
					goto err;
			}
		}
	}
	if (rule_type & APOL_DOMAIN_TRANS_RULE_ENTRYPOINT) {
		for (i = 0; i < apol_vector_get_size(tgt_types); i++) {
			tgt = apol_vector_get_element(tgt_types, i);
			qpol_type_get_value(policy->qh, policy->p, tgt, &tgt_val);
			for (j = 0; j < apol_vector_get_size(src_types); j++) {
				src = apol_vector_get_element(src_types, j);
				qpol_type_get_value(policy->qh, policy->p, src, &src_val);
				retv = apol_domain_trans_add_rule_to_list(policy, table->dom_list[src_val - 1].ep_rules,
						tgt, NULL, rule, 0);
				if (retv)
					goto err;
				retv = apol_domain_trans_add_rule_to_list(policy, table->exec_list[tgt_val - 1].ep_rules,
						src, NULL, rule, 0);
				if (retv)
					goto err;
			}
		}
	}
	if (rule_type & APOL_DOMAIN_TRANS_RULE_TYPE_TRANS) {
		for (i = 0; i < apol_vector_get_size(tgt_types); i++ ) {
			tgt = apol_vector_get_element(tgt_types, i);
			for (j = 0; j < apol_vector_get_size(src_types); j++) {
				src = apol_vector_get_element(src_types, j);
				qpol_type_get_value(policy->qh, policy->p, src, &src_val);
				retv = apol_domain_trans_add_rule_to_list(policy, table->dom_list[src_val - 1].type_trans_rules,
						tgt, dflt, rule, 0);
				if (retv)
					goto err;
			}
		}
	}
	if (rule_type & APOL_DOMAIN_TRANS_RULE_SETEXEC) {
		for (i = 0; i < apol_vector_get_size(tgt_types); i++ ) {
			tgt = apol_vector_get_element(tgt_types, i);
			qpol_type_get_value(policy->qh, policy->p, tgt, &tgt_val);
			for (j = 0; j < apol_vector_get_size(src_types); j++) {
				src = apol_vector_get_element(src_types, j);
				qpol_type_get_value(policy->qh, policy->p, src, &src_val);
				if (src_val != tgt_val)
					continue; /* only care about allow start self : processes setexec; */
				retv = apol_domain_trans_add_rule_to_list(policy, table->dom_list[src_val - 1].setexec_rules,
						tgt, NULL, rule, 0);
				if (retv)
					goto err;
			}
		}
	}

	apol_vector_destroy(&src_types, NULL);
	apol_vector_destroy(&tgt_types, NULL);
	return 0;

err:
	error = errno;
	apol_vector_destroy(&src_types, NULL);
	apol_vector_destroy(&tgt_types, NULL);
	errno = error;
	return -1;
}

static int apol_domain_trans_table_get_all_forward_trans(apol_policy_t *policy, apol_domain_trans_t **trans, qpol_type_t *start)
{
	apol_domain_trans_table_t *table = NULL;
	apol_domain_trans_t *entry = NULL, *cur_head = NULL, *cur_tail = NULL;
	qpol_type_t *ep = NULL, *end = NULL;
	uint32_t start_val, ep_val, end_val;
	size_t i, j;
	apol_domain_trans_rule_t *rule_entry = NULL, *tmp_rule = NULL, *tmp_rule2 = NULL;
	int error = 0, tmp;
	unsigned char isattr = 0;
	unsigned int policy_version = 0;

	if (!policy || !policy->domain_trans_table || !trans || !start) {
		errno = EINVAL;
		return -1;
	}

	table = policy->domain_trans_table;
	qpol_policy_get_policy_version(policy->qh, policy->p, &policy_version);

	qpol_type_get_isattr(policy->qh, policy->p, start, &isattr);
	if (isattr) {
		errno = EINVAL;
		return -1;
	}

	qpol_type_get_value(policy->qh, policy->p, start, &start_val);

	/* verify type transition rules */
	for (i = 0; i < apol_vector_get_size(table->dom_list[start_val - 1].type_trans_rules); i++) {
		rule_entry = apol_vector_get_element(table->dom_list[start_val - 1].type_trans_rules, i);
		rule_entry->used = TRUE;
		if (!(entry = apol_domain_trans_new())) {
			error = errno;
			goto exit_error;
		}
		entry->start_type = start;
		entry->ep_type = rule_entry->type;
		entry->end_type = rule_entry->dflt;
		entry->type_trans_rule = rule_entry->rule;
		qpol_type_get_value(policy->qh, policy->p, entry->ep_type, &ep_val);
		qpol_type_get_value(policy->qh, policy->p, entry->end_type, &end_val);
		tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].proc_trans_rules, entry->end_type);
		if (tmp >= 0) {
			tmp_rule = apol_vector_get_element(table->dom_list[start_val - 1].proc_trans_rules, tmp);
			tmp_rule->used = TRUE;
			entry->proc_trans_rule = tmp_rule->rule;
		}
		tmp = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].exec_rules, entry->start_type);
		if (tmp >= 0) {
			tmp_rule = apol_vector_get_element(table->exec_list[ep_val - 1].exec_rules, tmp);
			tmp_rule->used = TRUE;
			entry->exec_rule = tmp_rule->rule;
		}
		tmp = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].ep_rules, entry->end_type);
		if (tmp >= 0) {
			tmp_rule = apol_vector_get_element(table->exec_list[ep_val - 1].ep_rules, tmp);
			tmp_rule->used = TRUE;
			entry->ep_rule = tmp_rule->rule;
		}
		/* find a setexec rule if there is one */
		tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].setexec_rules, start);
		if (tmp >=0) {
			tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].setexec_rules, tmp);
			entry->setexec_rule = tmp_rule2->rule;
		}
		if (entry->exec_rule && entry->ep_rule && entry->proc_trans_rule && (policy_version >= 15 ? (entry->type_trans_rule || entry->setexec_rule) : 1))
			entry->valid = TRUE;
		entry->next = cur_head;
		cur_head = entry;
		if (!cur_tail)
			cur_tail = entry;
		entry = NULL;
	}

	/* follow process transition rules */
	for (i = 0; i < apol_vector_get_size(table->dom_list[start_val - 1].proc_trans_rules); i++) {
		rule_entry = apol_vector_get_element(table->dom_list[start_val - 1].proc_trans_rules, i);
		if (rule_entry->used)
			continue; /* we already found this transition */
		end = rule_entry->type;
		qpol_type_get_value(policy->qh, policy->p, end, &end_val);
		if (end_val == start_val)
			continue; /* if start is same as end no transition occurs */
		rule_entry->used = TRUE;
		/* follow each entrypoint of end */
		for (j = 0; j < apol_vector_get_size(table->dom_list[end_val - 1].ep_rules); j++) {
			tmp_rule = apol_vector_get_element(table->dom_list[end_val - 1].ep_rules, j);
			tmp_rule->used = TRUE;
			ep = tmp_rule->type;
			qpol_type_get_value(policy->qh, policy->p, ep, &ep_val);
			tmp = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].ep_rules, end);
                        assert(tmp >= 0);
			tmp_rule2 = apol_vector_get_element(table->exec_list[ep_val - 1].ep_rules, tmp);
			if (tmp_rule2->used)
				continue; /* we already found this transition */
			tmp_rule2->used = TRUE;
			if (!(entry = apol_domain_trans_new())) {
				error = errno;
				goto exit_error;
			}
			entry->start_type = start;
			entry->ep_type = ep;
			entry->end_type = end;
			entry->proc_trans_rule = rule_entry->rule;
			entry->ep_rule = tmp_rule->rule;
			/* find an execute rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].exec_rules, start);
			if (tmp >= 0) {
				tmp_rule2 = apol_vector_get_element(table->exec_list[ep_val - 1].exec_rules, tmp);
				entry->exec_rule = tmp_rule2->rule;
			}
			/* find a setexec rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].setexec_rules, start);
			if (tmp >=0) {
				tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].setexec_rules, tmp);
				entry->setexec_rule = tmp_rule2->rule;
			}
			if (entry->exec_rule && entry->ep_rule && entry->proc_trans_rule && (policy_version >= 15 ? (entry->type_trans_rule || entry->setexec_rule) : 1))
				entry->valid = TRUE;
			entry->next = cur_head;
			cur_head = entry;
			if (!cur_tail)
				cur_tail = entry;
			entry = NULL;
		}
		/* if no entrypoint add an entry for the existing rule */
		if (!apol_vector_get_size(table->dom_list[end_val - 1].ep_rules)) {
			if (!(entry = apol_domain_trans_new())) {
				error = errno;
				goto exit_error;
			}
			entry->start_type = start;
			entry->end_type = end;
			entry->proc_trans_rule = rule_entry->rule;
			entry->next = cur_head;
			cur_head = entry;
			if (!cur_tail)
				cur_tail = entry;
			entry = NULL;
		}
	}

	/* add results to list if found */
	if (cur_head) {
		cur_tail->next = *trans;
		*trans = cur_head;
	}

	return 0;

exit_error:
	apol_domain_trans_destroy(&entry);
	apol_domain_trans_destroy(&cur_head);
	errno = error;
	return -1;
}

static int apol_domain_trans_table_get_all_reverse_trans(apol_policy_t *policy, apol_domain_trans_t **trans, qpol_type_t *end)
{
	apol_domain_trans_table_t *table = NULL;
	apol_domain_trans_t *entry = NULL, *cur_head = NULL, *cur_tail = NULL;
	qpol_type_t *ep = NULL, *start = NULL, *dflt = NULL;
	uint32_t start_val, ep_val, end_val, dflt_val;
	size_t i, j;
	apol_domain_trans_rule_t *rule_entry = NULL, *tmp_rule = NULL, *tmp_rule2 = NULL;
	int error = 0, tmp, dead = 0;
	unsigned char isattr = 0;
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	unsigned int policy_version = 0;

	if (!policy || !policy->domain_trans_table || !trans || !start) {
		errno = EINVAL;
		return -1;
	}

	table = policy->domain_trans_table;
	qpol_policy_get_policy_version(policy->qh, policy->p, &policy_version);

	qpol_type_get_isattr(policy->qh, policy->p, end, &isattr);
	if (isattr) {
		errno = EINVAL;
		return -1;
	}

	qpol_type_get_value(policy->qh, policy->p, end, &end_val);

	/* follow entrypoints */
	for (i = 0; i < apol_vector_get_size(table->dom_list[end_val - 1].ep_rules); i++) {
		rule_entry = apol_vector_get_element(table->dom_list[end_val - 1].ep_rules, i);
		ep = rule_entry->type;
		qpol_type_get_value(policy->qh, policy->p, ep, &ep_val);
		rule_entry->used = TRUE;
		/* follow each execute rule of ep */
		for (j = 0; j < apol_vector_get_size(table->exec_list[ep_val - 1].exec_rules); j++) {
			tmp_rule = apol_vector_get_element(table->exec_list[ep_val - 1].exec_rules, j);
			start = tmp_rule->type;
			qpol_type_get_value(policy->qh, policy->p, start, &start_val);
			if (start_val == end_val) {
				if (apol_vector_get_size(table->exec_list[ep_val - 1].exec_rules) == 1)
					dead = 1; /* if there is only on execute rule for this entrypoint and its source the same as end the entrypoint is dead */
				continue; /* if start is same as end no transition occurs */
			}
			if (tmp_rule->used)
				continue; /* we already found this transition */
			tmp_rule->used = TRUE;
			if (!(entry = apol_domain_trans_new())) {
				error = errno;
				goto exit_error;
			}
			entry->end_type = end;
			entry->ep_type = ep;
			entry->start_type = tmp_rule->type;
			entry->ep_rule = rule_entry->rule;
			entry->exec_rule = tmp_rule->rule;
			/* find a process transition rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].proc_trans_rules, end);
			if (tmp >= 0) {
				tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].proc_trans_rules, tmp);
				entry->proc_trans_rule = tmp_rule2->rule;
				tmp_rule2->used = TRUE;
				tmp_rule2 = NULL;
			}
			/* find a type transition rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].type_trans_rules, ep);
			if (tmp >= 0) {
				tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].type_trans_rules, tmp);
				dflt = tmp_rule2->dflt;
				qpol_type_get_value(policy->qh, policy->p, dflt, &dflt_val);
				if (dflt_val == end_val) {
					tmp_rule2->used = TRUE;
					entry->type_trans_rule = tmp_rule2->rule;
				}
			}
			/* find a setexec rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].setexec_rules, start);
			if (tmp >=0) {
				tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].setexec_rules, tmp);
				entry->setexec_rule = tmp_rule2->rule;
			}
			if (entry->exec_rule && entry->ep_rule && entry->proc_trans_rule && (policy_version >= 15 ? (entry->type_trans_rule || entry->setexec_rule) : 1))
				entry->valid = TRUE;
			entry->next = cur_head;
			cur_head = entry;
			if (!cur_tail)
				cur_tail = entry;
			entry = NULL;
		}
		/* if no execute rule add an entry for the existing rule */
		if (!apol_vector_get_size(table->exec_list[ep_val - 1].exec_rules) || dead) {
			if (!(entry = apol_domain_trans_new())) {
				error = errno;
				goto exit_error;
			}
			entry->end_type = end;
			entry->ep_type = ep;
			entry->ep_rule = rule_entry->rule;
			entry->next = cur_head;
			cur_head = entry;
			if (!cur_tail)
				cur_tail = entry;
			entry = NULL;
		}
	}

	/* find unused process transitions and type_transition rules to end */
	for (i = 0; i < table->size; i++) {
		rule_entry = NULL;
		tmp_rule = NULL;
		start = NULL;
		ep = NULL;
		ep_val = 0;
		if (i == end_val)
			continue; /* no transition would occur */
		tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[i].proc_trans_rules, end);
		if (tmp >= 0) {
			rule_entry = apol_vector_get_element(table->dom_list[i].proc_trans_rules, tmp);
			if (rule_entry->used)
			rule_entry = NULL;
		}
		tmp = apol_domain_trans_find_rule_for_dflt(policy, table->dom_list[i].type_trans_rules, end);
		if (tmp >= 0) {
			tmp_rule = apol_vector_get_element(table->dom_list[i].type_trans_rules, tmp);
			if (rule_entry->used)
			tmp_rule = NULL;
		}
		if (!rule_entry && !tmp_rule)
			continue; /* either used or none exists */
		if (tmp_rule) {
			tmp_rule->used = TRUE;
			qpol_terule_get_source_type(policy->qh, policy->p, tmp_rule->rule, &start);
			ep = tmp_rule->type;
			qpol_type_get_value(policy->qh, policy->p, ep, &ep_val);
		} else if (rule_entry) {
			rule_entry->used = TRUE;
			qpol_avrule_get_source_type(policy->qh, policy->p, rule_entry->rule, &start);
		}
		qpol_type_get_isattr(policy->qh, policy->p, start, &isattr);
		if (isattr) {
			if (qpol_type_get_type_iter(policy->qh, policy->p, start, &iter)) {
				error = errno;
				goto exit_error;
			}
			if (!(v = apol_vector_create_from_iter(iter))) {
				error = errno;
				goto exit_error;
			}
			qpol_iterator_destroy(&iter);
		} else {
			if (!(v = apol_vector_create())) {
				error = errno;
				goto exit_error;
			}
			if (apol_vector_append(v, start)) {
				error = errno;
				goto exit_error;
			}
		}
		for (j = 0; j < apol_vector_get_size(v); j++) {
			if (!(entry = apol_domain_trans_new())) {
				error = errno;
				goto exit_error;
			}
			entry->start_type = apol_vector_get_element(v, j);
			qpol_type_get_value(policy->qh, policy->p, entry->start_type, &start_val);
			entry->ep_type = ep;
			entry->end_type = end;
			if (rule_entry)
				entry->proc_trans_rule = rule_entry->rule;
			if (tmp_rule) {
				entry->type_trans_rule = tmp_rule->rule;
				/* attempt to find an execute rule */
				tmp = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].exec_rules, start);
				if (tmp >= 0) {
					tmp_rule2 = apol_vector_get_element(table->exec_list[ep_val - 1].exec_rules, tmp);
					tmp_rule2->used = TRUE;
					entry->exec_rule = tmp_rule2->rule;
				}
			}
			/* find a setexec rule if there is one */
			tmp = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].setexec_rules, entry->start_type);
			if (tmp >=0) {
				tmp_rule2 = apol_vector_get_element(table->dom_list[start_val - 1].setexec_rules, tmp);
				entry->setexec_rule = tmp_rule2->rule;
			}
			entry->next = cur_head;
			cur_head = entry;
			if (!cur_tail)
				cur_tail = entry;
			entry = NULL;
		}
		apol_vector_destroy(&v, NULL);
	}

	/* add results to list if found */
	if (cur_head) {
		cur_tail->next = *trans;
		*trans = cur_head;
	}

	return 0;

exit_error:
	apol_vector_destroy(&v, NULL);
	apol_domain_trans_destroy(&entry);
	apol_domain_trans_destroy(&cur_head);
	errno = error;
	return -1;
}

/* removes all nodes in the linked list pointed to by trans
 * which do not have the same validity as the valid argument */
static int apol_domain_trans_filter_valid(apol_domain_trans_t **trans, bool_t valid)
{
	apol_domain_trans_t *cur = NULL, *prev = NULL;

	if (!trans) {
		errno = EINVAL;
		return -1;
	}

	if (valid)
		valid = 1;

	for (cur = *trans; cur;) {
		if (cur->valid == valid) {
			prev = cur;
			cur = cur->next;
			continue;
		}
		if (prev) {
			prev->next = cur->next;
		} else {
			*trans = cur->next;
		}
		cur->next = NULL;
		apol_domain_trans_destroy(&cur);
		if (prev) {
			cur = prev->next;
		} else {
			cur = *trans;
		}
	}

	return 0;
}

/* filter list of transitions to include only transitions
 * with an end type in the provided list */
static int apol_domain_trans_filter_end_types(apol_domain_trans_t **trans, apol_vector_t *end_types)
{
	apol_domain_trans_t *cur = NULL, *prev = NULL;
	size_t i = 0;

	if (!trans || !end_types) {
		errno = EINVAL;
		return -1;
	}

	for (cur = *trans; cur;) {
		if (!apol_vector_get_index(end_types, (void*)cur->end_type, NULL, NULL, &i)) {
			prev = cur;
			cur = cur->next;
			continue;
		}
		if (prev) {
			prev->next = cur->next;
		} else {
			*trans = cur->next;
		}
		cur->next = NULL;
		apol_domain_trans_destroy(&cur);
		if (prev) {
			cur = prev->next;
		} else {
			cur = *trans;
		}
	}

	return 0;
}

/* filter list of transitions to include only transitions
 * with a start type in the provided list */
static int apol_domain_trans_filter_start_types(apol_domain_trans_t **trans, apol_vector_t *start_types)
{
	apol_domain_trans_t *cur = NULL, *prev = NULL;
	size_t i = 0;

	if (!trans || !start_types) {
		errno = EINVAL;
		return -1;
	}

	for (cur = *trans; cur;) {
		if (!apol_vector_get_index(start_types, cur->start_type, NULL, NULL, &i)) {
			prev = cur;
			cur = cur->next;
			continue;
		}
		if (prev) {
			prev->next = cur->next;
		} else {
			*trans = cur->next;
		}
		cur->next = NULL;
		apol_domain_trans_destroy(&cur);
		if (prev) {
			cur = prev->next;
		} else {
			cur = *trans;
		}
	}

	return 0;
}

/* filter list of transitions to include only transitions
 * with an end type that has access to at least one of the provided
 * access_types for at least one of the object & permission sets */
static int apol_domain_trans_filter_access(apol_domain_trans_t **trans, apol_vector_t *access_types, apol_vector_t *obj_perm_sets, apol_policy_t *policy)
{
	apol_domain_trans_t *cur = NULL, *prev = NULL;
	size_t i, j, k;
	int error = 0;
	qpol_type_t *type = NULL;
	char *tmp = NULL;
	apol_avrule_query_t *avq = NULL;
	apol_obj_perm_t *op = NULL;
	apol_vector_t *v = NULL;

	if (!trans || !access_types || !obj_perm_sets || !policy) {
		errno = EINVAL;
		return -1;
	}

	if (!(*trans))
		return 0; /* list already empty */

	avq = apol_avrule_query_create();
	if (!avq) {
		error = errno;
		goto exit_error;
	}
	apol_avrule_query_set_rules(policy, avq, QPOL_RULE_ALLOW);

	for (cur = *trans; cur;) {
		qpol_type_get_name(policy->qh, policy->p, cur->end_type, &tmp);
		apol_avrule_query_set_source(policy, avq, tmp, 1);
		for (i = 0; i < apol_vector_get_size(access_types); i++) {
			type = apol_vector_get_element(access_types, i);
			qpol_type_get_name(policy->qh, policy->p, type, &tmp);
			apol_avrule_query_set_target(policy, avq, tmp, 1);
			for (j = 0; j < apol_vector_get_size(obj_perm_sets); j++) {
				apol_avrule_query_append_class(policy, avq, NULL);
				op = apol_vector_get_element(obj_perm_sets, j);
				apol_avrule_query_append_class(policy, avq, apol_obj_perm_get_obj_name(op));
				apol_avrule_query_append_perm(policy, avq, NULL);
				for (k = 0; k < apol_vector_get_size(apol_obj_perm_get_perm_vector(op)); k++) {
					tmp = apol_vector_get_element(apol_obj_perm_get_perm_vector(op), k);
					apol_avrule_query_append_perm(policy, avq, tmp);
				}
				apol_get_avrule_by_query(policy, avq, &v);
				apol_vector_cat(cur->access_rules, v);
				apol_vector_destroy(&v, NULL);
			}
		}
		if (apol_vector_get_size(cur->access_rules)) {
			prev = cur;
			cur = cur->next;
			continue;
		}
		if (prev) {
			prev->next = cur->next;
		} else {
			*trans = cur->next;
		}
		cur->next = NULL;
		apol_domain_trans_destroy(&cur);
		if (prev) {
			cur = prev->next;
		} else {
			cur = *trans;
		}
	}

	return 0;

exit_error:
	apol_avrule_query_destroy(&avq);
	errno = error;
	return -1;
}

/* public functions */
int apol_policy_domain_trans_table_build(apol_policy_t *policy)
{
	size_t i;
	unsigned char rule_type = 0x00;
	apol_avrule_query_t *avq = NULL;
	apol_terule_query_t *teq = NULL;
	qpol_avrule_t *avrule = NULL;
	qpol_terule_t *terule = NULL;
	qpol_iterator_t *iter = NULL;
	char *tmp = NULL;
	apol_vector_t *v = NULL;
	int error = 0;
	unsigned int policy_version = 0;

	if (!policy) {
		errno = EINVAL;
		return -1;
	}

	if (policy->domain_trans_table) {
		return 0; /* already built */
	}

	policy->domain_trans_table = apol_domain_trans_table_new(policy);
	if (!policy->domain_trans_table) {
		error = errno;
		ERR(policy, "Error building domain transition table: %s", strerror(error));
		goto err;
	}

	qpol_policy_get_policy_version(policy->qh, policy->p, &policy_version);

	avq = apol_avrule_query_create();
	apol_avrule_query_set_rules(policy, avq, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, avq, "process");
	apol_avrule_query_append_perm(policy, avq, "transition");
	apol_get_avrule_by_query(policy, avq, &v);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		avrule = apol_vector_get_element(v, i);
		if (apol_domain_trans_table_add_rule(policy, APOL_DOMAIN_TRANS_RULE_PROC_TRANS, (void*)avrule)) {
			error = errno;
			goto err;
		}
	}
	apol_vector_destroy(&v,  NULL);
	if (policy_version >= 15) {
		apol_avrule_query_append_perm(policy, avq, NULL);
		apol_avrule_query_append_perm(policy, avq, "setexec");
		apol_get_avrule_by_query(policy, avq, &v);
		for (i = 0; i < apol_vector_get_size(v); i++) {
			avrule = apol_vector_get_element(v, i);
			if (apol_domain_trans_table_add_rule(policy, APOL_DOMAIN_TRANS_RULE_SETEXEC, (void*)avrule)) {
				error = errno;
				goto err;
			}
		}
		apol_vector_destroy(&v,  NULL);
	}
	apol_avrule_query_append_class(policy, avq, NULL);
	apol_avrule_query_append_perm(policy, avq, NULL);

	apol_avrule_query_append_class(policy, avq, "file");
	apol_get_avrule_by_query(policy, avq, &v);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		avrule = apol_vector_get_element(v, i);
		if (qpol_avrule_get_perm_iter(policy->qh, policy->p, avrule, &iter)) {
			error = errno;
			goto err;
		}
		for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
			qpol_iterator_get_item(iter, (void**)&tmp);
			rule_type = 0x00;
			if (!strcmp(tmp, "execute")) {
				rule_type |= APOL_DOMAIN_TRANS_RULE_EXEC;
			} else if (!strcmp(tmp, "entrypoint")) {
				rule_type |= APOL_DOMAIN_TRANS_RULE_ENTRYPOINT;
			} else if (!strcmp(tmp, "execute_no_trans")) {
				rule_type |= APOL_DOMAIN_TRANS_RULE_EXEC_NO_TRANS;
			}
		}
		qpol_iterator_destroy(&iter);
		if (rule_type) {
			if (apol_domain_trans_table_add_rule(policy, rule_type, (void*)avrule)) {
				error = errno;
				goto err;
			}
		}
	}
	apol_vector_destroy(&v,  NULL);
	apol_avrule_query_destroy(&avq);

	teq = apol_terule_query_create();
	apol_terule_query_set_rules(policy, teq, QPOL_RULE_TYPE_TRANS);
	apol_terule_query_append_class(policy, teq, "process");
	apol_get_terule_by_query(policy, teq, &v);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		terule = apol_vector_get_element(v, i);
		if (apol_domain_trans_table_add_rule(policy, APOL_DOMAIN_TRANS_RULE_TYPE_TRANS, (void*)terule)) {
			error = errno;
			goto err;
		}
	}
	apol_vector_destroy(&v,  NULL);
	apol_terule_query_destroy(&teq);

	return 0;

err:
	apol_vector_destroy(&v,  NULL);
	apol_terule_query_destroy(&teq);
	apol_avrule_query_destroy(&avq);
	qpol_iterator_destroy(&iter);
	apol_domain_trans_table_destroy(&policy->domain_trans_table);
	errno = error;
	return -1;
}

void apol_domain_trans_table_destroy(apol_domain_trans_table_t **table)
{
	int i;

	if (!table || !(*table))
		return;

	for (i = 0; i < (*table)->size; i++) {
		apol_domain_trans_dom_node_free(&((*table)->dom_list[i]));
		apol_domain_trans_exec_node_free(&((*table)->exec_list[i]));
	}

	free((*table)->dom_list);
	free((*table)->exec_list);
	free(*table);
	*table = NULL;
}

void apol_domain_trans_table_reset(apol_policy_t *policy)
{
	size_t i, j;
	apol_domain_trans_rule_t *rule = NULL;
	apol_domain_trans_table_t *table = NULL;

	if (!policy) {
		errno = EINVAL;
		return;
	}

	table = policy->domain_trans_table;
	if (!table) {
		errno = EINVAL;
		return;
	}

	for (i = 0; i < table->size; i++) {
		for (j = 0; j < apol_vector_get_size(table->dom_list[i].proc_trans_rules); j++) {
			rule = apol_vector_get_element(table->dom_list[i].proc_trans_rules, j);
			rule->used = FALSE;
		}
		for (j = 0; j < apol_vector_get_size(table->dom_list[i].type_trans_rules); j++) {
			rule = apol_vector_get_element(table->dom_list[i].type_trans_rules, j);
			rule->used = FALSE;
		}
		for (j = 0; j < apol_vector_get_size(table->dom_list[i].ep_rules); j++) {
			rule = apol_vector_get_element(table->dom_list[i].ep_rules, j);
			rule->used = FALSE;
		}
		/* setexec rules do not use the used flag */
		for (j = 0; j < apol_vector_get_size(table->exec_list[i].ep_rules); j++) {
			rule = apol_vector_get_element(table->exec_list[i].ep_rules, j);
			rule->used = FALSE;
		}
		for (j = 0; j < apol_vector_get_size(table->exec_list[i].exec_rules); j++) {
			rule = apol_vector_get_element(table->exec_list[i].exec_rules, j);
			rule->used = FALSE;
		}
	}
}

apol_domain_trans_analysis_t *apol_domain_trans_analysis_create(void)
{
	apol_domain_trans_analysis_t *new_dta = NULL;
	int error = 0;

	if (!(new_dta = calloc(1, sizeof(apol_domain_trans_analysis_t)))) {
		error = errno;
		goto err;
	}

	new_dta->valid = APOL_DOMAIN_TRANS_SEARCH_VALID; /* by default search only valid transitions */

	return new_dta;

err:
	apol_domain_trans_analysis_destroy(&new_dta);
	errno = error;
	return NULL;
}

void apol_domain_trans_analysis_destroy(apol_domain_trans_analysis_t **dta)
{
	if (!dta || !(*dta))
		return;

	free((*dta)->start_type);
	free((*dta)->result);
	apol_vector_destroy(&((*dta)->access_types), free);
	apol_vector_destroy(&((*dta)->access_class_perms), apol_obj_perm_free);
	apol_regex_destroy(&((*dta)->result_regex));
	free(*dta);
	*dta = NULL;
}

int apol_domain_trans_analysis_set_direction(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, unsigned char direction)
{
	if (!dta || (direction != APOL_DOMAIN_TRANS_DIRECTION_FORWARD && direction != APOL_DOMAIN_TRANS_DIRECTION_REVERSE)) {
		ERR(policy, "Error setting analysis direction: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	dta->direction = direction;

	return 0;
}

int apol_domain_trans_analysis_set_valid(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, unsigned char valid)
{
	if (!dta || valid & ~(APOL_DOMAIN_TRANS_SEARCH_BOTH)) {
		ERR(policy, "Error setting analysis validity flag: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	dta->valid = valid;

	return 0;
}

int apol_domain_trans_analysis_set_start_type(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, const char *type_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta || !type_name) {
		ERR(policy, "Error setting analysis start type: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!(tmp = strdup(type_name))) {
		error = errno;
		ERR(policy, "Error setting analysis start type: %s", strerror(error));
		errno = error;
		return -1;
	}

	free(dta->start_type);
	dta->start_type = tmp;

	return 0;
}

int apol_domain_trans_analysis_set_result_regex(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, const char *regex)
{
	if (!dta) {
		ERR(policy, "Error setting analysis result expression: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!regex) {
		apol_regex_destroy(&dta->result_regex);
		return 0;
	}

	return apol_query_set(policy, &dta->result, &dta->result_regex, regex);
}

int apol_domain_trans_analysis_append_access_type(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, const char *type_name)
{
	char *tmp = NULL;
	int error = 0;

	if (!dta) {
		ERR(policy, "Error appending type to analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!dta->access_types) {
		if (!(dta->access_types = apol_vector_create())) {
			error = errno;
			ERR(policy, "Error appending type to analysis: %s", strerror(error));
			errno = error;
			return -1;
		}
	}

	if (!type_name) {
		apol_vector_destroy(&dta->access_types, free);
		return 0;
	}

	if (!(tmp = strdup(type_name))) {
		error = errno;
		ERR(policy, "Error appending type to analysis: %s", strerror(error));
		errno = error;
		return -1;
	}

	if (apol_vector_append(dta->access_types, tmp)) {
		error = errno;
		free(tmp);
		ERR(policy, "Error appending type to analysis: %s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

static int compare_class_perm_by_class_name(const void *in_op, const void *class_name, void *unused __attribute__ ((unused)))
{
	const apol_obj_perm_t *op = (const apol_obj_perm_t*)in_op;
	const char *name = (const char*)class_name;

	return strcmp(apol_obj_perm_get_obj_name(op), name);
}

int apol_domain_trans_analysis_append_class_perm(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, const char *class_name, const char *perm_name)
{
	int error = 0;
	apol_obj_perm_t *op = NULL;
	size_t i;

	if (!dta) {
		ERR(policy, "Error adding class and permission to analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!class_name) {
		apol_vector_destroy(&dta->access_class_perms, apol_obj_perm_free);
		return 0;
	}

	if (!(dta->access_class_perms)) {
		if (!(dta->access_class_perms = apol_vector_create())) {
			error = errno;
			ERR(policy, "Error adding class and permission to analysis: %s", strerror(error));
			errno = error;
			return -1;
		}
	}

	if (apol_vector_get_index(dta->access_class_perms, (void*)class_name, compare_class_perm_by_class_name, NULL, &i) < 0) {
		if (perm_name) {
			if ((op = apol_obj_perm_create())) {
				error = errno;
				ERR(policy, "Error adding class and permission to analysis: %s", strerror(error));
				errno = error;
				return -1;
			}
			if (apol_obj_perm_set_obj_name(op, class_name) ||
                            apol_obj_perm_append_perm(op, perm_name) ||
                            apol_vector_append(dta->access_class_perms, op)) {
				error = errno;
				ERR(policy, "Error adding class and permission to analysis: %s", strerror(error));
				apol_obj_perm_free(op);
				errno = error;
				return -1;
			}
		} else {
			return 0; /* noting to clear; done */
		}
	} else {
		op = apol_vector_get_element(dta->access_class_perms, i);
		if (apol_obj_perm_append_perm(op, perm_name)) {
			error = errno;
			ERR(policy, "Error adding class and permission to analysis: %s", strerror(error));
			errno = error;
			return -1;
		}
	}

	return 0;
}

int apol_domain_trans_analysis_do(apol_policy_t *policy, apol_domain_trans_analysis_t *dta, apol_vector_t **results)
{
	int error = 0;
	apol_domain_trans_t *trans_list = NULL, *cur = NULL, *next = NULL;
	apol_domain_trans_result_t *tmp_result = NULL;
	apol_vector_t *type_v = NULL;
	size_t i;
	qpol_type_t *start_type = NULL, *tmp_type = NULL;

	if (!policy || !dta || !results) {
		ERR(policy, "Unable to perform analysis: %s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	/* build table if not already present */
	if (!(policy->domain_trans_table)) {
		if (apol_policy_domain_trans_table_build(policy))
			return -1; /* errors already reported by build function */
	}

	/* validate analysis options */
	if (dta->direction == 0 ||
	    dta->valid & ~(APOL_DOMAIN_TRANS_SEARCH_BOTH) ||
	    (apol_vector_get_size(dta->access_types) && !apol_vector_get_size(dta->access_class_perms)) ||
	    (!apol_vector_get_size(dta->access_types) && apol_vector_get_size(dta->access_class_perms)) ||
	    (apol_vector_get_size(dta->access_types) && apol_vector_get_size(dta->access_class_perms) &&
	     dta->direction == APOL_DOMAIN_TRANS_DIRECTION_REVERSE) ||
	    !(dta->start_type) ) {
		error = EINVAL;
		ERR(policy, "Unable to perform analysis: Invalid analysis options");
		goto err;
	}

	/* get starting type */
	if (qpol_policy_get_type_by_name(policy->qh, policy->p, dta->start_type, &start_type)) {
		error = errno;
		ERR(policy, "Unable to perform analysis: Invalid starting type %s", dta->start_type);
		goto err;
	}

	/* get all trnsitions for the requested direction */
	if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_REVERSE) {
		if (apol_domain_trans_table_get_all_reverse_trans(policy, &trans_list, start_type)) {
			error = errno;
			ERR(policy, "Error performing domain transition analysis: %s", strerror(error));
			goto err;
		}
	} else {
		if (apol_domain_trans_table_get_all_forward_trans(policy, &trans_list, start_type)) {
			error = errno;
			ERR(policy, "Error performing domain transition analysis: %s", strerror(error));
			goto err;
		}
	}

	/* if filtering by validity do that first */
	if (dta->valid != APOL_DOMAIN_TRANS_SEARCH_BOTH) {
		if (apol_domain_trans_filter_valid(&trans_list, (dta->valid & APOL_DOMAIN_TRANS_SEARCH_VALID))) {
			error = errno;
			ERR(policy, "Error processing results: %s", strerror(error));
			goto err;
		}
	}

	/* next filtering by result type if requested */
	if (dta->result) {
		if ((type_v = apol_query_create_candidate_type_list(policy, dta->result, 1, 0))) {
			error = errno;
			ERR(policy, "Error processing results: %s", strerror(error));
			goto err;
		}
		if (!apol_vector_get_size(type_v)) {
			error = EINVAL;
			ERR(policy, "Error processing results: Result filter does not match any types");
			goto err;
		}
		if (dta->direction == APOL_DOMAIN_TRANS_DIRECTION_REVERSE) {
			if (apol_domain_trans_filter_start_types(&trans_list, type_v)) {
				error = errno;
				ERR(policy, "Error processing results: %s", strerror(error));
				goto err;
			}
		} else {
			if (apol_domain_trans_filter_end_types(&trans_list, type_v)) {
				error = errno;
				ERR(policy, "Error processing results: %s", strerror(error));
				goto err;
			}
		}
		apol_vector_destroy(&type_v, NULL);
	}

	/* if access filtering is requested do it last */
	if (apol_vector_get_size(dta->access_types)) {
		if ((type_v = apol_vector_create())) {
			error = errno;
			ERR(policy, "Error building access filters: %s", strerror(error));
			goto err;
		}
		for (i = 0; i < apol_vector_get_size(dta->access_types); i++) {
			if (qpol_policy_get_type_by_name(policy->qh, policy->p, apol_vector_get_element(dta->access_types, i), &tmp_type)) {
				error = errno;
				ERR(policy, "Error building access filters: %s", strerror(error));
				goto err;
			}
			if (apol_vector_append_unique(type_v, tmp_type, NULL, NULL)) {
				error = errno;
				ERR(policy, "Error building access filters: %s", strerror(error));
				goto err;
			}
		}
		if (apol_domain_trans_filter_access(&trans_list, type_v, dta->access_class_perms, policy)) {
			error = errno;
			ERR(policy, "Error processing results: %s", strerror(error));
			goto err;
		}
		apol_vector_destroy(&type_v, NULL);
	}

	/* build result vector */
	if (!(*results = apol_vector_create())) {
		error = errno;
		ERR(policy, "Error compiling results: %s", strerror(error));
		goto err;
	}
	for (cur = trans_list; cur; cur = next) {
		next = cur->next;
		if (!(tmp_result = calloc(1, sizeof(apol_domain_trans_result_t)))) {
			error = errno;
			ERR(policy, "Error compiling results: %s", strerror(error));
			goto err;
		}
		tmp_result->start_type = cur->start_type;
		tmp_result->ep_type = cur->ep_type;
		tmp_result->end_type = cur->end_type;
		tmp_result->proc_trans_rule = cur->proc_trans_rule;
		tmp_result->ep_rule = cur->ep_rule;
		tmp_result->exec_rule = cur->exec_rule;
		tmp_result->setexec_rule = cur->setexec_rule;
		tmp_result->type_trans_rule = cur->type_trans_rule;
		tmp_result->valid = cur->valid;
		if (cur->access_rules) {
			if (!(tmp_result->access_rules = apol_vector_create_from_vector(cur->access_rules))) {
				error = errno;
				ERR(policy, "Error compiling results: %s", strerror(error));
				goto err;
			}
		}
		if (apol_vector_append(*results, tmp_result)) {
			error = errno;
			ERR(policy, "Error compiling results: %s", strerror(error));
			goto err;
		}
		cur->next = NULL;
		apol_domain_trans_destroy(&cur);
	}

	return 0;

err:
	apol_domain_trans_destroy(&trans_list);
	apol_vector_destroy(&type_v, NULL);
	apol_vector_destroy(results, apol_domain_trans_result_free);
	errno = error;
	return -1;
}

void apol_domain_trans_result_free(void *dtr)
{
	apol_domain_trans_result_t *res = (apol_domain_trans_result_t*)dtr;

	if (!res)
		return;

	apol_vector_destroy(&res->access_rules, NULL);
	free(res);
}

qpol_type_t *apol_domain_trans_result_get_start_type(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->start_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_type_t *apol_domain_trans_result_get_entrypoint_type(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->ep_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_type_t *apol_domain_trans_result_get_end_type(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->end_type;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_avrule_t *apol_domain_trans_result_get_proc_trans_rule(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->proc_trans_rule;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_avrule_t *apol_domain_trans_result_get_entrypoint_rule(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->ep_rule;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_avrule_t *apol_domain_trans_result_get_exec_rule(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->exec_rule;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_avrule_t *apol_domain_trans_result_get_setexec_rule(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->setexec_rule;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

qpol_terule_t *apol_domain_trans_result_get_type_trans_rule(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->type_trans_rule;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

int apol_domain_trans_result_is_trans_valid(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->valid;
	} else {
		errno = EINVAL;
		return 0;
	}
}

apol_vector_t *apol_domain_trans_result_get_access_rules(apol_domain_trans_result_t *dtr)
{
	if (dtr) {
		return dtr->access_rules;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

int apol_domain_trans_table_verify_trans(apol_policy_t *policy, qpol_type_t *start_dom, qpol_type_t *ep_type, qpol_type_t *end_dom)
{
	apol_domain_trans_table_t *table = NULL;
	int retv;
	int missing_rules = 0;
	uint32_t start_val = 0, ep_val = 0, end_val = 0, dflt_val = 0;
	unsigned int policy_version = 0;
	apol_domain_trans_rule_t *rule = NULL;

	if (!policy || !start_dom || !ep_type || !end_dom) {
		errno = EINVAL;
		return -1;
	}

	/* build table if not already present */
	if (!(policy->domain_trans_table)) {
		if (apol_policy_domain_trans_table_build(policy))
			return -1; /* errors already reported by build function */
	}

	table = policy->domain_trans_table;
	qpol_policy_get_policy_version(policy->qh, policy->p, &policy_version);

	qpol_type_get_value(policy->qh, policy->p, start_dom, &start_val);
	qpol_type_get_value(policy->qh, policy->p, ep_type, &ep_val);
	qpol_type_get_value(policy->qh, policy->p, end_dom, &end_val);

	retv = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].proc_trans_rules, end_dom);
	if (retv < 0)
		missing_rules |= APOL_DOMAIN_TRANS_RULE_PROC_TRANS;
	retv = apol_domain_trans_find_rule_for_type(policy, table->exec_list[ep_val - 1].exec_rules, start_dom);
	if (retv < 0)
		missing_rules |= APOL_DOMAIN_TRANS_RULE_EXEC;
	retv = apol_domain_trans_find_rule_for_type(policy, table->dom_list[end_val - 1].ep_rules, start_dom);
	if (retv < 0)
		missing_rules |= APOL_DOMAIN_TRANS_RULE_ENTRYPOINT;

	/* for version 15 and later you must either have a type_transition rule or setexec permission */
	if (policy_version >= 15) {
		retv = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].type_trans_rules, ep_type);
		if (retv >= 0) {
			rule = apol_vector_get_element(table->dom_list[start_val - 1].type_trans_rules, retv);
			qpol_type_get_value(policy->qh, policy->p, rule->dflt, &dflt_val);
		}
		if (retv < 0 || dflt_val != end_val) { /* no type_transition or different default */
			retv = apol_domain_trans_find_rule_for_type(policy, table->dom_list[start_val - 1].setexec_rules, start_dom);
			if (retv < 0)
				missing_rules |= APOL_DOMAIN_TRANS_RULE_SETEXEC;
			if (!dflt_val)
				missing_rules |= APOL_DOMAIN_TRANS_RULE_TYPE_TRANS; /* only missing if none was found, not if different default */
		}
	}

	return missing_rules;
}
