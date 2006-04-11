/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jmowery@tresys.com 
 */ 

#include "dta.h"
#include "policy.h"
#include "analysis.h"
#include "semantic/avhash.h"
#include "semantic/avsemantics.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

/* internal functions */
static int dta_find_rule_for_type(dta_rule_t *rule_list, int list_sz, int type)
{
	int i = list_sz / 2;
	int left = 0, right = list_sz - 1;

	if (!rule_list || !list_sz)
		return -1; /* empty list, not necessarily an error */

	/* potentially a lot of entries but list is sorted so 
	 * we can do a binary search */
	do {
		if (rule_list[i].type_idx == type) {
			return i;
		} else if (rule_list[i].type_idx < type) {
			left = i+1;
			i += ((right - i)/2 + (right - i)%2);
		} else {
			right = i-1;
			i -= ((i - left)/2 + (i - left)%2);
		}
	} while (right >= left);

	return -1;
}

static int dta_rule_compare(const void *a, const void *b)
{
	const dta_rule_t *rule_a = (const dta_rule_t*)a;
	const dta_rule_t *rule_b = (const dta_rule_t*)b;
	
	return (rule_a->type_idx - rule_b->type_idx);
}

static int dta_add_rule_to_list(dta_rule_t **rule_list, int *list_sz, int type, int dflt, int idx, bool_t has_no_trans)
{
	int retv, tmp;

	if (!rule_list || !list_sz) {
		errno = EINVAL;
		return -1;
	}

	/* if rule with same key already exists add new rule index only */
	retv = dta_find_rule_for_type(*rule_list, *list_sz, type);
	if (retv < 0) {
		*rule_list = (dta_rule_t*)realloc(*rule_list, (*list_sz + 1) * sizeof(dta_rule_t));
		if (!(*rule_list))
			return -1;
		(*rule_list)[*list_sz].type_idx = type;
		if(has_no_trans)
			(*rule_list)[*list_sz].has_no_trans = TRUE;
		else
			(*rule_list)[*list_sz].has_no_trans = FALSE;
		(*rule_list)[*list_sz].num_rules = 1;
		(*rule_list)[*list_sz].rules = (int*)malloc(sizeof(int));
		if (!(*rule_list)[*list_sz].rules)
			return -1;
		(*rule_list)[*list_sz].rules[0] = idx;
		(*rule_list)[*list_sz].dflt_idx = dflt;
		(*rule_list)[*list_sz].used = FALSE;
		(*list_sz)++;
		qsort(*rule_list, *list_sz, sizeof(dta_rule_t), dta_rule_compare);
	} else {
		tmp = find_int_in_array(idx, (*rule_list)[retv].rules, (*rule_list)[retv].num_rules);
		if (tmp < 0) {
			tmp = add_i_to_a(idx, &((*rule_list)[retv].num_rules), &((*rule_list)[retv].rules));
			if (tmp) {
				errno = ENOMEM;
				return -1;
			}
		}
		if (!(*rule_list)[retv].has_no_trans && has_no_trans) {
			(*rule_list)[retv].has_no_trans = TRUE;
		}
	}

	return 0;
}

static trans_domain_t *dta_find_trans_type_in_dta(domain_trans_analysis_t *dta, int trans_type)
{
	llist_node_t *node = NULL;
	trans_domain_t *trans_dom = NULL;

	if (!dta) {
		errno = EINVAL;
		return NULL;
	}

	for (node = dta->trans_domains->head; node; node = node->next) {
		trans_dom = (trans_domain_t*)node->data;
		if (trans_dom->trans_type == trans_type)
			return trans_dom;
	}

	errno = 0; /* no error - item was not found */
	return NULL;
}

/* "public" functions */
dta_table_t *dta_table_new(policy_t *policy)
{
	dta_table_t *new_table = NULL;
	int retv;

	if (!policy || policy->num_types < 1) {
		errno = EINVAL;
		return NULL;
	}

	new_table = (dta_table_t*)calloc(1, sizeof(dta_table_t));
	if (!new_table) {
		return NULL;
	}

	new_table->size = policy->num_types;

	new_table->dom_list = (dta_dom_node_t*)calloc(new_table->size, sizeof(dta_dom_node_t));
	if (!new_table->dom_list) {
		retv = errno;
		free(new_table);
		errno = retv;
		return NULL;
	}
	new_table->exec_list = (dta_exec_node_t*)calloc(new_table->size, sizeof(dta_exec_node_t));
	if (!new_table->exec_list) {
		retv = errno;
		free(new_table->dom_list);
		free(new_table);
		errno = retv;
		return NULL;
	}

	return new_table;
}

dta_trans_t *dta_trans_new()
{
	dta_trans_t *new_trans = NULL;

	new_trans = (dta_trans_t*)calloc(1, sizeof(dta_trans_t));
	if (!new_trans) {
		return NULL;
	}

	/* set the following indexes to -1 */
	new_trans->start_type = new_trans->ep_type = new_trans->end_type = new_trans->type_trans_rule = -1;

	return new_trans;
}

void dta_table_free(dta_table_t *table)
{
	int i;

	if (!table)
		return;

	for (i = 0; i < table->size; i++) {
		dta_dom_node_free(&(table->dom_list[i]));
		dta_exec_node_free(&(table->exec_list[i]));
	}

	free(table->dom_list);
	free(table->exec_list);
	table->dom_list = NULL;
	table->exec_list = NULL;
	table->size = 0;
}

void dta_dom_node_free(dta_dom_node_t *node)
{
	int i;
	if (!node)
		return;

	for (i = 0; i < node->num_proc_trans_rules; i++)
		dta_rule_free(&(node->proc_trans_rules[i]));

	for (i = 0; i < node->num_ep_rules; i++)
		dta_rule_free(&(node->ep_rules[i]));

	for (i = 0; i < node->num_type_trans_rules; i++)
		dta_rule_free(&(node->type_trans_rules[i]));

	free(node->proc_trans_rules);
	free(node->ep_rules);
	free(node->type_trans_rules);
	node->proc_trans_rules = NULL;
	node->ep_rules = NULL;
	node->type_trans_rules = NULL;
	node->num_proc_trans_rules = 0;
	node->num_ep_rules = 0;
	node->num_type_trans_rules = 0;
}

void dta_exec_node_free(dta_exec_node_t *node)
{
	int i;

	if (!node)
		return;

	for (i = 0; i < node->num_exec_rules; i++)
		dta_rule_free(&(node->exec_rules[i]));

	for (i = 0; i < node->num_ep_rules; i++)
		dta_rule_free(&(node->ep_rules[i]));

	free(node->ep_rules);
	free(node->exec_rules);
	node->ep_rules = NULL;
	node->exec_rules = NULL;
	node->num_ep_rules = 0;
	node->num_exec_rules = 0;
}

void dta_rule_free(dta_rule_t *rule)
{
	if (!rule)
		return;

	free(rule->rules);
	rule->rules = NULL;
	rule->num_rules = 0;
	rule->type_idx = -1;
	rule->used = FALSE;
	rule->has_no_trans = FALSE;
}

void dta_trans_destroy(dta_trans_t **trans)
{
	dta_trans_t *trx = NULL, *next = NULL;
	
	if (!trans || !(*trans))
		return;

	for (trx = *trans; trx; trx = next) {
		free(trx->proc_trans_rules);
		free(trx->ep_rules);
		free(trx->exec_rules);
		free(trx->access_rules);
		next = trx->next;
		free(trx);
	}

	*trans = NULL;
}

void dta_table_reset_used_flags(dta_table_t *table)
{
	int i, j;

	if (!table) {
		errno = EINVAL;
		return;
	}

	for (i = 0; i < table->size; i++) {
		for (j = 0; j < table->dom_list[i].num_proc_trans_rules; j++)
			table->dom_list[i].proc_trans_rules[j].used = FALSE;
		for (j = 0; j < table->dom_list[i].num_type_trans_rules; j++)
			table->dom_list[i].type_trans_rules[j].used = FALSE;
		for (j = 0; j < table->dom_list[i].num_ep_rules; j++)
			table->dom_list[i].ep_rules[j].used = FALSE;
		for (j = 0; j < table->exec_list[i].num_exec_rules; j++)
			table->exec_list[i].exec_rules[j].used = FALSE;
		for (j = 0; j < table->exec_list[i].num_ep_rules; j++)
			table->exec_list[i].ep_rules[j].used = FALSE;
	}
}

int dta_table_build(dta_table_t *table, policy_t *policy)
{
	int i, retv;
	avh_node_t *cur;
	unsigned char rule_type = 0x00;
	int proc_idx, file_idx, chr_file_idx; /* object class index */
	int trans_idx, exec_idx, exec_no_trans_idx, ep_idx; /* permission index */
	avh_rule_t *hash_rule = NULL;

	if (!table || !policy) {
		errno = EINVAL;
		return -1;
	}

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			/*build_hashtab does not set errno, and condition cannot be detected here */
			return -1;
		}
	}

	proc_idx = get_obj_class_idx("process", policy);
	file_idx = get_obj_class_idx("file", policy);
	chr_file_idx = get_obj_class_idx("chr_file", policy);

	trans_idx = get_perm_idx("transition", policy);
	exec_idx = get_perm_idx("execute", policy);
	exec_no_trans_idx = get_perm_idx("execute_no_trans", policy);
	ep_idx = get_perm_idx("entrypoint", policy);

	/* here we walk the entire hash table once through
	 * each rule that matches one of the transition criteria 
	 * is inserted into the correct list(s) in the table */
	for (i = 0; i < AVH_SIZE; i++) {
		for (cur = policy->avh.tab[i]; cur; cur = cur->next) {
			rule_type = 0x00;
			if (cur->key.rule_type == RULE_TE_ALLOW) {
				if (cur->key.cls == proc_idx) {
					if (find_int_in_array(trans_idx, cur->data, cur->num_data) != -1) {
						/* have a process transition rule */
						rule_type = AP_DTA_RULE_PROC_TRANS;
						for (hash_rule = cur->rules; hash_rule; hash_rule = hash_rule->next) {
							if (does_av_rule_use_perms(hash_rule->rule, 1, &trans_idx, 1, policy)) {
								retv = dta_table_add_rule(table, rule_type, cur->key.src, cur->key.tgt, 0, hash_rule->rule);
								if (retv)
									return -1;
							}
						}
					}
				} else if (cur->key.cls == file_idx || cur->key.cls == chr_file_idx) {
					if (find_int_in_array(ep_idx, cur->data, cur->num_data) != -1) {
						/* have an entrypoint rule */
						rule_type = AP_DTA_RULE_ENTRYPOINT;
						for (hash_rule = cur->rules; hash_rule; hash_rule = hash_rule->next) {
							if (does_av_rule_use_perms(hash_rule->rule, 1, &ep_idx, 1, policy)) {
								retv = dta_table_add_rule(table, rule_type, cur->key.src, cur->key.tgt, 0, hash_rule->rule);
								if (retv)
									return -1;
							}
						}
					} 
					if (find_int_in_array(exec_idx, cur->data, cur->num_data) != -1) {
						/* have an execute rule */
						rule_type = AP_DTA_RULE_EXEC;
						if (find_int_in_array(exec_no_trans_idx, cur->data, cur->num_data) != -1)
							rule_type |= AP_DTA_RULE_EXEC_NO_TRANS;
						/* A note on execute_no_trans: 
						 * A type with execute_no_trans permission does not need to transition
						 * but will if a valid transition is possible. This permission is 
						 * tracked to prevent this case from showing up as an execute rule
						 * for a domain without a valid transition */
						for (hash_rule = cur->rules; hash_rule; hash_rule = hash_rule->next) {
							if (does_av_rule_use_perms(hash_rule->rule, 1, &exec_idx, 1, policy)) {
								retv = dta_table_add_rule(table, rule_type, cur->key.src, cur->key.tgt, 0, hash_rule->rule);
								if (retv)
									return -1;
							}
						}
					}
				}
			} else if (cur->key.rule_type == RULE_TE_TRANS && cur->key.cls == proc_idx) {
				/* have a type_transition rule
				 * Note: type_transition rules do not grant any permission and are optional
				 * when determining if a valid transition exists */
				retv = dta_table_add_rule(table, AP_DTA_RULE_TYPE_TRANS, cur->key.src, cur->key.tgt, policy->te_trans[cur->rules->rule].dflt_type.idx, cur->rules->rule);
				if (retv)
					return -1;
			} else {
				continue;
			}
		}
	}

	return 0;
}

int dta_table_add_rule(dta_table_t *table, unsigned char rule_type, 
	int src, int tgt, int dflt, int idx)
{
	int retv;

	if (!table) {
		errno = EINVAL;
		return -1;
	}

	switch (rule_type & ~(AP_DTA_RULE_EXEC_NO_TRANS)) {
	case AP_DTA_RULE_PROC_TRANS:
		retv = dta_add_rule_to_list(&(table->dom_list[src].proc_trans_rules), 
			&(table->dom_list[src].num_proc_trans_rules), 
			tgt, 0, idx, 0);
		if (retv)
			return -1;
		break;
	case AP_DTA_RULE_EXEC:
		retv = dta_add_rule_to_list(&(table->exec_list[tgt].exec_rules), 
			&(table->exec_list[tgt].num_exec_rules), 
			src, 0, idx, (rule_type & AP_DTA_RULE_EXEC_NO_TRANS));
		if (retv)
			return -1;
		break;
	case AP_DTA_RULE_ENTRYPOINT:
		retv = dta_add_rule_to_list(&(table->dom_list[src].ep_rules), 
			&(table->dom_list[src].num_ep_rules), 
			tgt, 0, idx, 0);
		if (retv)
			return -1;
		retv = dta_add_rule_to_list(&(table->exec_list[tgt].ep_rules), 
			&(table->exec_list[tgt].num_ep_rules), 
			src, 0, idx, 0);
		if (retv)
			return -1;
		break;
	case AP_DTA_RULE_TYPE_TRANS:
		retv = dta_add_rule_to_list(&(table->dom_list[src].type_trans_rules), 
			&(table->dom_list[src].num_type_trans_rules), 
			tgt, dflt, idx, 0);
		if (retv)
			return -1;
		break;
	default:
		errno = EINVAL;
		return -1;
		break;
	}

	return 0;
}

/* return values of verify_trans are as follows:
 * 0 success
 * -1 fatal error
 * otherwise a bitwise or of the missing rule types */
int dta_table_verify_trans(dta_table_t *table, int start_dom, int ep_type, int end_dom)
{
	int retv;
	int missing_rules = 0;

	if (!table || start_dom < 1 || ep_type < 1 || end_dom < 1 ||
		table->size < 1 || start_dom >= table->size || 
		ep_type >= table->size || end_dom >= table->size ) {
		errno = EINVAL;
		return -1;
	}

	retv = dta_find_rule_for_type(table->dom_list[start_dom].proc_trans_rules, table->dom_list[start_dom].num_proc_trans_rules, end_dom);
	if (retv < 0)
		missing_rules |= AP_DTA_RULE_PROC_TRANS;
	retv = dta_find_rule_for_type(table->exec_list[ep_type].exec_rules, table->exec_list[ep_type].num_exec_rules, start_dom);
	if (retv < 0)
		missing_rules |= AP_DTA_RULE_EXEC;
	retv = dta_find_rule_for_type(table->dom_list[end_dom].ep_rules, table->dom_list[end_dom].num_ep_rules, start_dom);
	if (retv < 0)
		missing_rules |= AP_DTA_RULE_ENTRYPOINT;

	return missing_rules;
}

int dta_table_get_all_trans(dta_table_t *table, dta_trans_t **trans, int start_idx)
{
	int i, j, retv, error = 0, tmp, cur_ep, cur_end;
	/* entry is the pointer to the new (yet to be inserted) node,
	 * cur_list is the dta_trans_t linked list for this start type,
	 * tail is the tail of that list. The trans pointer passed in
	 * is not changed except on successful completion of the call
	 * for this start_idx.  This allows successive calls to be made
	 * with most recent results prepended to trans */
	dta_trans_t *entry = NULL, *cur_list = NULL, *tail = NULL;

	if (!table || !trans || start_idx < -1 || start_idx >= table->size) {
		errno = EINVAL;
		return -1;
	}

	/* confirm each type_transition rule */
	for (i = 0; i < table->dom_list[start_idx].num_type_trans_rules; i++) {
		table->dom_list[start_idx].type_trans_rules[i].used = TRUE;
		entry = dta_trans_new();
		if (!entry) {
			error = errno;
			goto exit_error;
		}
		entry->start_type = start_idx;
		entry->ep_type = table->dom_list[start_idx].type_trans_rules[i].type_idx;
		entry->end_type = table->dom_list[start_idx].type_trans_rules[i].dflt_idx;
		entry->type_trans_rule = table->dom_list[start_idx].type_trans_rules[i].rules[0];

		/* find process transition rules */
		retv = dta_find_rule_for_type(table->dom_list[start_idx].proc_trans_rules, table->dom_list[start_idx].num_proc_trans_rules, table->dom_list[start_idx].type_trans_rules[i].dflt_idx);
		if (retv >= 0) {
			entry->num_proc_trans_rules = table->dom_list[start_idx].proc_trans_rules[retv].num_rules;
			if (entry->num_proc_trans_rules < 1) {
				error = EINVAL;
				goto exit_error;
			}
			entry->proc_trans_rules = (int*)malloc(entry->num_proc_trans_rules * sizeof(int));
			if (!entry->proc_trans_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->proc_trans_rules, table->dom_list[start_idx].proc_trans_rules[retv].rules, entry->num_proc_trans_rules * sizeof(int));
		}

		/* find execute rules */
		retv = dta_find_rule_for_type(table->exec_list[entry->ep_type].exec_rules, table->exec_list[entry->ep_type].num_exec_rules, start_idx);
		if (retv >= 0) {
			entry->num_exec_rules = table->exec_list[entry->ep_type].exec_rules[retv].num_rules;
			entry->num_exec_rules = table->exec_list[entry->ep_type].exec_rules[retv].used = TRUE;
			if (entry->num_exec_rules < 1) {
				error = EINVAL;
				goto exit_error;
			}
			entry->exec_rules = (int*)malloc(entry->num_exec_rules * sizeof(int));
			if (!entry->exec_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->exec_rules, table->exec_list[entry->ep_type].exec_rules[retv].rules, entry->num_exec_rules * sizeof(int));
		}

		/* find entrypoint rules */
		retv = dta_find_rule_for_type(table->exec_list[entry->ep_type].ep_rules, table->exec_list[entry->ep_type].num_ep_rules, table->dom_list[start_idx].type_trans_rules[i].dflt_idx);
		if (retv >= 0) {
			table->exec_list[entry->ep_type].ep_rules[retv].used = TRUE;
			entry->num_ep_rules = table->exec_list[entry->ep_type].ep_rules[retv].num_rules;
			if (entry->num_ep_rules < 1) {
				error = EINVAL;
				goto exit_error;
			}
			entry->ep_rules = (int*)malloc(entry->num_ep_rules * sizeof(int));
			if (!entry->ep_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->ep_rules, table->exec_list[entry->ep_type].ep_rules[retv].rules, entry->num_ep_rules * sizeof(int));
		}

		/* mark as valid if there is at least one of each required rules type */
		if (entry->num_ep_rules && entry->num_exec_rules && entry->num_proc_trans_rules)
			entry->valid = TRUE;
		entry->next = cur_list;
		cur_list = entry;
		if (!tail)
			tail = entry;
	}

	/* follow all process:transition rules */
	for (i = 0; i < table->dom_list[start_idx].num_proc_trans_rules; i++) {
		cur_end = table->dom_list[start_idx].proc_trans_rules[i].type_idx;
		if (cur_end == start_idx)
			continue; /* no transition occurs if start == end */
		table->dom_list[start_idx].proc_trans_rules[i].used = TRUE;
		/* number of entrypoint types */
		tmp = table->dom_list[cur_end].num_ep_rules;
		for (j = 0; j < tmp; j++) {
			cur_ep = table->dom_list[cur_end].ep_rules[j].type_idx;
			table->dom_list[cur_end].ep_rules[j].used = TRUE;
			retv = dta_find_rule_for_type(table->exec_list[cur_ep].ep_rules, table->exec_list[cur_ep].num_ep_rules, cur_end);
			if (table->exec_list[cur_ep].ep_rules[retv].used) {
				continue;
			}
			table->exec_list[cur_ep].ep_rules[retv].used = TRUE;
			entry = dta_trans_new();
			entry->start_type = start_idx;
			entry->ep_type = cur_ep;
			entry->end_type = cur_end;
			/* copy process transition rules */
			entry->num_proc_trans_rules = table->dom_list[start_idx].proc_trans_rules[i].num_rules;
			entry->proc_trans_rules = (int*)malloc(entry->num_proc_trans_rules * sizeof(int));
			if (!entry->proc_trans_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->proc_trans_rules, table->dom_list[start_idx].proc_trans_rules[i].rules, entry->num_proc_trans_rules * sizeof(int));
			/* copy entrypoint rules */
			entry->num_ep_rules = table->dom_list[cur_end].ep_rules[j].num_rules;
			if (entry->num_ep_rules < 1) {
				error = EINVAL;
				goto exit_error;
			}
			entry->ep_rules = (int*)malloc(entry->num_ep_rules * sizeof(int));
			if (!entry->ep_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->ep_rules, table->dom_list[cur_end].ep_rules[j].rules, entry->num_ep_rules * sizeof(int));
			/* find and copy any execute rules for this entrypoint type */
			retv = dta_find_rule_for_type(table->exec_list[cur_ep].exec_rules, table->exec_list[cur_ep].num_exec_rules, start_idx);
			if (retv >= 0) {
				entry->num_exec_rules = table->exec_list[cur_ep].exec_rules[retv].num_rules;
				table->exec_list[cur_ep].exec_rules[retv].used = TRUE;
				if (entry->num_exec_rules < 1) {
					error = EINVAL;
					goto exit_error;
				}
				entry->exec_rules = (int*)malloc(entry->num_exec_rules * sizeof(int));
				if (!entry->exec_rules) {
					error = errno;
					goto exit_error;
				}
				memcpy(entry->exec_rules, table->exec_list[cur_ep].exec_rules[retv].rules, entry->num_exec_rules * sizeof(int));
			}

			/* mark as valid if there is at least one of each required rules type */
			if (entry->num_proc_trans_rules && entry->num_ep_rules && entry->num_exec_rules)
				entry->valid = TRUE;
			entry->next = cur_list;
			cur_list = entry;
			if (!tail)
				tail = entry;
		}

		/* if there are no entrypoints record what rules there are */
		if (!tmp) {
			entry = dta_trans_new();
			entry->start_type = start_idx;
			entry->ep_type = -1;
			entry->end_type = cur_end;
			entry->num_proc_trans_rules = table->dom_list[start_idx].proc_trans_rules[i].num_rules;
			entry->proc_trans_rules = (int*)malloc(entry->num_proc_trans_rules * sizeof(int));
			if (!entry->proc_trans_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->proc_trans_rules, table->dom_list[start_idx].proc_trans_rules[i].rules, entry->num_proc_trans_rules * sizeof(int));
			entry->valid = FALSE;
			entry->next = cur_list;
			cur_list = entry;
			if (!tail)
				tail = entry;
		}
	}

	/* if results were found add to list */
	if (cur_list) {
		if (!tail) {
			error = EINVAL;
			goto exit_error;
		}
		tail->next = *trans;
		*trans = cur_list;
	}

	return 0;

exit_error:
	dta_trans_destroy(&entry);
	dta_trans_destroy(&cur_list);
	errno = error;
	return -1;
}

int dta_table_get_all_reverse_trans(dta_table_t *table, dta_trans_t **trans, int end_idx)
{
	int i, j, retv, error = 0, cur_ep, cur_start;
	/* entry is the pointer to the new (yet to be inserted) node,
	 * cur_list is the dta_trans_t linked list for this start type,
	 * tail is the tail of that list. The trans pointer passed in
	 * is not changed except on successful completion of the call
	 * for this start_idx.  This allows successive calls to be made
	 * with most recent results prepended to trans */
	dta_trans_t *entry = NULL, *cur_list = NULL, *tail = NULL;

	if (!table || !trans || end_idx < 1 || end_idx >= table->size) {
		errno = EINVAL;
		return -1;
	}

	/* follow entrypoints */
	for (i= 0; i < table->dom_list[end_idx].num_ep_rules; i++) {
		cur_ep = table->dom_list[end_idx].ep_rules[i].type_idx;
		table->dom_list[end_idx].ep_rules[i].used = TRUE;

		/* find domains that can exec cur_ep*/	
		for (j= 0; j < table->exec_list[cur_ep].num_exec_rules; j++) {
			cur_start = table->exec_list[cur_ep].exec_rules[j].type_idx;
			if (cur_start == end_idx)
				continue; /* no transition occurs if start == end */
			table->exec_list[cur_ep].exec_rules[j].used = TRUE;
			entry = dta_trans_new();
			entry->start_type = cur_start;
			entry->ep_type = cur_ep;
			entry->end_type = end_idx;

			/* copy entrypoint rules */
			entry->num_ep_rules = table->dom_list[end_idx].ep_rules[i].num_rules;
			entry->ep_rules = (int*)malloc(entry->num_ep_rules * sizeof(int));
			if (!entry->ep_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->ep_rules, table->dom_list[end_idx].ep_rules[i].rules, entry->num_ep_rules * sizeof(int));

			/* copy execute rules */
			entry->num_exec_rules = table->exec_list[cur_ep].exec_rules[j].num_rules;
			if (entry->num_exec_rules < 1) {
				error = EINVAL;
				goto exit_error;
			}
			entry->exec_rules = (int*)malloc(entry->num_exec_rules * sizeof(int));
			if (!entry->exec_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->exec_rules, table->exec_list[cur_ep].exec_rules[j].rules, entry->num_exec_rules * sizeof(int));

			/* find and copy any process transition rules */
			retv = dta_find_rule_for_type(table->dom_list[cur_start].proc_trans_rules, table->dom_list[cur_start].num_proc_trans_rules, end_idx);
			if (retv >= 0) {
				table->dom_list[cur_start].proc_trans_rules[retv].used = TRUE;
				entry->num_proc_trans_rules = table->dom_list[cur_start].proc_trans_rules[retv].num_rules;
				if (entry->num_proc_trans_rules < 1) {
					error = EINVAL;
					goto exit_error;
				}
				entry->proc_trans_rules = (int*)malloc(entry->num_proc_trans_rules * sizeof(int));
				if (!entry->proc_trans_rules) {
					error = errno;
					goto exit_error;
				}
				memcpy(entry->proc_trans_rules, table->dom_list[cur_start].proc_trans_rules[retv].rules, entry->num_proc_trans_rules * sizeof(int));
			}

			/* copy the type_transition rules if there is one */
			retv = dta_find_rule_for_type(table->dom_list[cur_start].type_trans_rules, table->dom_list[cur_start].num_type_trans_rules, cur_ep);
			if (retv != -1 && table->dom_list[cur_start].type_trans_rules[retv].dflt_idx == end_idx)
				entry->type_trans_rule = table->dom_list[cur_start].type_trans_rules[retv].rules[0];

			/* mark as valid if there is at least one of each required rules type */
			if (entry->num_proc_trans_rules && entry->num_ep_rules && entry->num_exec_rules)
				entry->valid = TRUE;
			entry->next = cur_list;
			cur_list = entry;
			if (!tail)
				tail = entry;
		}

		/* if no exec rules or only domian is end we have a dead entrypoint */
		if (table->exec_list[cur_ep].num_exec_rules == 0 ||
			(table->exec_list[cur_ep].num_exec_rules == 1 &&
			table->exec_list[cur_ep].exec_rules[0].type_idx == end_idx)) {

			entry = dta_trans_new();
			entry->start_type = -1;
			entry->ep_type = cur_ep;
			entry->end_type = end_idx;
			entry->num_ep_rules = table->dom_list[end_idx].ep_rules[i].num_rules;
			entry->ep_rules = (int*)malloc(entry->num_ep_rules * sizeof(int));
			if (!entry->ep_rules) {
				error = errno;
				goto exit_error;
			}
			memcpy(entry->ep_rules, table->dom_list[end_idx].ep_rules[i].rules, entry->num_ep_rules * sizeof(int));
			entry->valid = FALSE;
			entry->next = cur_list;
			cur_list = entry;
			if (!tail)
				tail = entry;
		}
	}

	/* find unused process transition and type_transition rules */
	for (i = 1; i < table->size; i++) {
		if (i == end_idx)
			continue;
		retv = dta_find_rule_for_type(table->dom_list[i].proc_trans_rules, table->dom_list[i].num_proc_trans_rules, end_idx);
		if (retv == -1 || table->dom_list[i].proc_trans_rules[retv].used)
			continue;
		entry = dta_trans_new();
		entry->start_type = i;
		entry->end_type = end_idx;
		entry->valid = FALSE;

		/* copy process transition rules */
		entry->num_proc_trans_rules = table->dom_list[i].proc_trans_rules[retv].num_rules;
		if (entry->num_proc_trans_rules < 1) {
			error = EINVAL;
			goto exit_error;
		}
		entry->proc_trans_rules = (int*)malloc(entry->num_proc_trans_rules * sizeof(int));
		if (!entry->proc_trans_rules) {
			error = errno;
			goto exit_error;
		}
		memcpy(entry->proc_trans_rules, table->dom_list[i].proc_trans_rules[retv].rules, entry->num_proc_trans_rules);

		/* look for a type_transition rule */
		cur_ep = 0; /* NOTE: while 0 is self this is not valid here and we can use 0 for logic false */
		for (j = 0; j < table->dom_list[i].num_type_trans_rules; j++) {
			if (table->dom_list[i].type_trans_rules[j].dflt_idx == end_idx){
				entry->ep_type = cur_ep = table->dom_list[i].type_trans_rules[j].type_idx;
				entry->type_trans_rule = table->dom_list[i].type_trans_rules[j].rules[0];
				table->dom_list[i].type_trans_rules[j].used = TRUE;
				break;
			}
		}
		/* if we found a type transition rule we can now get any execute rules for the 
		 * expected entrypoint type (which will still lack the entrypoint permission) */
		if (cur_ep) {
			retv = dta_find_rule_for_type(table->exec_list[cur_ep].exec_rules, table->exec_list[cur_ep].num_exec_rules, i);
			if (retv != -1) {
				entry->num_exec_rules = table->exec_list[cur_ep].exec_rules[retv].num_rules;
				if (entry->num_exec_rules < 1) {
					error = EINVAL;
					goto exit_error;
				}
				entry->exec_rules = (int*)malloc(entry->num_exec_rules * sizeof(int));
				if (!entry->exec_rules) {
					error = errno;
					goto exit_error;
				}
				memcpy(entry->exec_rules, table->exec_list[cur_ep].exec_rules[retv].rules, entry->num_exec_rules * sizeof(int));
			}
		}
		entry->next = cur_list;
		cur_list = entry;
		if (!tail)
			tail = entry;
	}

	/* if results were found add to list */
	if (cur_list) {
		if (!tail) {
			error = EINVAL;
			goto exit_error;
		}
		tail->next = *trans;
		*trans = cur_list;
	}

	return 0;

exit_error:
	dta_trans_destroy(&entry);
	dta_trans_destroy(&cur_list);
	errno = error;
	return -1;
}

/* removes all nodes in the linked list pointed to by trans
 * which do not have the same validity as the valid argument */
int dta_trans_filter_valid(dta_trans_t **trans, bool_t valid)
{
	dta_trans_t *cur = NULL, *prev = NULL;

	if (!trans) {
		errno = EINVAL;
		return -1;
	}

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
		dta_trans_destroy(&cur);
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
int dta_trans_filter_end_types(dta_trans_t **trans, int *end_types, int num_end_types)
{
	dta_trans_t *cur = NULL, *prev = NULL;

	if (!trans || !end_types) {
		errno = EINVAL;
		return -1;
	}

	for (cur = *trans; cur;) {
		if (find_int_in_array(cur->end_type, end_types, num_end_types) != -1) {
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
		dta_trans_destroy(&cur);
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
int dta_trans_filter_start_types(dta_trans_t **trans, int *start_types, int num_start_types)
{
	dta_trans_t *cur = NULL, *prev = NULL;

	if (!trans || !start_types) {
		errno = EINVAL;
		return -1;
	}

	for (cur = *trans; cur;) {
		if (find_int_in_array(cur->start_type, start_types, num_start_types) != -1) {
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
		dta_trans_destroy(&cur);
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
int dta_trans_filter_access_types(dta_trans_t **trans, int *access_types, int num_access_types, obj_perm_set_t *obj_perm_sets, int num_obj_perm_sets, policy_t *policy)
{
	dta_trans_t *cur = NULL, *prev = NULL;
	avh_idx_t *index = NULL;
	avh_node_t *node = NULL;
	avh_rule_t *rule = NULL;
	int i, j, retv;

	if (!trans || !access_types || !obj_perm_sets) {
		errno = EINVAL;
		return -1;
	}

	for (cur = *trans; cur;) {
		index = avh_src_type_idx_find(&(policy->avh), cur->end_type);
		if (index) { /* if index == NULL there are no rules permitting access */
			for (i = 0; i < index->num_nodes; i++) {
				node = index->nodes[i];

				/* must be an allow rule with a target in the list */
				if (node->key.rule_type != RULE_TE_ALLOW || find_int_in_array(node->key.tgt, access_types, num_access_types) == -1) 
					continue;
				/* find matching object class */
				for (j = 0; j < num_obj_perm_sets; j++) {
					if (node->key.cls == obj_perm_sets[j].obj_class) {
						for (rule = node->rules; rule; rule = rule->next) {
							/* add any rules that use any of the permissions included for that object class */
							if ((obj_perm_sets[j].num_perms == num_of_class_perms(obj_perm_sets[j].obj_class, policy)  
									|| does_av_rule_use_perms(rule->rule, 1, obj_perm_sets[j].perms, 
									obj_perm_sets[j].num_perms, policy)) &&
								find_int_in_array(rule->rule,  cur->access_rules, cur->num_access_rules) == -1) {
								retv = add_i_to_a(rule->rule, &(cur->num_access_rules), &(cur->access_rules));
								if (retv) {
									/* add_i_to_a does not set errno, and cannot detect error condition here */
									goto exit_error;
								}
							}
						}
						break; /* hash table rules have one class no need to keep looking */
					}
				}
			}
		}
		if (cur->num_access_rules) {
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
		dta_trans_destroy(&cur);
		if (prev) {
			cur = prev->next;
		} else {
			cur = *trans;
		}
	}

	return 0;

exit_error:
	return -1;
}

/* conversion function */
domain_trans_analysis_t *dta_trans_convert(dta_trans_t *trans, bool_t reverse)
{
	domain_trans_analysis_t *new_dta = NULL;
	dta_trans_t *cur = NULL;
	trans_domain_t *trans_dom = NULL;
	entrypoint_type_t *ept = NULL;
	int trans_type, error, retv;

	if (!trans) {
		errno = EINVAL;
		return NULL;
	}

	new_dta = new_domain_trans_analysis();
	if (!new_dta) {
		return NULL;
	}

	/* new_dta is from the perspective of the analysis direction
	 * while dta_trans_t structs are always from a forward perspective */
	new_dta->reverse = reverse;
	if (reverse)
		new_dta->start_type = trans->end_type;
	else
		new_dta->start_type = trans->start_type;

	/* walk the linked list of transitions and fill them into 
	 * new_dta one at a time by end_type (start_type if reverse) 
	 * adding each entrypoint type to the transition type (created as needed) */
	for (cur = trans; cur; cur = cur->next) {
		if (!cur->valid)
			continue; /* new_dta struct is only useable for valid transitions */
		if (reverse)
			trans_type = cur->start_type;
		else
			trans_type = cur->end_type;

		trans_dom = dta_find_trans_type_in_dta(new_dta, trans_type);
		if (!trans_dom) {
			error = errno;
			if (error) /* the case of not found explicitly sets errno to 0 */
				goto exit_error;

			/* first time we encounter this trans_type; create it */
			trans_dom = new_trans_domain();
			if (!trans_dom) {
				error = errno; /* should be set correctly in new fn by malloc */
				goto exit_error;
			}
			trans_dom->start_type = new_dta->start_type;
			trans_dom->trans_type = trans_type;
			trans_dom->reverse = reverse;
			/* copy proc trans rules */
			trans_dom->num_pt_rules = cur->num_proc_trans_rules;
			trans_dom->pt_rules = (int*)malloc(trans_dom->num_pt_rules * sizeof(int));
			if (!trans_dom->pt_rules) {
				free_trans_domain(trans_dom);
				error = errno;
				goto exit_error;
			}
			memcpy(trans_dom->pt_rules, cur->proc_trans_rules, trans_dom->num_pt_rules * sizeof(int));

			/* if access filters were used copy the access rules found for the inclusion of this type */
			if (cur->access_rules) {
				trans_dom->num_other_rules = cur->num_access_rules;
				trans_dom->other_rules = (int*)malloc(cur->num_access_rules * sizeof(int));
				if (!trans_dom->other_rules) {
					free_trans_domain(trans_dom);
					error = errno;
					goto exit_error;
				}
				memcpy(trans_dom->other_rules, cur->access_rules, cur->num_access_rules * sizeof(int));
			}
			retv = ll_append_data(new_dta->trans_domains, trans_dom);
			if (retv) {
				free_trans_domain(trans_dom);
				error = 0; /* error set to 0 here because error type cannot be detected */
				goto exit_error;
			}
		} /* end create new trans_dom */

		/* at this point trans_dom is valid 
		 * so add the current entrypoint 
		 * (it is new even if trans_dom isn't) */
		ept = new_entry_point_type();
		if (!ept) {
			error = errno;
			goto exit_error;
		}
		ept->start_type = new_dta->start_type;
		ept->trans_type = trans_type;
		ept->file_type = cur->ep_type;
		/* copy entrypoint rules */
		ept->num_ep_rules = cur->num_ep_rules;
		ept->ep_rules = (int*)malloc(ept->num_ep_rules * sizeof(int));
		if (!ept->ep_rules) {
			error = errno;
			goto exit_error;
		}
		memcpy(ept->ep_rules, cur->ep_rules, ept->num_ep_rules * sizeof(int));
		/* copy execute rules */
		ept->num_ex_rules = cur->num_exec_rules;
		ept->ex_rules = (int*)malloc(ept->num_ex_rules * sizeof(int));
		if (!ept->ex_rules) {
			error = errno;
			goto exit_error;
		}
		memcpy(ept->ex_rules, cur->exec_rules, ept->num_ex_rules * sizeof(int));
		retv = ll_append_data(trans_dom->entry_types, ept);
		if (retv) {
			error = 0; /* error set to 0 here because error type cannot be detected */
			goto exit_error;
		}
		ept = NULL;
	}

	return new_dta;

exit_error:
	free_entrypoint_type(ept);
	free_domain_trans_analysis(new_dta);
	errno = error;
	return NULL;
}


