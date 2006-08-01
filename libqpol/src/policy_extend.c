/**
 *  @file policy_extend.c
 *  Implementation of the interface for loading and using an extended
 *  policy image. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include <qpol/policy_extend.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/flask.h>
#include <qpol/policy.h>
#include <qpol/policy_query.h>
#include <qpol/iterator.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"
#include "syn_rule_internal.h"

#define QPOL_SYN_RULE_TABLE_BITS 15
#define QPOL_SYN_RULE_TABLE_SIZE (1 << QPOL_SYN_RULE_TABLE_BITS)
#define QPOL_SYN_RULE_TABLE_MASK (QPOL_SYN_RULE_TABLE_SIZE - 1)

#define QPOL_SYN_RULE_TABLE_HASH(rule_key) \
((rule_key->class_val + \
 (rule_key->target_val << 2) +\
 (rule_key->source_val << 9)) & \
 QPOL_SYN_RULE_TABLE_MASK)

typedef struct qpol_syn_rule_key {
	uint32_t rule_type;
	uint32_t source_val;
	uint32_t target_val;
	uint32_t class_val;
	cond_node_t *cond;
} qpol_syn_rule_key_t;

typedef struct qpol_syn_rule_list {
	struct qpol_syn_rule *rule;
	struct qpol_syn_rule_list *next;
} qpol_syn_rule_list_t;

typedef struct qpol_syn_rule_node {
	qpol_syn_rule_key_t *key;
	qpol_syn_rule_list_t *rules;
	struct qpol_syn_rule_node *next;
} qpol_syn_rule_node_t;

typedef struct qpol_syn_rule_table {
	qpol_syn_rule_node_t **buckets;
} qpol_syn_rule_table_t;

struct qpol_extended_image {
	qpol_syn_rule_table_t *syn_rule_table;
};

/**
 *  Builds data for the attributes and inserts them into the policydb. 
 *  This function modifies the policydb. Names created for attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param handle Error handler for the policy.
 *  @param policy The policy from which to read the attribute map and 
 *  create the type data for the attributes. This policy will be altered
 *  by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent 
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_build_attrs_from_map(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	size_t i;
	uint32_t bit = 0, count = 0;
	ebitmap_node_t *node = NULL;
	type_datum_t *tmp_type = NULL, *orig_type;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv;

	if (handle == NULL || policy == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		count = 0;
		ebitmap_for_each_bit(&db->attr_type_map[i], node, bit) {
			if (ebitmap_node_get_bit(node, bit))
				count++;
		}
		if (count == 0) {
			continue;
		}
		/* first create a new type_datum_t for the attribute,
		   with the attribute's type_list consisting of types
		   with this attribute */
		if (db->type_val_to_struct[i] != NULL) {
			continue; /* datum already exists? */
		}
		snprintf(buff, 9, "@ttr%04d", i+1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if(!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->value = i+1;
		if (ebitmap_cpy(&tmp_type->types, &db->attr_type_map[i])) {
			error = ENOMEM;
			goto err;
		}

		/* now go through each of the member types, and set
		   their type_list bit to point back */
		ebitmap_for_each_bit(&tmp_type->types, node, bit) {
			if (ebitmap_node_get_bit(node, bit)) {
				orig_type = db->type_val_to_struct[bit];
				if (ebitmap_set_bit(&orig_type->types, tmp_type->value - 1, 1)) {
					error = ENOMEM;
					goto err;
				}
			}
		}

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t)tmp_name, (hashtab_datum_t)tmp_type);
		if (retv) {
			if (retv == HASHTAB_OVERFLOW)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

err:
	free(tmp_name);
	type_datum_destroy(tmp_type);
	free(tmp_type);
	ERR(handle, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
};

/**
 *  Builds data for empty attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for the attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param handle Error handler for the policy.
 *  @param policy The policy to which to add type data for attributes.
 *  This policy will be altered by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_fill_attr_holes(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv = 0;
	ebitmap_t tmp_bmap = {NULL,0};
	type_datum_t *tmp_type = NULL;
	size_t i;

	if (handle == NULL || policy == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		if (db->type_val_to_struct[i])
			continue;
		snprintf(buff, 9, "@ttr%04d", i+1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = 1;
		tmp_type->flavor = TYPE_ATTRIB;
		tmp_type->value = i+1;
		tmp_type->types = tmp_bmap;

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t)tmp_name, (hashtab_datum_t)tmp_type);
		if (retv) {
			if (retv == HASHTAB_OVERFLOW)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

err:
	free(tmp_type);
	free(tmp_name);
	ERR(handle, "%s", strerror(error));
	errno = error;
	return STATUS_ERR;
}

static char *sidnames[] = 
{
"undefined",
"kernel", 
"security",
"unlabeled",
"fs",
"file",
"file_labels",
"init",
"any_socket",
"port",
"netif",
"netmsg",
"node",
"igmp_packet",
"icmp_socket",
"tcp_socket",
"sysctl_modprobe",
"sysctl",
"sysctl_fs",
"sysctl_kernel",
"sysctl_net",
"sysctl_net_unix",
"sysctl_vm",
"sysctl_dev",
"kmod",
"policy",
"scmp_packet",
"devnull"
};

/**
 *  Uses names from flask to fill in the isid names which are not normally 
 *  saved. This function modified the policydb.
 *  @param handle Error handler for the policy.
 *  @param policy Policy to which to add sid names.
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_isid_names(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	ocontext_t *sid = NULL;
	uint32_t val = 0;
	int error = 0;

	if (handle == NULL || policy == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	for (sid = db->ocontexts[OCON_ISID]; sid; sid = sid->next) {
		val = (uint32_t)sid->sid[0];
		if (val > SECINITSID_NUM)
			val = 0;

		if (!sid->u.name) {
			sid->u.name = strdup(sidnames[val]);
			if (!sid->u.name) {
				error = errno;
				ERR(handle, "%s",strerror(error));
				errno = error;
				return STATUS_ERR;
			}
		}
	}

	return 0;
}

/**
 *  Walks the conditional list and adds links for reverse look up from
 *  a te/av rule to the conditional from which it came.
 *  @param handle Error handler for the policy database.
 *  @param policy The policy to which to add conditional trace backs.
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_cond_rule_traceback(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	cond_node_t *cond = NULL;
	cond_av_list_t *list_ptr = NULL;
	qpol_iterator_t *iter = NULL;
	avtab_ptr_t rule = NULL;
	int error = 0;

	if (!handle || !policy) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	/* mark all unconditional rules as enabled */
	if (qpol_policy_get_avrule_iter(handle, policy, (QPOL_RULE_ALLOW|QPOL_RULE_NEVERALLOW|QPOL_RULE_AUDITALLOW|QPOL_RULE_DONTAUDIT), &iter))
		return STATUS_ERR;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void**)&rule)) {
			error = errno;
			ERR(handle, "%s", strerror(error));
			errno = error;
			return STATUS_ERR;
		}
		rule->parse_context = NULL;
		rule->merged = QPOL_COND_RULE_ENABLED;
	}
	qpol_iterator_destroy(&iter);
	if (qpol_policy_get_terule_iter(handle, policy, (QPOL_RULE_TYPE_TRANS|QPOL_RULE_TYPE_CHANGE|QPOL_RULE_TYPE_MEMBER), &iter))
		return STATUS_ERR;
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void**)&rule)) {
			error = errno;
			ERR(handle, "%s", strerror(error));
			errno = error;
			return STATUS_ERR;
		}
		rule->parse_context = NULL;
		rule->merged = QPOL_COND_RULE_ENABLED;
	}
	qpol_iterator_destroy(&iter);

	for (cond = db->cond_list; cond; cond = cond->next) {
		/* evaluate cond */
		cond->cur_state = cond_evaluate_expr(db, cond->expr);
		if (cond->cur_state < 0) {
			ERR(handle, "Error evaluating conditional: %s", strerror(EILSEQ));
			errno = EILSEQ;
			return STATUS_ERR;
		}

		/* walk true list */
		for (list_ptr = cond->true_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used after parse, now stores cond */
			list_ptr->node->parse_context = (void*)cond;
			/* field not used (except by write), 
			 * now storing list and enabled flags */
			list_ptr->node->merged = QPOL_COND_RULE_LIST;
			if (cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
		}

		/* walk false list */
		for (list_ptr = cond->false_list; list_ptr; list_ptr = list_ptr->next) {
			/* field not used after parse, now stores cond */
			list_ptr->node->parse_context = (void*)cond;
			/* field not used (except by write), 
			 * now storing list and enabled flags */
			list_ptr->node->merged = 0; /* i.e. !QPOL_COND_RULE_LIST */
			if (!cond->cur_state)
				list_ptr->node->merged |= QPOL_COND_RULE_ENABLED;
		}
	}

	return 0;
}

static void qpol_syn_rule_free(struct qpol_syn_rule *r) {
	if (!r)
		return;

	/* eventually will do more when module linking is done */
	free(r);
}

static void qpol_syn_rule_list_destroy(qpol_syn_rule_list_t **list)
{
	qpol_syn_rule_list_t *cur = NULL, *next = NULL;

	if (!list || !(*list))
		return;

	for (cur = *list; cur; cur = next) {
		next = cur->next;
		qpol_syn_rule_free(cur->rule);
		free(cur);
	}
}

static void qpol_syn_rule_node_destroy(qpol_syn_rule_node_t **node)
{
	qpol_syn_rule_node_t *cur = NULL, *next = NULL;

	if (!node || !(*node))
		return;

	for (cur = *node; cur; cur = next) {
		next = cur->next;
		qpol_syn_rule_list_destroy(&cur->rules);
		free(cur->key);
		free(cur);
	}
}

static void qpol_syn_rule_table_destroy(qpol_syn_rule_table_t **t)
{
	size_t i = 0;

	if (!t || !(*t))
		return;

	for (i = 0; i < QPOL_SYN_RULE_TABLE_SIZE; i++)
		qpol_syn_rule_node_destroy(&((*t)->buckets[i]));

	free((*t)->buckets);
	free(*t);
	*t = NULL;
}

/**
 *  Build the table of syntactic rules for a policy.
 *  @param handle Error handler for the policy.
 *  @param policy The policy for which to build the table.
 *  This policy will be modified by this call.
 *  @return 0 on success and < 0 on error; if the call fails,
 *  errno will be set.
 */
static int qpol_policy_build_syn_rule_table(qpol_handle_t *handle, qpol_policy_t *policy)
{
	int error = 0;

	if (!handle || !policy) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!policy->ext) {
		policy->ext = calloc(1, sizeof(qpol_extended_image_t));
		if (!policy->ext) {
			error = errno;
			ERR(handle, "%s", strerror(error));
			goto err;
		}
	}

	if (policy->ext->syn_rule_table)
		return 0; /* already built */

	policy->ext->syn_rule_table = calloc(1, sizeof(qpol_syn_rule_table_t));
	if (!policy->ext->syn_rule_table) {
		error = errno;
		ERR(handle, "%s", strerror(error));
		goto err;
	}
	policy->ext->syn_rule_table->buckets = calloc(QPOL_SYN_RULE_TABLE_SIZE, sizeof(qpol_syn_rule_node_t*));
	if (!policy->ext->syn_rule_table->buckets) {
		error = errno;
		ERR(handle, "%s", strerror(error));
		goto err;
	}


	return 0;

err:
	if (policy->ext)
		qpol_syn_rule_table_destroy(&policy->ext->syn_rule_table);
	errno = error;
	return -1;
}

int qpol_policy_extend(qpol_handle_t *handle, qpol_policy_t *policy)
{
	int retv, error;
	policydb_t *db = NULL;

	if (handle == NULL || policy == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	db = &policy->p->p;

	retv = qpol_policy_build_attrs_from_map(handle, policy);
	if (retv) {
		error = errno;
		goto err;
	}
	if (db->policy_type == POLICY_KERN) {
		retv = qpol_policy_fill_attr_holes(handle, policy);
		if (retv) {
			error = errno;
			goto err;
		}
	}
	retv = qpol_policy_add_isid_names(handle, policy);
	if (retv) {
		error = errno;
		goto err;
	}

	retv = qpol_policy_add_cond_rule_traceback(handle, policy);
	if (retv) {
		error = errno;
		goto err;
	}

	retv = qpol_policy_build_syn_rule_table(handle, policy);
	if (retv) {
		error = errno;
		goto err;
	}

	return STATUS_SUCCESS;

err:
	/* no need to call ERR here as it will already have been called */
	qpol_extended_image_destroy(&policy->ext);
	errno = error;
	return STATUS_ERR;
}

void qpol_extended_image_destroy(qpol_extended_image_t **ext)
{
	if (!ext || !(*ext))
		return;

	qpol_syn_rule_table_destroy(&((*ext)->syn_rule_table));
	free(*ext);
	*ext = NULL;
}

