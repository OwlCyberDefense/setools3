 /**
 *  @file avrule_query.c
 *  Implementation for the public interface for searching and iterating over avrules.
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

#include "iterator_internal.h"
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/avrule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include "debug.h"

int qpol_policy_get_avrule_iter(qpol_handle_t *handle, qpol_policy_t *policy, uint32_t rule_type_mask, qpol_iterator_t **iter)
{
	policydb_t *db;
	avtab_state_t *state;

	if (iter) {
		*iter = NULL;
	}
	if (handle == NULL || policy == NULL || iter == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	db = &policy->p;

	state = calloc(1, sizeof(avtab_state_t));
	if (state == NULL) {
		ERR(handle, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return STATUS_ERR;
	}
	state->ucond_tab = &db->te_avtab;
	state->cond_tab = &db->te_cond_avtab;
	state->rule_type_mask = rule_type_mask;
	state->node = db->te_avtab.htable[0];

	if (qpol_iterator_create(handle, db, state, avtab_state_get_cur, avtab_state_next, avtab_state_end, avtab_state_size, free, iter)) {
		free(state);
		return STATUS_ERR;
	}
	if (state->node == NULL || !(state->node->key.specified & state->rule_type_mask)) {
		avtab_state_next(*iter);
	}
	return STATUS_SUCCESS;
}

int qpol_avrule_get_source_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_type_t **source)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (source) {
		*source = NULL;
	}

	if (!handle || !policy || !rule || !source) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	avrule = (avtab_ptr_t)rule;

	*source = (qpol_type_t*)db->type_val_to_struct[avrule->key.source_type - 1];

	return STATUS_SUCCESS;
}

int qpol_avrule_get_target_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_type_t **target)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (target) {
		*target = NULL;
	}

	if (!handle || !policy || !rule || !target) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	avrule = (avtab_ptr_t)rule;

	*target = (qpol_type_t*)db->type_val_to_struct[avrule->key.target_type - 1];

	return STATUS_SUCCESS;
}

int qpol_avrule_get_object_class(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_class_t **obj_class)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (obj_class) {
		*obj_class = NULL;
	}

	if (!handle || !policy || !rule || !obj_class) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	avrule = (avtab_ptr_t)rule;

	*obj_class = (qpol_class_t*)db->class_val_to_struct[avrule->key.target_class - 1];

	return STATUS_SUCCESS;
}

typedef struct perm_state {
	uint32_t perm_set;
	uint32_t obj_class_val;
	uint8_t cur;
} perm_state_t;

static int perm_state_end(qpol_iterator_t *iter)
{
	perm_state_t *ps = NULL;
	policydb_t *db = NULL;
	unsigned int perm_max = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL ||
		(db = qpol_iterator_policy(iter)) == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* permission max is number of permissions in the class which includes
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val-1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM; /* perms set mask is a uint32_t cannot use more than 32 bits */
		return STATUS_ERR;
	}

	if (!(ps->perm_set) || ps->cur >= perm_max)
		return 1;

	return 0;
}

static void *perm_state_get_cur(qpol_iterator_t *iter)
{
	policydb_t *db = NULL;
	class_datum_t *obj_class = NULL;
	common_datum_t *comm = NULL;
	perm_state_t *ps = NULL;
	unsigned int perm_max = 0;
	char *tmp = NULL;

	if (iter == NULL || (db = qpol_iterator_policy(iter)) == NULL || 
		(ps = (perm_state_t*)qpol_iterator_state(iter)) == NULL ||
		perm_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	obj_class = db->class_val_to_struct[ps->obj_class_val - 1];
	comm = obj_class->comdatum;

	/* permission max is number of permissions in the class which includes 
	 * the number of permissions in its common if it inherits one */
	perm_max = obj_class->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM; /* perms set mask is a uint32_t cannot use more than 32 bits */
		return NULL;
	}
	if (ps->cur >= perm_max) {
		errno = ERANGE;
		return NULL;
	}
	if (!(ps->perm_set & 1<<(ps->cur))) { /* perm bit not set? */
		errno = EINVAL;
		return NULL;
	}

	tmp = sepol_av_to_string(db, ps->obj_class_val, (sepol_access_vector_t) 1<<(ps->cur));
	if (tmp) {
		tmp++; /*sepol_av_to_string prepends a ' ' to the name */
		return tmp;
	} else {
		errno = EINVAL;
		return NULL;
	}
}

static int perm_state_next(qpol_iterator_t *iter)
{
	perm_state_t *ps = NULL;
	policydb_t *db = NULL;
	unsigned int perm_max = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL ||
		(db = qpol_iterator_policy(iter)) == NULL ||
		perm_state_end(iter)) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	/* permission max is number of permissions in the class which includes 
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val-1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM; /* perms set mask is a uint32_t cannot use more than 32 bits */
		return STATUS_ERR;
	}

	if (ps->cur >= perm_max) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		ps->cur++;
	} while (ps->cur < perm_max && !(ps->perm_set & 1 << (ps->cur)));

	return STATUS_SUCCESS;
}

static size_t perm_state_size(qpol_iterator_t *iter)
{
	perm_state_t *ps = NULL;
	policydb_t *db = NULL;
	unsigned int perm_max = 0;
	size_t i, count = 0;

	if (iter == NULL || (ps = qpol_iterator_state(iter)) == NULL ||
		(db = qpol_iterator_policy(iter)) == NULL ||
		perm_state_end(iter)) {
		errno = EINVAL;
		return 0; /* as a size_t 0 is error */
	}

	/* permission max is number of permissions in the class which includes 
	 * the number of permissions in its common if it inherits one */
	perm_max = db->class_val_to_struct[ps->obj_class_val-1]->permissions.nprim;
	if (perm_max > 32) {
		errno = EDOM; /* perms set mask is a uint32_t cannot use more than 32 bits */
		return 0; /* as a size_t 0 is error */
	}

	for (i = 0; i < perm_max; i++) {
		if ( ps->perm_set & 1<<i)
			count++;
	}

	return count;	
}

int qpol_avrule_get_perm_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, qpol_iterator_t **perms)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;
	perm_state_t *ps = NULL;

	if (perms) {
		*perms = NULL;
	}

	if (!handle || !policy || !rule || !perms) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	avrule = (avtab_ptr_t)rule;
	ps = calloc(1, sizeof(perm_state_t));
	if (!ps) {
		return STATUS_ERR;
	}
	if (avrule->key.specified & QPOL_RULE_DONTAUDIT) {
		ps->perm_set = ~(avrule->datum.data); /* stored as auditdeny flip the bits */
	} else {
		ps->perm_set = avrule->datum.data;
	}
	ps->obj_class_val = avrule->key.target_class;

	if (qpol_iterator_create(handle, db, (void*)ps, perm_state_get_cur,
		perm_state_next, perm_state_end, perm_state_size, free, perms)) {
		return STATUS_ERR;
	}

	if (!(ps->perm_set & 1)) /* defaults to bit 0, if off: advance */
		perm_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_avrule_get_rule_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_avrule_t *rule, uint32_t *rule_type)
{
	policydb_t *db = NULL;
	avtab_ptr_t avrule = NULL;

	if (rule_type) {
		*rule_type = 0;
	}

	if (!handle || !policy || !rule || !rule_type) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	avrule = (avtab_ptr_t)rule;

	*rule_type = (avrule->key.specified & (QPOL_RULE_ALLOW|QPOL_RULE_NEVERALLOW|QPOL_RULE_AUDITALLOW|QPOL_RULE_DONTAUDIT));

	return STATUS_SUCCESS;
}
