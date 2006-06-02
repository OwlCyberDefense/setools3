/**
 *  @file mlsrule_query.c
 *  Implementation for the public interface for searching and iterating over 
 *  range transition rules.
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
#include <qpol/mlsrule_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/util.h>
#include <stdlib.h>
#include "debug.h"

typedef struct range_trans_state {
	range_trans_t *head;
	range_trans_t *cur;
} range_trans_state_t;

static int range_trans_state_end(qpol_iterator_t *iter)
{
	range_trans_state_t *rs = NULL;

	if (!iter || !(rs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return rs->cur ? 0 : 1;
}

static void *range_trans_state_get_cur(qpol_iterator_t *iter)
{
	range_trans_state_t *rs = NULL;

	if (!iter || !(rs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return NULL;
	}

	return rs->cur;
}

static int range_trans_state_next(qpol_iterator_t *iter)
{
	range_trans_state_t *rs = NULL;

	if (!iter || !(rs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (range_trans_state_end(iter)) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	rs->cur = rs->cur->next;

	return STATUS_SUCCESS;
}

static size_t range_trans_state_size(qpol_iterator_t *iter)
{
	range_trans_state_t *rs = NULL;
	size_t count = 0;
	range_trans_t *tmp = NULL;

	if (!iter || !(rs = qpol_iterator_state(iter))) {
		errno = EINVAL;
		return 0;
	}

	for (tmp = rs->head; tmp; tmp = tmp->next)
		count++;

	return count;
}

int qpol_policy_get_range_trans_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	range_trans_state_t *rs = NULL;
	int error = 0;

	if (iter)
		*iter = NULL;

	if (!handle || !policy || !iter) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	rs = calloc(1, sizeof(range_trans_state_t));
	if (!rs) {
		error = errno;
		ERR(handle, "%s", strerror(error));
		errno = error;
		return STATUS_ERR;
	}

	if (qpol_iterator_create(handle, db, (void*)rs, range_trans_state_get_cur,
		range_trans_state_next, range_trans_state_end, range_trans_state_size,
		free, iter)) {
		error = errno;
		free(rs);
		errno = error;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_range_trans_get_source_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_type_t **source)
{
	policydb_t *db = NULL;
	range_trans_t *rt = NULL;

	if (source) {
		*source = NULL;
	}

	if (!handle || !policy || !rule || !source) {
		errno = EINVAL;
		ERR(handle, "%s", strerror(EINVAL));
		return STATUS_ERR;
	}

	db = &policy->p;
	rt = (range_trans_t*)rule;

	*source = (qpol_type_t*)db->type_val_to_struct[rt->dom - 1];

	return STATUS_SUCCESS;
}

int qpol_range_trans_get_target_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_type_t **target)
{
	policydb_t *db = NULL;
	range_trans_t *rt = NULL;

	if (target) {
		*target = NULL;
	}

	if (!handle || !policy || !rule || !target) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	rt = (range_trans_t*)rule;

	*target = (qpol_type_t*)db->type_val_to_struct[rt->type - 1];

	return STATUS_SUCCESS;
}

int qpol_range_trans_get_range(qpol_handle_t *handle, qpol_policy_t *policy, qpol_range_trans_t *rule, qpol_mls_range_t **range)
{
	policydb_t *db = NULL;
	range_trans_t *rt = NULL;

	if (range) {
		*range = NULL;
	}

	if (!handle || !policy || !rule || !range) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	rt = (range_trans_t*)rule;

	*range = (qpol_mls_range_t*)&rt->range;

	return STATUS_SUCCESS;
}

