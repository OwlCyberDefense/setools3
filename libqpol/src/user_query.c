/**
 *  @file user_query.c
 *  Implementation of the interface for searching and iterating over users.
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
 
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sepol/handle.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/user_query.h>
#include <qpol/role_query.h>
#include <qpol/mls_query.h>
#include "debug.h"


int qpol_policy_get_user_by_name(sepol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_user_t **datum)
{
	hashtab_datum_t internal_datum;
	policydb_t *db;

	if (handle == NULL || policy == NULL || name == NULL || datum == NULL) {
		if (datum != NULL)
			*datum = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	
	db = &policy->p;
	internal_datum = hashtab_search(db->p_users.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(handle, "could not find datum for user %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_user_t*)internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_user_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	hash_state_t *hs = NULL;
	int error = 0;

	if (handle == NULL || policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_users.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(handle, db, (void*)hs, hash_state_get_cur,
		hash_state_next, hash_state_end, hash_state_size, free, iter)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*iter);

	return STATUS_SUCCESS;
}

int qpol_user_get_value(sepol_handle_t *handle, qpol_policy_t *policy, qpol_user_t *datum, uint32_t *value)
{
	user_datum_t *internal_datum;

	if (handle == NULL || policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t*)datum;
	*value = internal_datum->value;

	return STATUS_SUCCESS;
}

int qpol_user_get_role_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_user_t *datum, qpol_iterator_t **roles)
{
	user_datum_t *internal_datum = NULL;
	int error = 0;
	ebitmap_state_t *es = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || roles == NULL){
		if (roles != NULL)
			*roles = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t*)datum;

	es = calloc(1, sizeof(ebitmap_state_t));
	if (es == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}

	es->bmap = &(internal_datum->roles.roles);
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(handle, &policy->p, es, ebitmap_state_get_cur_role,
		ebitmap_state_next, ebitmap_state_end, ebitmap_state_size, free, roles)) {
		free(es);
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*roles);

	return STATUS_SUCCESS;
}

int qpol_user_get_range(sepol_handle_t *handle, qpol_policy_t *policy, qpol_user_t *datum, qpol_mls_range_t **range)
{
	user_datum_t *internal_datum = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || range == NULL) {
		if (range != NULL)
			*range = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t*)datum;
	*range = (qpol_mls_range_t*)&internal_datum->range;

	return STATUS_SUCCESS;
}

int qpol_user_get_dfltlevel(sepol_handle_t *handle, qpol_policy_t *policy, qpol_user_t *datum, qpol_mls_level_t **level)
{
	user_datum_t *internal_datum = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || level == NULL) {
		if (level != NULL)
			*level = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (user_datum_t*)datum;
	*level = (qpol_mls_level_t*)&internal_datum->dfltlevel;

	return STATUS_SUCCESS;
}

int qpol_user_get_name(sepol_handle_t *handle, qpol_policy_t *policy, qpol_user_t *datum, char **name)
{
	user_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (handle == NULL ||  policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	internal_datum = (user_datum_t*)datum;

	*name = db->p_user_val_to_name[internal_datum->value - 1];

	return STATUS_SUCCESS;
}
 
