 /**
 *  @file role_query.c
 *  Implementation of the interface for searching and iterating over roles.
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
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/role_query.h>
#include <qpol/type_query.h>
#include "debug.h"

int qpol_policy_get_role_by_name(qpol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_role_t **datum)
{
	hashtab_datum_t internal_datum;
	policydb_t *db;

	if (handle == NULL || policy == NULL || name == NULL || datum == NULL) {
		if (datum != NULL)
			*datum = NULL;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}
	
	db = &policy->p;
	internal_datum = hashtab_search(db->p_roles.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(handle, "could not find datum for role %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_role_t*)internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_role_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

	if (handle == NULL || policy == NULL || iter == NULL) {
		if (iter != NULL)
			*iter = NULL;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "%s", "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_roles.table;
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

int qpol_role_get_value(qpol_handle_t *handle, qpol_policy_t *policy, qpol_role_t *datum, uint32_t *value)
{
	role_datum_t *internal_datum = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (role_datum_t*)datum;
	*value = internal_datum->value;

	return STATUS_SUCCESS;
}

int qpol_role_get_dominate_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_role_t *datum, qpol_iterator_t **dominates)
{
	role_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error;
	ebitmap_state_t *es = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || dominates == NULL) {
		if (dominates != NULL)
			*dominates = NULL;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (role_datum_t*)datum;
	db = &policy->p;

	if (!(es = calloc(1, sizeof(ebitmap_state_t)))) {
		error = errno;
		ERR(handle, "%s", "unable to create iterator state object");
		errno = error;
		return STATUS_ERR;
	}
	es->bmap = 	&internal_datum->dominates;

	if (qpol_iterator_create(handle, db, (void*)es, ebitmap_state_get_cur_role,
		ebitmap_state_next, ebitmap_state_end, ebitmap_state_size,
		free, dominates)) {
		error = errno;
		ERR(handle, "%s", "unable to create iterator");
		errno = error;
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*dominates);

	return STATUS_SUCCESS;
}

int qpol_role_get_type_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_role_t *datum, qpol_iterator_t **types)
{
	role_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	ebitmap_t *expanded_set = NULL;
	int error;
	ebitmap_state_t *es = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || types == NULL) {
		if (types != NULL)
			*types = NULL;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (role_datum_t*)datum;
	db = &policy->p;

	if(!(expanded_set = calloc(1, sizeof(ebitmap_t)))) {
		error = errno;
		ERR(handle, "%s", "unable to create bitmap");
		errno = error;
		return STATUS_ERR;
	}

	if (type_set_expand(&internal_datum->types, expanded_set, db, 1)) {
		ebitmap_destroy(expanded_set);
		free(expanded_set);
		ERR(handle, "error reading type set for role %s", db->p_role_val_to_name[internal_datum->value -1]);
		errno = EIO;
		return STATUS_ERR;
	}

	if (!(es = calloc(1, sizeof(ebitmap_state_t)))) {
		error = errno;
		ERR(handle, "%s", "unable to create iterator state object");
		ebitmap_destroy(expanded_set);
		free(expanded_set);
		errno = error;
		return STATUS_ERR;
	}
	es->bmap = expanded_set;
	es->cur = es->bmap->node ? es->bmap->node->startbit : 0;

	if (qpol_iterator_create(handle, db, (void*)es, ebitmap_state_get_cur_type,
		ebitmap_state_next, ebitmap_state_end, ebitmap_state_size,
		ebitmap_state_destroy, types)) {
		error = errno;
		ebitmap_destroy(expanded_set);
		ERR(handle, "%s", "unable to create iterator");
		errno = error;
		return STATUS_ERR;
	}

	if (es->bmap->node && !ebitmap_get_bit(es->bmap, es->cur))
		ebitmap_state_next(*types);

	return STATUS_SUCCESS;
}

int qpol_role_get_name(qpol_handle_t *handle, qpol_policy_t *policy, qpol_role_t *datum, char **name)
{
	role_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (handle == NULL ||  policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	internal_datum = (role_datum_t*)datum;

	*name = db->p_role_val_to_name[internal_datum->value - 1];

	return STATUS_SUCCESS;
}


