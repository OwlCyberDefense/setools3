/**
 *  @file class_perm_query.c
 *  Implementation of the interface for searching and iterating over
 *  classes, commons, and permissions.
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
#include <string.h>
#include <sepol/handle.h>
#include <qpol/iterator.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/expand.h>
#include "iterator_internal.h"
#include <qpol/class_perm_query.h>
#include "debug.h"

/* perms */
typedef struct perm_hash_state {
	unsigned int bucket;
	hashtab_node_t *node;
	hashtab_t *table;
	const char *perm_name;
} perm_hash_state_t;

static int hash_state_next_class_w_perm(qpol_iterator_t *iter)
{
	class_datum_t *internal_class = NULL;
	qpol_iterator_t *internal_perms = NULL;
	unsigned char has_perm = 0;
	perm_hash_state_t *hs = NULL;
	qpol_policy_t sp;
	char *tmp = NULL;

	hs = (perm_hash_state_t*)qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);

	do {
		hash_state_next(iter);
		if (hash_state_end(iter))
			break;
		internal_class = hs->node ? (class_datum_t*)hs->node->datum : NULL;
		/* can use any non-NULL handle as it will never be called from here */
		qpol_class_get_perm_iter((sepol_handle_t*)1, &sp, (qpol_class_t*)internal_class, &internal_perms);
		for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
			qpol_iterator_get_item(internal_perms, (void**)&tmp);
			if (!strcmp(tmp, hs->perm_name)) {
				has_perm = 1;
				break;
			}
		}
		qpol_iterator_destroy(&internal_perms);
	} while (!has_perm && !hash_state_end(iter));

	return STATUS_SUCCESS;
}

static int hash_state_next_common_w_perm(qpol_iterator_t *iter)
{
	common_datum_t *internal_common = NULL;
	qpol_iterator_t *internal_perms = NULL;
	unsigned char has_perm = 0;
	perm_hash_state_t *hs = NULL;
	qpol_policy_t sp;
	char *tmp = NULL;

	hs = (perm_hash_state_t*)qpol_iterator_state(iter);
	if (hs == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	/* shallow copy ok here as only internal values are used */
	sp.p = *qpol_iterator_policy(iter);

	do {
		hash_state_next(iter);
		if (hash_state_end(iter))
			break;
		internal_common = hs->node ? (common_datum_t*)hs->node->datum : NULL;
		/* can use any non-NULL handle as it will never be called from here */
		qpol_common_get_perm_iter((sepol_handle_t*)1, &sp, (qpol_common_t*)internal_common, &internal_perms);
		for (; !qpol_iterator_end(internal_perms); qpol_iterator_next(internal_perms)) {
			qpol_iterator_get_item(internal_perms, (void**)&tmp);
			if (!strcmp(tmp, hs->perm_name)) {
				has_perm = 1;
				break;
			}
		}
		qpol_iterator_destroy(&internal_perms);
	} while (!has_perm && !hash_state_end(iter));

	return STATUS_SUCCESS;
}

int qpol_perm_get_class_iter(sepol_handle_t *handle, qpol_policy_t *policy, const char *perm, qpol_iterator_t **classes)
{
	policydb_t *db;
	int error = 0;
	perm_hash_state_t *hs = NULL;

	if (handle == NULL || policy == NULL || classes == NULL) {
		if (classes != NULL)
			*classes = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	hs = calloc(1, sizeof(perm_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_classes.table;
	hs->node = (*(hs->table))->htable[0];
	hs->perm_name = perm;

	if (qpol_iterator_create(handle, db, (void*)hs, hash_state_get_cur,
		hash_state_next_class_w_perm, hash_state_end, hash_state_size, free, classes)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next_class_w_perm(*classes);

	return STATUS_SUCCESS;
}

int qpol_perm_get_common_iter(sepol_handle_t *handle, qpol_policy_t *policy, const char *perm, qpol_iterator_t **commons)
{
	policydb_t *db;
	int error = 0;
	perm_hash_state_t *hs = NULL;

	if (handle == NULL || policy == NULL || commons == NULL) {
		if (commons != NULL)
			*commons = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	hs = calloc(1, sizeof(perm_hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &db->p_commons.table;
	hs->node = (*(hs->table))->htable[0];
	hs->perm_name = perm;

	if (qpol_iterator_create(handle, db, (void*)hs, hash_state_get_cur,
		hash_state_next_common_w_perm, hash_state_end, hash_state_size, free, commons)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next_common_w_perm(*commons);

	return STATUS_SUCCESS;}

/* classes */
int qpol_policy_get_class_by_name(sepol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_class_t **datum)
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
	internal_datum = hashtab_search(db->p_classes.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(handle, "could not find datum for class %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}

	*datum = (qpol_class_t*)internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_class_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

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
	hs->table = &db->p_classes.table;
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

int qpol_class_get_value(sepol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, uint32_t *value)
{
	class_datum_t *internal_datum;

	if (handle == NULL || policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t*)datum;
	*value = internal_datum->value;

	return STATUS_SUCCESS;
}

int qpol_class_get_common(sepol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, qpol_common_t **common)
{
	class_datum_t *internal_datum = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || common == NULL) {
		if (common != NULL)
			*common = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t*)datum;
	*common = (qpol_common_t*)internal_datum->comdatum;

	return STATUS_SUCCESS;
}

int qpol_class_get_perm_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, qpol_iterator_t **perms)
{
	class_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error = 0;
	hash_state_t *hs = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || perms == NULL) {
		if (perms != NULL)
			*perms = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (class_datum_t*)datum;
	db = &policy->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &internal_datum->permissions.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(handle, db, (void*)hs, hash_state_get_cur_key,
		hash_state_next, hash_state_end, hash_state_size, free, perms)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_class_get_name(sepol_handle_t *handle, qpol_policy_t *policy, qpol_class_t *datum, char **name)
{
	class_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (handle == NULL ||  policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	internal_datum = (class_datum_t*)datum;

	*name = db->p_class_val_to_name[internal_datum->value - 1];

	return STATUS_SUCCESS;
}

/* commons */
int qpol_policy_get_common_by_name(sepol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_common_t **datum)
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
	internal_datum = hashtab_search(db->p_commons.table, (const hashtab_key_t)name);
	if (internal_datum == NULL) {
		*datum = NULL;
		ERR(handle, "could not find datum for common %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}
	*datum = (qpol_common_t*)internal_datum;

	return STATUS_SUCCESS;
}

int qpol_policy_get_common_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db;
	int error = 0;
	hash_state_t *hs = NULL;

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
	hs->table = &db->p_commons.table;
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

int qpol_common_get_value(sepol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, uint32_t *value)
{
	common_datum_t *internal_datum;

	if (handle == NULL || policy == NULL || datum == NULL || value == NULL) {
		if (value != NULL)
			*value = 0;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (common_datum_t*)datum;
	*value = internal_datum->value;

	return STATUS_SUCCESS;	
}

int qpol_common_get_perm_iter(sepol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, qpol_iterator_t **perms)
{
	common_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;
	int error = 0;
	hash_state_t *hs = NULL;

	if (handle == NULL || policy == NULL || datum == NULL || perms == NULL) {
		if (perms != NULL)
			*perms = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_datum = (common_datum_t*)datum;
	db = &policy->p;

	hs = calloc(1, sizeof(hash_state_t));
	if (hs == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}
	hs->table = &internal_datum->permissions.table;
	hs->node = (*(hs->table))->htable[0];

	if (qpol_iterator_create(handle, db, (void*)hs, hash_state_get_cur_key,
		hash_state_next, hash_state_end, hash_state_size, free, perms)) {
		free(hs);
		return STATUS_ERR;
	}

	if (hs->node == NULL)
		hash_state_next(*perms);

	return STATUS_SUCCESS;
}

int qpol_common_get_name(sepol_handle_t *handle, qpol_policy_t *policy, qpol_common_t *datum, char **name)
{
	common_datum_t *internal_datum = NULL;
	policydb_t *db = NULL;

	if (handle == NULL ||  policy == NULL || datum == NULL || name == NULL) {
		if (name != NULL)
			*name = NULL;
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	internal_datum = (common_datum_t*)datum;

	*name = db->p_common_val_to_name[internal_datum->value - 1];

	return STATUS_SUCCESS;
}

 
