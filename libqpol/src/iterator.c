/**
 * @file iterator.c
 * Contains the implementation of the qpol_iterator API, both
 * public and private, for returning lists of components and rules
 * from the policy database.
 *
 * @author Kevin Carr kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang jtang@tresys.com
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

#include <qpol/iterator.h>
#include <qpol/mls_query.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "debug.h"
#include "iterator_internal.h" 

/**
 * Declaration of qpol_iterator, an arbitrary valued policy component
 * iterator used to return lists of components.
 * 
 */
struct qpol_iterator {
	policydb_t *policy;
	void *state;
	void *(*get_cur)(qpol_iterator_t *iter);
	int (*next)(qpol_iterator_t *iter);
	int (*end)(qpol_iterator_t *iter);
	size_t (*size)(qpol_iterator_t *iter);
	void (*free_fn)(void*x);
};

int qpol_iterator_create(sepol_handle_t *handle, policydb_t *policy, void *state,
	void *(*get_cur)(qpol_iterator_t *iter),
	int (*next)(qpol_iterator_t *iter),
	int (*end)(qpol_iterator_t *iter),
	size_t (*size)(qpol_iterator_t *iter),
	void (*free_fn)(void *x),
	qpol_iterator_t **iter)
{
	int error = 0;

	if (iter != NULL)
		*iter = NULL;

	if (handle == NULL || policy == NULL || state == NULL || iter == NULL ||
		get_cur == NULL || next == NULL || end == NULL || size == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	*iter = calloc(1, sizeof(struct qpol_iterator));
	if (*iter == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}

	(*iter)->policy = policy;
	(*iter)->state = state;
	(*iter)->get_cur = get_cur;
	(*iter)->next = next;
	(*iter)->end = end;
	(*iter)->size = size;
	(*iter)->free_fn = free_fn;

	return STATUS_SUCCESS;
}

void *qpol_iterator_state(qpol_iterator_t *iter) {
	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return iter->state;
}

policydb_t *qpol_iterator_policy(qpol_iterator_t *iter) {
	if (iter == NULL || iter->policy == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return iter->policy;
}

void *hash_state_get_cur(qpol_iterator_t *iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL || hash_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	hs = (hash_state_t*)iter->state;

	return hs->node->datum;
}

void *hash_state_get_cur_key(qpol_iterator_t *iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL || hash_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	hs = (hash_state_t*)iter->state;

	return hs->node->key;
}

void *ocon_state_get_cur(qpol_iterator_t *iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL || ocon_state_end(iter)) {
		errno = EINVAL;
		return NULL;
	}

	os = (ocon_state_t*)iter->state;

	return os->cur;
}

int hash_state_next(qpol_iterator_t *iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	hs = (hash_state_t*)iter->state;

	if (hs->bucket >= (*(hs->table))->size) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	if (hs->node != NULL && hs->node->next != NULL) {
		hs->node = hs->node->next;
	} else {
		do {
			hs->bucket++;
			if (hs->bucket < (*(hs->table))->size) {
				hs->node = (*(hs->table))->htable[hs->bucket];
			} else {
				hs->node = NULL;
			}
		} while (hs->bucket < (*(hs->table))->size && hs->node == NULL);
	}

	return STATUS_SUCCESS;
}

int ebitmap_state_next(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	es = (ebitmap_state_t*)iter->state;

	if (es->cur >= es->bmap->highbit) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	do {
		es->cur++;
	} while (es->cur < es->bmap->highbit && !ebitmap_get_bit(es->bmap, es->cur));

	return STATUS_SUCCESS;
}

int ocon_state_next(qpol_iterator_t *iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	os = (ocon_state_t*)iter->state;

	if (os->cur == NULL) {
		errno = ERANGE;
		return STATUS_ERR;
	}

	os->cur = os->cur->next;

	return STATUS_SUCCESS;
}


int hash_state_end(qpol_iterator_t *iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	hs = (hash_state_t*)iter->state;

	if ((*(hs->table))->nel == 0 || hs->bucket >= (*(hs->table))->size)
		return 1;

	return 0;
}

int ebitmap_state_end(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	es = (ebitmap_state_t*)iter->state;

	if (es->cur >= es->bmap->highbit)
		return 1;

	return 0;
}

int ocon_state_end(qpol_iterator_t *iter)
{
	ocon_state_t *os = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	os = (ocon_state_t*)iter->state;

	if (os->cur == NULL)
		return 1;

	return 0;
}


size_t hash_state_size(qpol_iterator_t *iter)
{
	hash_state_t *hs = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	hs = (hash_state_t*)iter->state;

	return (*(hs->table))->nel;
}

size_t ebitmap_state_size(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;
	size_t count = 0, bit = 0;
	ebitmap_node_t *node = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	es = (ebitmap_state_t*)iter->state;

	ebitmap_for_each_bit(es->bmap, node, bit) {
		count += ebitmap_get_bit(es->bmap, bit);
	}

	return count;
}

size_t ocon_state_size(qpol_iterator_t *iter)
{
	ocon_state_t *os = NULL;
	size_t count = 0;
	ocontext_t *ocon = NULL;

	if (iter == NULL || iter->state == NULL) {
		errno = EINVAL;
		return 0;
	}

	os = (ocon_state_t*)iter->state;

	for (ocon = os->head; ocon; ocon = ocon->next)
		count++;

	return count;
}

void qpol_iterator_destroy(qpol_iterator_t **iter)
{
	if (iter == NULL || *iter == NULL)
		return;

	if ((*iter)->free_fn)
		(*iter)->free_fn((*iter)->state);

	free(*iter);
	*iter = NULL;
}

int qpol_iterator_get_item(qpol_iterator_t *iter, void **item)
{
	if (item != NULL)
		*item = NULL;

	if (iter == NULL || iter->get_cur == NULL || item == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*item = iter->get_cur(iter);
	if (*item == NULL)
		return STATUS_ERR;

	return STATUS_SUCCESS;
}

int qpol_iterator_next(qpol_iterator_t *iter)
{
	if (iter == NULL || iter->next == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return iter->next(iter);
}

int qpol_iterator_end(qpol_iterator_t *iter)
{
	if (iter == NULL || iter->end == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	return iter->end(iter);
}

int qpol_iterator_get_size(qpol_iterator_t *iter, size_t *size)
{
	if (size != NULL)
		*size = 0;

	if (iter == NULL || size == NULL || iter->size == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	*size = iter->size(iter);

	return STATUS_SUCCESS;
}

void *ebitmap_state_get_cur_type(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;
	policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return db->type_val_to_struct[es->cur];
}

void *ebitmap_state_get_cur_role(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;
	policydb_t *db = NULL;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return db->role_val_to_struct[es->cur];
}

void *ebitmap_state_get_cur_cat(qpol_iterator_t *iter)
{
	ebitmap_state_t *es = NULL;
	policydb_t *db = NULL;
	qpol_cat_t *cat = NULL;
	qpol_policy_t sp;

	if (iter == NULL) {
		errno = EINVAL;
		return NULL;
	}
	es = qpol_iterator_state(iter);
	if (es == NULL) {
		errno = EINVAL;
		return NULL;
	}
	db = qpol_iterator_policy(iter);
	if (db == NULL) {
		errno = EINVAL;
		return NULL;
	}

	/* shallow copy is safe here */
	sp.p = *db;

	/* handle passed in as 1, but should never fail as the name is retrieved from the list into which we are looking */
	qpol_policy_get_cat_by_name((sepol_handle_t*)1, &sp, db->p_cat_val_to_name[es->cur], &cat);

	return cat;
}

void ebitmap_state_destroy(void *es)
{
	ebitmap_state_t *ies = (ebitmap_state_t*)es;

	if (!es)
		return;

	ebitmap_destroy(ies->bmap);
	free(ies->bmap);
	free(ies);
}

