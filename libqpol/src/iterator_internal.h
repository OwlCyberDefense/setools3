/**
 * @file iterator_internal.h
 * Declaration of the internal interface for 
 * qpol_iterator, an arbitrary valued policy component
 * iterator used to return lists of components.
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

#ifndef QPOL_ITERATOR_INTERNAL_H
#define  QPOL_ITERATOR_INTERNAL_H

#include <sepol/policydb/policydb.h>
#include <qpol/iterator.h>
#include <stddef.h>

typedef struct hash_state {
	unsigned int bucket;
	hashtab_node_t *node;
	hashtab_t *table;
} hash_state_t;

typedef struct ebitmap_state {
	ebitmap_t *bmap;
	size_t cur;
} ebitmap_state_t;

typedef struct ocon_state {
	ocontext_t *head;
	ocontext_t *cur;
} ocon_state_t;

int qpol_iterator_create(sepol_handle_t *handle, policydb_t *policy, void *state,
	void *(*get_cur)(qpol_iterator_t *iter),
	int (*next)(qpol_iterator_t *iter),
	int (*end)(qpol_iterator_t *iter),
	size_t (*size)(qpol_iterator_t *iter),
	void (*free_fn)(void *x),
	qpol_iterator_t **iter);

void *qpol_iterator_state(qpol_iterator_t *iter);
policydb_t *qpol_iterator_policy(qpol_iterator_t *iter);

void *hash_state_get_cur(qpol_iterator_t *iter);
void *hash_state_get_cur_key(qpol_iterator_t *iter);
void *ebitmap_state_get_cur_type(qpol_iterator_t *iter);
void *ebitmap_state_get_cur_role(qpol_iterator_t *iter);
void *ebitmap_state_get_cur_cat(qpol_iterator_t *iter);
void *ocon_state_get_cur(qpol_iterator_t *iter);

int hash_state_next(qpol_iterator_t *iter);
int ebitmap_state_next(qpol_iterator_t *iter);
int ocon_state_next(qpol_iterator_t *iter);

int hash_state_end(qpol_iterator_t *iter);
int ebitmap_state_end(qpol_iterator_t *iter);
int ocon_state_end(qpol_iterator_t *iter);

size_t hash_state_size(qpol_iterator_t *iter);
size_t ebitmap_state_size(qpol_iterator_t *iter);
size_t ocon_state_size(qpol_iterator_t *iter);

void ebitmap_state_destroy(void *es);
#endif /* QPOL_ITERATOR_INTERNAL_H */
