/**
 *  @file vector.c
 *  Contains the implementation of a generic vector.
 *
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

#include "vector.h"
#include <stdlib.h>
#include <errno.h>

apol_vector_t *apol_vector_create(void)
{
	return apol_vector_create_with_capacity(APOL_VECTOR_DFLT_INIT_CAP);
}

apol_vector_t *apol_vector_create_with_capacity(size_t cap)
{
	apol_vector_t *v = NULL;
	int error;

	if (cap < 1) {
		cap = 1;
	}
	v = calloc(1, sizeof(apol_vector_t));
	if (!v)
		return NULL;
	v->array = calloc((v->capacity = cap), sizeof(void*));
	if (!(v->array)) {
		error = errno;
		free(v);
		errno = error;
		return NULL;
	}

	return v;
}

apol_vector_t *apol_vector_create_from_iter(sepol_iterator_t *iter)
{
	size_t iter_size;
	apol_vector_t *v;
	void *item;
	int error;
	if (sepol_iterator_get_size(iter, &iter_size) < 0 ||
	    (v = apol_vector_create_with_capacity(iter_size)) == NULL) {
		return NULL;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, &item)) {
			error = errno;
			free(v);
			errno = error;
			return NULL;
		}
		apol_vector_append(v, item);
	}
	return v;
}

void apol_vector_destroy(apol_vector_t **v, void(*free_fn)(void *elem))
{
	size_t i = 0;

	if (!v || !(*v))
		return;

	if (free_fn) {
		for (i = 0; i < (*v)->size; i++) {
			free_fn((*v)->array[i]);
		}
	}
	free((*v)->array);
	free(*v);
	*v = NULL;
}

size_t apol_vector_get_size(const apol_vector_t *v)
{
	if (!v) {
		errno = EINVAL;
		return 0;
	} else {
		return v->size;
	}
}

size_t apol_vector_get_capacity(const apol_vector_t *v)
{
	if (!v) {
		errno = EINVAL;
		return 0;
	} else {
		return v->capacity;
	}
}

void *apol_vector_get_element(const apol_vector_t *v, size_t idx)
{
	if (!v || !(v->array)) {
		errno = EINVAL;
		return NULL;
	}

	if (idx >= v->size) {
		errno = ERANGE;
		return NULL;
	}

	return v->array[idx];
}

/**
 * Grows a vector, by reallocating additional space for it.
 *
 * @param v Vector to which increase its size.
 *
 * @return 0 on success, -1 on error.
 */
static int apol_vector_grow(apol_vector_t *v)
{
	void **tmp;
	size_t new_capacity = v->capacity;
	if (new_capacity >= 128) {
		new_capacity += 128;
	}
	else {
		new_capacity *= 2;
	}
	tmp = realloc(v->array, new_capacity * sizeof(void *));
	if (!tmp) {
		return -1;
	}
	v->capacity = new_capacity;
	v->array = tmp;
	return 0;	 
}

size_t apol_vector_get_index(const apol_vector_t *v, void *elem,
			     apol_vector_comp_func *cmp, void *data)
{
	size_t i;
	if (!v || !elem || !cmp) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < v->size; i++) {
		if (cmp(v->array[i], elem, data) == 0) {
			return i;
		}
	}
	return -1;
}

int apol_vector_append(apol_vector_t *v, void *elem)
{
	if (!v || !elem) {
		errno = EINVAL;
		return -1;
	}

	if (v->size >= v->capacity && apol_vector_grow(v)) {
		return -1;
	}

	v->array[v->size] = elem;
	v->size++;

	return 0;
}

int apol_vector_append_unique(apol_vector_t *v, void *elem,
			      apol_vector_comp_func *cmp, void *data)
{
	if (apol_vector_get_index(v, elem, cmp, data) == -1) {
	    return apol_vector_append(v, elem);
	}
	errno = EEXIST;
	return 1;
}
