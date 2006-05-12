/**
 *  @file vector.h
 *  Contains the API for a generic vector.
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

#ifndef APOL_VECTOR_H
#define APOL_VECTOR_H

#include <stdlib.h>
#include <sepol/iterator.h>

typedef struct apol_vector apol_vector_t;

typedef int(apol_vector_comp_func)(const void *a, const void *b, void *data);

/**
 *  Allocate and initialize an empty vector with default start
 *  capacity.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
apol_vector_t *apol_vector_create(void);

/**
 *  Allocate and initialize an empty vector with starting capacity of
 *  cap.
 *
 *  @param cap The starting capacity to allocate for the internal
 *  array.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
apol_vector_t *apol_vector_create_with_capacity(size_t cap);

/**
 *  Allocate and return a vector that has been initialized with the
 *  contents of a sepol iterator.  <b>This function merely makes a
 *  shallow copy of the iterator's contents</b>; any memory ownership
 *  restrictions imposed by the iterator apply to this vector as well.
 *  Also note that this function begins copying from the iterator's
 *  current position, leaving the iterator at its end position
 *  afterwards.
 *
 *  @param iter sepol iterator from which to obtain vector's contents.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
apol_vector_t *apol_vector_create_from_iter(sepol_iterator_t *iter);

/**
 *  Allocate and return a vector that has been initialized with the
 *  contents of another vector.  <b>This function merely makes a
 *  shallow copy of the vector's contents</b>; any memory ownership
 *  restrictions imposed by the original vector apply to this new
 *  vector as well.
 *
 *  @param v Vector from which to copy.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
apol_vector_t *apol_vector_create_from_vector(const apol_vector_t *v);

/**
 *  Free a vector and any memory used by it.
 *
 *  @param v Pointer to the vector to free.  The pointer will be set
 *  to NULL afterwards.
 *  @param free_fn Function to call to free the memory used by an
 *  element.  If NULL, the elements will not be freed.
 */
void apol_vector_destroy(apol_vector_t **v, void(*free_fn)(void*elem));

/**
 *  Get the number of elements in the vector.
 *
 *  @param v The vector from which to get the number of elements.
 *  Must be non-NULL.
 *
 *  @return The number of elements in the vector; if v is NULL,
 *  returns 0.
 */
size_t apol_vector_get_size(const apol_vector_t *v);

/**
 *  Get the current capacity of the vector.
 *
 *  @param v The vector from which to get the current capacity.  Must
 *  be non-NULL.
 *
 *  @return The capacity of the vector; this value will be greater or
 *  equal to the number of elements in the vector.  If v is NULL,
 *  returns 0.
 */
size_t apol_vector_get_capacity(const apol_vector_t *v);

/**
 *  Get the element at the requested index.
 *
 *  @param v The vector from which to get the element.
 *  @param idx The index of the desired element.
 *
 *  @return A pointer to the element requested.  If v is NULL or idx is
 *  out of range, returns NULL and sets errno.
 */
void *apol_vector_get_element(const apol_vector_t *v, size_t idx);

/**
 *  Find an element within a vector, returning its index within the vector.
 *
 *  @param v The vector from which to get the element.
 *  @param elem The element to find.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.  For
 *  use in this function the return value is only checked for 0 or
 *  non-zero return.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *
 *  @return The element's position, or < 0 if it could not be found.
 */
size_t apol_vector_get_index(const apol_vector_t *v, void *elem,
                             apol_vector_comp_func *cmp, void *data);

/**
 *  Add an element to the end of a vector.
 *
 *  @param v The vector to which to add the element.
 *  @param elem The element to add. This function performs no checking
 *  on this element other than a check for NULL.  Once added the
 *  element will be the last element in the vector.
 *
 *  @return 0 on success and < 0 on failure.  If the call fails, errno
 *  will be set and v will be unchanged.
 */
int apol_vector_append(apol_vector_t *v, void *elem);

/**
 *  Add an element to the end of a vector unless that element is equal
 *  to an existing element.
 *
 *  @param v The vector to which to add the element.
 *  @param elem The element to add; must be non-NULL.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.  For
 *  use in this function the return value is only checked for 0 or
 *  non-zero return.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *
 *  @return 0 on success, < 0 on failure, and > 0 if the element
 *  already exists in the vector.  If the call fails or the element
 *  already exists errno will be set.
 */
int apol_vector_append_unique(apol_vector_t *v, void *elem,
                              apol_vector_comp_func *cmp, void *data);

/**
 *  Sort the vector's elements within place, using an unstable sorting
 *  algorithm.
 *
 *  @param v The vector to sort.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 */
void apol_vector_sort(apol_vector_t *v, apol_vector_comp_func *cmp, void *data);

#endif /* APOL_VECTOR_H */
