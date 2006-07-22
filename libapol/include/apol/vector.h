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
#include <qpol/iterator.h>

typedef struct apol_vector apol_vector_t;

typedef int(apol_vector_comp_func)(const void *a, const void *b, void *data);
typedef void(apol_vector_free_func)(void *elem);

/**
 *  Allocate and initialize an empty vector with default start
 *  capacity.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
extern apol_vector_t *apol_vector_create(void);

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
extern apol_vector_t *apol_vector_create_with_capacity(size_t cap);

/**
 *  Allocate and return a vector that has been initialized with the
 *  contents of a qpol iterator.  <b>This function merely makes a
 *  shallow copy of the iterator's contents</b>; any memory ownership
 *  restrictions imposed by the iterator apply to this vector as well.
 *  Also note that this function begins copying from the iterator's
 *  current position, leaving the iterator at its end position
 *  afterwards.
 *
 *  @param iter qpol iterator from which to obtain vector's contents.
 *
 *  @return A pointer to a newly created vector on success and NULL on
 *  failure.  If the call fails, errno will be set.  The caller is
 *  responsible for calling apol_vector_destroy() to free memory used.
 */
extern apol_vector_t *apol_vector_create_from_iter(qpol_iterator_t *iter);

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
extern apol_vector_t *apol_vector_create_from_vector(const apol_vector_t *v);

/**
 *  Free a vector and any memory used by it.
 *
 *  @param v Pointer to the vector to free.  The pointer will be set
 *  to NULL afterwards.
 *  @param fr Function to call to free the memory used by an element.
 *  If NULL, the elements will not be freed.
 */
extern void apol_vector_destroy(apol_vector_t **v, apol_vector_free_func *fr);

/**
 *  Get the number of elements in the vector.
 *
 *  @param v The vector from which to get the number of elements.
 *  Must be non-NULL.
 *
 *  @return The number of elements in the vector; if v is NULL,
 *  returns 0.
 */
extern size_t apol_vector_get_size(const apol_vector_t *v);

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
extern size_t apol_vector_get_capacity(const apol_vector_t *v);

/**
 *  Get the element at the requested index.
 *
 *  @param v The vector from which to get the element.
 *  @param idx The index of the desired element.
 *
 *  @return A pointer to the element requested.  If v is NULL or idx is
 *  out of range, returns NULL and sets errno.
 */
extern void *apol_vector_get_element(const apol_vector_t *v, size_t idx);

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
 *  non-zero return.  If this is NULL then do pointer address
 *  comparison.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *  @param i Index into vector where element was found.  This value is
 *  undefined if the element was not found.
 *
 *  @return 0 if element was found, or < 0 if not found.
 */
extern int apol_vector_get_index(const apol_vector_t *v, void *elem,
				 apol_vector_comp_func *cmp, void *data, size_t *i);

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
extern int apol_vector_append(apol_vector_t *v, void *elem);

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
 *  non-zero return.  If this is NULL then do pointer address
 *  comparison.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *
 *  @return 0 on success, < 0 on failure, and > 0 if the element
 *  already exists in the vector.  If the call fails or the element
 *  already exists errno will be set.
 */
extern int apol_vector_append_unique(apol_vector_t *v, void *elem,
				     apol_vector_comp_func *cmp, void *data);

/**
 *  Concatenate two vectors.  Appends all elements of src to dest.
 *  <b>NOTE: No type checking is done for elements in the two
 *  vectors.</b> Elements are not deep copies.
 *  @param dest vector to which to append elements.
 *  @param src vector containing elements to append.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and dest's contents will be reverted.
 */
extern int apol_vector_cat(apol_vector_t *dest, const apol_vector_t *src);

/**
 *  Compares two vectors, determining if one is different than
 *  another.  This uses a callback to compare elements across the
 *  vectors.
 *
 *  @param a First vector to compare.
 *  @param b Second vector to compare.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.  If
 *  this is NULL then do pointer address comparison.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *  @param i Reference to where to store the index of the first
 *  detected difference.  The value is undefined if vectors are
 *  equivalent (return value of 0).  Note that the index may be
 *  greater than a vector's size if the vectors are of unequal
 *  lengths.
 *
 *  @return < 0 if vector A is less than B, > 0 if A is greater than
 *  B, or 0 if equivalent.
 */
extern int apol_vector_compare(apol_vector_t *a, apol_vector_t *b,
			       apol_vector_comp_func *cmp, void *data,
			       size_t *i);

/**
 *  Sort the vector's elements within place, using an unstable sorting
 *  algorithm.
 *
 *  @param v The vector to sort.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.  If
 *  this is NULL then treat the vector's contents as unsigned integers
 *  and sort in increasing order.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 */
extern void apol_vector_sort(apol_vector_t *v,
			     apol_vector_comp_func *cmp, void *data);

/**
 *  Sort the vector's elements within place (see apol_vector_sort()),
 *  and then compact vector by removing duplicate entries.
 *
 *  @param v The vector to sort.
 *  @param cmp A comparison call back for the type of element stored
 *  in the vector.  The expected return value from this function is
 *  less than, equal to, or greater than 0 if the first argument is
 *  less than, equal to, or greater than the second respectively.  If
 *  this is NULL then treat the vector's contents as unsigned integers
 *  and sort in increasing order.
 *  @param data Arbitrary data to pass as the comparison function's
 *  third paramater.
 *  @param fr Function to call to free the memory used by a non-unique
 *  element.  If NULL, those excess elements will not be freed.
 */
extern void apol_vector_sort_uniquify(apol_vector_t *v,
				      apol_vector_comp_func *cmp, void *data,
				      apol_vector_free_func *fr);

#endif /* APOL_VECTOR_H */
