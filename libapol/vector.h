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

/** The default initial capacity of a vector; must be a positive integer */
#define APOL_VECTOR_DFLT_INIT_CAP 10

/**
 *  Generic vector structure. Stores elements as void*.
 */
typedef struct apol_vector {
        /** The array of element pointers, which will be resized as needed */
        void    **array;
        /** The number of elements currently stored in array. */
        size_t  size;
        /** The actually amount of space in array. This amount will always 
         *  be >= size and will grow exponentially as needed. */
        size_t  capacity; 
} apol_vector_t;

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
 *
 *  @return 0 on success, < 0 on failure, and > 0 if the element
 *  already exists in the vector.  If the call fails or the element
 *  already exists errno will be set.
 */
int apol_vector_append_unique(apol_vector_t *v, void *elem, int(*cmp)(void*a,void*b));

#endif /* APOL_VECTOR_H */
