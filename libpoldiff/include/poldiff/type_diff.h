/**
 *  @file type_diff.h
 *  Public Interface for computing a semantic difference of types.
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

#ifndef POLDIFF_TYPE_DIFF_H
#define POLDIFF_TYPE_DIFF_H

#include <apol/vector.h>
#include <poldiff/poldiff.h>

/******************** types ********************/

typedef struct poldiff_type poldiff_type_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for types.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_type_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of type differences from the type difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  type difference summary.
 *
 *  @return a vector of elements of type poldiff_type_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_type_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a type.
 *
 *  @param diff The policy difference structure associated with the type.
 *  @param type The type from which to generate the string.
 *
 *  @return A string representation of type difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
extern char *poldiff_type_to_string(poldiff_t *diff, const void *type);

/**
 *  Get the name of the type from a type diff.
 *
 *  @param type The type from which to get the name.
 *
 *  @return name of the type on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
extern const char *poldiff_type_get_name(poldiff_type_t *type);

/**
 *  Get the form of difference from a type diff.
 *
 *  @param cls The type from which to get the difference form.
 *
 *  @return the form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_type_get_form(poldiff_type_t *type);

/**
 *  Get a vector of attributes added to the type.
 *
 *  @param type The type diff from which to get the attribute
 *  vector.
 *
 *  @return a vector of attribute names (type char *) that are
 *  assigned to the type in the modified policy.  If no attributes
 *  were added the size of the returned vector will be 0.  The
 *  caller must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_type_get_added_attribs(poldiff_type_t *type);

/**
 *  Get a vector of attributes removed from the type.
 *
 *  @param type The type diff from which to get the attribute
 *  vector.
 *
 *  @return a vector of attribute names (type char *) that are
 *  assigned to the type in the original policy.  If no attributes
 *  were removed the size of the returned vector will be 0.  The
 *  caller must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_type_get_removed_attribs(poldiff_type_t *type);


#endif /* POLDIFF_TYPE_DIFF_H */
