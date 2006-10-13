/**
 *  @file attrib_diff.h
 *  Public Interface for computing a semantic differences in attribs.
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

#ifndef POLDIFF_ATTRIB_DIFF_H
#define POLDIFF_ATTRIB_DIFF_H

#include <apol/vector.h>
#include <poldiff/poldiff.h>

typedef struct poldiff_attrib poldiff_attrib_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for attribs.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_attrib_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of attrib differences from the attrib difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  attrib difference summary.
 *
 *  @return A vector of elements of type poldiff_attrib_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_attrib_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a attrib.
 *
 *  @param diff The policy difference structure associated with the attrib.
 *  @param attrib The attrib from which to generate the string.
 *
 *  @return A string representation of attrib difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
extern char *poldiff_attrib_to_string(poldiff_t *diff, const void *attrib);

/**
 *  Get the name of the attrib from a attrib diff.
 *
 *  @param attrib The attrib from which to get the name.
 *
 *  @return Name of the attrib on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
extern const char *poldiff_attrib_get_name(const poldiff_attrib_t *attrib);

/**
 *  Get the form of difference from a attrib diff.
 *
 *  @param attrib The attrib from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_attrib_get_form(const void *attrib);

/**
 *  Get a vector of types added to the attrib.
 *
 *  @param attrib The attrib diff from which to get the types vector.
 *
 *  @return A vector of type names (type char *) that are allowed to
 *  the attrib in the modified policy.  If no types were added the size
 *  of the returned vector will be 0.  The caller must not destroy
 *  this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_attrib_get_added_attribs(const poldiff_attrib_t *attrib);

/**
 *  Get a vector of types removed from the attrib.
 *
 *  @param attrib The attrib diff from which to get the types vector.
 *
 *  @return A vector of type names (type char *) that are allowed to
 *  the attrib in the original policy.  If no types were removed the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_attrib_get_removed_attribs(const poldiff_attrib_t *attrib);

#endif /* POLDIFF_ATTRIB_DIFF_H */
