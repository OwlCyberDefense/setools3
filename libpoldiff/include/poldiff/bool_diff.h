/**
 *  @file bool_diff.h
 *  Public Interface for computing a semantic differences in bools.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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

#ifndef POLDIFF_BOOL_DIFF_H
#define POLDIFF_BOOL_DIFF_H

#include <apol/vector.h>
#include <poldiff/poldiff.h>

/************************ booleans **********************/

typedef struct poldiff_bool poldiff_bool_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for bools.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated). The order of the values written to the array is as
 *  follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  form POLDIFF_FORM_ADD_TYPE, and number of
 *  POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_bool_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of bool differences from the boolean difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  bool difference summary.
 *
 *  @return A vector of elements of type poldiff_bool_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_bool_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a bool.
 *
 *  @param diff The policy difference structure associated with the bool.
 *  @param item The bool from which to generate the string.
 *
 *  @return A string representation of bool difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
extern char *poldiff_bool_to_string(poldiff_t *diff, const void *boolean);

/**
 *  Get the number of added bools from a policy difference
 *  structure.
 *
 *  @param diff The policy difference structure from which to get the
 *  number of added bools.
 *
 *  @return The number of added bools or 0 if not yet run.  (The
 *  number of differences could also be zero.)
 */
extern size_t poldiff_get_num_added_bools(poldiff_t *diff);

/**
 *  Get the number of removed bools from a policy difference
 *  structure.
 *
 *  @param diff The policy difference structure from which to get the
 *  number of removed bools.
 *
 *  @return The number of removed bools or 0 if not yet run.  (The
 *  number of differences could also be zero.)
 */
extern size_t poldiff_get_num_removed_bools(poldiff_t *diff);

/**
 *  Get the number of modified bools from a policy difference
 *  structure.
 *
 *  @param diff The policy difference structure from which to get the
 *  number of modified bools.
 *
 *  @return The number of modified bools or 0 if not yet run.  (The
 *  number of differences could also be zero.)
 */
extern size_t poldiff_get_num_modified_bools(poldiff_t *diff);

/**
 *  Get the name of the bool from a bool diff.
 *
 *  @param diff The policy difference structure associated with the
 *  bool diff.
 *  @param cls The bool from which to get the name.
 *
 *  @return Name of the bool on success and NULL on failure; if the
 *  call fails, errno will be set. The caller should not free the
 *  returned string.
 */
extern const char *poldiff_bool_get_name(const poldiff_bool_t *boolean);

/**
 *  Get the form of difference from a bool diff.
 *
 *  @param diff The policy difference structure associated with the
 *  bool diff.
 *
 *  @param cls The bool from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_bool_get_form(const poldiff_bool_t *boolean);

#endif /* POLDIFF_BOOL_DIFF_H */
