/**
 *  @file
 *  Public interface for computing a semantic differences in range
 *  transition rules.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#ifndef POLDIFF_RANGETRANS_DIFF_H
#define POLDIFF_RANGETRANS_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/mls-query.h>
#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_range_trans poldiff_range_trans_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for range transition rules.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
	extern void poldiff_range_trans_get_stats(poldiff_t * diff, size_t stats[5]);

/**
 *  Get the vector of range transition differences from the policy
 *  difference structure.
 *
 *  @param diff The policy difference structure from which to get the
 *  differences.
 *
 *  @return A vector of elements of type poldiff_range_trans_t, or
 *  NULL on error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
	extern apol_vector_t *poldiff_get_range_trans_vector(poldiff_t * diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a range transition rule.
 *
 *  @param diff The policy difference structure associated with the rule.
 *  @param range_trans The range transition diff from which to
 *  generate the string.
 *
 *  @return A string representation of the rule difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
	extern char *poldiff_range_trans_to_string(poldiff_t * diff, const void *range_trans);

/**
 *  Get the name of the source type from a range transition diff.
 *
 *  @param range_trans The rule from which to get the source type.
 *
 *  @return Name of the source type on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
	extern const char *poldiff_range_trans_get_source_type(const poldiff_range_trans_t * range_trans);

/**
 *  Get the name of the target type from a range transition diff.
 *
 *  @param range_trans The rule from which to get the target type.
 *
 *  @return Name of the target type on success and NULL on failure; if
 *  the call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
	extern const char *poldiff_range_trans_get_target_type(const poldiff_range_trans_t * range_trans);

/**
 *  Get the name of the target object class from a range transition
 *  diff.
 *
 *  @param range_trans The rule from which to get the target class.
 *
 *  @return Name of the target class on success and NULL on failure;
 *  if the call fails, errno will be set.  The caller should not free
 *  the returned string.
 */
	extern const char *poldiff_range_trans_get_target_class(const poldiff_range_trans_t * range_trans);

/**
 *  Get the change in target range from a range transition diff.
 *
 *  @param range_trans The rule from which to get the target range.
 *
 *  @return Rule's target range on success, or NULL upon error or if
 *  there is no difference in range.  Do not modify the returned value.
 */
	extern const poldiff_range_t *poldiff_range_trans_get_range(const poldiff_range_trans_t * range_trans);

/**
 *  Get the form of difference from a range transition diff.
 *
 *  @param range_trans The range transition rule from which to get the
 *  difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
	extern poldiff_form_e poldiff_range_trans_get_form(const void *range_trans);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_RANGETRANS_DIFF_H */
