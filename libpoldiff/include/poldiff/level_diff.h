/**
 *  @file
 *  Public Interface for computing a semantic differences in levels.
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

#ifndef POLDIFF_LEVEL_DIFF_H
#define POLDIFF_LEVEL_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_level poldiff_level_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for levels.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
	extern void poldiff_level_get_stats(poldiff_t * diff, size_t stats[5]);

/**
 *  Get the vector of level differences from the level difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  level difference summary.
 *
 *  @return A vector of elements of type poldiff_level_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
	extern apol_vector_t *poldiff_get_level_vector(poldiff_t * diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a level.
 *
 *  @param diff The policy difference structure associated with the level.
 *  @param level The level from which to generate the string.
 *
 *  @return A string representation of level difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
	extern char *poldiff_level_to_string(poldiff_t * diff, const void *level);

/**
 *  Get the name of the level (i.e., the sensitivity) from a level diff.
 *
 *  @param level The level from which to get the name.
 *
 *  @return Name of the level on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
	extern const char *poldiff_level_get_name(const poldiff_level_t * level);

/**
 *  Get the form of difference from a level diff.
 *
 *  @param level The level from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
	extern poldiff_form_e poldiff_level_get_form(const void *level);

/**
 *  Get a vector of unmodified categories from the level.  These will
 *  be sorted in the same order as given by the original policy.
 *
 *  @param level The level diff from which to get the category vector.
 *
 *  @return A vector of category names (type char *) that are assigned to
 *  the level in the original policy.  If no categories were removed the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_level_get_unmodified_cats(const poldiff_level_t * level);

/**
 *  Get a vector of categories added to the level.  These will be
 *  sorted in the same order as given by the modified policy.  If the
 *  level was added by modified policy then this vector will hold all
 *  of the categories.
 *
 *  @param level The level diff from which to get the categories.
 *
 *  @return A vector of category names (type char *) that are assigned
 *  to the level in the modified policy.  If no categories were added
 *  the size of the returned vector will be 0.  The caller must not
 *  modify this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_level_get_added_cats(const poldiff_level_t * level);

/**
 *  Get a vector of categories removed from the level.  These will be
 *  sorted in the same order as given by the original policy.  If the
 *  level was removed by modified policy then this vector will hold
 *  all of the categories.
 *
 *  @param level The level diff from which to get the category vector.
 *
 *  @return A vector of category names (type char *) that are assigned to
 *  the level in the original policy.  If no categories were removed the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_level_get_removed_cats(const poldiff_level_t * level);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_LEVEL_DIFF_H */
