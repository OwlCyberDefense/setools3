/**
 *  @file
 *  Public interface for computing a semantic differences in categories.
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

#ifndef POLDIFF_CAT_DIFF_H
#define POLDIFF_CAT_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_cat poldiff_cat_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for categories.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
	extern void poldiff_cat_get_stats(poldiff_t * diff, size_t stats[5]);

/**
 *  Get the vector of user differences from the category difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  category difference summary.
 *
 *  @return A vector of elements of type poldiff_cat_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
	extern apol_vector_t *poldiff_get_cat_vector(poldiff_t * diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a category.
 *
 *  @param diff The policy difference structure associated with the category.
 *  @param cat The category from which to generate the string.
 *
 *  @return A string representation of category difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
	extern char *poldiff_cat_to_string(poldiff_t * diff, const void *cat);

/**
 *  Get the name of the category from a category diff.
 *
 *  @param cat The category from which to get the name.
 *
 *  @return Name of the category on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
	extern const char *poldiff_cat_get_name(const poldiff_cat_t * cat);

/**
 *  Get the form of difference from a category diff.
 *
 *  @param cat The category from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
	extern poldiff_form_e poldiff_cat_get_form(const void *cat);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_CAT_DIFF_H */
