/**
 *  @file
 *  Public interface for returning the differences in MLS ranges.
 *  Obtain a range difference object from its respective policy
 *  component (e.g., a user's assigned range).  The individual level
 *  difference querying functions are in the level_diff.h header.
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

#ifndef POLDIFF_RANGE_DIFF_H
#define POLDIFF_RANGE_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/mls-query.h>
#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_range poldiff_range_t;

/**
 * Allocate and return a string that represents the differences
 * encoded by the given range.  The returned string is suitable for
 * embedding within another item's to_string() display.
 *
 * @param diff Poldiff diff structure containing policies.
 * @param range Range object to render.
 *
 * @return Rendered string, or NULL upon error.  Caller must free()
 * string afterwards.
 */
	char *poldiff_range_to_string_brief(poldiff_t * diff, const poldiff_range_t * range);

/**
 *  Get the vector of level differences from a range diffence object.
 *
 *  @param range Range object to query.
 *
 *  @return A vector of elements of type poldiff_level_t, or NULL on
 *  error.  The caller should <b>not</b> modify the returned vector.
 */
	extern apol_vector_t *poldiff_range_get_levels(const poldiff_range_t * range);

/**
 *  Get the original item's range.  This could represent a user's
 *  original assigned range or the original target range for a
 *  range_transition.  If there was no original range (such as for
 *  items that are added) then this returns NULL.
 *
 *  @param range Range object to query.
 *
 *  @return Original range, or NULL upon error or no range available.
 *  The caller should <b>not</b> modify the returned object.
 */
	extern const apol_mls_range_t *poldiff_range_get_original_range(const poldiff_range_t * range);

/**
 *  Get the modified item's range.  This could represent a user's
 *  modified assigned range or the modified target range for a
 *  range_transition.  If there was no original range (such as for
 *  items that are removed) then this returns NULL.
 *
 *  @param range Range object to query.
 *
 *  @return Modified range, or NULL upon error or no range available.
 *  The caller should <b>not</b> modify the returned object.
 */
	extern const apol_mls_range_t *poldiff_range_get_modified_range(const poldiff_range_t * range);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_RANGE_DIFF_H */
