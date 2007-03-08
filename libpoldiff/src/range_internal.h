/**
 *  @file
 *  Protected interface for range differences.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef POLDIFF_RANGE_INTERNAL_H
#define POLDIFF_RANGE_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

/**
 * Allocate and return a poldiff_range_t object.  This will fill in
 * the orig_range and mod_range strings.  If the form is modified,
 * then this will allocate the levels vector but leave it empty.
 * Otherwise the levels vector will be filled with the levels that
 * were added/removed.
 *
 * @param diff Diff object containing policies.
 * @param orig_range Range from original policy, or NULL if there is
 * no original range.
 * @param mod_range Range from modified policy, or NULL if there is no
 * modified range.
 * @param form Form of the range.
 *
 * @return An initialized range, or NULL upon error.  Caller must call
 * range_destroy() upon the returned value.
 */
	poldiff_range_t *range_create(poldiff_t * diff, qpol_mls_range_t * orig_range, qpol_mls_range_t * mod_range,
				      poldiff_form_e form);

/**
 * Deallocate all space for a range, including the pointer itself.
 * Afterwards set the pointer to NULL.
 *
 * @param range Reference to a range to destroy.
 */
	void range_destroy(poldiff_range_t ** range);

/**
 * Calculate the differences between two ranges (that are stored
 * within the poldiff_range_t object).  This involves two things:
 * changes in the expanded levels, and changes to minimum category
 * sets.  If differences are found then the range's levels vector will
 * be filled with those differences.
 *
 * @param diff Diff object containing policies.
 * @param range Range object to diff.
 *
 * @return Greater than zero if a diff was found, zero if none found,
 * less than zero for errors.
 */
	int range_deep_diff(poldiff_t * diff, poldiff_range_t * range);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_RANGE_INTERNAL_H */
