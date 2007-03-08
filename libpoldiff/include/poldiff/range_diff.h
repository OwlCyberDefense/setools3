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

#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_range poldiff_range_t;

/**
 *  Get the vector of level differences from a range diffence object.
 *
 *  @param range Range object to query.
 *
 *  @return A vector of elements of type poldiff_level_t, or NULL on
 *  error.  The caller should <b>not</b> modify the returned vector.
 */
	extern apol_vector_t *poldiff_range_get_levels(poldiff_range_t * range);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_RANGE_DIFF_H */
