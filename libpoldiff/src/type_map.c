/**
 *  @file type_map.c
 *  Implementation of type equivalence mapping for semantic 
 *  difference calculations.
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

/** 
 *  The mapping of types is handled by creating a list of pseudo type values to
 *  represent the set of all semantically unique types in both the original and
 *  modified policies. This mapping takes into account both inferred and user
 *  specified mappings of types and may contain holes where a type does not
 *  exist in one of the policies.
 */

#include <poldiff/poldiff.h>
#include <poldiff/type_map.h>
#include "type_map_internal.h"

struct poldiff_type_map {
	/** array of size num_orig_types mapping types by (value -1) to pseudo value */
	uint32_t *orig_to_pseudo;
	/** array of size num_mod_types mapping types by (value -1) to pseudo value */
	uint32_t *mod_to_pseudo;
	/** vector of vectors reverse mapping pseudo value to mod_policy value(s) */
	apol_vector_t *pseudo_to_mod;
	/** vector of vectors reverse mapping pseudo value to orig_policy value(s) */
	apol_vector_t *pseudo_to_orig;
	size_t num_orig_types;
	size_t num_mod_types;
}
