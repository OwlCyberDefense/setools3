/**
 *  @file type_map_internal.h
 *  Protected Interface for type equivalence mapping for semantic 
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

#ifndef POLDIFF_TYPE_MAP_INTERNAL_H
#define POLDIFF_TYPE_MAP_INTERNAL_H

#include <apol/vector.h>
#include <poldiff/type_map.h>
#include <poldiff/poldiff.h>

#define POLDIFF_POLICY_ORIG 1
#define POLDIFF_POLICY_MOD  2

/**
 *  Build the type map for a policy difference structure.
 *  @param diff The policy difference structure containing the policies
 *  from which to construct the type map.
 *  @return 0 on success and < 0 on error, if the call fails, errno will
 *  be set and the policy difference structure will be unchanged.
 */
int poldiff_type_map_build(poldiff_t *diff);

/**
 *  Free all memory used by the type map.
 *  @param map Reference pointer to the type map to destroy. This pointer
 *  will be set to NULL.
 */
void poldiff_type_map_destroy(poldiff_type_map_t **map);

/**
 *  Given a vector of types get an equivalent vector of pseudo type values.
 *  @param diff The policy difference structure assocated with the types.
 *  @param types Vector of qpol_type_t elements to convert.
 *  @param which_pol One of POLDIFF_POLICY_* above to indicate from which
 *  policy the types in the vector come.
 *  @return A newly allocated vector of type uint32_t of equivalent pseudo type
 *  values. The caller is responsible for calling apol_vector_destroy() passing
 *  NULL as the second parameter to free memory used by this vector. If the call
 *  fails, NULL will be returned and errno will be set.
 */
apol_vector_t *poldiff_type_vector_map(poldiff_t *diff, apol_vector_t *types, int which_pol);

/**
 *  Get the vector of types which map to a pseudo type value for a given policy.
 *  @param diff The policy difference structure associated with the type mapping.
 *  @param val The pseudo type value for which to get the types.
 *  @param which_pol One of POLDIFF_POLICY_* above to indicate from which
 *  policy the types in the vector should come.
 *  @return A newly allocated vector of qpol_type_t elements corresponding to
 *  the pseudo type value in the specified policy. The size of this vector may
 *  be zero in the case where no types from the specified policy map to that
 *  value. The caller is responsible for calling apol_vector_destroy() passing
 *  NULL as the second parameter to free memory used by this vector. If the call
 *  fails, NULL will be returned and errno will be set.
 */
apol_vector_t *poldiff_pseudo_type_get_types(poldiff_t *dif, uint32_t val, int which_pol);

#endif /* POLDIFF_TYPE_MAP_INTERNAL_H */

