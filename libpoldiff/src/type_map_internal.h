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

#ifdef	__cplusplus
extern "C" {
#endif

#include <apol/vector.h>
#include <qpol/policy_query.h>

typedef struct type_map type_map_t;

#define POLDIFF_POLICY_ORIG 1
#define POLDIFF_POLICY_MOD  2

/**
 *  Allocate and return a new type_map_t object.
 *
 *  @return a new type map object.  The caller must call
 *  type_map_destroy() afterwards.  On error, return NULL and set
 *  errno.
 */
type_map_t *type_map_create(void);

/**
 *  Free all memory used by the type map.
 *
 *  @param map Reference pointer to the type map to destroy.  This
 *  pointer will be set to NULL afterwards.
 */
void type_map_destroy(type_map_t ** map);

/**
 *  Build the type map for a policy difference structure, using all
 *  enabled poldiff_type_remap_entry entries as hints for the
 *  mappings.  This function should be called by poldiff_run() before
 *  each run.
 *
 *  @param diff The policy difference structure containing the
 *  policies from which to construct the type map.
 *  @return 0 on success and < 0 on error, if the call fails, errno will
 *  be set and the policy difference structure will be unchanged.
 */
int type_map_build(poldiff_t * diff);

/**
 *  Clear away all type remap entries within the type map.  This
 *  function should be called some time after type_map_create().
 *
 *  @param diff The policy difference structure containing the
 *  policies from which to construct the type map.
 */
void poldiff_type_remap_flush(poldiff_t * diff);

/**
 *  Infer type remappings and append them to the current type remap
 *  vector.  The vector should probably be first flushed via
 *  poldiff_type_remap_flush().  Generated entries will have their
 *  'enabled' flag set.
 *
 *  The heuristic for determining type remaps is as follow.
 *  <ol>
 *
 *  <li>If any type name exists as a primary in both policies then map
 *  it.
 *
 *  <li>For all remaining unmapped primary types in the original
 *  policy, if that type name appears as an alias to an unmapped
 *  primary in the modified then map it.
 *
 *  <li>For all remaining unmapped primary types in the modified
 *  policy, if that type name appears as an alias to an unmapped
 *  primary in the original then map it.
 *
 *  <li>For all remaining unmapped primary types in both policies, if
 *  all of the aliases of one type are exactly the same as another
 *  type's aliases then map it.
 *
 *  <li>All remaining types are left as unmapped.
 *
 *  </ol>
 *
 *  A side-effect of this heuristic is that it is reversible; the same
 *  inferences are made regardless of the order of policies.
 *
 *  @param diff The policy difference structure containing the
 *  policies from which to construct the type map.
 *
 *  @return 0 on success, < 0 on error and errno will be set.
 */
int type_map_infer(poldiff_t * diff);

/**
 *  Given a qpol_type_t and a flag indicating from which the policy
 *  the type originated, return its remapped value.  (type_map_build()
 *  must have been first called.)
 *
 *  @param diff The policy difference structure assocated with the
 *  types.
 *  @param type Type to lookup.
 *  @param which_pol One of POLDIFF_POLICY_ORIG or POLDIFF_POLICY_MOD.
 *
 *  @return The type's remapped value.  On error this will be 0 and
 *  errno will be set.
 */
uint32_t type_map_lookup(poldiff_t * diff, qpol_type_t * type, int which_pol);

/**
 *  Given a pseudo-type's value and a flag indicating for which policy
 *  to look up, return a vector of qpol_type_t pointers to reference
 *  back to the unmapped types.  (type_map_build() must have been
 *  first called.)  Note that the returned vector could be empty for
 *  the situation where a type was added or removed.
 *
 *  @param diff The policy difference structure assocated with the
 *  types.
 *  @param val Pseudo-type value to lookup.
 *  @param which_pol One of POLDIFF_POLICY_ORIG or POLDIFF_POLICY_MOD.
 *
 *  @return A vector of qpol_type_t pointers.  The caller should not
 *  free this vector.  If the call fails, NULL will be returned and
 *  errno will be set.
 */
apol_vector_t *type_map_lookup_reverse(poldiff_t * diff, uint32_t val, int which_pol);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_TYPE_MAP_INTERNAL_H */
