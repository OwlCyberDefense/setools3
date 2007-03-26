/**
 *  @file
 *  Public interface for type equivalence mapping for semantic
 *  difference calculations.
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

#ifndef POLDIFF_TYPE_MAP_H
#define POLDIFF_TYPE_MAP_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <poldiff/poldiff.h>
#include <apol/vector.h>

	typedef struct poldiff_type_remap_entry poldiff_type_remap_entry_t;

/**
 *  Note that a type(s) from the original policy should be remapped in
 *  the modified policy.  Subsequent diffs will treat type(s) in
 *  orig_names to be equivalent to type(s) in mod_names.  The created
 *  remap entry will be marked as enabled.
 *
 *  It is an error for the size of both vectors to be greater than
 *  one.
 *
 *  Note that you may only remap primary types, not attributes nor
 *  aliases.
 *
 *  @param diff The difference structure associated with the types.
 *  Note that renaming a type will reset the status of previously run
 *  difference calculations and they will need to be rerun.
 *  @param orig_names A vector of type names (char *) in the original
 *  policy.
 *  @param mod_name A vector of type names (char *) in the modified
 *  policy to consider equivalent.
 *
 *  @return 0 on success or < 0 on error; if the call fails, errno
 *  will be set and the poldiff object remains unchanged.
 */
	extern int poldiff_type_remap_create(poldiff_t * diff, const apol_vector_t * orig_names, const apol_vector_t * mod_names);

/**
 *  Get a vector of all identified type remap entries.  The caller may
 *  then manipulate this list by selectively enabling/disabling
 *  individual entries.
 *
 *  @param diff The difference structure associated with the types
 *  remaps.
 *
 *  @return Vector of poldiff_type_remap_entry_t objects.  The caller
 *  should not destroy this vector.
 */
	extern apol_vector_t *poldiff_type_remap_get_entries(poldiff_t * diff);

/**
 *  Remove a poldiff_type_remap_entry object.  This function will
 *  destroy the entry object afterwards.
 *
 *  @param diff The difference structure associated with the types
 *  remaps.
 *  @param entry Type remap entry to remove and destroy.
 */
	extern void poldiff_type_remap_entry_remove(poldiff_t * diff, poldiff_type_remap_entry_t * entry);

/**
 *  Allocate and return a sorted vector of type names (char *)
 *  corresponding to the original types within a
 *  poldiff_type_remap_entry_t object.  The strings themselves are to
 *  be considered immutable; if the caller needs them for future use
 *  it should duplicate them.
 *
 *  @param diff Difference structure, for error reporting.
 *  @param entry Remap entry from which to get type names.
 *
 *  @return Vector of type names.  The caller is responsible for
 *  calling apol_vector_destroy() afterwards.  Upon error return NULL
 *  and set errno.
 */
	extern apol_vector_t *poldiff_type_remap_entry_get_original_types(poldiff_t * diff, poldiff_type_remap_entry_t * entry);

/**
 *  Allocate and return a sorted vector of type names (char *)
 *  corresponding to the modified types within a
 *  poldiff_type_remap_entry_t object.  The strings themselves are to
 *  be considered immutable; if the caller needs them for future use
 *  it should duplicate them.
 *
 *  @param diff Difference structure, for error reporting.
 *  @param entry Remap entry from which to get type names.
 *
 *  @return Vector of type names.  The caller is responsible for
 *  calling apol_vector_destroy() afterwards.  Upon error return NULL
 *  and set errno.
 */
	extern apol_vector_t *poldiff_type_remap_entry_get_modified_types(poldiff_t * diff, poldiff_type_remap_entry_t * entry);

/**
 *  Given a poldiff_type_remap_entry_t object, determine if was
 *  an inferred mapping or not.
 *
 *  @param entry Remap entry from which to get its inference status.
 *
 *  @return 1 if it was inferred, 0 if not, < 0 on error.
 */
	extern int poldiff_type_remap_entry_get_is_inferred(poldiff_type_remap_entry_t * entry);

/**
 *  Given a poldiff_type_remap_entry_t object, determine if it is
 *  enabled or not.
 *
 *  @param entry Remap entry from which to get its enabled status.
 *
 *  @return 1 if it is enabled, 0 if not, < 0 on error.
 */
	extern int poldiff_type_remap_entry_get_is_enabled(poldiff_type_remap_entry_t * entry);

/**
 *  Enable or disable a poldiff_type_remap_entry_t object.
 *
 *  @param entry Remap entry from which to set its enabled status.
 *  @param enabled 0 to disable this entry, non-zero to enable it.
 */
	extern void poldiff_type_remap_entry_set_enabled(poldiff_type_remap_entry_t * entry, int enabled);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_TYPE_MAP_H */
