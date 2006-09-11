/**
 *  @file role_allow_diff.h
 *  Public Interface for computing a semantic differences in roles allow rules.
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

#ifndef POLDIFF_ROLE_ALLOW_DIFF_H
#define POLDIFF_ROLE_ALLOW_DIFF_H

#include <apol/vector.h>
#include <poldiff/poldiff.h>

typedef struct poldiff_role_allow poldiff_role_allow_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for role allow rules.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_role_allow_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of role allow differences from the policy difference
 *  structure.
 *
 *  @param diff The policy difference structure from which to get the
 *  differences.
 *
 *  @return A vector of elements of type poldiff_role_allow_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_role_allow_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a role allow rule.
 *
 *  @param diff The policy difference structure associated with the role.
 *  @param role_allow The role from which to generate the string.
 *
 *  @return A string representation of role difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
extern char *poldiff_role_allow_to_string(poldiff_t *diff, const void *role_allow);

/**
 *  Get the name of the source role from a role allow diff.
 *
 *  @param role_alloe The role allow from which to get the source role name.
 *
 *  @return Name of the source role on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
extern const char *poldiff_role_allow_get_name(const poldiff_role_allow_t *role_allow);

/**
 *  Get the form of difference from a role allow diff.
 *
 *  @param role_allow The role allow rule from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_role_allow_get_form(const poldiff_role_allow_t *role_allow);

/**
 *  Get a vector of roles added to the role allow rule.
 *
 *  @param role_allow The role allow diff from which to get the types vector.
 *
 *  @return A vector of role names (type char *) that are allowed to
 *  the role in the modified policy.  If no roles were added the size
 *  of the returned vector will be 0.  The caller must not destroy
 *  this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_role_allow_get_added_roles(const poldiff_role_allow_t *role_allow);

/**
 *  Get a vector of roles removed from the role allow rule.
 *
 *  @param role_allow The role allow diff from which to get the types vector.
 *
 *  @return A vector of role names (type char *) that are allowed to
 *  the role in the original policy.  If no roles were removed the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_role_allow_get_removed_roles(const poldiff_role_allow_t *role_allow);

#endif /* POLDIFF_ROLE_ALLOW_DIFF_H */ 
