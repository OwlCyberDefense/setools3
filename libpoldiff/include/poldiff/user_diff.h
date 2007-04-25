/**
 *  @file
 *  Public interface for computing semantic differences in users.
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

#ifndef POLDIFF_USER_DIFF_H
#define POLDIFF_USER_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_user poldiff_user_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for users.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
	extern void poldiff_user_get_stats(poldiff_t * diff, size_t stats[5]);

/**
 *  Get the vector of user differences from the user difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  user difference summary.
 *
 *  @return A vector of elements of type poldiff_user_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
	extern apol_vector_t *poldiff_get_user_vector(poldiff_t * diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a user.
 *
 *  @param diff The policy difference structure associated with the user.
 *  @param user The user from which to generate the string.
 *
 *  @return A string representation of user difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
	extern char *poldiff_user_to_string(poldiff_t * diff, const void *user);

/**
 *  Get the name of the user from a user diff.
 *
 *  @param user The user from which to get the name.
 *
 *  @return Name of the user on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
	extern const char *poldiff_user_get_name(const poldiff_user_t * user);

/**
 *  Get the form of difference from a user diff.
 *
 *  @param user The user from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
	extern poldiff_form_e poldiff_user_get_form(const void *user);

/**
 *  Get a vector of unmodified roles for the user.
 *
 *  @param user The user diff from which to get the roles vector.
 *
 *  @return A vector of role names (type char *) that are assigned to
 *  the user in the modified policy.  If no roles were added the size
 *  of the returned vector will be 0.  The caller must not destroy
 *  this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_user_get_unmodified_roles(const poldiff_user_t * user);

/**
 *  Get a vector of roles added to the user.  If a user was added by
 *  the modified policy then this vector will hold all of the roles.
 *
 *  @param user The user diff from which to get the roles vector.
 *
 *  @return A vector of role names (type char *) that are assigned to
 *  the user in the modified policy.  If no roles were added the size
 *  of the returned vector will be 0.  The caller must not destroy
 *  this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_user_get_added_roles(const poldiff_user_t * user);

/**
 *  Get a vector of roles removed from the user.  If a user was
 *  removed by the modified policy then this vector will hold all of
 *  the roles.
 *
 *  @param user The user diff from which to get the roles vector.
 *
 *  @return A vector of role names (type char *) that are assigned to
 *  the user in the original policy.  If no roles were removed the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.  On error, errno will be set.
 */
	extern apol_vector_t *poldiff_user_get_removed_roles(const poldiff_user_t * user);

/**
 *  Get the original user's default MLS level.  That is, this is the
 *  level assigned to the user in the original policy.  If the level
 *  has the form POLDIFF_FORM_MODIFIED, then this indiciates that the
 *  user had the same sensitivity between the two policies but
 *  different categories.
 *
 *  If neither policy is MLS or there are no differences in default
 *  level, then the return value is NULL.
 *
 *  @param user The user diff from which to get default level.
 *
 *  @return User's original default MLS level.  Returns NULL upon
 *  error or if there is no difference in level.
 */
	extern const poldiff_level_t *poldiff_user_get_original_dfltlevel(const poldiff_user_t * user);

/**
 *  Get the modified user's MLS level.  That is, this is the level
 *  assigned to the user in the modified policy.  If the level had the
 *  same sensitivity but different categories call
 *  poldiff_user_get_original_dfltlevel() to get the difference; this
 *  function will return NULL.
 *
 *  If neither policy is MLS or there are no differences in
 *  default level, then the return value is NULL.
 *
 *  @param user The user diff from which to get default level.
 *
 *  @return User's modified default MLS level.  Returns NULL upon
 *  error, if there is no difference in level, or if the sensitivity
 *  was unchanged.
 */
	extern const poldiff_level_t *poldiff_user_get_modified_dfltlevel(const poldiff_user_t * user);

/**
 *  Get the change in user's assigned MLS range.
 *
 *  If neither policy is MLS or there are no differences in range,
 *  then the return value is NULL.
 *
 *  @param user The user diff from which to get assigned range
 *  differences.
 *
 *  @return User's MLS range differences.  Returns NULL upon error or
 *  if there is no difference in range.
 */
	extern const poldiff_range_t *poldiff_user_get_range(const poldiff_user_t * user);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_USER_DIFF_H */
