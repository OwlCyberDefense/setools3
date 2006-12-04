/**
 *  @file role_internal.h
 *  Protected Interface for role differences.
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

#ifndef POLDIFF_ROLE_INTERNAL_H
#define POLDIFF_ROLE_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	typedef struct poldiff_role_summary poldiff_role_summary_t;

/**
 * Allocate and return a new poldiff_role_summary_t object.
 *
 * @return A new role summary.  The caller must call role_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
	poldiff_role_summary_t *role_create(void);

/**
 * Deallocate all space associated with a poldiff_role_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param us Reference to a role summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void role_destroy(poldiff_role_summary_t ** us);

/**
 * Reset the state of all role differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int role_reset(poldiff_t * diff);

/**
 * Get a vector of all roles from the given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all roles.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
	apol_vector_t *role_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Compare two qpol_role_t objects, determining if they have the same
 * name or not.
 *
 * @param x The role from the original policy.
 * @param y The role from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if role x is respectively less than, equal
 * to, or greater than role y.
 */
	int role_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a role.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int role_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two roles for which the compare
 * callback returns 0.  If a difference is found then allocate,
 * initialize, and insert a new semantic difference entry for that
 * role.
 *
 * @param diff The policy difference structure associated with both
 * roles and to which to add an entry if needed.
 * @param x The role from the original policy.
 * @param y The role from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int role_deep_diff(poldiff_t * diff, const void *x, const void *y);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_ROLE_INTERNAL_H */
