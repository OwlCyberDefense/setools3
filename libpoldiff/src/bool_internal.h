/**
 *  @file
 *  Protected interface for boolean differences.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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

#ifndef POLDIFF_BOOL_INTERNAL_H
#define POLDIFF_BOOL_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	typedef struct poldiff_bool_summary poldiff_bool_summary_t;

/**
 * Allocate and return a new poldiff_bool_summary_t object.
 *
 * @return A new bool summary.  The caller must call bool_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
	poldiff_bool_summary_t *bool_create(void);

/**
 * Deallocate all space associated with a poldiff_bool_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param bs Reference to a bool summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void bool_destroy(poldiff_bool_summary_t ** bs);

/**
 * Reset the state of all boolean differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int bool_reset(poldiff_t * diff);

/**
 * Get a vector of all bools from the given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all bools.  The caller is
 * responsible for calling apol_vector_destroy() afterwards.  On
 * error, return NULL and set errno.
 */
	apol_vector_t *bool_get_items(poldiff_t * diff, const apol_policy_t * policy);

/**
 * Compare two qpol_bool_t objects, determining if they have the same
 * name or not.
 *
 * @param x The bool from the original policy.
 * @param y The bool from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if bool x is respectively less than, equal
 * to, or greater than bool y.
 */
	int bool_comp(const void *x, const void *y, const poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a bool.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int bool_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two bools for which the
 * compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert an new semantic difference entry
 * for that bool.
 *
 * @param diff The policy difference structure associated with both
 * bools and to which to add an entry if needed.
 * @param x The bool from the original policy.
 * @param y The bool from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int bool_deep_diff(poldiff_t * diff, const void *x, const void *y);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_BOOL_INTERNAL_H */
