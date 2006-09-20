/**
 *  @file type_internal.h
 *  Protected Interface for type differences.
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

#ifndef POLDIFF_TYPE_INTERNAL_H
#define POLDIFF_TYPE_INTERNAL_H

/******************** types ********************/

typedef struct poldiff_type_summary poldiff_type_summary_t;

/**
 * Allocate and return a new poldiff_type_summary_t object.
 *
 * @return A new type summary.  The caller must call type_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
poldiff_type_summary_t *type_summary_create(void);

/**
 * Deallocate all space associated with a poldiff_type_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param type Reference to a type summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
void type_summary_destroy(poldiff_type_summary_t **type);

/**
 * Reset the state of all type differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
int type_reset(poldiff_t *diff);

/**
 * Get a vector of all type (type qpol_type_t) from the
 * given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all typees.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
apol_vector_t *type_get_items(poldiff_t *diff, apol_policy_t *policy);

/**
 * Compare two qpol_type_t objects, determining if they have the same
 * name or not.
 *
 * @param x The type from the original policy.
 * @param y The type from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if type x is respectively less than, equal
 * to, or greater than type y.
 */
int type_comp(const void *x, const void *y, poldiff_t *diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a type.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int type_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two types for which the
 * compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert a new semantic difference entry
 * for that type.
 *
 * @param diff The policy difference structure associated with both
 * types and to which to add an entry if needed.
 * @param x The type from the original policy.
 * @param y The type from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int type_deep_diff(poldiff_t *diff, const void *x, const void *y);

#endif /* POLDIFF_TYPE_INTERNAL_H */
