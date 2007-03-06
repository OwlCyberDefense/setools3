/**
 *  @file
 *  Protected Interface for computing a semantic differences in
 *  levels, either from level declarations, user's default level,
 *  user's permitted range, or a range_transition's target range.
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

#ifndef POLDIFF_LEVEL_INTERNAL_H
#define POLDIFF_LEVEL_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	typedef struct poldiff_level_summary poldiff_level_summary_t;

	struct poldiff_level
	{
		char *name;
		poldiff_form_e form;
		apol_vector_t *added_cats;
		apol_vector_t *removed_cats;
		apol_vector_t *unmodified_cats;
	};

/**
 * Allocate and return a new poldiff_level_summary_t object.
 *
 * @return A new level summary.  The caller must call level_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
	poldiff_level_summary_t *level_create(void);

/**
 * Deallocate all space associated with a poldiff_level_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param ls Reference to a level summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void level_destroy(poldiff_level_summary_t ** ls);

/**
 * Reset the state of all level differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int level_reset(poldiff_t * diff);

/**
 * Get a vector of all levels from the given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all levels.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
	apol_vector_t *level_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Compare two qpol_level_t objects, determining if they have the same
 * level name or not.
 *
 * @param x The level from the original policy.
 * @param y The level from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if level x is respectively less than, equal
 * to, or greater than level y.
 */
	int level_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a level.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int level_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two levels for which the compare
 * callback returns 0.  If a difference is found then allocate,
 * initialize, and insert a new semantic difference entry for that
 * level.
 *
 * @param diff The policy difference structure associated with both
 * levels and to which to add an entry if needed.
 * @param x The level from the original policy.
 * @param y The level from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int level_deep_diff(poldiff_t * diff, const void *x, const void *y);

/**
 * Deallocate all space associated with a poldiff_level_t,
 * including the pointer itself.
 *
 * @param elem Pointer to a poldiff_level_t object.  If NULL then do
 * nothing.
 */
	void level_free(void *elem);

/**
 * Comparison function for two category names from the same policy.
 *
 * @param a Name of a category.
 * @param b Name of another category.
 * @param data qpol policy from which the categories originate.
 *
 * @return Less than zero, zero, or greater than zero based upon the
 * categories' order within the policy.
 */
	int level_cat_comp(const void *a, const void *b, void *data);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_LEVEL_INTERNAL_H */
