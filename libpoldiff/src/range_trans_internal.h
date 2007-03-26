/**
 *  @file
 *  Protected interface for range transition rule differences.
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

#ifndef POLDIFF_RANGE_TRANS_INTERNAL_H
#define POLDIFF_RANGE_TRANS_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	typedef struct poldiff_range_trans_summary poldiff_range_trans_summary_t;

/**
 * Allocate and return a new poldiff_range_trans_summary_t object.
 *
 * @return A new range transition summary.  The caller must call
 * range_trans_destroy() afterwards.  On error, return NULL and set
 * errno.
 */
	poldiff_range_trans_summary_t *range_trans_create(void);

/**
 * Deallocate all space associated with a
 * poldiff_range_trans_summary_t object, including the pointer itself.
 * If the pointer is already NULL then do nothing.
 *
 * @param rts Reference to a range transition summary to destroy.  The
 * pointer will be set to NULL afterwards.
 */
	void range_trans_destroy(poldiff_range_trans_summary_t ** rts);

/**
 * Reset the state of all range transition rule differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int range_trans_reset(poldiff_t * diff);

/**
 * Get a vector of all range transition rules from the given policy,
 * sorted by source type.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of all range transition rules (of
 * type pseudo_range_trans_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards.  On error, return NULL and set
 * errno.
 */
	apol_vector_t *range_trans_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Compare two pseudo_range_trans_t objects, determining if they have
 * the same source type, target type, and target class or not.
 *
 * @param x The range transition from the original policy.
 * @param y The range transition from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if x is respectively less than, equal to, or
 * greater than source role of y.
 */
	int range_trans_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a range transition rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int range_trans_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two role allow rules for which
 * the compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert a new semantic difference entry
 * for that range transition rule.
 *
 * @param diff The policy difference structure associated with both
 * rules and to which to add an entry if needed.
 * @param x The range transition rule from the original policy.
 * @param y The range transition rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int range_trans_deep_diff(poldiff_t * diff, const void *x, const void *y);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_RANGE_TRANS_INTERNAL_H */
