/**
 *  @file
 *  Protected interface for rule differences, both AV and Type rules.
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

#ifndef POLDIFF_TERULE_INTERNAL_H
#define POLDIFF_TERULE_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

	typedef struct poldiff_terule_summary poldiff_terule_summary_t;

/**
 * Allocate and return a new poldiff_terule_summary_t object, used by
 * TE rule searches.
 *
 * @return A new rule summary.  The caller must call terule_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
	poldiff_terule_summary_t *terule_create(void);

/**
 * Deallocate all space associated with a poldiff_terule_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param rs Reference to an rule summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void terule_destroy(poldiff_terule_summary_t ** rs);

/**
 * Reset the state of TE rule type_change differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int terule_reset_change(poldiff_t * diff);

/**
 * Reset the state of TE rule type_member differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int terule_reset_member(poldiff_t * diff);

/**
 * Reset the state of TE rule type_transition differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int terule_reset_trans(poldiff_t * diff);

/**
 * Get a vector of type_change rules from the given policy, sorted.
 * This function will remap source and target types to their
 * pseudo-type value equivalents.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of type_change rules (of type
 * pseudo_terule_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards.  On error, return NULL and set
 * errno.
 */
	apol_vector_t *terule_get_items_change(poldiff_t * diff, const apol_policy_t * policy);

/**
 * Get a vector of type_member rules from the given policy, sorted.
 * This function will remap source and target types to their
 * pseudo-type value equivalents.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 * @param flags Kind of rule to get, one of QPOL_RULE_TYPE_TRANS, etc.
 *
 * @return A newly allocated vector of type_member rules (of type
 * pseudo_terule_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards.  On error, return NULL and set
 * errno.
 */
	apol_vector_t *terule_get_items_member(poldiff_t * diff, const apol_policy_t * policy);

/**
 * Get a vector of type_transition rules from the given policy,
 * sorted.  This function will remap source and target types to their
 * pseudo-type value equivalents.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of type_transition rules (of type
 * pseudo_terule_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards.  On error, return NULL and set
 * errno.
 */
	apol_vector_t *terule_get_items_trans(poldiff_t * diff, const apol_policy_t * policy);

/**
 * Compare two pseudo_terule_t objects, determining if they have the
 * same key (specified + source + target + class + conditional
 * expression).
 *
 * @param x The pseudo-te rule from the original policy.
 * @param y The pseudo-te rule from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if te rule x is respectively less than,
 * equal to, or greater than te rule y.
 */
	int terule_comp(const void *x, const void *y, const poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a pseudo-te rule that was originally from a type_change rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_new_diff_change(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a pseudo-te rule that was originally from a type_member rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_new_diff_member(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a pseudo-te rule that was originally from a type_transition rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_new_diff_trans(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two pseudo-te rules (that were
 * type_change rules) for which the compare callback returns 0.  If a
 * difference is found then allocate, initialize, and insert a new
 * semantic difference entry for that pseudo-te rule.
 *
 * @param diff The policy difference structure associated with both
 * pseudo-te rules and to which to add an entry if needed.
 * @param x The pseudo-te rule from the original policy.
 * @param y The pseudo-te rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_deep_diff_change(poldiff_t * diff, const void *x, const void *y);

/**
 * Compute the semantic difference of two pseudo-te rules (that were
 * type_member rules) for which the compare callback returns 0.  If a
 * difference is found then allocate, initialize, and insert a new
 * semantic difference entry for that pseudo-te rule.
 *
 * @param diff The policy difference structure associated with both
 * pseudo-te rules and to which to add an entry if needed.
 * @param x The pseudo-te rule from the original policy.
 * @param y The pseudo-te rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_deep_diff_member(poldiff_t * diff, const void *x, const void *y);

/**
 * Compute the semantic difference of two pseudo-te rules (that were
 * type_transition rules) for which the compare callback returns 0.
 * If a difference is found then allocate, initialize, and insert a
 * new semantic difference entry for that pseudo-te rule.
 *
 * @param diff The policy difference structure associated with both
 * pseudo-te rules and to which to add an entry if needed.
 * @param x The pseudo-te rule from the original policy.
 * @param y The pseudo-te rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int terule_deep_diff_trans(poldiff_t * diff, const void *x, const void *y);

/**
 * Iterate through a TE rule differences, filling in its line numbers.
 *
 * @param diff Diff structure containing avrule differences.
 * @param idx Index into the terule differences specifying which line
 * number table to enable.
 *
 * @return 0 on success, < 0 on errno.
 */
	int terule_enable_line_numbers(poldiff_t * diff, unsigned int idx);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_TERULE_INTERNAL_H */
