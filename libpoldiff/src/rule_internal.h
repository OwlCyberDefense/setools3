/**
 *  @file rule_internal.h
 *  Protected Interface for rule differences (both av and te rules).
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

#ifndef POLDIFF_RULE_INTERNAL_H
#define POLDIFF_RULE_INTERNAL_H

/******************** avrule diffs ********************/

typedef struct poldiff_avrule_summary poldiff_avrule_summary_t;

/**
 * Allocate and return a new poldiff_avrule_summary_t object.
 *
 * @return A new av rule summary.  The caller must call
 * avrule_destroy() afterwards.  On error, return NULL and set errno.
 */
poldiff_avrule_summary_t *avrule_create(void);

/**
 * Deallocate all space associated with a poldiff_avrule_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param as Reference to an avrule summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
void avrule_destroy(poldiff_avrule_summary_t **as);

/**
 * Get a vector of all avrule from the given policy, sorted.  This
 * function will remap source and target types to their pseudo-type
 * value equivalents.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of all av rules (of type
 * pseudo_avrule_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards, passing avrule_free_item() as the
 * second parameter.  On error, return NULL and set errno.
 */
apol_vector_t *avrule_get_items(poldiff_t *diff, apol_policy_t *policy);

/**
 * Free the space used by a pseudo_avrule_t.  Does nothing if the
 * pointer is already NULL.
 *
 * @param item Pointer to a pseudo_avrule_t.
 */
void avrule_free_item(void *item);

/**
 * Compare two pseudo_avrule_t objects, determining if they have the
 * key (specified + source + target + class + conditional expression).
 *
 * @param x The pseudo-av rule from the original policy.
 * @param y The pseudo-av rule from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if av rule x is respectively less than,
 * equal to, or greater than av rule y.
 */
int avrule_comp(const void *x, const void *y, poldiff_t *diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a pseudo-av rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int avrule_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two pseudo-av rules for which
 * the compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert a new semantic difference entry
 * for that pseudo-av rule.
 *
 * @param diff The policy difference structure associated with both
 * pseudo-av rules and to which to add an entry if needed.
 * @param x The pseudo-av rule from the original policy.
 * @param y The pseudo-av rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int avrule_deep_diff(poldiff_t *diff, const void *x, const void *y);

#endif /* POLDIFF_RULE_INTERNAL_H */
