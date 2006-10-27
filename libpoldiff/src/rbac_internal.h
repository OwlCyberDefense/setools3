/**
 *  @file rbac_internal.h
 *  Protected Interface for role allow rule and role_transition 
 *  rule differences.
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

#ifndef POLDIFF_RBAC_INTERNAL_H
#define POLDIFF_RBAC_INTERNAL_H

typedef struct poldiff_role_allow_summary poldiff_role_allow_summary_t;
typedef struct poldiff_role_trans_summary poldiff_role_trans_summary_t;

/**
 * Allocate and return a new poldiff_role_allow_summary_t object.
 *
 * @return A new role allow summary.  The caller must call role_allow_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
poldiff_role_allow_summary_t *role_allow_create(void);

/**
 * Deallocate all space associated with a poldiff_role_allow_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param ras Reference to a role allow summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
void role_allow_destroy(poldiff_role_allow_summary_t ** ras);

/**
 * Reset the state of all role allow rule differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
int role_allow_reset(poldiff_t * diff);

/**
 * Get a vector of all role allow rules from the given policy,
 * sorted by source name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of all role allow rules (of type
 * pseudo_role_allow_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards, passing NULL as the second parameter. On
 * error, return NULL and set errno.
 */
apol_vector_t *role_allow_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Free the space used by a pseudo_role_allow_t. Does nothing if the
 * pointer is already NULL.
 *
 *@param item Pointer to a pseudo_role_allow_t.
 */
void role_allow_free_item(void *item);

/**
 * Compare two pseudo_role_allow_t objects, determining if they have the same
 * source name or not.
 *
 * @param x The role allow from the original policy.
 * @param y The role allow from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if source role of x is respectively less than, equal
 * to, or greater than source role of y.
 */
int role_allow_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a role allow rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int role_allow_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two role allow rules for which the
 * compare callback returns 0.  If a difference is found then allocate,
 * initialize, and insert a new semantic difference entry for that role allow
 * rule.
 *
 * @param diff The policy difference structure associated with both
 * rules and to which to add an entry if needed.
 * @param x The role allow rule from the original policy.
 * @param y The role allow rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int role_allow_deep_diff(poldiff_t * diff, const void *x, const void *y);

/**
 * Allocate and return a new poldiff_role_trans_summary_t object.
 *
 * @return A new role transition summary.  The caller must call
 * role_trans_destroy() afterwards.  On error, return NULL and set errno.
 */
poldiff_role_trans_summary_t *role_trans_create(void);

/**
 * Deallocate all space associated with a poldiff_role_trans_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param rts Reference to a role transition summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
void role_trans_destroy(poldiff_role_trans_summary_t ** rts);

/**
 * Reset the state of all role_transition rule differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
int role_trans_reset(poldiff_t * diff);

/**
 * Get a vector of all role_transition rules from the given policy,
 * sorted by source name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return A newly allocated vector of all role_transition rules (of type
 * pseudo_role_trans_t).  The caller is responsible for calling
 * apol_vector_destroy() afterwards, passing NULL as the second parameter. On
 * error, return NULL and set errno.
 */
apol_vector_t *role_trans_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Free the space used by a pseudo_role_trans_t. Does nothing if the
 * pointer is already NULL.
 *
 *@param item Pointer to a pseudo_role_trans_t.
 */
void role_trans_free_item(void *item);

/**
 * Compare two pseudo_role_trans_t objects, determining if they have the same
 * source name and target or not.
 *
 * @param x The role_transition from the original policy.
 * @param y The role_transition from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if source role of x is respectively less than, equal
 * to, or greater than source role of y.
 */
int role_trans_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a role_transition rule.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int role_trans_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two role_transition rules for which the
 * compare callback returns 0.  If a difference is found then allocate,
 * initialize, and insert a new semantic difference entry for that
 * role_transition rule.
 *
 * @param diff The policy difference structure associated with both
 * rules and to which to add an entry if needed.
 * @param x The role_transition rule from the original policy.
 * @param y The role_transition rule from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
int role_trans_deep_diff(poldiff_t * diff, const void *x, const void *y);

#endif				       /* POLDIFF_RBAC_INTERNAL_H */
