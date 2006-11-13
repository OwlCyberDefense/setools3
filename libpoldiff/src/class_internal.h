/**
 *  @file class_internal.h
 *  Protected Interface for class and common differences.
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

#ifndef POLDIFF_CLASS_INTERNAL_H
#define POLDIFF_CLASS_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

/******************** object classes ********************/

	typedef struct poldiff_class_summary poldiff_class_summary_t;

/**
 * Allocate and return a new poldiff_class_summary_t object.
 *
 * @return A new class summary.  The caller must call class_destroy()
 * afterwards.  On error, return NULL and set errno.
 */
	poldiff_class_summary_t *class_create(void);

/**
 * Deallocate all space associated with a poldiff_class_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param cs Reference to a class summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void class_destroy(poldiff_class_summary_t ** cs);

/**
 * Reset the state of all class differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int class_reset(poldiff_t * diff);

/**
 * Get a vector of all object classes (type qpol_class_t) from the
 * given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all classes.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
	apol_vector_t *class_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Compare two qpol_class_t objects, determining if they have the same
 * name or not.
 *
 * @param x The class from the original policy.
 * @param y The class from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if class x is respectively less than, equal
 * to, or greater than class y.
 */
	int class_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a class.
 *
 * @param diff The policy difference structure to which to add the entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int class_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two classes for which the
 * compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert a new semantic difference entry
 * for that class.
 *
 * @param diff The policy difference structure associated with both
 * classes and to which to add an entry if needed.
 * @param x The class from the original policy.
 * @param y The class from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int class_deep_diff(poldiff_t * diff, const void *x, const void *y);

/******************** common classes ********************/

	typedef struct poldiff_common_summary poldiff_common_summary_t;

/**
 * Allocate and return a new poldiff_common_summary_t object.
 *
 * @return A new common summary.  The caller must call
 * common_destroy() afterwards.  On error, return NULL and set errno.
 */
	poldiff_common_summary_t *common_create(void);

/**
 * Deallocate all space associated with a poldiff_common_summary_t
 * object, including the pointer itself.  If the pointer is already
 * NULL then do nothing.
 *
 * @param cs Reference to a common summary to destroy.  The pointer
 * will be set to NULL afterwards.
 */
	void common_destroy(poldiff_common_summary_t ** cs);

/**
 * Reset the state of all common differences.
 * @param diff The policy difference structure containing the differences
 * to reset.
 * @return 0 on success and < 0 on error; if the call fails,
 * errno will be set and the user should call poldiff_destroy() on diff.
 */
	int common_reset(poldiff_t * diff);

/**
 * Get a vector of all common classes (type qpol_common_t) from the
 * given policy, sorted by name.
 *
 * @param diff Policy diff error handler.
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all commons.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
	apol_vector_t *common_get_items(poldiff_t * diff, apol_policy_t * policy);

/**
 * Compare two qpol_common_t objects, determining if they have the
 * same name or not.
 *
 * @param x The common from the original policy.
 * @param y The common from the modified policy.
 * @param diff The policy difference structure associated with both
 * policies.
 *
 * @return < 0, 0, or > 0 if common x is respectively less than, equal
 * to, or greater than common y.
 */
	int common_comp(const void *x, const void *y, poldiff_t * diff);

/**
 * Create, initialize, and insert a new semantic difference entry for
 * a common.
 *
 * @param diff The policy difference structure to which to add the
 * entry.
 * @param form The form of the difference.
 * @param item Item for which the entry is being created.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int common_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 * Compute the semantic difference of two commons for which the
 * compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert a new semantic difference entry
 * for that common.
 *
 * @param diff The policy difference structure associated with both
 * commons and to which to add an entry if needed.
 * @param x The common from the original policy.
 * @param y The common from the modified policy.
 *
 * @return 0 on success and < 0 on error; if the call fails, set errno
 * and leave the policy difference structure unchanged.
 */
	int common_deep_diff(poldiff_t * diff, const void *x, const void *y);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_CLASS_INTERNAL_H */
