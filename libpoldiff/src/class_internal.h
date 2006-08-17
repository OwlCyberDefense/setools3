/**
 *  @file class_internal.h
 *  Protected Interface for class differences.
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

#ifndef POLDIFF_CLASSDIFF_INTERNAL_H
#define POLDIFF_CLASSDIFF_INTERNAL_H

#include "poldiff_internal.h"

/**
 * Get a vector of all object classes from the given policy.
 *
 * @param policy The policy from which to get the items.
 *
 * @return a newly allocated vector of all classes.  The caller is
 * responsible for calling apol_vector_destroy() afterwards, passing
 * NULL as the second parameter.  On error, return NULL and set errno.
 */
apol_vector_t *poldiff_class_get_items(apol_policy_t *policy);

/**
 * Compare two qpol_class_t objects, determining if they have the same
 * name or not.
 *
 * @param x The class from the original policy.
 * @param y The class from the modified policy.
 * @param diff The policy difference structure associated with both
 * items cast to poldiff_t
 * inside this function.
 *
 * @return < 0, 0, or > 0 if class x is respectively less than, equal
 * to, or greater than class y.
 */
int poldiff_class_comp(const void *x, const void *y, void *diff);

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
int poldiff_class_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item);

/**
 * Computing the semantic difference of two classes for which the
 * compare callback returns 0.  If a difference is found then
 * allocate, initialize, and insert an new semantic difference entry
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
int poldiff_class_deep_diff(poldiff_t *diff, const void *x, const void *y);

#endif /* POLDIFF_CLASSDIFF_INTERNAL_H */
