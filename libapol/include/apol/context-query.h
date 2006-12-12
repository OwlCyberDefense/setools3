/**
 *  @file context-query.h
 *  Public interface for querying and manipulating a context.
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

#ifndef APOL_CONTEXT_QUERY_H
#define APOL_CONTEXT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "mls-query.h"
#include <qpol/policy.h>

	typedef struct apol_context
	{
		char *user, *role, *type;
		apol_mls_range_t *range;
	} apol_context_t;

/**
 * Allocate and return a new context structure.	 All fields are
 * initialized to nothing.  The caller must call
 * apol_context_destroy() upon the return value afterwards.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
	extern apol_context_t *apol_context_create(void);

/**
 * Allocate and return a new context structure, initialized from an
 * existing qpol_context_t.  The caller must call
 * apol_context_destroy() upon the return value afterwards.
 *
 * @param p Policy from which the qpol_context_t was obtained.
 * @param context The libqpol context for which to create a new apol
 * context.  This context will not be altered by this call.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
	extern apol_context_t *apol_context_create_from_qpol_context(apol_policy_t * p, qpol_context_t * context);

/**
 * Deallocate all memory associated with a context structure and then
 * set it to NULL.  This function does nothing if the context is
 * already NULL.
 *
 * @param context Reference to a context structure to destroy.
 */
	extern void apol_context_destroy(apol_context_t ** context);

/**
 * Set the user field of a context structure.  This function
 * duplicates the incoming string.
 *
 * @param p Error reporting handler.
 * @param context Context to modify.
 * @param user New user field to set, or NULL to unset this field.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_context_set_user(apol_policy_t * p, apol_context_t * context, const char *user);

/**
 * Set the role field of a context structure.  This function
 * duplicates the incoming string.
 *
 * @param p Error reporting handler.
 * @param context Context to modify.
 * @param role New role field to set, or NULL to unset this field.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_context_set_role(apol_policy_t * p, apol_context_t * context, const char *role);

/**
 * Set the type field of a context structure.  This function
 * duplicates the incoming string.
 *
 * @param p Error reporting handler.
 * @param context Context to modify.
 * @param type New type field to set, or NULL to unset this field.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_context_set_type(apol_policy_t * p, apol_context_t * context, const char *type);

/**
 * Set the range field of a context structure.	This function takes
 * ownership of the range, such that the caller must not modify nor
 * destroy it afterwards.
 *
 * @param p Error reporting handler.
 * @param context Context to modify.
 * @param range New range field to set, or NULL to unset this field.
 *
 * @return 0 on success, < 0 on error.
 */
	extern int apol_context_set_range(apol_policy_t * p, apol_context_t * context, apol_mls_range_t * range);

/**
 * Compare two contexts, determining if one matches the other.	The
 * search context may have empty elements that indicate not to compare
 * that field.	Types will be matched if the two or any of their
 * aliases are the same.  The last parameter gives how to match ranges
 * (assuming that context2 has a range); it must be one of
 * APOL_QUERY_SUB, APOL_QUERY_SUPER, APOL_QUERY_EXACT or
 * APOL_QUERY_INTERSECT as per apol_mls_range_compare().  If a context
 * is not valid according to the policy then this function returns -1.
 * If search is NULL then comparison always succeeds.
 *
 * @param p Policy within which to look up policy and MLS information.
 * @param target Target context to compare.
 * @param search Source context to compare.
 * @param range_compare_type Specifies how to compare the ranges.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
	extern int apol_context_compare(apol_policy_t * p,
					apol_context_t * target, apol_context_t * search, unsigned int range_compare_type);

/**
 * Given a complete context (user, role, type, and range if policy is
 * MLS), determine if it is legal according to the supplied policy.
 * (Check that the user has that role, the role has that type, etc.)
 * This function will convert from aliases to canonical forms as
 * necessary.
 *
 * @param p Policy within which to look up context information.
 * @param context Context to check.
 *
 * @return 1 If context is legal, 0 if not; -1 on error.
 */
	extern int apol_context_validate(apol_policy_t * p, apol_context_t * context);

/**
 * Given a partial context, determine if it is legal according to the
 * supplied policy.  For fields that are not specified, assume that
 * they would be legal.	 For example, if a user is given but not a
 * role, then return truth if the user is in the policy.  If the
 * context is NULL then this function returns 1.  This function will
 * convert from aliases to canonical forms as necessary.
 *
 * @param p Policy within which to look up context information.
 * @param context Context to check.
 *
 * @return 1 If context is legal, 0 if not; -1 on error.
 */
	extern int apol_context_validate_partial(apol_policy_t * p, apol_context_t * context);

/**
 * Given a complete context (user, role, type, and range if policy is
 * MLS), allocate and return a string that represents that context.
 * This function does not check if the context is valid or not.
 *
 * @param p Policy within which to look up context information.
 * @param context Context to render.
 *
 * @return A newly allocated string on success, caller must free;
 * NULL on error.
 */
	extern char *apol_context_render(apol_policy_t * p, apol_context_t * context);

#ifdef	__cplusplus
}
#endif

#endif				       /* APOL_CONTEXT_QUERY_H */
