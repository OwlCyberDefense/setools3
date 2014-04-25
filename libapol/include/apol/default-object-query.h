/**
 * @file
 *
 * Routines to query default objects in policy.
 *
 *  @author Richard Haines richard_c_haines@btinternet.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#ifndef APOL_DEFAULT_OBJECT_QUERY_H
#define APOL_DEFAULT_OBJECT_QUERY_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include "policy.h"
#include "vector.h"
#include <qpol/policy.h>

	typedef struct apol_default_object_query apol_default_object_query_t;
/**
 * Execute a query against all policy capabilities within the policy.
 *
 * @param p Policy within which to look up policy capabilities.
 * @param t Structure containing parameters for query.	If this is
 * NULL then return all policy capabilities.
 * @param v Reference to a vector of qpol_default_object_t.  The vector will be
 * allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards.  This will be set to NULL upon no
 * results or upon error.
 *
 * @return 0 on success (including none found), negative on error.
 */
	extern int apol_default_object_get_by_query(const apol_policy_t * p, apol_default_object_query_t * t, apol_vector_t ** v);

/**
 * Allocate and return a new default_object query structure.  All fields are
 * initialized, such that running this blank query results in
 * returning all policy capabilities within the policy.  The caller must call
 * apol_default_object_query_destroy() upon the return value afterwards.
 *
 * @return An initialized default_object query structure, or NULL upon error.
 */
	extern apol_default_object_query_t *apol_default_object_query_create(void);

/**
 * Deallocate all memory associated with the referenced default_object query,
 * and then set it to NULL.  This function does nothing if the query
 * is already NULL.
 *
 * @param t Reference to a default_object query structure to destroy.
 */
	extern void apol_default_object_query_destroy(apol_default_object_query_t ** t);



#ifdef	__cplusplus
}
#endif

#endif
