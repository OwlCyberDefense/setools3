/**
 *  @file mls-query.h
 *  Public Interface for querying MLS components.
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

#ifndef APOL_MLS_QUERY_H
#define APOL_MLS_QUERY_H

#include <sepol/sepol.h>
#include <sepol/policydb-query.h>
#include <sys/types.h>

#include "vector.h"

typedef struct apol_mls_level {
	char *sens;
	apol_vector_t *cats;
} apol_mls_level_t;

typedef struct apol_mls_range {
	apol_mls_level_t *low, *high;
} apol_mls_range_t;

typedef struct apol_sens_query apol_sens_query_t;
typedef struct apol_cats_query apol_cats_query_t;

/******************** level stuff ********************/

/**
 * Allocate and return a new MLS level structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_level_destroy() upon the return value afterwards.
 *
 * @return An initialized MLS level structure, or NULL upon error.
 */
extern apol_mls_level_t *apol_mls_level_create(void);

/**
 * Take a MLS level string (e.g., <t>S0:C0.C127</t>) and parse it.
 * Fill in a newly allocated apol_mls_level_t and return it.  This
 * function needs a policy to resolve dots within categories.  If the
 * string represents an illegal level then return NULL.	 The caller
 * must call apol_mls_level_destroy() upon the returned value
 * afterwards.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to validate mls_level_string.
 * @param mls_level_string Pointer to a string representing a valid
 * MLS level.  Caller is responsible for memory management of this
 * string.
 *
 * @return A filled in MLS level structure, or NULL upon error.
 */
extern apol_mls_level_t *apol_mls_level_create_from_string(sepol_handle_t *h, sepol_policydb_t *p, char *mls_level_string);

/**
 * Create a new apol_mls_level_t and initialize it with a
 * sepol_mls_level_t.  The caller must call apol_mls_level_destroy()
 * upon the returned value afterwards.
 * 
 * @param h Error reporting handler.
 * @param p Policy from which the sepol_mls_level_t was obtained.
 * @param sepol_level The libsepol level for which to create a new
 * apol level.	This level will not be altered by this call.
 * 
 * @return A MLS level structure initialized to the value of
 * sepol_level, or NULL upon error.
 */
extern apol_mls_level_t *apol_mls_level_create_from_sepol_mls_level(sepol_handle_t *h, sepol_policydb_t *p, sepol_mls_level_t *sepol_level);

/**
 * Create a new apol_mls_level_t and initialize it with a
 * sepol_level_datum_t.	 The caller must call apol_mls_level_destroy()
 * upon the returned value afterwards.
 *
 * @param h Error reporting handler.
 * @param p Policy from which the sepol_level_datum_t was obtained.
 * @param sepol_level The libsepol level for which to create a new
 * apol level.	This level will not be altered by this call.
 * 
 * @return A MLS level structure initialized to the value of
 * sepol_level, or NULL upon error.

 */
apol_mls_level_t *apol_mls_level_create_from_sepol_level_datum(sepol_handle_t *h, sepol_policydb_t *p, sepol_level_datum_t *sepol_level);

/**
 * Deallocate all memory associated with a MLS level structure and
 * then set it to NULL.	 This function does nothing if the level is
 * already NULL.
 *
 * @param level Reference to a MLS level structure to destroy.
 */
extern void apol_mls_level_destroy(apol_mls_level_t **level);

/**
 * Set the sensitivity component of an MLS level structure.  This
 * function duplicates the incoming string.
 *
 * @param level MLS level to modify.
 * @param sens New sensitivity component to set, or NULL to unset this
 * field.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_mls_level_set_sens(apol_mls_level_t *level, char *sens);

/**
 * Add a category component of an MLS level structure.	This function
 * duplicates the incoming string.
 *
 * @param level MLS level to modify.
 * @param cats New category component to append.
 * 
 * @return 0 on success or < 0 on failure.
 */
extern int apol_mls_level_append_cats(apol_mls_level_t *level, char *cats);

/**
 * Compare two levels, determining if one matches the other.  The
 * second level is a search filter; for each of its non-empty fields
 * if compare it the the first (target) level. If categories are being
 * compared, then target must have all of the categories given by
 * search level.  If search is NULL then comparison always succeeds.
 * Note that this function converts the search level to the canonical
 * (non-aliased) form before applying it.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up MLS information.
 * @param target Target MLS level to compare.  It is assumed that this
 * is already in canonical form.
 * @param search Source MLS level to compare.
 *
 * @return 1 If comparison succeeds, 0 if not; -1 on error.
 */
extern int apol_mls_compare_level(sepol_handle_t *h, sepol_policydb_t *p,
				  apol_mls_level_t *target,
				  apol_mls_level_t *search);
    
/******************** range stuff ********************/

/**
 * Allocate and return a new MLS range structure.  All fields are
 * initialized to nothing.  The caller must call
 * apol_mls_range_destroy() upon the return value afterwards.
 *
 * @return An initialized MLS range structure, or NULL upon error.
 */
extern apol_mls_range_t *apol_mls_range_create(void);

/**
 * Create a new apol_mls_range_t and initialize it with a
 * sepol_mls_range_t.  The caller must call apol_mls_range_destroy()
 * upon the return value afterwards.
 * 
 * @param h Error reporting handler.
 * @param p Policy from which the sepol_mls_range_t was obtained.
 * @param sepol_level The libsepol range for which to create a new
 * apol range.	This range will not be altered by this call.
 * 
 * @return A MLS range structure initialized to the value of
 * sepol_range, or NULL upon error.
 */
extern apol_mls_range_t *apol_mls_range_create_from_sepol_mls_range(sepol_handle_t *h, sepol_policydb_t *p, sepol_mls_range_t *sepol_range);

/**
 * Deallocate all memory associated with a MLS range structure and
 * then set it to NULL.	 This function does nothing if the range is
 * already NULL.
 *
 * @param level Reference to a MLS level structure to destroy.
 */
extern void apol_mls_range_destroy(apol_mls_range_t **range);

/**
 * Set the low level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param range MLS range to modify.
 * @param level New low level for range, or NULL to unset this field.
 *
 * @return 0 on success or < 0 on failure.
 */
extern int apol_mls_range_set_low(apol_mls_range_t *range, apol_mls_level_t *level);

/**
 * Set the high level component of a MLS range structure.  This
 * function takes ownership of the level, such that the caller must
 * not modify nor destroy it afterwards.
 *
 * @param range MLS range to modify.
 * @param level New high level for range, or NULL to unset this field.
 *
 * @return 0 on success or < 0 on failure.
 */
extern int apol_mls_range_set_high(apol_mls_range_t *range, apol_mls_level_t *level);

#endif /* APOL_MLS_QUERY_H */
