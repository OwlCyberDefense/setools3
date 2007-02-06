/**
 * @file
 *
 * An opaque structure that represents a policy "path".  A policy path
 * may really be a base policy and a number of modules, thus a single
 * string is not sufficient.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
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

#ifndef APOL_POLICY_PATH_H
#define APOL_POLICY_PATH_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <config.h>

#include "vector.h"

	typedef struct apol_policy_path apol_policy_path_t;

/**
 * Type of policy this path represents - either a single path, for a
 * monolithic policy, or a path + multiple modules for modular policy.
 */
	typedef enum apol_policy_path_type
	{
		APOL_POLICY_PATH_TYPE_MONOLITHIC = 0,
		APOL_POLICY_PATH_TYPE_MODULAR
	} apol_policy_path_type_e;

/**
 * Create a policy path from scratch.  The resulting object represents
 * the file or files needed to load a policy.
 *
 * @param path_type Type of policy to represent.
 * @param path Primary path name.  For modular policies this is the
 * base policy's path.
 * @param modules Vector of strings representing modules' paths.  The
 * vector can be NULL to mean no modules.  This parameter is ignored
 * if path_type is not APOL_POLICY_PATH_TYPE_MODULAR.  The function
 * will duplicate the vector and its contents.
 *
 * @return An apol_policy_path object, or NULL upon error.
 */
	apol_policy_path_t *apol_policy_path_create(apol_policy_path_type_e path_type, const char *path,
						    const apol_vector_t * modules);

/**
 * Create a policy path, initialized from another policy path.  This
 * function recursively duplicates all data within the original path.
 *
 * @param path Policy path to duplicate.
 *
 * @return An apol_policy_path object, or NULL upon error.
 */
	apol_policy_path_t *apol_policy_path_create_from_policy_path(const apol_policy_path_t * path);

/**
 * Create a policy path, initialized by a special path format string.
 * Call apol_policy_path_to_string() to create this string.
 *
 * @param path_string String containing initialization data for the
 * object.
 *
 * @return An apol_policy_path object, or NULL upon error.
 */
	apol_policy_path_t *apol_policy_path_create_from_string(const char *path_string);

/**
 * Destroy the referencened policy path object.
 *
 * @param path Policy path to destroy.  The pointer will be set to
 * NULL afterwards.  (If pointer is already NULL then do nothing.)
 */
	void apol_policy_path_destroy(apol_policy_path_t ** path);

/**
 * Compare two policy paths, determining if one is different than the
 * other.  The returned value is stable, in that it may be used as the
 * basis for sorting a list of policy paths.  Monolithic policies are
 * considered "less than" modular policies.
 *
 * @param a First policy path to compare.
 * @param b Second policy path to compare.
 *
 * @return < 0 if path A is "less than" B, > 0 if A is "greater than"
 * B, or 0 if equivalent or undeterminable.
 */
	int apol_policy_path_compare(const apol_policy_path_t * a, const apol_policy_path_t * b);

/**
 * Get the type of policy this path object represents.
 *
 * @param path Policy path object to query.
 *
 * @return Type of policy the object represents.
 */
	apol_policy_path_type_e apol_policy_path_get_type(const apol_policy_path_t * path);

/**
 * Get the primary path name from a path object.  For monolithic
 * policies this is the path to the policy.  For modular policies this
 * is the base policy path.
 *
 * @param path Policy path object to query.
 *
 * @return Primary path, or NULL upon error.  Do not modify
 * this string.
 */
	const char *apol_policy_path_get_primary(const apol_policy_path_t * path);

/**
 * Get the list of modules from a path object.  This will be a vector
 * of strings.  It is an error to call this function for non-modular
 * policies.
 *
 * @param path Policy path object to query.
 *
 * @return Vector of module paths, or NULL upon error.  Do not modify
 * this vector or its contents.  Note that the vector could be empty.
 */
	const apol_vector_t *apol_policy_path_get_modules(const apol_policy_path_t * path);

/**
 * Encode a path object into a specially formatted string.  The
 * resulting string is suitable as input to
 * apol_policy_path_create_from_string().
 *
 * @param path Policy path object to encode.
 *
 * @return Formatted string for the path object, or NULL upon error.
 * The caller is responsible for calling free() upon the returned
 * value.
 */
	char *apol_policy_path_to_string(const apol_policy_path_t * path);

#ifdef	__cplusplus
}
#endif

#endif
