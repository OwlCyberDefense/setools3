/**
 *  @file class_diff.h
 *  Public Interface for computing a semantic differences in classes
 *  and commons.
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

#ifndef POLDIFF_CLASS_DIFF_H
#define POLDIFF_CLASS_DIFF_H

#include <apol/vector.h>
#include <poldiff/poldiff.h>

/******************** object classes ********************/

typedef struct poldiff_class poldiff_class_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for object classes.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_class_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of class differences from the class difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  class difference summary.
 *
 *  @return a vector of elements of type poldiff_class_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_class_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  an object class.
 *
 *  @param diff The policy difference structure associated with the class.
 *  @param item The class from which to generate the string.
 *
 *  @return A string representation of class difference; the caller is
 *  responsible for free()ing this string.  On error, return NULL and
 *  set errno.
 */
extern char *poldiff_class_to_string(poldiff_t *diff, const void *cls);

/**
 *  Get the name of the class from a class diff.
 *
 *  @param cls The class from which to get the name.
 *
 *  @return name of the class on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
extern const char *poldiff_class_get_name(poldiff_class_t *cls);

/**
 *  Get the form of difference from a class diff.
 *
 *  @param cls The class from which to get the difference form.
 *
 *  @return the form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_class_get_form(poldiff_class_t *cls);

/**
 *  Get a vector of permissions added to the class.
 *
 *  @param cls The class diff from which to get the permission vector.
 *
 *  @return a vector of permission names (type char *) that are
 *  assigned to the class in the modified policy.  If no permissions
 *  were added the size of the returned vector will be 0.  The caller
 *  must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_class_get_added_perms(poldiff_class_t *cls);

/**
 *  Get a vector of permissions removed from the class.
 *
 *  @param cls The class diff from which to get the permission vector.
 *
 *  @return a vector of permission names (type char *) that are
 *  assigned to the class in the original policy.  If no permissions
 *  were removed the size of the returned vector will be 0.  The
 *  caller must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_class_get_removed_perms(poldiff_class_t *cls);


/******************** common classes ********************/

typedef struct poldiff_common poldiff_common_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for common classes.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
extern void poldiff_common_get_stats(poldiff_t *diff, size_t stats[5]);

/**
 *  Get the vector of commons differences from the commons difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the
 *  commons difference summary.
 *
 *  @return a vector of elements of type poldiff_common_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector
 *  returned.  If the call fails, errno will be set.
 */
extern apol_vector_t *poldiff_get_common_vector(poldiff_t *diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  a common class.
 *
 *  @param diff The policy difference structure associated with the
 *  common.
 *  @param item The common from which to generate the string.
 *
 *  @return A string representation of common difference; the caller
 *  is responsible for free()ing this string.  On error, return NULL
 *  and set errno.
 */
extern char *poldiff_common_to_string(poldiff_t *diff, const void *common);

/**
 *  Get the name of the common from a common diff.
 *
 *  @param common The common from which to get the name.
 *
 *  @return name of the common on success and NULL on failure; if the
 *  call fails, errno will be set.  The caller should not free the
 *  returned string.
 */
extern const char *poldiff_common_get_name(poldiff_common_t *common);

/**
 *  Get the form of difference from a common diff.
 *
 *  @param common The common from which to get the difference form.
 *
 *  @return the form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.  If the call fails, errno will be set.
 */
extern poldiff_form_e poldiff_common_get_form(poldiff_common_t *common);

/**
 *  Get a vector of permissions added to the common.
 *
 *  @param common The common diff from which to get the permission
 *  vector.
 *
 *  @return a vector of permission names (type char *) that are
 *  assigned to the common in the modified policy.  If no permissions
 *  were added the size of the returned vector will be 0.  The caller
 *  must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_common_get_added_perms(poldiff_common_t *common);

/**
 *  Get a vector of permissions removed from the common.
 *
 *  @param common The common diff from which to get the permission
 *  vector.
 *
 *  @return a vector of permission names (type char *) that are
 *  assigned to the common in the original policy.  If no permissions
 *  were removed the size of the returned vector will be 0.  The
 *  caller must not destroy this vector.  On error, errno will be set.
 */
extern apol_vector_t *poldiff_common_get_removed_perms(poldiff_common_t *common);


#endif /* POLDIFF_CLASS_DIFF_H */
