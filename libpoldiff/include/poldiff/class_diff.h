/**
 *  @file class_diff.h
 *  Public Interface for computing a semantic differences in classes.
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

typedef struct poldiff_class_diff_summary poldiff_class_diff_summary_t;
typedef struct poldiff_class_diff poldiff_class_diff_t;

/**
 *  Get the name of the class from a class diff.
 *  @param diff The policy difference structure associated with the class diff.
 *  @param cls The class from which to get the name.
 *  @return name of the class on success and NULL on failure; if the call fails,
 *  errno will be set. The caller should not free the returned string.
 */
extern char *poldiff_class_diff_get_name(poldiff_t *diff, poldiff_class_diff_t *cls);

/**
 *  Get the type of difference from a class diff.
 *  @param diff The policy difference structure associated with the class diff.
 *  @param cls The class from which to get the difference type.
 *  @return the type of difference or DIFF_TYPE_NONE on error.
 *  If the call fails, errno will be set.
 */
extern poldiff_diff_type_e poldiff_class_diff_get_diff_type(poldiff_t *diff, poldiff_class_diff_t *cls);

/**
 *  Get a vector of the permissions added to the class.
 *  @param diff The policy difference structure associated with the class diff.
 *  @param cls The class diff from which to get the permission vector.
 *  @return a vector of permission names that are assigned to the class
 *  in only policy 2 or NULL on error. If no permissions were added the size
 *  of the returned vector will be 0. On error, errno will be set.
 */
extern apol_vector_t *poldiff_class_diff_get_added_perms(poldiff_t *diff, poldiff_class_diff_t *cls);

/**
 *  Get a vector of the permissions removed from the class.
 *  @param diff The policy difference structure associated with the class diff.
 *  @param cls The class diff from which to get the permission vector.
 *  @return a vector of permission names that are assigned to the class
 *  in only policy 1 or NULL on error. If no permissions were removed the size
 *  of the returned vector will be 0. On error, errno will be set.
 */
extern apol_vector_t *poldiff_class_diff_get_removed_perms(poldiff_t *diff, poldiff_class_diff_t *cls);

/**
 *  Get the number of added classes from a class difference summary;
 *  @param diff The policy difference structure associated with the
 *  class difference summary.
 *  @param cds The class difference summary from which to get the number
 *  of added classes.
 *  @return the number of added classes or 0 if not yet run.
 */
extern size_t poldiff_class_diff_summary_get_num_added_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds);

/**
 *  Get the number of removed classes from a class difference summary;
 *  @param diff The policy difference structure associated with the
 *  class difference summary.
 *  @param cds The class difference summary from which to get the number
 *  of removed classes.
 *  @return the number of removed classes or 0 if not yet run.
 */
extern size_t poldiff_class_diff_summary_get_num_removed_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds);
/**
 *  Get the number of mocified classes from a class difference summary;
 *  @param diff The policy difference structure associated with the
 *  class difference summary.
 *  @param cds The class difference summary from which to get the number
 *  of modified classes.
 *  @return the number of modified classes or 0 if not yet run.
 */
extern size_t poldiff_class_diff_summary_get_num_modified_classes(poldiff_t *diff, poldiff_class_diff_summary_t *cds);
/**
 *  Get the vector of class differences from the class difference summary;
 *  @param diff The policy difference structure associated with the
 *  class difference summary.
 *  @param cds The class difference summary from which to get the vector
 *  of class differences.
 *  @return a vector of elements of type class_diff_t, or NULL on error.
 *  The caller should <b>not</b> destroy the vector returned. If the call
 *  fails, errno will be set.
 */
extern apol_vector_t *poldiff_class_diff_summary_get_class_diff_vector(poldiff_t *diff, poldiff_class_diff_summary_t *cds);

#endif /* POLDIFF_CLASS_DIFF_H */
