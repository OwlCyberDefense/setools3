/**
 *  @file
 *  Public interface for computing semantic differences in av rules
 *  (allow, neverallow, auditallow, dontaudit).
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

#ifndef POLDIFF_AVRULE_DIFF_H
#define POLDIFF_AVRULE_DIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/vector.h>
#include <poldiff/poldiff.h>

	typedef struct poldiff_avrule poldiff_avrule_t;

/**
 *  Get an array of statistics for the number of differences of each
 *  form for av rules.
 *
 *  @param diff The policy difference structure from which to get the
 *  stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated).  The order of the values written to the array is
 *  as follows:  number of items of form POLDIFF_FORM_ADDED, number of
 *  POLDIFF_FORM_REMOVED, number of POLDIFF_FORM_MODIFIED, number of
 *  POLDIFF_FORM_ADD_TYPE, and number of POLDIFF_FORM_REMOVE_TYPE.
 */
	extern void poldiff_avrule_get_stats(poldiff_t * diff, size_t stats[5]);

/**
 *  Get the vector of av rule differences from the av rule difference
 *  summary.
 *
 *  @param diff The policy difference structure associated with the av
 *  rule difference summary.
 *
 *  @return A vector of elements of type poldiff_avrule_t, or NULL on
 *  error.  The caller should <b>not</b> destroy the vector returned.
 *  If the call fails, errno will be set.
 */
	extern apol_vector_t *poldiff_get_avrule_vector(poldiff_t * diff);

/**
 *  Obtain a newly allocated string representation of a difference in
 *  an av rule.
 *
 *  @param diff The policy difference structure associated with the av
 *  rule.
 *  @param avrule The av rule from which to generate the string.
 *
 *  @return A string representation of av rule difference; the caller
 *  is responsible for free()ing this string.  On error, return NULL
 *  and set errno.
 */
	extern char *poldiff_avrule_to_string(poldiff_t * diff, const void *avrule);

/**
 *  Get the form of difference from an av rule diff.
 *
 *  @param avrule The av rule from which to get the difference form.
 *
 *  @return The form of difference (one of POLDIFF_FORM_*) or
 *  POLDIFF_FORM_NONE on error.
 */
	extern poldiff_form_e poldiff_avrule_get_form(const void *avrule);

/**
 *  Get the type of rule this is from an av rule diff.
 *
 *  @param avrule The av rule from which to get the rule type.
 *
 *  @return One of QPOL_RULE_ALLOW etc, suitable for printing via
 *  apol_rule_type_to_str().
 */
	extern uint32_t poldiff_avrule_get_rule_type(const poldiff_avrule_t * avrule);

/**
 *  Get the source type from an av rule diff.
 *
 *  @param avrule The av rule from which to get the type.
 *
 *  @return A string for the type.  <b>Do not free() this string.</b>
 */
	extern const char *poldiff_avrule_get_source_type(const poldiff_avrule_t * avrule);

/**
 *  Get the target type from an av rule diff.
 *
 *  @param avrule The av rule from which to get the type.
 *
 *  @return A string for the type.  <b>Do not free() this string.</b>
 */
	extern const char *poldiff_avrule_get_target_type(const poldiff_avrule_t * avrule);

/**
 *  Get the object class from an av rule diff.
 *
 *  @param avrule The av rule from which to get the class.
 *
 *  @return A string for the class.  <b>Do not free() this string.</b>
 */
	extern const char *poldiff_avrule_get_object_class(const poldiff_avrule_t * avrule);

/**
 *  Get the conditional expression from an av rule diff.  Note that
 *  this really returns a qpol_cond_t and an apol_policy_t, which may
 *  then be used in other routines such as apol_cond_expr_render().
 *
 *  @param diff Difference structure from which the rule originated.
 *  @param avrule The av rule from which to get the conditional.
 *  @param cond Reference to the rule's conditional pointer, or NULL
 *  if the rule is not conditional.  The caller must not free() this
 *  pointer.
 *  @param which_list Reference to which list the rule belongs, either
 *  1 if in the true branch, 0 if in false.  If the rule is not
 *  conditional then this value will be set to 1.
 *  @param p Reference to the policy from which the conditional
 *  originated, or NULL if the rule is not conditional.  The caller
 *  must not destroy this pointer.
 */
	extern void poldiff_avrule_get_cond(const poldiff_t * diff, const poldiff_avrule_t * avrule,
					    qpol_cond_t ** cond, uint32_t * which_list, apol_policy_t ** p);

/**
 *  Get a vector of permissions unmodified by the av rule.  This
 *  vector will be non-empty only if the form is
 *  POLDIFF_FORM_MODIFIED.
 *
 *  @param avrule The av rule diff from which to get the permissions
 *  vector.
 *
 *  @return A vector of permissions strings (type char *) that both
 *  policies have.  If no permissions are common to both policies then
 *  the sizof of the returned vector will be 0.  The caller must not
 *  destroy this vector.
 */
	extern apol_vector_t *poldiff_avrule_get_unmodified_perms(const poldiff_avrule_t * avrule);

/**
 *  Get a vector of permissions added to the av rule.  If the rule was
 *  added by modified policy then this vector will hold all of the
 *  permissions.
 *
 *  @param avrule The av rule diff from which to get the permissions
 *  vector.
 *
 *  @return A vector of permissions strings (type char *) added to the
 *  rule in the modified policy.  If no permissions were added the
 *  size of the returned vector will be 0.  The caller must not
 *  destroy this vector.
 */
	extern apol_vector_t *poldiff_avrule_get_added_perms(const poldiff_avrule_t * avrule);

/**
 *  Get a vector of permissions removed from the av rule.  If the rule
 *  was removed by modified policy then this vector will hold all of
 *  the permissions.
 *
 *  @param avrule The av rule diff from which to get the permissions
 *  vector.
 *
 *  @return A vector of permissions strings (type char *) removed from
 *  the rule in the original policy.  If no permissions were removed
 *  the size of the returned vector will be 0.  The caller must not
 *  destroy this vector.
 */
	extern apol_vector_t *poldiff_avrule_get_removed_perms(const poldiff_avrule_t * avrule);

/**
 *  Get a vector of line numbers (of type unsigned long) for this av rule
 *  difference from the original policy.  Note that if the form is
 *  POLDIFF_FORM_ADDED or POLDIFF_FORM_ADD_TYPE then this will return NULL.
 *  Also, if the original policy is a binary policy or line numbers are not yet
 *  enabled then this returns NULL.
 *  @see poldiff_enable_line_numbers() to enable line numbers.
 *
 *  @param avrule The av rule diff from which to get line numbers.
 *
 *  @return A vector of line numbers (type unsigned long) for the rule
 *  in the original policy, or NULL if no numbers are available.
 */
	extern apol_vector_t *poldiff_avrule_get_orig_line_numbers(const poldiff_avrule_t * avrule);

/**
 *  Get a vector of line numbers (of type unsigned long) for this av rule
 *  difference from the modified policy.  Note that if the form is
 *  POLDIFF_FORM_REMOVED or POLDIFF_FORM_REMOVE_TYPE then this will return
 *  NULL.  Also, if the modified policy is a binary policy  or line numbers are
 *  not yet enabled then this returns NULL.
 *  @see poldiff_enable_line_numbers() to enable line numbers.
 *
 *  @param avrule The av rule diff from which to get line numbers.
 *
 *  @return A vector of line numbers (type unsigned long) for the rule
 *  in the modified policy, or NULL if no numbers are available.
 */
	extern apol_vector_t *poldiff_avrule_get_mod_line_numbers(const poldiff_avrule_t * avrule);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_AVRULE_DIFF_H */