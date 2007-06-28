/**
 *  @file
 *  Public interface for computing semantic policy differences
 *  between two policies.  The user loads two policies, the "original"
 *  and "modified" policies, and then calls poldiff_create() to obtain
 *  a poldiff object.  Next call poldiff_run() to actually execute the
 *  differencing algorithm.  Results are retrieved via
 *  poldiff_get_type_vector(), poldiff_get_avrule_vector(), and so
 *  forth.
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

#ifndef POLDIFF_POLDIFF_H
#define POLDIFF_POLDIFF_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/vector.h>
#include <stdarg.h>
#include <stdint.h>

	typedef struct poldiff poldiff_t;

/**
 *  Form of a difference. This enumeration describes the kind of change
 *  in a policy component or rule from policy1 to policy2.
 *  Differences can be additions (item present only in policy2),
 *  removals (item present only in policy1) or a modification
 *  (item present in both policies with different semantic meaning).
 *  For rules there are two more options - added or removed due to a
 *  type being added or removed; these forms differentiate these cases
 *  from those of added/removed rules where the types exist in both policies.
 */
	typedef enum poldiff_form
	{
	/** only for error conditions */
		POLDIFF_FORM_NONE,
	/** item was added - only in policy 2 */
		POLDIFF_FORM_ADDED,
	/** item was removed - only in policy 1 */
		POLDIFF_FORM_REMOVED,
	/** item was modified - in both policies but with different meaning */
		POLDIFF_FORM_MODIFIED,
	/** item was added due to an added type - for rules only */
		POLDIFF_FORM_ADD_TYPE,
	/** item was removed due to a removed type - for rules only */
		POLDIFF_FORM_REMOVE_TYPE
	} poldiff_form_e;

/**
 *  Callback function signature for getting an array of statistics for the
 *  number of differences of each form for a given item.
 *  @param diff The policy difference structure from which to get the stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated). The order of the values written to the array is as follows:
 *  number of items of form POLDIFF_FORM_ADDED, number of POLDIFF_FORM_REMOVED,
 *  number of POLDIFF_FORM_MODIFIED, number of form POLDIFF_FORM_ADD_TYPE, and
 *  number of POLDIFF_FORM_REMOVE_TYPE.
 */
	typedef void (*poldiff_get_item_stats_fn_t) (const poldiff_t * diff, size_t stats[5]);

/**
 *  Callback function signature for getting a vector of all result
 *  items that were created during a call to poldiff_do_item_diff().
 *  @param diff Policy diff structure containing results.
 *  @return A vector of result items, which the caller may not modify
 *  or destroy.  Upon error, return NULL and set errno.
 */
	typedef const apol_vector_t *(*poldiff_get_result_items_fn_t) (const poldiff_t * diff);

/**
 *  Callback function signature for getting the form of difference for
 *  a result item.
 *  @param diff The policy difference structure associated with the item.
 *  @param item The item from which to get the form.
 *  @return One of the POLDIFF_FORM_* enumeration.
 */
	typedef poldiff_form_e(*poldiff_item_get_form_fn_t) (const void *item);

/**
 *  Callback function signature for obtaining a newly allocated string
 *  representation of a difference item.
 *  @param diff The policy difference structure associated with the item.
 *  @param item The item from which to generate the string.
 *  @return Expected return value from this function is a newly allocated
 *  string representation of the item or NULL on error; if the call fails,
 *  it is expected to set errno.
 */
	typedef char *(*poldiff_item_to_string_fn_t) (const poldiff_t * diff, const void *item);

/**
 *  Callbackfunction signature for resetting the diff results for an item.
 *  called when mapping of the symbols used by the diff change.
 *  @param diff The policy difference structure containing the diffs to reset.
 *  @return 0 on success and < 0 on error; if the call fails,
 *  it is expected to set errno.
 */
	typedef int (*poldiff_reset_fn_t) (poldiff_t * diff);

/**
 *  Callback function signature for getting a vector of all unique
 *  items of a given kind in a policy.  The vector must be sorted
 *  prior to returning from this function.
 *
 *  @param diff Policy diff error handler.
 *  @param policy The policy from which to get the items.
 *  @return a newly allocated vector of all unique items
 *  of the appropriate kind on success, or NULL on error;
 *  if the call fails, errno will be set.
 */
	typedef apol_vector_t *(*poldiff_get_items_fn_t) (poldiff_t * diff, const apol_policy_t * policy);

/**
 *  Callback funtion signature for quickly comparing two items to
 *  determine if they are semantically the same item.  This operation
 *  should quickly determine if the two are obviously different or
 *  not.
 *
 *  @param x The item from the original policy.
 *  @param y The item from the modified policy.
 *  @param diff The policy difference structure associated with both
 *  items.
 *
 *  @return Expected return value from this function is < 0, 0, or > 0
 *  if item x is respectively less than, equal to, or greater than item y.
 *  This must be able to return a defined stable ordering for all items
 *  not semantically equivalent.
 */
	typedef int (*poldiff_item_comp_fn_t) (const void *x, const void *y, const poldiff_t * diff);

/**
 *  Callback function signature for creating, initializing and inserting
 *  a new semantic difference entry for an item.
 *  @param diff The policy difference structure to which to add the entry.
 *  @param form The form of the difference, one of POLDIFF_FORM_ADDED or
 *  POLDIFF_FORM_REMOVED.
 *  @param item Item for which the entry is being created.
 *  @return Expected return value from this function is 0 on success and
 *  < 0 on error; if the call fails, it is expected to set errno and to
 *  leave the policy difference structure unchanged.
 */
	typedef int (*poldiff_new_diff_fn_t) (poldiff_t * diff, poldiff_form_e form, const void *item);

/**
 *  Callback function signature for computing the semantic difference of
 *  two items for which the compare callback returns 0. This function should
 *  calculate the difference of any properties of the items and if a difference
 *  is found to allocate, initialize, and insert an new semantic difference
 *  entry for that item.
 *  @param diff The policy difference structure associated with both items and
 *  to which to add an entry if needed.
 *  @param x The item from the original policy.
 *  @param y The item from the modified policy.
 *  @return Expected return value from this function is 0 on success and
 *  < 0 on error; if the call fails, it is expected to set errno and to
 *  leave the policy difference structure unchanged.
 */
	typedef int (*poldiff_deep_diff_fn_t) (poldiff_t * diff, const void *x, const void *y);

	typedef struct poldiff_item_record poldiff_item_record_t;

	typedef void (*poldiff_handle_fn_t) (void *arg, const poldiff_t * diff, int level, const char *fmt, va_list va_args);

#include <poldiff/attrib_diff.h>
#include <poldiff/avrule_diff.h>
#include <poldiff/cat_diff.h>
#include <poldiff/bool_diff.h>
#include <poldiff/class_diff.h>
#include <poldiff/level_diff.h>
#include <poldiff/range_diff.h>
#include <poldiff/range_trans_diff.h>
#include <poldiff/rbac_diff.h>
#include <poldiff/role_diff.h>
#include <poldiff/terule_diff.h>
#include <poldiff/type_diff.h>
#include <poldiff/user_diff.h>
#include <poldiff/type_map.h>
#include <poldiff/util.h>

/* NOTE: while defined OCONS are not currently supported */
#define POLDIFF_DIFF_CLASSES       0x00000001U
#define POLDIFF_DIFF_COMMONS       0x00000002U
#define POLDIFF_DIFF_TYPES         0x00000004U
#define POLDIFF_DIFF_ATTRIBS       0x00000008U
#define POLDIFF_DIFF_ROLES         0x00000010U
#define POLDIFF_DIFF_USERS         0x00000020U
#define POLDIFF_DIFF_BOOLS         0x00000040U
#define POLDIFF_DIFF_LEVELS        0x00000080U
#define POLDIFF_DIFF_CATS          0x00000100U
#define POLDIFF_DIFF_ROLE_ALLOWS   0x00000800U
#define POLDIFF_DIFF_ROLE_TRANS    0x00001000U
#define POLDIFF_DIFF_RANGE_TRANS   0x00002000U
#define POLDIFF_DIFF_AVALLOW       0x10000000U
#define POLDIFF_DIFF_AVNEVERALLOW  0x20000000U
#define POLDIFF_DIFF_AVAUDITALLOW  0x40000000U
#define POLDIFF_DIFF_AVDONTAUDIT   0x80000000U
#define POLDIFF_DIFF_TEMEMBER      0x01000000U
#define POLDIFF_DIFF_TECHANGE      0x02000000U
#define POLDIFF_DIFF_TETRANS       0x04000000U

#define POLDIFF_DIFF_TERULES_COMPAT 0x00000400U
#define POLDIFF_DIFF_AVRULES_COMPAT 0x00000200U

#define POLDIFF_DIFF_AVRULES     (POLDIFF_DIFF_AVALLOW | POLDIFF_DIFF_AVNEVERALLOW | POLDIFF_DIFF_AVAUDITALLOW | POLDIFF_DIFF_AVDONTAUDIT | POLDIFF_DIFF_AVRULES_COMPAT )
#define POLDIFF_DIFF_TERULES     (POLDIFF_DIFF_TEMEMBER | POLDIFF_DIFF_TECHANGE | POLDIFF_DIFF_TETRANS | POLDIFF_DIFF_TERULES_COMPAT)
/*
 * Add ocons here and modify POLDIFF_DIFF_OCONS below
 * #define POLDIFF_DIFF_ *
 */
#define POLDIFF_DIFF_SYMBOLS (POLDIFF_DIFF_CLASSES|POLDIFF_DIFF_COMMONS|POLDIFF_DIFF_TYPES|POLDIFF_DIFF_ATTRIBS|POLDIFF_DIFF_ROLES|POLDIFF_DIFF_USERS|POLDIFF_DIFF_BOOLS)
#define POLDIFF_DIFF_RULES (POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_TRANS)
#define POLDIFF_DIFF_RBAC (POLDIFF_DIFF_ROLES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_TRANS)
#define POLDIFF_DIFF_MLS (POLDIFF_DIFF_LEVELS|POLDIFF_DIFF_CATS|POLDIFF_DIFF_RANGE_TRANS)
#define POLDIFF_DIFF_OCONS 0
#define POLDIFF_DIFF_REMAPPED (POLDIFF_DIFF_TYPES|POLDIFF_DIFF_ATTRIBS|POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES|POLDIFF_DIFF_ROLES|POLDIFF_DIFF_ROLE_TRANS|POLDIFF_DIFF_RANGE_TRANS|POLDIFF_DIFF_OCONS)
#define POLDIFF_DIFF_ALL (POLDIFF_DIFF_SYMBOLS|POLDIFF_DIFF_RULES|POLDIFF_DIFF_MLS|POLDIFF_DIFF_OCONS)

/**
 * Get the poldiff_item_record_t out of the item_records[] so that
 * the callbacks for each type can be used externally.
 *
 * Takes a flag as defined above (IE POLDIFF_DIFF_AVALLOW) and
 * returns the poldiff_item_record_t associated with it or NULL
 * if not found.
 */
	extern const poldiff_item_record_t *poldiff_get_item_record(uint32_t which);

/**
 *  Allocate and initialize a new policy difference structure.  This
 *  function takes ownership of the supplied policies and will handle
 *  their destruction upon poldiff_destroy().  The poldiff object will
 *  be responsible for rebuilding the policy (such as if neverallows
 *  are requested).  It is still safe to access elements within the
 *  policies, but avoid making changes to the policy while the poldiff
 *  object still exists.
 *  @param orig_policy The original policy.
 *  @param mod_policy The new (modified) policy.
 *  @param fn Function to be called by the error handler.  If NULL
 *  then write messages to standard error.
 *  @param callback_arg Argument for the callback.
 *  @return a newly allocated and initialized difference structure or
 *  NULL on error; if the call fails, errno will be set.
 *  The caller is responsible for calling poldiff_destroy() to free
 *  memory used by this structure.
 */
	extern poldiff_t *poldiff_create(apol_policy_t * orig_policy,
					 apol_policy_t * mod_policy, poldiff_handle_fn_t fn, void *callback_arg);

/**
 *  Free all memory used by a policy difference structure and set it to NULL.
 *  @param diff Reference pointer to the difference structure to destroy.
 *  This pointer will be set to NULL. (If already NULL, function is a no-op.)
 */
	extern void poldiff_destroy(poldiff_t ** diff);

/**
 *  Run the difference algorithm for the selected policy components/rules.
 *  @param diff The policy difference structure for which to compute
 *  the differences.
 *  @param flags Bit-wise or'd set of POLDIFF_DIFF_* from above indicating
 *  the components and rules for which to compute the difference.
 *  If an item has already been computed the flag for that item is ignored.
 *  @return 0 on success or < 0 on error; if the call fails, errno will
 *  be set and the only defined operation on the difference structure is
 *  poldiff_destroy().
 */
	extern int poldiff_run(poldiff_t * diff, uint32_t flags);

/**
 *  Determine if a particular policy component/rule diff was actually
 *  run yet or not.
 *  @param diff The policy difference structure for which to compute
 *  the differences.
 *  @param flags Bit-wise or'd set of POLDIFF_DIFF_* from above indicating
 *  which components/rules diffs were run.
 *  @return 1 if all indicated diffs were run, 0 if any were not, < 0
 *  on error.
 */
	extern int poldiff_is_run(const poldiff_t * diff, uint32_t flags);

/**
 *  Get a total of the differences of each form for a given item (or set
 *  of items).
 *  @param diff The policy difference structure from which to get the stats.
 *  @param flags Bit-wise or'd set of POLDIFF_DIFF_* from above indicating
 *  the items for which to get the total differences. If more that one bit
 *  is set differences of the same form are totaled for all specified items.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated). The order of the values written to the array is as follows:
 *  number of items of form POLDIFF_FORM_ADDED, number of POLDIFF_FORM_REMOVED,
 *  number of POLDIFF_FORM_MODIFIED, number of form POLDIFF_FORM_ADD_TYPE, and
 *  number of POLDIFF_FORM_REMOVE_TYPE.
 *  @return 0 on success and < 0 on error; if the call fails, errno will be set.
 */
	extern int poldiff_get_stats(const poldiff_t * diff, uint32_t flags, size_t stats[5]);

/**
 *  Enable line numbers for all rule differences.  If not called, line
 *  numbers will not be available when displaying differences.  This
 *  function is safe to call multiple times and will have no effect
 *  after the first time.  It also has no effect if one policy (or
 *  both of them) does not support line numbers.  Be aware that line
 *  numbers will need to be re-enabled each time poldiff_run() is
 *  called.
 *
 *  @param diff The policy difference structure.
 *
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set and the difference structure should be destroyed.
 */
	extern int poldiff_enable_line_numbers(poldiff_t * diff);

	extern poldiff_item_get_form_fn_t poldiff_get_form_fn(const poldiff_item_record_t * diff);
	extern poldiff_item_to_string_fn_t poldiff_get_to_string_fn(const poldiff_item_record_t * diff);
	extern poldiff_get_item_stats_fn_t poldiff_get_stats_fn(const poldiff_item_record_t * diff);
	extern poldiff_get_result_items_fn_t poldiff_get_results_fn(const poldiff_item_record_t * diff);
	extern const char *poldiff_item_get_label(const poldiff_item_record_t * diff);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_POLDIFF_H */
