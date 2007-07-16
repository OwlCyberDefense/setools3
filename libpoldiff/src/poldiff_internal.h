/**
 *  @file
 *  Protected interface for computing semantic policy difference.
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

#ifndef POLDIFF_POLDIFF_INTERNAL_H
#define POLDIFF_POLDIFF_INTERNAL_H

#ifdef	__cplusplus
extern "C"
{
#endif

#include <poldiff/poldiff.h>
#include <apol/bst.h>

	typedef enum
	{
		AVRULE_OFFSET_ALLOW = 0, AVRULE_OFFSET_NEVERALLOW,
		AVRULE_OFFSET_DONTAUDIT, AVRULE_OFFSET_AUDITALLOW,
		AVRULE_OFFSET_MAX
	} avrule_offset_e;

	typedef enum
	{
		TERULE_OFFSET_MEMBER = 0, TERULE_OFFSET_CHANGE,
		TERULE_OFFSET_TRANS,
		TERULE_OFFSET_MAX
	} terule_offset_e;

#include "attrib_internal.h"
#include "avrule_internal.h"
#include "bool_internal.h"
#include "cat_internal.h"
#include "class_internal.h"
#include "level_internal.h"
#include "range_internal.h"
#include "range_trans_internal.h"
#include "rbac_internal.h"
#include "role_internal.h"
#include "terule_internal.h"
#include "user_internal.h"
#include "type_internal.h"

#include "type_map_internal.h"

/* forward declarations */
	struct poldiff_attrib_summary;
	struct poldiff_avrule_summary;
	struct poldiff_bool_summary;
	struct poldiff_cat_summary;
	struct poldiff_class_summary;
	struct poldiff_common_summary;
	struct poldiff_level_summary;
	struct poldiff_range_trans_summary;
	struct poldiff_role_summary;
	struct poldiff_role_allow_summary;
	struct poldiff_role_trans_summary;
	struct poldiff_terule_summary;
	struct poldiff_type_summary;
	struct poldiff_user_summary;
/* and so forth for ocon_summary structs */

	struct poldiff
	{
		/** the "original" policy */
		apol_policy_t *orig_pol;
		/** the "modified" policy */
		apol_policy_t *mod_pol;
		/** pointer to original's qpol policy within orig_pol */
		qpol_policy_t *orig_qpol;
		/** pointer to modified's qpol policy within mod_pol */
		qpol_policy_t *mod_qpol;
		/** non-zero if rules' line numbers are accurate */
		int line_numbers_enabled;
		/** BST of duplicated strings, used when making pseudo-rules */
		apol_bst_t *class_bst;
		/** BST of duplicated strings, used when making pseudo-rules */
		apol_bst_t *perm_bst;
		/** BST of duplicated strings, used when making pseudo-rules */
		apol_bst_t *bool_bst;
		poldiff_handle_fn_t fn;
		void *handle_arg;
		/** set of POLDIF_DIFF_* bits for diffs run */
		uint32_t diff_status;
		struct poldiff_attrib_summary *attrib_diffs;
		struct poldiff_avrule_summary *avrule_diffs[AVRULE_OFFSET_MAX];
		struct poldiff_bool_summary *bool_diffs;
		struct poldiff_cat_summary *cat_diffs;
		struct poldiff_class_summary *class_diffs;
		struct poldiff_common_summary *common_diffs;
		struct poldiff_level_summary *level_diffs;
		struct poldiff_range_trans_summary *range_trans_diffs;
		struct poldiff_role_summary *role_diffs;
		struct poldiff_role_allow_summary *role_allow_diffs;
		struct poldiff_role_trans_summary *role_trans_diffs;
		struct poldiff_terule_summary *terule_diffs[TERULE_OFFSET_MAX];
		struct poldiff_type_summary *type_diffs;
		struct poldiff_user_summary *user_diffs;
		/* and so forth if we want ocon_diffs */
		type_map_t *type_map;
		/** most recently used flags to open the two policies */
		int policy_opts;
		/** set if type mapping was changed since last run */
		int remapped;
	};

/**
 *  Callback function signature for getting a vector of all unique
 *  items of a given kind in a policy.  The vector must be sorted
 *  prior to returning from this function.
 *
 *  @param diff Policy diff error handler.
 *  @param policy The policy from which to get the items.
 *  @return a newly allocated vector of all unique items of the
 *  appropriate kind on success, or NULL on error; if the call fails,
 *  errno will be set.
 */
	typedef apol_vector_t *(*poldiff_get_items_fn_t) (poldiff_t * diff, const apol_policy_t * policy);

/**
 *  Callback function signature for quickly comparing two items to
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

/**
 *  Callback function signature for resetting the diff results for an
 *  item.  called when mapping of the symbols used by the diff change.
 *  @param diff The policy difference structure containing the diffs
 *  to reset.
 *  @return 0 on success and < 0 on error; if the call fails,
 *  it is expected to set errno.
 */
	typedef int (*poldiff_reset_fn_t) (poldiff_t * diff);

/******************** error handling code below ********************/

#define POLDIFF_MSG_ERR  1
#define POLDIFF_MSG_WARN 2
#define POLDIFF_MSG_INFO 3

/**
 * Write a message to the callback stored within a poldiff error
 * handler.  If the msg_callback field is empty then suppress the
 * message.
 *
 * @param p Error reporting handler.  If NULL then write message to
 * stderr.
 * @param level Severity of message, one of POLDIFF_MSG_ERR,
 * POLDIFF_MSG_WARN, or POLDIFF_MSG_INFO.
 * @param fmt Format string to print, using syntax of printf(3).
 */
	__attribute__ ((format(printf, 3, 4))) extern void poldiff_handle_msg(const poldiff_t * p, int level, const char *fmt, ...);

#undef ERR
#undef WARN
#undef INFO

#define ERR(handle, format, ...) poldiff_handle_msg(handle, POLDIFF_MSG_ERR, format, __VA_ARGS__)
#define WARN(handle, format, ...) poldiff_handle_msg(handle, POLDIFF_MSG_WARN, format, __VA_ARGS__)
#define INFO(handle, format, ...) poldiff_handle_msg(handle, POLDIFF_MSG_INFO, format, __VA_ARGS__)

/**
 * Build the BST for classes, permissions, and booleans if the
 * policies have changed.  This effectively provides a partial mapping
 * of rules from one policy to the other.
 *
 * @param diff Policy difference structure containing policies to diff.
 *
 * @return 0 on success, < 0 on error.
 */
	int poldiff_build_bsts(poldiff_t * diff);

#ifdef	__cplusplus
}
#endif

#endif				       /* POLDIFF_POLDIFF_INTERNAL_H */
