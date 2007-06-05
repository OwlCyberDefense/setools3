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

#define POLDIFF_ALLOW_OFFSET       0
#define POLDIFF_NEVERALLOW_OFFSET  1
#define POLDIFF_DONTAUDIT_OFFSET   2
#define POLDIFF_AUDITALLOW_OFFSET  3

#define POLDIFF_MEMBER_OFFSET      0
#define POLDIFF_CHANGE_OFFSET      1
#define POLDIFF_TRANS_OFFSET       2

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
		struct poldiff_avrule_summary *avrule_diffs[4];
		struct poldiff_bool_summary *bool_diffs;
		struct poldiff_cat_summary *cat_diffs;
		struct poldiff_class_summary *class_diffs;
		struct poldiff_common_summary *common_diffs;
		struct poldiff_level_summary *level_diffs;
		struct poldiff_range_trans_summary *range_trans_diffs;
		struct poldiff_role_summary *role_diffs;
		struct poldiff_role_allow_summary *role_allow_diffs;
		struct poldiff_role_trans_summary *role_trans_diffs;
		struct poldiff_terule_summary *terule_diffs[3];
		struct poldiff_type_summary *type_diffs;
		struct poldiff_user_summary *user_diffs;
		/* and so forth if we want ocon_diffs */
		type_map_t *type_map;
		/** set if type mapping was changed since last run */
		int remapped;
	};


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
	__attribute__ ((format(printf, 3, 4))) extern void poldiff_handle_msg(poldiff_t * p, int level, const char *fmt, ...);

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
