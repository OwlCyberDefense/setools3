/**
 *  @file poldiff.h
 *  Public Interface for computing a semantic policy difference.
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

#ifndef POLDIFF_POLDIFF_H
#define POLDIFF_POLDIFF_H

#include <apol/vector.h>
#include <stdarg.h>

typedef struct poldiff_state poldiff_state_t;

/* forward declarations */
struct poldiff_class_diff_summary;
struct common_diff_summary;
struct type_diff_summary;
struct attrib_diff_summary;
struct role_diff_summary;
struct user_diff_summary;
struct bool_diff_summary;
struct sens_diff_summary;
struct cat_diff_summary;
struct avrule_diff_summary;
struct terule_diff_summary;
struct role_allow_diff_summary;
struct role_trans_diff_summary;
struct range_trans_diff_summary;

typedef struct poldiff {
	poldiff_state_t *state;
	struct class_diff_summary *class_diffs;
	struct common_diff_summary *common_diffs;
	struct type_diff_summary *type_diffs;
	struct attrib_diff_summary *attrib_diffs;
	struct role_diff_summary *role_diffs;
	struct user_diff_summary *user_diffs;
	struct bool_diff_summary *bool_diffs;
	struct sens_diff_summary *sens_diffs;
	struct cat_diff_summary *cat_diffs;
	struct avrule_diff_summary *avrule_diffs;
	struct terule_diff_summary *terule_diffs;
	struct role_allow_diff_summary *role_allow_diffs;
	struct role_trans_diff_summary *role_trans_diffs;
	struct range_trans_diff_summary *range_trans_diffs;
	/* and so forth if we want ocon_diffs */
	apol_vector_t *type_renames;
} poldiff_t;

typedef struct poldiff_type_rename poldiff_type_rename_t;
typedef void (*poldiff_handle_callback_fn_t)(void *arg, poldiff_t *diff, char *fmt, va_list va_args);

typedef enum poldiff_diff_type {
	DIFF_TYPE_NONE,	/* only for error conditions */
	DIFF_TYPE_ADDED,	   /* item was added - only in policy 2 */
	DIFF_TYPE_REMOVED,	/* item was removed - only in policy 1 */
	DIFF_TYPE_MODIFIED	/* item was modified - exists in both policies but with different semantic meaning */
} poldiff_diff_type_e;

extern int poldiff_run(poldiff_t *diff, uint32_t flags);
extern poldiff_t *poldiff_create(apol_policy_t *policy1, apol_policy_t *polciy2, poldiff_handle_callback_fn_t fn, void *callback_arg);
extern void poldiff_destroy(poldiff_t **diff);
extern int poldiff_type_rename_append(poldiff_t *diff, poldiff_type_rename_t *rename);

#endif /* POLDIFF_POLDIFF_H */
