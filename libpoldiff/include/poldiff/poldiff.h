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

#include <apol/policy.h>
#include <apol/vector.h>
#include <stdarg.h>
#include <stdint.h>

typedef struct poldiff poldiff_t;
typedef void (*poldiff_handle_fn_t)(void *arg, poldiff_t *diff, int level, const char *fmt, va_list va_args);

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
typedef enum poldiff_form {
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

#include <poldiff/class_diff.h>

/* NOTE: while defined MLS amd OCONS are not currently supported */
#define POLDIFF_DIFF_CLASSES     0x00000001
#define POLDIFF_DIFF_COMMONS     0x00000002
#define POLDIFF_DIFF_TYPES       0x00000004
#define POLDIFF_DIFF_ATTRIBS     0x00000008
#define POLDIFF_DIFF_ROLES       0x00000010
#define POLDIFF_DIFF_USERS       0x00000020
#define POLDIFF_DIFF_BOOLS       0x00000040
#define POLDIFF_DIFF_SENS        0x00000080
#define POLDIFF_DIFF_CATS        0x00000100
#define POLDIFF_DIFF_AVRULES     0x00000200
#define POLDIFF_DIFF_TERULES     0x00000400
#define POLDIFF_DIFF_ROLE_ALLOWS 0x00000800
#define POLDIFF_DIFF_ROLE_TRANS  0x00001000
#define POLDIFF_DIFF_RANGE_TRANS 0x00002000
#define POLDIFF_DIFF_CONDS       0x00004000
/*
 * Add ocons here and modify POLDIFF_DIFF_OCONS below
 * #define POLDIFF_DIFF_ *
 */
#define POLDIFF_DIFF_SYMBOLS (POLDIFF_DIFF_CLASSES|POLDIFF_DIFF_COMMONS|POLDIFF_DIFF_TYPES|POLDIFF_DIFF_ATTRIBS|POLDIFF_DIFF_ROLES|POLDIFF_DIFF_USERS|POLDIFF_DIFF_BOOLS)
#define POLDIFF_DIFF_RULES (POLDIFF_DIFF_AVRULES|POLDIFF_DIFF_TERULES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_TRANS)
#define POLDIFF_DIFF_RBAC (POLDIFF_DIFF_ROLES|POLDIFF_DIFF_ROLE_ALLOWS|POLDIFF_DIFF_ROLE_ALLOWS)
#define POLDIFF_DIFF_COND_ITEMS (POLDIFF_DIFF_BOOLS|POLDIFF_DIFF_CONDS)
#define POLDIFF_DIFF_MLS (POLDIFF_DIFF_SENS|POLDIFF_DIFF_CATS|POLDIFF_DIFF_RANGE_TRANS)
#define POLDIFF_DIFF_OCONS 0
#define POLDIFF_DIFF_ALL (POLDIFF_DIFF_SYMBOLS|POLDIFF_DIFF_RULES|POLDIFF_DIFF_CONDS|POLDIFF_DIFF_MLS|POLDIFF_DIFF_OCONS)

/**
 *  Allocate and initialize a new policy difference structure.
 *  @param orig_policy The original policy.
 *  @param mod_policy The new (modified) policy.
 *  @param fn Function to be called by the error handler.
 *  @param callback_arg Argument for the callback.
 *  @return a newly allocated and initialized difference structure or
 *  NULL on error; if the call fails, errno will be set.
 *  The caller is responsible for calling poldiff_destroy() to free
 *  memory used by this structure.
 */
extern poldiff_t *poldiff_create(apol_policy_t *orig_policy,
				 apol_policy_t *mod_policy,
				 poldiff_handle_fn_t fn,
				 void *callback_arg);

/**
 *  Free all memory used by a policy difference structure and set it to NULL.
 *  @param diff Reference pointer to the difference structure to destroy.
 *  This pointer will be set to NULL. (If already NULL, function is a no-op.)
 */
extern void poldiff_destroy(poldiff_t **diff);

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
extern int poldiff_run(poldiff_t *diff, uint32_t flags);

/**
 *  Note a type from policy1 was renamed in policy2.  Subsequent diffs
 *  will thus treat policy1_name to be equivalent to policy2_name.
 *
 *  @param diff The difference structure to which to append a type rename.
 *  Note that changing the list of type renames will reset the status of
 *  previously run difference calculations and they will need to be rerun.
 *  @param policy1_name The name of the type in policy 1.
 *  @param policy2_name The name of a type in policy 2 to consider equivalent.
 *  If both name parameters are NULL the list of renames will be cleared.
 *  @return 0 on success or < 0 on error; if the call fails,
 *  errno will be set and the difference structure will be unchanged.
 */
extern int poldiff_type_rename_append(poldiff_t *diff, const char *policy1_name, const char *policy2_name);

#endif /* POLDIFF_POLDIFF_H */
