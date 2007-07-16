/**
 *  @file
 *  Implementation for computing a semantic policy difference.
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

#include <config.h>

#include "poldiff_internal.h"
#include <poldiff/component_record.h>

#include <apol/util.h>
#include <qpol/policy_extend.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/**
 * All policy items (object classes, types, rules, etc.) must
 * implement at least these functions.  Next, a record should be
 * appended to the array 'item_records' below.
 */
struct poldiff_item_record
{
	const char *item_name;
	uint32_t flag_bit;
	poldiff_get_item_stats_fn_t get_stats;
	poldiff_get_result_items_fn_t get_results;
	poldiff_item_get_form_fn_t get_form;
	poldiff_item_to_string_fn_t to_string;
	poldiff_reset_fn_t reset;
	poldiff_get_items_fn_t get_items;
	poldiff_item_comp_fn_t comp;
	poldiff_new_diff_fn_t new_diff;
	poldiff_deep_diff_fn_t deep_diff;
};

static const poldiff_item_record_t item_records[] = {
	{
	 "attribute",
	 POLDIFF_DIFF_ATTRIBS,
	 poldiff_attrib_get_stats,
	 poldiff_get_attrib_vector,
	 poldiff_attrib_get_form,
	 poldiff_attrib_to_string,
	 attrib_reset,
	 attrib_get_items,
	 attrib_comp,
	 attrib_new_diff,
	 attrib_deep_diff,
	 },
	{
	 "AVrule allow",
	 POLDIFF_DIFF_AVALLOW,
	 poldiff_avrule_get_stats_allow,
	 poldiff_get_avrule_vector_allow,
	 poldiff_avrule_get_form,
	 poldiff_avrule_to_string,
	 avrule_reset_allow,
	 avrule_get_allow,
	 avrule_comp,
	 avrule_new_diff_allow,
	 avrule_deep_diff_allow,
	 },
	{
	 "AVrule neverallow",
	 POLDIFF_DIFF_AVNEVERALLOW,
	 poldiff_avrule_get_stats_neverallow,
	 poldiff_get_avrule_vector_neverallow,
	 poldiff_avrule_get_form,
	 poldiff_avrule_to_string,
	 avrule_reset_neverallow,
	 avrule_get_neverallow,
	 avrule_comp,
	 avrule_new_diff_neverallow,
	 avrule_deep_diff_neverallow,
	 },
	{
	 "AVrule auditallow",
	 POLDIFF_DIFF_AVAUDITALLOW,
	 poldiff_avrule_get_stats_auditallow,
	 poldiff_get_avrule_vector_auditallow,
	 poldiff_avrule_get_form,
	 poldiff_avrule_to_string,
	 avrule_reset_auditallow,
	 avrule_get_auditallow,
	 avrule_comp,
	 avrule_new_diff_auditallow,
	 avrule_deep_diff_auditallow,
	 },
	{
	 "AVrule dontaudit",
	 POLDIFF_DIFF_AVDONTAUDIT,
	 poldiff_avrule_get_stats_dontaudit,
	 poldiff_get_avrule_vector_dontaudit,
	 poldiff_avrule_get_form,
	 poldiff_avrule_to_string,
	 avrule_reset_dontaudit,
	 avrule_get_dontaudit,
	 avrule_comp,
	 avrule_new_diff_dontaudit,
	 avrule_deep_diff_dontaudit,
	 },
	{
	 "bool",
	 POLDIFF_DIFF_BOOLS,
	 poldiff_bool_get_stats,
	 poldiff_get_bool_vector,
	 poldiff_bool_get_form,
	 poldiff_bool_to_string,
	 bool_reset,
	 bool_get_items,
	 bool_comp,
	 bool_new_diff,
	 bool_deep_diff,
	 },
	{
	 "category",
	 POLDIFF_DIFF_CATS,
	 poldiff_cat_get_stats,
	 poldiff_get_cat_vector,
	 poldiff_cat_get_form,
	 poldiff_cat_to_string,
	 cat_reset,
	 cat_get_items,
	 cat_comp,
	 cat_new_diff,
	 cat_deep_diff,
	 },
	{
	 "class",
	 POLDIFF_DIFF_CLASSES,
	 poldiff_class_get_stats,
	 poldiff_get_class_vector,
	 poldiff_class_get_form,
	 poldiff_class_to_string,
	 class_reset,
	 class_get_items,
	 class_comp,
	 class_new_diff,
	 class_deep_diff,
	 },
	{
	 "common",
	 POLDIFF_DIFF_COMMONS,
	 poldiff_common_get_stats,
	 poldiff_get_common_vector,
	 poldiff_common_get_form,
	 poldiff_common_to_string,
	 common_reset,
	 common_get_items,
	 common_comp,
	 common_new_diff,
	 common_deep_diff,
	 },
	{
	 "level",
	 POLDIFF_DIFF_LEVELS,
	 poldiff_level_get_stats,
	 poldiff_get_level_vector,
	 poldiff_level_get_form,
	 poldiff_level_to_string,
	 level_reset,
	 level_get_items,
	 level_comp,
	 level_new_diff,
	 level_deep_diff,
	 },
	{
	 "range transition",
	 POLDIFF_DIFF_RANGE_TRANS,
	 poldiff_range_trans_get_stats,
	 poldiff_get_range_trans_vector,
	 poldiff_range_trans_get_form,
	 poldiff_range_trans_to_string,
	 range_trans_reset,
	 range_trans_get_items,
	 range_trans_comp,
	 range_trans_new_diff,
	 range_trans_deep_diff,
	 },
	{
	 "role",
	 POLDIFF_DIFF_ROLES,
	 poldiff_role_get_stats,
	 poldiff_get_role_vector,
	 poldiff_role_get_form,
	 poldiff_role_to_string,
	 role_reset,
	 role_get_items,
	 role_comp,
	 role_new_diff,
	 role_deep_diff,
	 },
	{
	 "role_allow",
	 POLDIFF_DIFF_ROLE_ALLOWS,
	 poldiff_role_allow_get_stats,
	 poldiff_get_role_allow_vector,
	 poldiff_role_allow_get_form,
	 poldiff_role_allow_to_string,
	 role_allow_reset,
	 role_allow_get_items,
	 role_allow_comp,
	 role_allow_new_diff,
	 role_allow_deep_diff,
	 },
	{
	 "role_transition",
	 POLDIFF_DIFF_ROLE_TRANS,
	 poldiff_role_trans_get_stats,
	 poldiff_get_role_trans_vector,
	 poldiff_role_trans_get_form,
	 poldiff_role_trans_to_string,
	 role_trans_reset,
	 role_trans_get_items,
	 role_trans_comp,
	 role_trans_new_diff,
	 role_trans_deep_diff,
	 },
	{
	 "TErule transition",
	 POLDIFF_DIFF_TETRANS,
	 poldiff_terule_get_stats_trans,
	 poldiff_get_terule_vector_trans,
	 poldiff_terule_get_form,
	 poldiff_terule_to_string,
	 terule_reset_trans,
	 terule_get_items_trans,
	 terule_comp,
	 terule_new_diff_trans,
	 terule_deep_diff_trans,
	 },
	{
	 "TErule change",
	 POLDIFF_DIFF_TECHANGE,
	 poldiff_terule_get_stats_change,
	 poldiff_get_terule_vector_change,
	 poldiff_terule_get_form,
	 poldiff_terule_to_string,
	 terule_reset_change,
	 terule_get_items_change,
	 terule_comp,
	 terule_new_diff_change,
	 terule_deep_diff_change,
	 },
	{
	 "TErule member",
	 POLDIFF_DIFF_TEMEMBER,
	 poldiff_terule_get_stats_member,
	 poldiff_get_terule_vector_member,
	 poldiff_terule_get_form,
	 poldiff_terule_to_string,
	 terule_reset_member,
	 terule_get_items_member,
	 terule_comp,
	 terule_new_diff_member,
	 terule_deep_diff_member,
	 },
	{
	 "type",
	 POLDIFF_DIFF_TYPES,
	 poldiff_type_get_stats,
	 poldiff_get_type_vector,
	 poldiff_type_get_form,
	 poldiff_type_to_string,
	 type_reset,
	 type_get_items,
	 type_comp,
	 type_new_diff,
	 type_deep_diff,
	 },
	{
	 "user",
	 POLDIFF_DIFF_USERS,
	 poldiff_user_get_stats,
	 poldiff_get_user_vector,
	 poldiff_user_get_form,
	 poldiff_user_to_string,
	 user_reset,
	 user_get_items,
	 user_comp,
	 user_new_diff,
	 user_deep_diff,
	 },
};

const poldiff_item_record_t *poldiff_get_component_record(uint32_t which)
{
	size_t i = 0;
	size_t num_items;

	num_items = sizeof(item_records) / sizeof(poldiff_item_record_t);
	for (i = 0; i < num_items; i++) {
		if (item_records[i].flag_bit == which)
			return &item_records[i];
	}
	return NULL;
}

poldiff_t *poldiff_create(apol_policy_t * orig_policy, apol_policy_t * mod_policy, poldiff_handle_fn_t fn, void *callback_arg)
{
	poldiff_t *diff = NULL;
	int error;

	if (!orig_policy || !mod_policy) {
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	if (!(diff = calloc(1, sizeof(poldiff_t)))) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return NULL;
	}
	diff->orig_pol = orig_policy;
	diff->mod_pol = mod_policy;
	diff->orig_qpol = apol_policy_get_qpol(diff->orig_pol);
	diff->mod_qpol = apol_policy_get_qpol(diff->mod_pol);
	diff->fn = fn;
	diff->handle_arg = callback_arg;
	if ((diff->type_map = type_map_create()) == NULL) {
		ERR(diff, "%s", strerror(ENOMEM));
		poldiff_destroy(&diff);
		errno = ENOMEM;
		return NULL;
	}
	if (type_map_infer(diff) < 0) {
		error = errno;
		poldiff_destroy(&diff);
		errno = error;
		return NULL;
	}

	if ((diff->attrib_diffs = attrib_summary_create()) == NULL ||
	    (diff->avrule_diffs[0] = avrule_create()) == NULL ||
	    (diff->avrule_diffs[1] = avrule_create()) == NULL ||
	    (diff->avrule_diffs[2] = avrule_create()) == NULL ||
	    (diff->avrule_diffs[3] = avrule_create()) == NULL ||
	    (diff->bool_diffs = bool_create()) == NULL ||
	    (diff->cat_diffs = cat_create()) == NULL ||
	    (diff->class_diffs = class_create()) == NULL ||
	    (diff->common_diffs = common_create()) == NULL ||
	    (diff->level_diffs = level_create()) == NULL ||
	    (diff->range_trans_diffs = range_trans_create()) == NULL ||
	    (diff->role_diffs = role_create()) == NULL ||
	    (diff->role_allow_diffs = role_allow_create()) == NULL ||
	    (diff->role_trans_diffs = role_trans_create()) == NULL ||
	    (diff->terule_diffs[0] = terule_create()) == NULL ||
	    (diff->terule_diffs[1] = terule_create()) == NULL ||
	    (diff->terule_diffs[2] = terule_create()) == NULL ||
	    (diff->type_diffs = type_summary_create()) == NULL || (diff->user_diffs = user_create()) == NULL) {
		ERR(diff, "%s", strerror(ENOMEM));
		poldiff_destroy(&diff);
		errno = ENOMEM;
		return NULL;
	}

	diff->policy_opts = QPOL_POLICY_OPTION_NO_RULES | QPOL_POLICY_OPTION_NO_NEVERALLOWS;
	return diff;
}

void poldiff_destroy(poldiff_t ** diff)
{
	if (!diff || !(*diff))
		return;
	apol_policy_destroy(&(*diff)->orig_pol);
	apol_policy_destroy(&(*diff)->mod_pol);
	apol_bst_destroy(&(*diff)->class_bst);
	apol_bst_destroy(&(*diff)->perm_bst);
	apol_bst_destroy(&(*diff)->bool_bst);

	type_map_destroy(&(*diff)->type_map);
	attrib_summary_destroy(&(*diff)->attrib_diffs);
	avrule_destroy(&(*diff)->avrule_diffs[0]);
	avrule_destroy(&(*diff)->avrule_diffs[1]);
	avrule_destroy(&(*diff)->avrule_diffs[2]);
	avrule_destroy(&(*diff)->avrule_diffs[3]);
	bool_destroy(&(*diff)->bool_diffs);
	cat_destroy(&(*diff)->cat_diffs);
	class_destroy(&(*diff)->class_diffs);
	common_destroy(&(*diff)->common_diffs);
	level_destroy(&(*diff)->level_diffs);
	range_trans_destroy(&(*diff)->range_trans_diffs);
	role_destroy(&(*diff)->role_diffs);
	role_allow_destroy(&(*diff)->role_allow_diffs);
	role_trans_destroy(&(*diff)->role_trans_diffs);
	user_destroy(&(*diff)->user_diffs);
	terule_destroy(&(*diff)->terule_diffs[0]);
	terule_destroy(&(*diff)->terule_diffs[1]);
	terule_destroy(&(*diff)->terule_diffs[2]);
	type_summary_destroy(&(*diff)->type_diffs);
	free(*diff);
	*diff = NULL;
}

/**
 * Given a particular policy item record (e.g., one for object
 * classes), (re-)perform a diff of them between the two policies
 * listed in the poldiff_t structure.  Upon success, set the status
 * flag within 'diff' to indicate that this diff is done.
 *
 * @param diff The policy difference structure containing the policies
 * to compare and to populate with the item differences.
 * @param item_record Item record containg callbacks to perform each
 * step of the computation for a particular kind of item.
 *
 * @return 0 on success and < 0 on error; if the call fails; errno
 * will be set and the only defined operation on the policy difference
 * structure will be poldiff_destroy().
 */
static int poldiff_do_item_diff(poldiff_t * diff, const poldiff_item_record_t * item_record)
{
	apol_vector_t *p1_v = NULL, *p2_v = NULL;
	int error = 0, retv;
	size_t x = 0, y = 0;
	void *item_x = NULL, *item_y = NULL;

	if (!diff || !item_record) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	diff->diff_status &= (~item_record->flag_bit);

	INFO(diff, "Getting %s items from original policy.", item_record->item_name);
	p1_v = item_record->get_items(diff, diff->orig_pol);
	if (!p1_v) {
		error = errno;
		goto err;
	}

	INFO(diff, "Getting %s items from modified policy.", item_record->item_name);
	p2_v = item_record->get_items(diff, diff->mod_pol);
	if (!p2_v) {
		error = errno;
		goto err;
	}

	INFO(diff, "Finding differences in %s.", item_record->item_name);
	for (x = 0, y = 0; x < apol_vector_get_size(p1_v);) {
		if (y >= apol_vector_get_size(p2_v))
			break;
		item_x = apol_vector_get_element(p1_v, x);
		item_y = apol_vector_get_element(p2_v, y);
		retv = item_record->comp(item_x, item_y, diff);
		if (retv < 0) {
			if (item_record->new_diff(diff, POLDIFF_FORM_REMOVED, item_x)) {
				error = errno;
				goto err;
			}
			x++;
		} else if (retv > 0) {
			if (item_record->new_diff(diff, POLDIFF_FORM_ADDED, item_y)) {
				error = errno;
				goto err;
			}
			y++;
		} else {
			if (item_record->deep_diff(diff, item_x, item_y)) {
				error = errno;
				goto err;
			}
			x++;
			y++;
		}
	}
	for (; x < apol_vector_get_size(p1_v); x++) {
		item_x = apol_vector_get_element(p1_v, x);
		if (item_record->new_diff(diff, POLDIFF_FORM_REMOVED, item_x)) {
			error = errno;
			goto err;
		}
	}
	for (; y < apol_vector_get_size(p2_v); y++) {
		item_y = apol_vector_get_element(p2_v, y);
		if (item_record->new_diff(diff, POLDIFF_FORM_ADDED, item_y)) {
			error = errno;
			goto err;
		}
	}

	apol_vector_destroy(&p1_v);
	apol_vector_destroy(&p2_v);
	diff->diff_status |= item_record->flag_bit;
	return 0;
      err:
	apol_vector_destroy(&p1_v);
	apol_vector_destroy(&p2_v);
	errno = error;
	return -1;
}

int poldiff_run(poldiff_t * diff, uint32_t flags)
{
	size_t i, num_items;

	if (!flags)
		return 0;	       /* nothing to do */

	if (!diff) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	int policy_opts = diff->policy_opts;
	if (flags & POLDIFF_DIFF_RULES) {
		policy_opts &= ~(QPOL_POLICY_OPTION_NO_RULES);
	}
	if (flags & POLDIFF_DIFF_AVNEVERALLOW) {
		policy_opts &= ~(QPOL_POLICY_OPTION_NO_NEVERALLOWS);
	}
	if (policy_opts != diff->policy_opts) {
		INFO(diff, "%s", "Loading rules from original policy.");
		if (qpol_policy_rebuild(diff->orig_qpol, policy_opts)) {
			return -1;
		}
		INFO(diff, "%s", "Loading rules from modified policy.");
		if (qpol_policy_rebuild(diff->mod_qpol, policy_opts)) {
			return -1;
		}
		// force flushing of existing pointers into policies
		diff->remapped = 1;
		diff->policy_opts = policy_opts;
	}

	num_items = sizeof(item_records) / sizeof(poldiff_item_record_t);
	if (diff->remapped) {
		for (i = 0; i < num_items; i++) {
			if (item_records[i].flag_bit & POLDIFF_DIFF_REMAPPED) {
				INFO(diff, "Resetting %s diff.", item_records[i].item_name);
				if (item_records[i].reset(diff))
					return -1;
			}
		}
		diff->diff_status &= ~(POLDIFF_DIFF_REMAPPED);
		diff->remapped = 0;
	}

	INFO(diff, "%s", "Building type map.");
	if (type_map_build(diff)) {
		return -1;
	}

	diff->line_numbers_enabled = 0;
	for (i = 0; i < num_items; i++) {
		/* item requested but not yet run */
		if ((flags & item_records[i].flag_bit) && !(item_records[i].flag_bit & diff->diff_status)) {
			INFO(diff, "Running %s diff.", item_records[i].item_name);
			if (poldiff_do_item_diff(diff, &(item_records[i]))) {
				return -1;
			}
		}
	}

	return 0;
}

int poldiff_is_run(const poldiff_t * diff, uint32_t flags)
{
	if (!flags)
		return 1;	       /* nothing to do */

	if (!diff) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if ((diff->diff_status & flags) == flags) {
		return 1;
	}
	return 0;
}

int poldiff_get_stats(const poldiff_t * diff, uint32_t flags, size_t stats[5])
{
	size_t i, j, num_items, tmp_stats[5] = { 0, 0, 0, 0, 0 };

	if (!diff || !flags) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	stats[0] = stats[1] = stats[2] = stats[3] = stats[4] = 0;

	num_items = sizeof(item_records) / sizeof(poldiff_item_record_t);
	for (i = 0; i < num_items; i++) {
		if (flags & item_records[i].flag_bit) {
			item_records[i].get_stats(diff, tmp_stats);
			for (j = 0; j < 5; j++)
				stats[j] += tmp_stats[j];
		}
	}

	return 0;
}

int poldiff_enable_line_numbers(poldiff_t * diff)
{
	int retval;
	if (diff == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (!diff->line_numbers_enabled) {
		if (qpol_policy_build_syn_rule_table(diff->orig_qpol))
			return -1;
		if (qpol_policy_build_syn_rule_table(diff->mod_qpol))
			return -1;
		if ((retval = avrule_enable_line_numbers(diff, POLDIFF_ALLOW_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = avrule_enable_line_numbers(diff, POLDIFF_NEVERALLOW_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = avrule_enable_line_numbers(diff, POLDIFF_DONTAUDIT_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = avrule_enable_line_numbers(diff, POLDIFF_AUDITALLOW_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = terule_enable_line_numbers(diff, POLDIFF_MEMBER_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = terule_enable_line_numbers(diff, POLDIFF_CHANGE_OFFSET)) < 0) {
			return retval;
		}
		if ((retval = terule_enable_line_numbers(diff, POLDIFF_TRANS_OFFSET)) < 0) {
			return retval;
		}
		diff->line_numbers_enabled = 1;
	}
	return 0;
}

int poldiff_build_bsts(poldiff_t * diff)
{
	apol_vector_t *classes[2] = { NULL, NULL };
	apol_vector_t *perms[2] = { NULL, NULL };
	apol_vector_t *bools[2] = { NULL, NULL };
	size_t i, j;
	const qpol_class_t *cls;
	qpol_bool_t *qbool;
	const char *name;
	char *new_name;
	int retval = -1, error = 0;
	if (diff->class_bst != NULL) {
		return 0;
	}
	if ((diff->class_bst = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (diff->perm_bst = apol_bst_create(apol_str_strcmp, free)) == NULL ||
	    (diff->bool_bst = apol_bst_create(apol_str_strcmp, free)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < 2; i++) {
		apol_policy_t *p = (i == 0 ? diff->orig_pol : diff->mod_pol);
		qpol_policy_t *q = apol_policy_get_qpol(p);
		if (apol_class_get_by_query(p, NULL, &classes[i]) < 0 ||
		    apol_perm_get_by_query(p, NULL, &perms[i]) < 0 || apol_bool_get_by_query(p, NULL, &bools[i]) < 0) {
			error = errno;
			goto cleanup;
		}
		for (j = 0; j < apol_vector_get_size(classes[i]); j++) {
			cls = apol_vector_get_element(classes[i], j);
			if (qpol_class_get_name(q, cls, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->class_bst, (void **)&new_name, NULL) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		for (j = 0; j < apol_vector_get_size(perms[i]); j++) {
			name = (char *)apol_vector_get_element(perms[i], j);
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->perm_bst, (void **)&new_name, NULL) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		for (j = 0; j < apol_vector_get_size(bools[i]); j++) {
			qbool = (qpol_bool_t *) apol_vector_get_element(bools[i], j);
			if (qpol_bool_get_name(q, qbool, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if ((new_name = strdup(name)) == NULL ||
			    apol_bst_insert_and_get(diff->bool_bst, (void **)&new_name, NULL) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&classes[0]);
	apol_vector_destroy(&classes[1]);
	apol_vector_destroy(&perms[0]);
	apol_vector_destroy(&perms[1]);
	apol_vector_destroy(&bools[0]);
	apol_vector_destroy(&bools[1]);
	errno = error;
	return retval;
}

static void poldiff_handle_default_callback(void *arg __attribute__ ((unused)),
					    poldiff_t * p __attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	switch (level) {
	case POLDIFF_MSG_INFO:
	{
		/* by default do not display these messages */
		return;
	}
	case POLDIFF_MSG_WARN:
	{
		fprintf(stderr, "WARNING: ");
		break;
	}
	case POLDIFF_MSG_ERR:
	default:
	{
		fprintf(stderr, "ERROR: ");
		break;
	}
	}
	vfprintf(stderr, fmt, va_args);
	fprintf(stderr, "\n");
}

void poldiff_handle_msg(const poldiff_t * p, int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (p == NULL || p->fn == NULL) {
		poldiff_handle_default_callback(NULL, NULL, level, fmt, ap);
	} else {
		p->fn(p->handle_arg, p, level, fmt, ap);
	}
	va_end(ap);
}

poldiff_item_get_form_fn_t poldiff_component_get_form_fn(const poldiff_item_record_t * diff)
{
	if (!diff)
		return NULL;
	return diff->get_form;
}

poldiff_item_to_string_fn_t poldiff_component_get_to_string_fn(const poldiff_item_record_t * diff)
{
	if (!diff)
		return NULL;
	return diff->to_string;
}

poldiff_get_item_stats_fn_t poldiff_component_get_stats_fn(const poldiff_item_record_t * diff)
{
	if (!diff)
		return NULL;
	return diff->get_stats;
}

poldiff_get_result_items_fn_t poldiff_component_get_results_fn(const poldiff_item_record_t * diff)
{
	if (!diff)
		return NULL;
	return diff->get_results;
}

const char *poldiff_component_get_label(const poldiff_item_record_t * diff)
{
	if (!diff)
		return NULL;
	return diff->item_name;
}
