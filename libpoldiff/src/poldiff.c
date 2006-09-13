/**
 *  @file poldiff.c
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

#include "poldiff_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

/**
 * All policy items (object classes, types, rules, etc.) must
 * implement at least these functions.  Next, a record should be
 * appended to the array 'item_records' below.
 */
typedef struct poldiff_item_record {
	const char *item_name;
	uint32_t flag_bit;
	poldiff_get_item_stats_fn_t get_stats;
	poldiff_get_result_items_fn_t get_results;
	poldiff_item_to_string_fn_t to_string;
	poldiff_get_items_fn_t get_items;
	poldiff_free_item_fn_t free_item;
	poldiff_item_comp_fn_t comp;
	poldiff_new_diff_fn_t new_diff;
	poldiff_deep_diff_fn_t deep_diff;
} poldiff_item_record_t;

static const poldiff_item_record_t item_records[] = {
	{
		"avrule",
		POLDIFF_DIFF_AVRULES,
		poldiff_avrule_get_stats,
		poldiff_get_avrule_vector,
		poldiff_avrule_to_string,
		avrule_get_items,
		avrule_free_item,
		avrule_comp,
		avrule_new_diff,
		avrule_deep_diff,
	},
	{
		"class",
		POLDIFF_DIFF_CLASSES,
		poldiff_class_get_stats,
		poldiff_get_class_vector,
		poldiff_class_to_string,
		class_get_items,
		NULL,
		class_comp,
		class_new_diff,
		class_deep_diff,
	},
	{
		"bool",
		POLDIFF_DIFF_BOOLS,
		poldiff_bool_get_stats,
		poldiff_get_bool_vector,
		poldiff_bool_to_string,
		bool_get_items,
		NULL,
		bool_comp,
		bool_new_diff,
		bool_deep_diff,
	},
	{
		"common",
		POLDIFF_DIFF_COMMONS,
		poldiff_common_get_stats,
		poldiff_get_common_vector,
		poldiff_common_to_string,
		common_get_items,
		NULL,
		common_comp,
		common_new_diff,
		common_deep_diff,
	},
	{
		"role_allow",
		POLDIFF_DIFF_ROLE_ALLOWS,
		poldiff_role_allow_get_stats,
		poldiff_get_role_allow_vector,
		poldiff_role_allow_to_string,
		role_allow_get_items,
		role_allow_free_item,
		role_allow_comp,
		role_allow_new_diff,
		role_allow_deep_diff,
	},
	{
		"role",
		POLDIFF_DIFF_ROLES,
		poldiff_role_get_stats,
		poldiff_get_role_vector,
		poldiff_role_to_string,
		role_get_items,
		NULL,
		role_comp,
		role_new_diff,
		role_deep_diff,
	},
	{
		"user",
		POLDIFF_DIFF_USERS,
		poldiff_user_get_stats,
		poldiff_get_user_vector,
		poldiff_user_to_string,
		user_get_items,
		NULL,
		user_comp,
		user_new_diff,
		user_deep_diff,
	},
	{
		"terule",
		POLDIFF_DIFF_TERULES,
		poldiff_terule_get_stats,
		poldiff_get_terule_vector,
		poldiff_terule_to_string,
		terule_get_items,
		terule_free_item,
		terule_comp,
		terule_new_diff,
		terule_deep_diff,
	},
	{
		"type",
		POLDIFF_DIFF_TYPES,
		poldiff_type_get_stats,
		poldiff_get_type_vector,
		poldiff_type_to_string,
		type_get_items,
		NULL,
		type_comp,
		type_new_diff,
		type_deep_diff,
	},
	{
		"attribute",
		POLDIFF_DIFF_ATTRIBS,
		poldiff_attrib_get_stats,
		poldiff_get_attrib_vector,
		poldiff_attrib_to_string,
		attrib_get_items,
		NULL,
		attrib_comp,
		attrib_new_diff,
		attrib_deep_diff,
	}
};

poldiff_t *poldiff_create(apol_policy_t *orig_policy, apol_policy_t *mod_policy,
				 poldiff_handle_fn_t fn, void *callback_arg)
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

	//TODO: allocate and initialize fields here
	if ((diff->rule_diffs = rule_create()) == NULL ||
	    (diff->bool_diffs = bool_create()) == NULL ||
	    (diff->class_diffs = class_create()) == NULL ||
	    (diff->common_diffs = common_create()) == NULL ||
	    (diff->role_diffs = role_create()) == NULL ||
	    (diff->role_allow_diffs = role_allow_create()) == NULL ||
	    (diff->user_diffs = user_create()) == NULL ||
	    (diff->type_diffs = type_summary_create()) == NULL ||
	    (diff->attrib_diffs = attrib_summary_create()) == NULL){
		ERR(diff, "%s", strerror(ENOMEM));
		poldiff_destroy(&diff);
		errno = ENOMEM;
		return NULL;
	}

	return diff;
}

void poldiff_destroy(poldiff_t **diff)
{
	if (!diff || !(*diff))
		return;
	apol_policy_destroy(&(*diff)->orig_pol);
	apol_policy_destroy(&(*diff)->mod_pol);
	type_map_destroy(&(*diff)->type_map);
	//TODO: free stuff here
	rule_destroy(&(*diff)->rule_diffs);
	bool_destroy(&(*diff)->bool_diffs);
	class_destroy(&(*diff)->class_diffs);
	common_destroy(&(*diff)->common_diffs);
	role_destroy(&(*diff)->role_diffs);
	role_allow_destroy(&(*diff)->role_allow_diffs);
	user_destroy(&(*diff)->user_diffs);
	type_summary_destroy(&(*diff)->type_diffs);
	attrib_summary_destroy(&(*diff)->attrib_diffs);
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
static int poldiff_do_item_diff(poldiff_t *diff, const poldiff_item_record_t *item_record)
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
	for (x = 0, y = 0; x < apol_vector_get_size(p1_v); ) {
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

	apol_vector_destroy(&p1_v, item_record->free_item);
	apol_vector_destroy(&p2_v, item_record->free_item);
	diff->diff_status |= item_record->flag_bit;
	return 0;
err:
	apol_vector_destroy(&p1_v, item_record->free_item);
	apol_vector_destroy(&p2_v, item_record->free_item);
	errno = error;
	return -1;
}

int poldiff_run(poldiff_t *diff, uint32_t flags)
{
	size_t i, num_items;
	int error = 0;

	if (!flags)
		return 0; /* noting to do */

	if (!diff) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (type_map_build(diff)) {
		return -1;
	}

	num_items = sizeof(item_records)/sizeof(poldiff_item_record_t);
	for (i = 0; i < num_items; i++) {
		/* item requested but not yet run */
		if ((flags & item_records[i].flag_bit) && !(item_records[i].flag_bit & diff->diff_status)) {
			INFO(diff, "Running %s diff.", item_records[i].item_name);
			if (poldiff_do_item_diff(diff, &(item_records[i]))) {
				error = errno;
				return -1;
			}
		}
	}

	return 0;
}

int poldiff_get_stats(poldiff_t *diff, uint32_t flags, size_t stats[5])
{
	size_t i, j, num_items, tmp_stats[5] = {0, 0, 0, 0, 0};

	if (!diff || !flags) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	stats[0] = stats[1] = stats[2] = stats[3] = stats[4] = 0;

	num_items = sizeof(item_records)/sizeof(poldiff_item_record_t);
	for (i = 0; i < num_items; i++) {
		if (flags & item_records[i].flag_bit) {
			item_records[i].get_stats(diff, tmp_stats);
			for (j = 0; j < 5; j++)
				stats[j] += tmp_stats[j];
		}
	}

	return 0;
}

static void poldiff_handle_default_callback(void *arg __attribute__((unused)),
					    poldiff_t *p __attribute__ ((unused)),
					    int level,
					    const char *fmt,
					    va_list va_args)
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

void poldiff_handle_msg(poldiff_t *p, int level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (p == NULL || p->fn == NULL) {
		poldiff_handle_default_callback(NULL, NULL, level, fmt, ap);
	}
	else {
		p->fn(p->handle_arg, p, level, fmt, ap);
	}
	va_end(ap);
}
