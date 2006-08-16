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

#include <poldiff/poldiff.h>
#include <poldiff/class_diff.h>
#include "poldiff_internal.h"

#include <apol/vector.h>

#include <errno.h>

const poldiff_item_record_t item_records[] = {
/* TODO
{
		"class",
		POLDIFF_DIFF_CLASSES,
		poldiff_class_get_classes,
		poldiff_class_comp,
		poldiff_class_new,
		poldiff_class_deep_diff,
		poldiff_class_get_stats,
		poldiff_class_to_string
	},
	{
		"common",
		POLDIFF_DIFF_COMMONS,
		poldiff_common_get_classes,
		poldiff_common_comp,
		poldiff_common_new,
		poldiff_common_deep_diff,
		poldiff_common_get_stats,
		poldiff_common_to_string
}*/
};

poldiff_t *poldiff_create(apol_policy_t *policy1, apol_policy_t *policy2,
				 poldiff_handle_fn_t fn, void *callback_arg)
{
	poldiff_t *diff = NULL;

	if (!policy1 || !policy2) {
		//TODO: error reporting
		errno = EINVAL;
		return NULL;
	}

	if (!(diff = calloc(1, sizeof(poldiff_t)))) {
		//TODO: ERR();
		errno = EINVAL;
		return NULL;
	}

	//TODO: allocate and initialize fields here

	return diff;
}

void poldiff_destroy(poldiff_t **diff)
{
	if (!diff || !(*diff))
		return;

	//TODO: free stuff here
	free(*diff);
	*diff = NULL;
}

int poldiff_run(poldiff_t *diff, uint32_t flags)
{
	size_t i, num_items;
	int error = 0;

	if (!flags)
		return 0; /* noting to do */

	if (!diff) {
		//TODO ERR();
		errno = EINVAL;
		return -1;
	}

	num_items = sizeof(item_records)/sizeof(poldiff_item_record_t);
	for (i = 0; i < num_items; i++) {
		/* item requested but not yet run */
		if (flags & item_records[i].flag_bit && !(flags & diff->diff_status)) {
			if (poldiff_do_item_diff(diff, &(item_records[i]))) {
				error = errno;
				//TODO ERR();
				return -1;
			}
		}
	}

	return 0;
}

int poldiff_do_item_diff(poldiff_t *diff, const poldiff_item_record_t *item_record)
{
	apol_vector_t *p1_v = NULL, *p2_v = NULL;
	int error = 0, retv;
	size_t x = 0, y = 0;
	void *item_x = NULL, *item_y = NULL;

	if (!diff || !item_record) {
		//TODO ERR();
		errno = EINVAL;
		return -1;
	}

	diff->diff_step = POLDIFF_STEP_P1_SORT;
	p1_v = item_record->get_items(diff->policy1);
	if (!p1_v) {
		error = errno;
		//TODO ERR();
		goto err;
	}
	apol_vector_sort(p1_v, item_record->comp, (void*)diff);

	diff->diff_step = POLDIFF_STEP_P2_SORT;
	p2_v = item_record->get_items(diff->policy2);
	if (!p2_v) {
		error = errno;
		//TODO ERR();
		goto err;
	}
	apol_vector_sort(p2_v, item_record->comp, (void*)diff);

	diff->diff_step = POLDIFF_STEP_DIFF;
	for (x = 0, y = 0; x < apol_vector_get_size(p1_v); x++) {
		if (y >= apol_vector_get_size(p2_v))
			break;
		if (!(item_x = apol_vector_get_element(p1_v, x)) || !(item_y = apol_vector_get_element(p2_v, y))) {
			error = errno;
			//TODO ERR();
			goto err;
		}
		retv = item_record->comp(item_x, item_y, (void*)diff);
		if (retv < 0) {
			if (item_record->new_diff(diff, POLDIFF_FORM_REMOVED, item_x)) {
				error = errno;
				//TODO ERR();
				goto err;
			}
		} else if (retv > 0) {
			if (item_record->new_diff(diff, POLDIFF_FORM_ADDED, item_y)) {
				error = errno;
				//TODO ERR();
				goto err;
			}
			y++;
		} else {
			if (item_record->deep_diff(diff, item_x, item_y)) {
				error = errno;
				//TODO ERR();
				goto err;
			}
			y++;
		}
		for (; x < apol_vector_get_size(p1_v); x++) {
			if (!(item_x = apol_vector_get_element(p1_v, x))) {
				error = errno;
				//TODO ERR();
				goto err;
			}
			if (item_record->new_diff(diff, POLDIFF_FORM_REMOVED, item_x)) {
				error = errno;
				//TODO ERR();
				goto err;
			}
		}
		for (; y < apol_vector_get_size(p2_v); y++) {
			if (!(item_y = apol_vector_get_element(p2_v, y))) {
				error = errno;
				//TODO ERR();
				goto err;
			}
			if (item_record->new_diff(diff, POLDIFF_FORM_ADDED, item_y)) {
				error = errno;
				//TODO ERR();
				goto err;
			}
		}
	}
	return 0;

err:
	errno = error;
	return -1;
}
