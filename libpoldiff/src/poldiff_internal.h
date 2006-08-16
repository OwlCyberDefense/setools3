/**
 *  @file poldiff_internal.h
 *  Protected Interface for computing a semantic policy difference.
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

#ifndef POLDIFF_POLDIFF_INTERNAL_H
#define POLDIFF_POLDIFF_INTERNAL_H

#include <apol/policy.h>
#include <apol/vector.h>
#include <poldiff/poldiff.h>

/* forward declarations */
struct poldiff_class_summary;
struct poldiff_common_summary;
struct poldiff_type_summary;
struct poldiff_attrib_summary;
struct poldiff_role_summary;
struct poldiff_user_summary;
struct poldiff_bool_summary;
struct poldiff_cond_summary;
/*struct poldiff_sens_summary;*/
/*struct poldiff_cat_summary;*/
struct poldiff_avrule_summary;
struct poldiff_terule_summary;
struct poldiff_role_allow_summary;
struct poldiff_role_trans_summary;
/*struct range_trans_summary;*/
/* and so forth for ocon_summary structs */

#define POLDIFF_STEP_P1_SORT 1
#define POLDIFF_STEP_P2_SORT 2
#define POLDIFF_STEP_DIFF    3

struct poldiff {
	apol_policy_t *policy1; /* The "original" policy */
	apol_policy_t *policy2; /* The "modified" policy */
	poldiff_handle_fn_t fn;
	void *handle_arg;
	uint32_t diff_status; /* set of POLDIF_DIFF_* for diffs run */
	int diff_step; /* used by do_item_diff one of POLDIFF_STEP_* */
	/* symbol maps ? */
	struct poldiff_class_summary *class_diffs;
	struct poldiff_common_summary *common_diffs;
	struct poldiff_type_summary *type_diffs;
	struct poldiff_attrib_summary *attrib_diffs;
	struct poldiff_role_summary *role_diffs;
	struct poldiff_user_summary *user_diffs;
	struct poldiff_bool_summary *bool_diffs;
	struct poldiff_cond_summary *cond_diffs;
/*	struct poldiff_sens_summary *sens_diffs;*/
/*	struct poldiff_cat_summary *cat_diffs;*/
	struct poldiff_avrule_summary *avrule_diffs;
	struct poldiff_terule_summary *terule_diffs;
	struct poldiff_role_allow_summary *role_allow_diffs;
	struct poldiff_role_trans_summary *role_trans_diffs;
/*	struct poldiff_range_trans_summary *range_trans_diffs;*/
	/* and so forth if we want ocon_diffs */
	apol_vector_t *type_renames;
};

typedef struct poldiff_type_rename poldiff_type_rename_t;

/**
 *  Callback function signature for getting a vector of all
 *  unique items of a given kind in a policy.
 *  @param policy The policy from which to get the items.
 *  @return a newly allocated vector of all unique items
 *  of the appropriate kind on success, or NULL on error;
 *  if the call fails, errno will be set.
 */
typedef apol_vector_t *(*poldiff_get_items_fn_t)(apol_policy_t *policy);

/**
 *  Callback funtion signature for comparing two items
 *  to determine if they are semantically the same item.
 *  @param x The item from the first policy.
 *  @param y The item from the second policy.
 *  @param diff The policy difference structure associated with both
 *  items. Note: due to requirements of apol_vector_sort() this parameter
 *  is passed as a void pointer and must internally be cast to poldiff_t
 *  inside this function.
 *  @return Expected return value from this function is < 0, 0, or > 0
 *  if item x is respectively less than, equal to, or greater than item y.
 *  This must be able to return a defined stable ordering for all items
 *  not semantically equivalent.
 */
typedef int (*poldiff_item_comp_fn_t)(const void *x, const void *y, void *diff);

/**
 *  Callback function signature for creating, initializing and inserting
 *  a new semantic difference entry for an item.
 *  @param diff The policy difference structure to which to add the entry.
 *  @param form The form of the difference.
 *  @param item Item for which the entry is being created.
 *  @return Expected return value from this function is 0 on success and
 *  < 0 on error; if the call fails, it is expected to set errno and to
 *  leave the policy difference structure unchanged.
 */
typedef int (*poldiff_new_diff_fn_t)(poldiff_t *diff, poldiff_form_e form, const void *item);

/**
 *  Callback function signature for computing the semantic difference of
 *  two items for which the compare callback returns 0. This function should
 *  calculate the difference of any properties of the items and if a difference
 *  is found to allocate, initialize, and insert an new semantic difference
 *  entry for that item.
 *  @param diff The policy difference structure associated with both items and
 *  to which to add an entry if needed.
 *  @param x The item from the first policy.
 *  @param y The item from the second policy.
 *  @return Expected return value from this function is 0 on success and
 *  < 0 on error; if the call fails, it is expected to set errno and to
 *  leave the policy difference structure unchanged.
 */
typedef int (*poldiff_deep_diff_fn_t)(poldiff_t *diff, const void *x, const void *y);

/**
 *  Callback function signature for getting an array of statistics for the
 *  number of differences of each form for a given item.
 *  @param diff The policy difference structure from which to get the stats.
 *  @param stats Array into which to write the numbers (array must be
 *  pre-allocated). The order of the values written to the array is as follows:
 *  number of items of form POLDIFF_FORM_ADDED, number of POLDIFF_FORM_REMOVED,
 *  number of POLDIFF_FORM_MODIFIED, number of form POLDIFF_FORM_ADD_TYPE, and
 *  number of POLDIFF_FORM_REMOVE_TYPE.
 *  @return Expected return value from this function is 0 on success and
 *  < 0 on error; if the call fails, it is expected to set errno.
 */
typedef void (*poldiff_get_item_stats_fn_t)(poldiff_t *diff, size_t stats[5]);

/**
 *  Callback function signature for obtaining a string representation of
 *  a difference item.
 *  @param diff The policy difference structure associated with the item.
 *  @param item The item from which to generate the string.
 *  @return Expected return value from this function is a newly allocated
 *  string representation of the item or NULL on error; if the call fails,
 *  it is expected to set errno.
 */
typedef char *(*poldiff_item_to_string_fn_t)(poldiff_t *diff, const void *item);

typedef struct poldiff_item_record {
	const char *item_name;
	uint32_t flag_bit;
	poldiff_get_items_fn_t get_items;
	poldiff_item_comp_fn_t comp;
	poldiff_new_diff_fn_t new_diff;
	poldiff_deep_diff_fn_t deep_diff;
	poldiff_get_item_stats_fn_t get_stats;
	poldiff_item_to_string_fn_t to_string;
} poldiff_item_record_t;

/**
 *  Compute the differences for a particular kind of item.
 *  @param diff The policy difference structure containing the policies to
 *  compare and to populate with the item differences.
 *  @param item_record Item record containg callbacks to perform each step
 *  of the computation for a particular kind of item.
 *  @return 0 on success and < 0 on error; if the call fails; errno will be
 *  set and the only defined operation on the policy difference structure
 *  will be poldiff_destroy().
 */
int poldiff_do_item_diff(poldiff_t *diff, const poldiff_item_record_t *item_record);

#endif /* POLDIFF_POLDIFF_INTERNAL_H */
