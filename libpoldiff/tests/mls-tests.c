/**
 *  @file
 *
 *  Test the libpoldiff's correctness for MLS.
 *
 *  @author Paul Rosenfeld prosenfeld@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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

#include "libpoldiff-tests.h"
#include "mls-tests.h"
#include "policy-defs.h"
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include <poldiff/poldiff.h>
#include <apol/policy.h>
#include <apol/vector.h>
#include <apol/util.h>

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *unchanged_users_mls[] = {
	/* 13.0 */
	"placeholder_u",
	"reyna_u",
	NULL
};

/* these aren't real tests, but the arrays must be declared anyways */
char *added_users_mls[] = { NULL };
char *removed_users_mls[] = { NULL };

/* These strings are always in the same order: added, removed, modified
 *
 * Modified User fields are always in this order:
 * d[...]      represents a change in the default level
 * range[...]
 * roles[...]
 */
char *modified_users_mls[] = {
	/* 13.3.03 */
	"su_u: d[+s2 -s1]",
	/* 13.3.04 */
	"cyn_u: d[s1 +c2] range[*{s1:c1 c2 +c3}]",
	/* 13.3.05 */
	"devona_u: d[s1 -c1]",
	/* 13.3.06 */
	"danika_u: d[s1 +c3 -c1] range[*{s1:c1 c2 +c3}]",
	/* 13.3.07 */
	"mehnlo_u: range[+{s4:c4}]",
	/* 13.3.08 */
	"meloni_u: range[-{s4:c4 c5}]",
	/* 13.3.09 */
	"eve_u: range[+{s6} -{s0}]",
	/* 13.3.10 */
	"nika_u: range[*{s1:c1 c2 +c3} *{s2:c1 c2 c3 +c4}]",
	/* 13.3.11 */
	"koss_u: range[*{s3:c4 -c5} *{s4:c4 -c5} *{s5:c4 -c5}]",
	/* 13.3.12 */
	"kihm_u: range[+{s6:c1 c2 c3 c4 c5 c6} -{s0:c0 c1 c2} *{s1:c1 c2 +c3} *{s2:c1 c2 c3 c4 c5 -c0} *{s3:c1 c4 c5 +c6} *{s5:c1 c2 c3 c4 c5 +c6 -c0}]",
	/* 13.3.13 */
	"aidan_u: range[*{s1:c1 +c3 -c2} *{s2:c1 c3 -c2}]",
	/* 13.3.14 */
	"timera_u: d[+s2 -s1] roles[-admin_r]",
	/* 13.3.15 */
	"sheena_u: range[+{s4:c5} *{s2:+c5} *{s3:+c5}] roles[+user_r]",
	/* 13.3.16 */
	"chiyo_u: d[+s2 -s1] range[+{s4:c5} *{s2:+c5} *{s3:+c5}]",
	/* 13.3.17 -- separate test -- see nomls-tests.c */
	/* 13.3.18 -- separate test -- see nomls-tests.c */

	/* 13.3.19 */
	"jamei_u: d[+s2 -s1] range[+{s4:c5} *{s2:+c5} *{s3:+c5}] roles[-aquarium_r]",
	NULL
};

char *unchanged_rangetrans[] = {
/* 07.0  */
	"range_transition placeholder_t oak_t : file s2",
	NULL
};

char *added_rangetrans[] = {
/* 07.1 */
	"range_transition bear_t stone_t : gc s1",
	"range_transition log_t bear_t : ipc s2",
	"range_transition log_t file_t : fd s1",
	"range_transition rock_t stone_t : dir s3",
	NULL
};
char *removed_rangetrans[] = {

/* 07.2 */
	"range_transition potato_t daikon_t : dir s0:c2",
	"range_transition rock_t stone_t : file s3",
	"range_transition bear_t file_t : msg s1 - s5",
	"range_transition bear_t log_t : msg s1 - s5",
	"range_transition trout_t bear_t : pax s1",
	NULL
};

/* m{...} represents a change in the minimum set of the transition and is always first,
 * the rest of string is in the same order: added, removed, modified*/
char *modified_rangetrans[] = {
/* 07.3.0 */
	"range_transition file_t system_t : process +{s2:c1} ",
/* 07.3.1 */
	"range_transition tiger_t trout_t : node m{+c1 +c2} -{s0:c1 c2}",
/* 07.3.2 */
	"range_transition glass_t log_t : netif +{s6:c1 c2 c3 c4 c5} -{s0:c1 c2} *{s1:c1 c2 +c3}",
/* 07.3.3 */
	"range_transition pine_t holly_t : lnk_file m{+c5} *{s3:c4 +c5}",
/* 07.3.4 */
	"range_transition rock_t finch_t : chr_file m{-c5} *{s3:c4 -c5}",
/* 07.3.5 */
	"range_transition trout_t dirt_t : blk_file m{-c0} *{s2:c1 c2 c3 c4 c5 -c0} *{s3:c1 c4 c5 +c6} *{s5:c1 c2 c3 c4 c5 +c6 -c0}",
/* 07.3.6 */
	"range_transition tiger_t stone_t : sock_file m{+c3} *{s1:c1 c2 +c3}",
/* 07.3.7 */
	"range_transition firefly_t log_t : fd m{+c5}",
/* 07.3.8 */
	"range_transition file_t trout_t : process m{-c2} *{s1:c1 c2 +c3}",
/* 07.3.9 */
	"range_transition pine_t oak_t : lnk_file m{+c5 -c0} *{s2:c1 c2 c3 c4 c5 -c0} *{s5:c1 c2 c3 c4 c5 -c0}",
	NULL
};
char *added_rangetrans_type[] = {
/* 07.4.0 */
	"range_transition pipe_t rock_t : file s3",
/* 07.4.1 */
	"range_transition glass_t pipe_t : process s1",
/* 07.4.2 */
	"range_transition hippo_t file_t : msg s1 - s5",
	"range_transition hippo_t log_t : msg s1 - s5",
	"range_transition pipe_t oak_t : fifo_file s2 - s3:c5",
/* 07.4.3 */
	"range_transition lion_t pipe_t : msg s1 - s5",
	"range_transition pine_t pipe_t : sem s1 - s4:c4.c5",
	"range_transition tiger_t pipe_t : msg s1 - s5",
/* 07.4.4 */
	"range_transition pipe_t acorn_t : file s2",
/* 07.4.5 */
	"range_transition hippo_t pipe_t : msg s1 - s5",
/* needs to be added */
	"range_transition trout_t hippo_t : pax s1",
	NULL
};
char *removed_rangetrans_type[] = {
/* 07.5.0 */
	"range_transition koala_t stone_t : gc s1",
/* 07.5.1 */
	"range_transition log_t koala_t : ipc s2",
/* 07.5.2 */
	"range_transition bass_t bear_t : pax s1",
	"range_transition bass_t lion_t : pax s1",
	"range_transition bass_t log_t : dir s3:c1",
	"range_transition bass_t tiger_t : pax s1",
/* 07.5.3 */
	"range_transition firefly_t bass_t : passwd s2:c1.c5 - s5:c1.c5",
/*	"range_transition trout_t bear_t : pax s1", this rule is "simply removed" so its in the
		normal removed array */
/* 07.5.4 */
	"range_transition bass_t koala_t : shm s0",
/* 07.5.5 is a duplicate of the first rule in 07.5.2 */

	NULL
};

char *unchanged_levels[] = {
/* 06.0 */
	"s4",
	NULL
};
char *added_levels[] = {
/* 06.1 */
	"s6",
	NULL
};
char *removed_levels[] = {
/* 06.2 */
	"s0",
	NULL
};
char *modified_levels[] = {
/* 06.3.0 */
	"s3 +c6",
/* 06.3.1 */
	"s2 -c0",
/* 06.3.2 */
	"s5 +c6 -c0",
/* 06.3.3 */
	"s1 +c3",
	NULL
};

char *unchanged_categories[] = {
	/* 03.0 */
	"c1", "c2", "c3", "c4", "c5",
	NULL
};
char *added_categories[] = {
	/* 03.1 */
	"c6",
	NULL
};
char *removed_categories[] = {
	/* 03.2 */
	"c0",
	NULL
};

char *modified_categories[] = { NULL };

int mls_test_init()
{
	if (!(diff = init_poldiff(MLS_ORIG_POLICY, MLS_MOD_POLICY))) {
		return 1;
	} else {
		return 0;
	}
}

void build_category_vecs()
{
	char *str = NULL;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_cat_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); ++i) {
		item = apol_vector_get_element(v, i);
		const char *name = poldiff_cat_get_name(item);
		str = strdup(name);
		poldiff_form_e form = poldiff_cat_get_form(item);
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		default:
			// can never get here
			assert(0);
		}
		str = NULL;
	}
}

char *level_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	poldiff_level_t *level = (poldiff_level_t *) arg;
	char *str = NULL, *cat = NULL;
	size_t i, str_len = 0;
	const char *name = poldiff_level_get_name(level);
	if (name) {
		apol_str_appendf(&str, &str_len, "%s", name);
		if (show_changes) {
			if (form == POLDIFF_FORM_MODIFIED) {
				const apol_vector_t *added_cats = poldiff_level_get_added_cats(level);
				for (i = 0; i < apol_vector_get_size(added_cats); ++i) {
					cat = apol_vector_get_element(added_cats, i);
					apol_str_appendf(&str, &str_len, " +%s", cat);
				}
				const apol_vector_t *removed_cats = poldiff_level_get_removed_cats(level);
				for (i = 0; i < apol_vector_get_size(removed_cats); ++i) {
					cat = apol_vector_get_element(removed_cats, i);
					apol_str_appendf(&str, &str_len, " -%s", cat);
				}
			}
		}
	}
	if (str)
		apol_str_trim(str);
	return str;
}

char *modified_mls_range_to_string(const poldiff_range_t * range)
{
	char *str = NULL;
	apol_vector_t *levels = NULL;
	if (!(levels = poldiff_range_get_levels(range)))
		goto err;
	size_t i, str_len = 0;
	char *min_set_str = NULL;
	size_t min_set_str_len = 0;

	apol_vector_t *min_set_added = poldiff_range_get_min_added_cats(range);
	apol_vector_t *min_set_removed = poldiff_range_get_min_removed_cats(range);
	size_t num_min_added = apol_vector_get_size(min_set_added);
	size_t num_min_removed = apol_vector_get_size(min_set_removed);
	if (min_set_added && num_min_added > 0) {
		char *min_set_added_str = vector_to_string(min_set_added, "", " +");
		apol_str_appendf(&min_set_str, &min_set_str_len, "%s", min_set_added_str);
		free(min_set_added_str);
	}
	if (min_set_removed && num_min_removed > 0) {
		char *min_set_removed_str = vector_to_string(min_set_removed, "", " -");
		apol_str_appendf(&min_set_str, &min_set_str_len, "%s%s", num_min_added > 0 ? " " : "", min_set_removed_str);
		free(min_set_removed_str);
	}
	if (num_min_added || num_min_removed) {
		char *tmp = strdup(min_set_str);
		free(min_set_str);
		min_set_str = NULL;
		min_set_str_len = 0;
		apol_str_appendf(&min_set_str, &min_set_str_len, "m{%s} ", tmp);
		free(tmp);
	}
	if (min_set_str) {
		apol_str_appendf(&str, &str_len, "%s", min_set_str);
		free(min_set_str);
	}

	for (i = 0; i < apol_vector_get_size(levels); ++i) {
		poldiff_level_t *level = apol_vector_get_element(levels, i);
		poldiff_form_e form = poldiff_level_get_form(level);
		const char *level_str = poldiff_level_get_name(level);
		char *sep = NULL, *add_sep = " +", *remove_sep = " -";
		switch (form) {
		case POLDIFF_FORM_ADDED:
			sep = "+";
			add_sep = " ";
			break;
		case POLDIFF_FORM_REMOVED:
			sep = "-";
			remove_sep = " ";
			break;
		case POLDIFF_FORM_MODIFIED:
			sep = "*";
			break;
		default:
			// should never get here
			assert(0);
		}
		const apol_vector_t *unmod_cats = poldiff_level_get_unmodified_cats(level);
		const apol_vector_t *added_cats = poldiff_level_get_added_cats(level);
		const apol_vector_t *removed_cats = poldiff_level_get_removed_cats(level);
		size_t num_unmod_cats = apol_vector_get_size(unmod_cats);
		size_t num_added_cats = apol_vector_get_size(added_cats);
		size_t num_removed_cats = apol_vector_get_size(removed_cats);
		size_t num_cats = num_unmod_cats + num_added_cats + num_removed_cats;
		char *unmod_cats_str = vector_to_string(unmod_cats, "", " ");
		char *added_cats_str = vector_to_string(added_cats, num_unmod_cats > 0 ? " " : "", add_sep);
		char *removed_cats_str = vector_to_string(removed_cats, num_added_cats > 0 ||
							  num_unmod_cats > 0 ? " " : "", remove_sep);
		apol_str_appendf(&str, &str_len, "%s{%s%s%s%s%s} ", sep, level_str, num_cats > 0 ? ":" : "", unmod_cats_str,
				 added_cats_str, removed_cats_str);
		free(unmod_cats_str);
		free(added_cats_str);
		free(removed_cats_str);
	}
	apol_str_trim(str);
	return str;
      err:
	return NULL;
}

char *rangetrans_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	char *str = NULL;
	size_t str_len = 0;
	poldiff_range_trans_t *rt = (poldiff_range_trans_t *) arg;
	const poldiff_range_t *range = poldiff_range_trans_get_range(rt);
	const apol_mls_range_t *mod_range = poldiff_range_get_modified_range(range);
	const apol_mls_range_t *orig_range = poldiff_range_get_original_range(range);
	char *range_str = NULL;
	switch (form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
		range_str = apol_mls_range_render(mod_policy, mod_range);
		break;
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
		range_str = apol_mls_range_render(orig_policy, orig_range);
		break;
	case POLDIFF_FORM_MODIFIED:
		range_str = modified_mls_range_to_string(range);
		break;
	default:
		// should never get here
		assert(0);
	}
	const char *source_type = poldiff_range_trans_get_source_type(rt);
	const char *target_type = poldiff_range_trans_get_target_type(rt);
	const char *target_class = poldiff_range_trans_get_target_class(rt);
	if (show_changes) {
		apol_str_appendf(&str, &str_len, "range_transition %s %s : %s %s", source_type, target_type, target_class,
				 range_str);
	} else {
		apol_str_appendf(&str, &str_len, "range_transition %s %s : %s", source_type, target_type, target_class);
	}
	free(range_str);
	return str;
}

void build_rangetrans_vecs()
{
	apol_vector_t *added_rangetrans_type_v = apol_vector_create(free);
	apol_vector_t *removed_rangetrans_type_v = apol_vector_create(free);
	apol_vector_t *correct_added_rangetrans_type_v = string_array_to_vector(added_rangetrans_type);
	apol_vector_t *correct_removed_rangetrans_type_v = string_array_to_vector(removed_rangetrans_type);

	char *str = NULL, *name_only = NULL;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_range_trans_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); ++i) {
		item = apol_vector_get_element(v, i);
		poldiff_form_e form = poldiff_range_trans_get_form(item);
		str = rangetrans_to_string(item, form, 1);
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_ADD_TYPE:
			apol_vector_append(added_rangetrans_type_v, str);
			break;
		case POLDIFF_FORM_REMOVE_TYPE:
			apol_vector_append(removed_rangetrans_type_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = rangetrans_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
	int test_result;
	size_t first_diff = 0;
	apol_vector_sort(added_rangetrans_type_v, compare_str, NULL);
	apol_vector_sort(correct_added_rangetrans_type_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(added_rangetrans_type_v, correct_added_rangetrans_type_v, compare_str, NULL,
					    &first_diff));
	if (test_result) {
		print_test_failure(added_rangetrans_type_v, correct_added_rangetrans_type_v, first_diff, "Added Due to Types");
	}
	apol_vector_sort(removed_rangetrans_type_v, compare_str, NULL);
	apol_vector_sort(correct_removed_rangetrans_type_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(removed_rangetrans_type_v, correct_removed_rangetrans_type_v, compare_str, NULL,
					    &first_diff));
	if (test_result) {
		print_test_failure(removed_rangetrans_type_v, correct_removed_rangetrans_type_v, first_diff,
				   "Removed Due to Types");
	}
	apol_vector_destroy(&added_rangetrans_type_v);
	apol_vector_destroy(&correct_added_rangetrans_type_v);
	apol_vector_destroy(&removed_rangetrans_type_v);
	apol_vector_destroy(&correct_removed_rangetrans_type_v);

}

void build_level_vecs()
{
	char *str = NULL, *name_only = NULL;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_level_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); ++i) {
		item = apol_vector_get_element(v, i);
		poldiff_form_e form = poldiff_cat_get_form(item);
		str = level_to_string(item, form, 1);
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = level_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
	}
}

char *mls_user_to_string(const void *arg, poldiff_form_e form, int show_changes)
{
	poldiff_user_t *u = (poldiff_user_t *) arg;
	char *str = NULL, *dlevel_str = NULL, *range_str = NULL, *roles_str = NULL;
	size_t str_len = 0, dlevel_str_len = 0, range_str_len = 0, roles_str_len = 0;
	const poldiff_range_t *range = poldiff_user_get_range(u);
	const poldiff_level_t *orig_level = poldiff_user_get_original_dfltlevel(u);
	const poldiff_level_t *mod_level = poldiff_user_get_modified_dfltlevel(u);
	poldiff_form_e orig_form = poldiff_level_get_form(orig_level);
	poldiff_form_e mod_form = poldiff_level_get_form(mod_level);
	char *orig_level_str = level_to_string(orig_level, orig_form, 1);
	char *mod_level_str = level_to_string(mod_level, mod_form, 1);
	//change of default sensitivity
	if (mod_level_str && orig_level_str) {
		apol_str_appendf(&dlevel_str, &dlevel_str_len, "d[+%s -%s] ", mod_level_str, orig_level_str);
	}
	//change of default category within a sensitivity
	else if (!mod_level_str && orig_level_str) {
		apol_str_appendf(&dlevel_str, &dlevel_str_len, "d[%s] ", orig_level_str);
	} else if (!orig_level_str && mod_level_str) {
		//this should never happen
		CU_ASSERT_FALSE(1);
	}
	if ((range_str = modified_mls_range_to_string(range)) != NULL) {
		char *tmp = strdup(range_str);
		free(range_str);
		range_str = NULL;
		range_str_len = 0;
		apol_str_appendf(&range_str, &range_str_len, "range[%s] ", tmp);
		free(tmp);
	}
	char *added_roles_str = vector_to_string(poldiff_user_get_added_roles(u), "", " +");
	char *removed_roles_str = vector_to_string(poldiff_user_get_removed_roles(u), "", " -");
	if (strlen(added_roles_str) > 0 || strlen(removed_roles_str) > 0) {
		apol_str_appendf(&roles_str, &roles_str_len, "roles[%s%s] ", added_roles_str ? added_roles_str : "",
				 removed_roles_str ? removed_roles_str : "");
	}
	const char *user_name = poldiff_user_get_name(u);
	if (show_changes) {
		apol_str_appendf(&str, &str_len, "%s: %s%s%s", user_name, dlevel_str ? dlevel_str : "", range_str ? range_str : "",
				 roles_str ? roles_str : "");
	} else {
		apol_str_appendf(&str, &str_len, "%s", user_name);
	}

	free(range_str);
	free(roles_str);
	free(dlevel_str);
	free(mod_level_str);
	free(orig_level_str);
	free(added_roles_str);
	free(removed_roles_str);
	return str;
}

void build_user_vecs()
{
	char *str = NULL, *name_only;
	size_t i;
	const void *item = NULL;
	const apol_vector_t *v = NULL;
	v = poldiff_get_user_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); ++i) {
		item = apol_vector_get_element(v, i);
		poldiff_form_e form = poldiff_cat_get_form(item);
		str = mls_user_to_string(item, form, 1);
		switch (form) {
		case POLDIFF_FORM_ADDED:
			apol_vector_append(added_v, str);
			break;
		case POLDIFF_FORM_REMOVED:
			apol_vector_append(removed_v, str);
			break;
		case POLDIFF_FORM_MODIFIED:
			name_only = mls_user_to_string(item, form, 0);
			apol_vector_append(modified_name_only_v, name_only);
			apol_vector_append(modified_v, str);
			break;
		default:
			// should never get here
			assert(0);
		}
		str = NULL;
	}
}

void mls_category_tests()
{
	test_numbers_e test_num = MLS_CATEGORY;
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_categories, removed_categories, unchanged_categories, modified_categories);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void mls_rangetrans_tests()
{
	test_numbers_e test_num = MLS_RANGETRANS;
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_rangetrans, removed_rangetrans, unchanged_rangetrans, modified_rangetrans);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void mls_level_tests()
{
	test_numbers_e test_num = MLS_LEVEL;
	poldiff_test_answers_t *answers = init_answer_vectors(added_levels, removed_levels, unchanged_levels, modified_levels);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}

void mls_user_tests()
{
	test_numbers_e test_num = MLS_USER;
	poldiff_test_answers_t *answers =
		init_answer_vectors(added_users_mls, removed_users_mls, unchanged_users_mls, modified_users_mls);
	run_test(NULL, answers, test_num);
	cleanup_test(answers);
}
