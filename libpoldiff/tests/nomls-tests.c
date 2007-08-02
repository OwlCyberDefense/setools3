/**
 *  @file
 *
 *  Test the libpoldiff's correctness for MLS versus non-MLS policies.
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
#include "nomls-tests.h"
#include "policy-defs.h"
#include <CUnit/Basic.h>
#include <CUnit/TestDB.h>

#include <poldiff/poldiff.h>
#include <apol/util.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *nomls_unchanged_users[] = {
/* 13.3.17 */
	"placeholder_u",
	"su_u",
	"cyn_u",
	"devona_u",
	"danika_u",
	"mehnlo_u",
	"meloni_u",
	"eve_u",
	"nika_u",
	"koss_u",
	"kihm_u",
	"aidan_u",
	"chiyo_u",
	"reyna_u",
	NULL
};
apol_vector_t *unchanged_users_v;
apol_vector_t *changed_users_v;

char *nomls_changed_users[] = {
/* 13.3.18 */
	"timera_u -admin_r",
	"sheena_u +user_r",
	"jamei_u -aquarium_r",
	NULL
};

int nomls_test_init()
{
	if (!(diff = init_poldiff(NOMLS_ORIG_POLICY, NOMLS_MOD_POLICY))) {
		return 1;
	} else {
		return 0;
	}
}

static void build_nomls_vecs()
{
	const void *item;
	const apol_vector_t *v = NULL;
	size_t i, str_len = 0;
	char *str = NULL;
	v = poldiff_get_user_vector(diff);
	for (i = 0; i < apol_vector_get_size(v); ++i) {
		item = apol_vector_get_element(v, i);
		poldiff_user_t *u = (poldiff_user_t *) item;
		const char *name = poldiff_user_get_name(u);
		const apol_vector_t *added_roles = poldiff_user_get_added_roles(u);
		const apol_vector_t *removed_roles = poldiff_user_get_removed_roles(u);
		if (apol_vector_get_size(added_roles) == 0 && apol_vector_get_size(removed_roles) == 0) {
			apol_vector_append(unchanged_users_v, strdup(name));
		} else {
			char *added_roles_str = vector_to_string(added_roles, "", " +");
			char *removed_roles_str = vector_to_string(removed_roles, "-", " ");
			apol_str_appendf(&str, &str_len, "%s %s%s", name, added_roles_str, removed_roles_str);
			free(added_roles_str);
			free(removed_roles_str);
			apol_str_trim(str);
			apol_vector_append(changed_users_v, str);
			str = NULL;
			str_len = 0;
		}
	}
}
void nomls_tests()
{
	size_t first_diff = 0;
	int test_result;
	unchanged_users_v = apol_vector_create(free);
	changed_users_v = apol_vector_create(free);

	apol_vector_t *correct_unchanged_users_v = string_array_to_vector(nomls_unchanged_users);
	apol_vector_t *correct_changed_users_v = string_array_to_vector(nomls_changed_users);

	build_nomls_vecs();
	apol_vector_sort(unchanged_users_v, compare_str, NULL);
	apol_vector_sort(correct_unchanged_users_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(unchanged_users_v, correct_unchanged_users_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(unchanged_users_v, correct_unchanged_users_v, first_diff, "Unchanged MLS Users");
	}
	apol_vector_sort(changed_users_v, compare_str, NULL);
	apol_vector_sort(correct_changed_users_v, compare_str, NULL);
	CU_ASSERT_FALSE(test_result =
			apol_vector_compare(changed_users_v, correct_changed_users_v, compare_str, NULL, &first_diff));
	if (test_result) {
		print_test_failure(changed_users_v, correct_changed_users_v, first_diff, "Changed MLS Users");
	}
	apol_vector_destroy(&unchanged_users_v);
	apol_vector_destroy(&changed_users_v);
	apol_vector_destroy(&correct_unchanged_users_v);
	apol_vector_destroy(&correct_changed_users_v);

}
