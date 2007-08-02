/**
 *  @file
 *
 *  Header for for CUnit testing framework of libpoldiff's correctness.
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

#ifndef LIBPOLDIFF_TESTS
#define LIBPOLDIFF_TESTS

#include <poldiff/poldiff.h>
#include <apol/vector.h>

typedef const apol_vector_t *(*poldiff_get_diff_vector) (const poldiff_t *);
typedef const char *(*poldiff_get_name) (const void *);
typedef poldiff_form_e(*poldiff_get_form) (const void *);
typedef const apol_vector_t *(*poldiff_get_added) (const void *);
typedef const apol_vector_t *(*poldiff_get_removed) (const void *);

typedef struct _test_answers
{
	apol_vector_t *correct_added_v;
	apol_vector_t *correct_removed_v;
	apol_vector_t *correct_unchanged_v;
	apol_vector_t *correct_modified_v;
} poldiff_test_answers_t;

typedef struct _component_funcs
{
	poldiff_get_diff_vector get_diff_vector;
	poldiff_get_name get_name;
	poldiff_get_form get_form;
	poldiff_get_added get_added;
	poldiff_get_removed get_removed;
} component_funcs_t;

typedef enum _test_numbers
{
	COMPONENT = 0, RULES_AVRULE, RULES_TERULE, RULES_ROLEALLOW, RULES_ROLETRANS,
	MLS_CATEGORY, MLS_LEVEL, MLS_RANGETRANS, MLS_USER
} test_numbers_e;

poldiff_t *init_poldiff(char *orig_base_path, char *mod_base_path);
component_funcs_t *init_test_funcs(poldiff_get_diff_vector, poldiff_get_name, poldiff_get_form, poldiff_get_added,
				   poldiff_get_removed);
void run_test(component_funcs_t *, poldiff_test_answers_t *, test_numbers_e);

apol_vector_t *string_array_to_vector(char *[]);
void cleanup_test(poldiff_test_answers_t *);
char *vector_to_string(const apol_vector_t *, const char *, const char *);

int compare_str(const void *s1, const void *s2, void *debug);
poldiff_test_answers_t *init_answer_vectors(char *[], char *[], char *[], char *[]);
void print_test_failure(apol_vector_t *, apol_vector_t *, size_t, const char *);

apol_vector_t *shallow_copy_str_vec_and_sort(const apol_vector_t * v);

poldiff_t *diff;

apol_policy_t *orig_policy;
apol_policy_t *mod_policy;

apol_vector_t *added_v;
apol_vector_t *removed_v;
apol_vector_t *modified_v;
apol_vector_t *modified_name_only_v;

#endif
