/**
 *  @file
 *
 *  Test the new domain transition analysis code introduced in SETools
 *  3.3.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#include <CUnit/CUnit.h>
#include <apol/avrule-query.h>
#include <apol/domain-trans-analysis.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>

#define POLICY TEST_POLICIES "/setools-3.3/apol/dta_test.policy.conf"

static apol_policy_t *p = NULL;

static void dta_forward(void)
{
	apol_policy_reset_domain_trans_table(p);
	apol_domain_trans_analysis_t *d = apol_domain_trans_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	int retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_start_type(p, d, "tuna_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_domain_trans_analysis_do(p, d, &v);
	apol_domain_trans_analysis_destroy(&d);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT_PTR_NOT_NULL(v);

	qpol_policy_t *q = apol_policy_get_qpol(p);
	size_t i;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const apol_domain_trans_result_t *dtr = (const apol_domain_trans_result_t *)apol_vector_get_element(v, i);

		const qpol_type_t *qt = apol_domain_trans_result_get_start_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		const char *name, *ep_name;
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "tuna_t");

		qt = apol_domain_trans_result_get_end_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(strcmp(name, "boat_t") == 0 || strcmp(name, "sand_t") == 0);

		qt = apol_domain_trans_result_get_entrypoint_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &ep_name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);

		if (strcmp(name, "boat_t") == 0) {
			CU_ASSERT_STRING_EQUAL(ep_name, "net_t");
		} else if (strcmp(name, "sand_t") == 0) {
			CU_ASSERT(strcmp(ep_name, "reel_t") == 0 || strcmp(ep_name, "wave_t") == 0);
		}
	}

	apol_vector_destroy(&v);
}

static void dta_forward_access(void)
{
	apol_policy_reset_domain_trans_table(p);
	apol_domain_trans_analysis_t *d = apol_domain_trans_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	int retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_start_type(p, d, "tuna_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_access_type(p, d, "boat_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_access_type(p, d, "sand_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_access_type(p, d, "wave_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_class(p, d, "file");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_perm(p, d, "write");
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_domain_trans_analysis_do(p, d, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) > 0);

	qpol_policy_t *q = apol_policy_get_qpol(p);
	size_t i;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const apol_domain_trans_result_t *dtr = (const apol_domain_trans_result_t *)apol_vector_get_element(v, i);

		const qpol_type_t *qt = apol_domain_trans_result_get_start_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		const char *name;
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "tuna_t");

		qt = apol_domain_trans_result_get_end_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "boat_t");

		const apol_vector_t *rules_v = apol_domain_trans_result_get_access_rules(dtr);
		CU_ASSERT_FATAL(rules_v != NULL && apol_vector_get_size(rules_v) > 0);
		size_t j;
		for (j = 0; j < apol_vector_get_size(rules_v); j++) {
			const qpol_avrule_t *qa = (const qpol_avrule_t *)apol_vector_get_element(rules_v, j);
			char *render = apol_avrule_render(p, qa);
			CU_ASSERT_PTR_NOT_NULL_FATAL(render);
			CU_ASSERT_STRING_EQUAL(render, "allow boat_t wave_t : file { write getattr execute };");
			free(render);
		}
	}

	apol_vector_destroy(&v);

	retval = apol_domain_trans_analysis_set_start_type(p, d, "boat_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_access_type(p, d, NULL);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_class(p, d, NULL);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_append_perm(p, d, NULL);
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_policy_reset_domain_trans_table(p);
	retval = apol_domain_trans_analysis_do(p, d, &v);
	apol_domain_trans_analysis_destroy(&d);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) > 0);

	for (i = 0; i < apol_vector_get_size(v); i++) {
		const apol_domain_trans_result_t *dtr = (const apol_domain_trans_result_t *)apol_vector_get_element(v, i);

		const qpol_type_t *qt = apol_domain_trans_result_get_start_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		const char *name;
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "boat_t");

		qt = apol_domain_trans_result_get_end_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(strcmp(name, "sand_t") == 0 || strcmp(name, "dock_t") == 0);
	}
	apol_vector_destroy(&v);
}

static void dta_reverse(void)
{
	apol_policy_reset_domain_trans_table(p);
	apol_domain_trans_analysis_t *d = apol_domain_trans_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	int retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_start_type(p, d, "sand_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_REVERSE);
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_domain_trans_analysis_do(p, d, &v);
	apol_domain_trans_analysis_destroy(&d);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) > 0);

	qpol_policy_t *q = apol_policy_get_qpol(p);
	size_t i;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const apol_domain_trans_result_t *dtr = (const apol_domain_trans_result_t *)apol_vector_get_element(v, i);

		const qpol_type_t *qt = apol_domain_trans_result_get_end_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		const char *name;
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "sand_t");

		qt = apol_domain_trans_result_get_start_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(strcmp(name, "boat_t") == 0 || strcmp(name, "grouper_t") == 0 || strcmp(name, "shark_t") == 0 ||
			  strcmp(name, "tuna_t") == 0);
	}

	apol_vector_destroy(&v);
}

static void dta_reverse_regexp(void)
{
	apol_policy_reset_domain_trans_table(p);
	apol_domain_trans_analysis_t *d = apol_domain_trans_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	int retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_start_type(p, d, "sand_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_REVERSE);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_result_regex(p, d, "u");
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_domain_trans_analysis_do(p, d, &v);
	apol_domain_trans_analysis_destroy(&d);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) > 0);

	qpol_policy_t *q = apol_policy_get_qpol(p);
	size_t i;
	bool found_tuna_wave = false, found_grouper_reel = false, found_grouper_wave = false;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const apol_domain_trans_result_t *dtr = (const apol_domain_trans_result_t *)apol_vector_get_element(v, i);

		const qpol_type_t *qt = apol_domain_trans_result_get_end_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		const char *name, *ep_name;
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(name, "sand_t");

		qt = apol_domain_trans_result_get_start_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(strcmp(name, "tuna_t") == 0 || strcmp(name, "grouper_t") == 0);

		qt = apol_domain_trans_result_get_entrypoint_type(dtr);
		CU_ASSERT_PTR_NOT_NULL(qt);
		retval = qpol_type_get_name(q, qt, &ep_name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);

		if (strcmp(name, "tuna_t") == 0) {
			if (strcmp(ep_name, "wave_t") == 0) {
				found_tuna_wave = true;
			}
		} else if (strcmp(name, "grouper_t") == 0) {
			if (strcmp(ep_name, "reel_t") == 0) {
				found_grouper_reel = true;
			} else if (strcmp(ep_name, "wave_t") == 0) {
				found_grouper_wave = true;
			}
		}
	}
	CU_ASSERT(found_tuna_wave && found_grouper_reel && found_grouper_wave);

	apol_vector_destroy(&v);
}

CU_TestInfo dta_tests[] = {
	{"dta forward", dta_forward}
	,
	{"dta forward + access", dta_forward_access}
	,
	{"dta reverse", dta_reverse}
	,
	{"dta reverse + regexp", dta_reverse_regexp}
	,
	CU_TEST_INFO_NULL
};

int dta_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((p = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	int retval = apol_policy_build_domain_trans_table(p);
	if (retval != 0) {
		return 1;
	}
	return 0;
}

int dta_cleanup()
{
	apol_policy_destroy(&p);
	return 0;
}
