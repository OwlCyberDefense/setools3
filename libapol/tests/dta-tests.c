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
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <apol/domain-trans-analysis.h>

#define POLICY TEST_POLICIES "/setools-3.3/apol/dta_test.policy.conf"

static apol_policy_t *p = NULL;

static void dta_forward(void)
{
	apol_domain_trans_analysis_t *d = apol_domain_trans_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(d);
	int retval = apol_domain_trans_analysis_set_direction(p, d, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_domain_trans_analysis_set_start_type(p, d, "tuna_t");
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_domain_trans_analysis_do(p, d, &v);
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

CU_TestInfo dta_tests[] = {
	{"dta forward", dta_forward}
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
