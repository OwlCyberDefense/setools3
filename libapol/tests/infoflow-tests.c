/**
 *  @file
 *
 *  Test the information flow analysis code.
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
#include <apol/infoflow-analysis.h>
#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>
#include <string.h>

#define BIG_POLICY TEST_POLICIES "/snapshots/fc4_targeted.policy.conf"
#define PERMMAP TOP_SRCDIR "/apol/perm_maps/apol_perm_mapping_ver19"

static apol_policy_t *p = NULL;

static void infoflow_direct_overview(void)
{
	apol_infoflow_analysis_t *ia = apol_infoflow_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(ia);
	int retval;
	retval = apol_infoflow_analysis_set_mode(p, ia, APOL_INFOFLOW_MODE_DIRECT);
	CU_ASSERT(retval == 0);
	retval = apol_infoflow_analysis_set_dir(p, ia, APOL_INFOFLOW_IN);
	CU_ASSERT(retval == 0);
	retval = apol_infoflow_analysis_set_type(p, ia, "agp_device_t");
	CU_ASSERT(retval == 0);

	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	// no permmap loaded, so analysis run will abort with error
	retval = apol_infoflow_analysis_do(p, ia, &v, &g);
	CU_ASSERT(retval < 0);

	retval = apol_policy_open_permmap(p, PERMMAP);
	CU_ASSERT(retval == 0);

	retval = apol_infoflow_analysis_do(p, ia, &v, &g);
	CU_ASSERT(retval == 0);
	CU_ASSERT_PTR_NOT_NULL(v);
	CU_ASSERT(apol_vector_get_size(v) > 0);
	CU_ASSERT_PTR_NOT_NULL(g);

	apol_infoflow_analysis_destroy(&ia);
	apol_vector_destroy(&v);
	apol_infoflow_graph_destroy(&g);
}

static void infoflow_trans_overview(void)
{
	apol_infoflow_analysis_t *ia = apol_infoflow_analysis_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(ia);
	int retval;
	retval = apol_infoflow_analysis_set_mode(p, ia, APOL_INFOFLOW_MODE_DIRECT);
	CU_ASSERT(retval == 0);
	retval = apol_infoflow_analysis_set_dir(p, ia, APOL_INFOFLOW_IN);
	CU_ASSERT(retval == 0);
	retval = apol_infoflow_analysis_set_type(p, ia, "local_login_t");
	CU_ASSERT(retval == 0);

	apol_vector_t *v = NULL;
	apol_infoflow_graph_t *g = NULL;
	// permmap was loaded by infoflow_direct_overview()
	retval = apol_infoflow_analysis_do(p, ia, &v, &g);
	CU_ASSERT(retval == 0);
	CU_ASSERT_PTR_NOT_NULL(v);
	CU_ASSERT(apol_vector_get_size(v) > 0);
	CU_ASSERT_PTR_NOT_NULL(g);

	apol_infoflow_analysis_destroy(&ia);
	apol_vector_destroy(&v);
	apol_infoflow_graph_destroy(&g);
}

CU_TestInfo infoflow_tests[] = {
	{"infoflow direct overview", infoflow_direct_overview}
	,
	{"infoflow trans overview", infoflow_trans_overview}
	,
	CU_TEST_INFO_NULL
};

int infoflow_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, BIG_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((p = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int infoflow_cleanup()
{
	apol_policy_destroy(&p);
	return 0;
}
