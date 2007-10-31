/**
 *  @file
 *
 *  Test the user queries.
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
#include <apol/user-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>

#define SOURCE_POLICY TEST_POLICIES "/setools/apol/user_mls_testing_policy.conf"

static apol_policy_t *sp = NULL;
static qpol_policy_t *qp = NULL;

static void user_basic(void)
{
	apol_user_query_t *q = apol_user_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(q);

	apol_vector_t *v = NULL;
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 10);
	apol_vector_destroy(&v);

	apol_user_query_set_role(sp, q, "object_r");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 10);
	apol_vector_destroy(&v);

	apol_user_query_set_user(sp, q, "sys");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	apol_user_query_set_user(sp, q, NULL);
	apol_user_query_set_role(sp, q, "staff_r");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 3);
	bool found_staff = false, found_rick = false, found_simple = false;
	for (size_t i = 0; i < apol_vector_get_size(v); i++) {
		qpol_user_t *u = (qpol_user_t *) apol_vector_get_element(v, i);
		const char *name;
		qpol_user_get_name(qp, u, &name);
		if (strcmp(name, "staff_u") == 0) {
			found_staff = true;
		} else if (strcmp(name, "rick_u") == 0) {
			found_rick = true;
		} else if (strcmp(name, "simple_u") == 0) {
			found_simple = true;
		} else {
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_staff && found_rick && found_simple);
	apol_vector_destroy(&v);

	apol_user_query_set_role(sp, q, "not_in_the_policy_r");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	apol_user_query_destroy(&q);
}

static void user_regex(void)
{
	apol_user_query_t *q = apol_user_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(q);
	apol_user_query_set_regex(sp, q, 1);

	apol_user_query_set_user(sp, q, "*");
	apol_vector_t *v = NULL;
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) < 0 && v == NULL);

	apol_user_query_set_user(sp, q, "st");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 3);
	bool found_staff = false, found_system = false, found_guest = false;
	for (size_t i = 0; i < apol_vector_get_size(v); i++) {
		qpol_user_t *u = (qpol_user_t *) apol_vector_get_element(v, i);
		const char *name;
		qpol_user_get_name(qp, u, &name);
		if (strcmp(name, "staff_u") == 0) {
			found_staff = true;
		} else if (strcmp(name, "system_u") == 0) {
			found_system = true;
		} else if (strcmp(name, "guest_u") == 0) {
			found_guest = true;
		} else {
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_staff && found_system && found_guest);
	apol_vector_destroy(&v);

	apol_user_query_set_user(sp, q, NULL);
	apol_user_query_set_role(sp, q, "user_r");
	CU_ASSERT(apol_user_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 3);
	apol_vector_destroy(&v);

	apol_user_query_destroy(&q);
}

CU_TestInfo user_tests[] = {
	{"basic query", user_basic}
	,
	{"regex query", user_regex}
	,
	CU_TEST_INFO_NULL
};

int user_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	qp = apol_policy_get_qpol(sp);

	return 0;
}

int user_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
