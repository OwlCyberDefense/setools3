/**
 *  @file
 *
 *  Test the role queries.
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
#include <apol/role-query.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>

#define SOURCE_POLICY TEST_POLICIES "/setools/apol/role_dom.conf"

static apol_policy_t *sp = NULL;
static qpol_policy_t *qp = NULL;

static void role_basic(void)
{
	apol_role_query_t *q = apol_role_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(q);

	apol_vector_t *v = NULL;
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 26);
	apol_vector_destroy(&v);

	apol_role_query_set_role(sp, q, "sh");
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	apol_role_query_set_role(sp, q, NULL);
	apol_role_query_set_type(sp, q, "silly_t");
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 2);
	bool found_silly = false, found_object = false;
	for (size_t i = 0; i < apol_vector_get_size(v); i++) {
		qpol_role_t *r = (qpol_role_t *) apol_vector_get_element(v, i);
		const char *name;
		qpol_role_get_name(qp, r, &name);
		if (strcmp(name, "silly_r") == 0) {
			found_silly = true;
		} else if (strcmp(name, "object_r") == 0) {
			found_object = true;
		} else {
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_silly && found_object);
	apol_vector_destroy(&v);

	apol_role_query_set_type(sp, q, "not_in_the_policy_t");
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);

	apol_role_query_destroy(&q);
}

static void role_regex(void)
{
	apol_role_query_t *q = apol_role_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(q);
	apol_role_query_set_regex(sp, q, 1);

	apol_role_query_set_role(sp, q, "*");
	apol_vector_t *v = NULL;
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) < 0 && v == NULL);

	apol_role_query_set_role(sp, q, "^sh");
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 2);
	bool found_shirt = false, found_shoe = false;
	for (size_t i = 0; i < apol_vector_get_size(v); i++) {
		qpol_role_t *r = (qpol_role_t *) apol_vector_get_element(v, i);
		const char *name;
		qpol_role_get_name(qp, r, &name);
		if (strcmp(name, "shirt_r") == 0) {
			found_shirt = true;
		} else if (strcmp(name, "shoe_r") == 0) {
			found_shoe = true;
		} else {
			CU_ASSERT(0);
		}
	}
	CU_ASSERT(found_shirt && found_shoe);
	apol_vector_destroy(&v);

	apol_role_query_set_role(sp, q, NULL);
	apol_role_query_set_type(sp, q, "file");
	CU_ASSERT(apol_role_get_by_query(sp, q, &v) == 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 1);
	qpol_role_t *r = (qpol_role_t *) apol_vector_get_element(v, 0);
	const char *name;
	qpol_role_get_name(qp, r, &name);
	CU_ASSERT_STRING_EQUAL(name, "object_r");
	apol_vector_destroy(&v);

	apol_role_query_destroy(&q);
}

CU_TestInfo role_tests[] = {
	{"basic query", role_basic}
	,
	{"regex query", role_regex}
	,
	CU_TEST_INFO_NULL
};

int role_init()
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

int role_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
