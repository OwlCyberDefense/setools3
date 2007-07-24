/**
 *  @file
 *
 *  Test features of policy version 21, that were introduced in
 *  SETools 3.2.
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
#include <apol/range_trans-query.h>

#define POLICY TEST_POLICIES "/setools-3.2/apol/rangetrans_testing_policy.conf"

static apol_policy_t *p = NULL;

static void policy_21_range_trans_all(void)
{
	apol_range_trans_query_t *rt = apol_range_trans_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
	apol_vector_t *v = NULL;
	int retval = apol_range_trans_get_by_query(p, rt, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 17);
	apol_vector_destroy(&v);
}

static void policy_21_range_trans_process(void)
{
	apol_range_trans_query_t *rt = apol_range_trans_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
	int retval;
	retval = apol_range_trans_query_append_class(p, rt, "process");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	apol_vector_t *v = NULL;
	retval = apol_range_trans_get_by_query(p, rt, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 10);
	size_t i;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_range_trans_t *qrt = (const qpol_range_trans_t *)apol_vector_get_element(v, i);
		const qpol_class_t *c;
		retval = qpol_range_trans_get_target_class(q, qrt, &c);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		const char *class_name;
		retval = qpol_class_get_name(q, c, &class_name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(class_name, "process");
	}
	apol_vector_destroy(&v);
}

static void policy_21_range_trans_lnk_file(void)
{
	apol_range_trans_query_t *rt = apol_range_trans_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
	int retval;
	retval = apol_range_trans_query_append_class(p, rt, "lnk_file");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	apol_vector_t *v = NULL;
	retval = apol_range_trans_get_by_query(p, rt, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 2);
	size_t i;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_range_trans_t *qrt = (const qpol_range_trans_t *)apol_vector_get_element(v, i);
		const qpol_class_t *c;
		retval = qpol_range_trans_get_target_class(q, qrt, &c);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		const char *class_name;
		retval = qpol_class_get_name(q, c, &class_name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT_STRING_EQUAL(class_name, "lnk_file");
	}
	apol_vector_destroy(&v);
}

static void policy_21_range_trans_either(void)
{
	apol_range_trans_query_t *rt = apol_range_trans_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
	int retval;
	retval = apol_range_trans_query_append_class(p, rt, "process");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	retval = apol_range_trans_query_append_class(p, rt, "lnk_file");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	apol_vector_t *v = NULL;
	retval = apol_range_trans_get_by_query(p, rt, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 12);
	size_t i;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_range_trans_t *qrt = (const qpol_range_trans_t *)apol_vector_get_element(v, i);
		const qpol_class_t *c;
		retval = qpol_range_trans_get_target_class(q, qrt, &c);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		const char *class_name;
		retval = qpol_class_get_name(q, c, &class_name);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(strcmp(class_name, "process") == 0 || strcmp(class_name, "lnk_file") == 0);
	}
	apol_vector_destroy(&v);
}

static void policy_21_range_trans_socket(void)
{
	apol_range_trans_query_t *rt = apol_range_trans_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(rt);
	int retval;
	retval = apol_range_trans_query_append_class(p, rt, "socket");
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	apol_vector_t *v = NULL;
	retval = apol_range_trans_get_by_query(p, rt, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);
}

CU_TestInfo policy_21_tests[] = {
	{"range_trans all", policy_21_range_trans_all},
	{"range_trans process", policy_21_range_trans_process},
	{"range_trans lnk_file", policy_21_range_trans_lnk_file},
	{"range_trans process or lnk_file", policy_21_range_trans_either},
	{"range_trans socket", policy_21_range_trans_socket},
	CU_TEST_INFO_NULL
};

int policy_21_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((p = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_RULES, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);
	return 0;
}

int policy_21_cleanup()
{
	apol_policy_destroy(&p);
	return 0;
}
