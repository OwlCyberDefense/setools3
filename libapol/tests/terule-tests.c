/**
 *  @file
 *
 *  Test the TE rule queries, both semantic and syntactic searches.
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
#include <apol/terule-query.h>
#include <qpol/policy_extend.h>
#include <stdbool.h>

#define BIN_POLICY TEST_POLICIES "/setools-3.3/rules/rules-mls.21"
#define SOURCE_POLICY TEST_POLICIES "/setools-3.3/rules/rules-mls.conf"

static apol_policy_t *bp = NULL;
static apol_policy_t *sp = NULL;

static void terule_basic_syn(void)
{
	apol_terule_query_t *tq = apol_terule_query_create();
	CU_ASSERT_PTR_NOT_NULL_FATAL(tq);

	int retval;
	retval = apol_terule_query_set_rules(sp, tq, QPOL_RULE_TYPE_TRANS | QPOL_RULE_TYPE_CHANGE | QPOL_RULE_TYPE_MEMBER);
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	apol_vector_t *v = NULL;
	retval = apol_syn_terule_get_by_query(sp, tq, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT_PTR_NOT_NULL(v);

	size_t num_trans = 0, num_changes = 0, num_members = 0;

	qpol_policy_t *q = apol_policy_get_qpol(sp);
	size_t i;
	for (i = 0; i < apol_vector_get_size(v); i++) {
		const qpol_syn_terule_t *syn = (const qpol_syn_terule_t *)apol_vector_get_element(v, i);
		uint32_t rule_type;
		retval = qpol_syn_terule_get_rule_type(q, syn, &rule_type);
		CU_ASSERT_EQUAL_FATAL(retval, 0);
		CU_ASSERT(rule_type == QPOL_RULE_TYPE_TRANS || rule_type == QPOL_RULE_TYPE_CHANGE ||
			  rule_type == QPOL_RULE_TYPE_MEMBER);

		if (rule_type == QPOL_RULE_TYPE_TRANS) {
			num_trans++;
		} else if (rule_type == QPOL_RULE_TYPE_CHANGE) {
			num_changes++;
		} else if (rule_type == QPOL_RULE_TYPE_MEMBER) {
			num_members++;
		}
	}
	CU_ASSERT(num_trans == 6 && num_changes == 3 && num_members == 4);
	apol_vector_destroy(&v);

	retval = apol_terule_query_append_class(sp, tq, "cursor");
	CU_ASSERT_EQUAL_FATAL(retval, 0);

	retval = apol_syn_terule_get_by_query(sp, tq, &v);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT(v != NULL && apol_vector_get_size(v) == 0);
	apol_vector_destroy(&v);
	apol_terule_query_destroy(&tq);
}

CU_TestInfo terule_tests[] = {
	{"basic syntactic search", terule_basic_syn}
	,
	CU_TEST_INFO_NULL
};

int terule_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, BIN_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((bp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	if (qpol_policy_build_syn_rule_table(apol_policy_get_qpol(sp)) != 0) {
		return 1;
	}

	return 0;
}

int terule_cleanup()
{
	apol_policy_destroy(&bp);
	apol_policy_destroy(&sp);
	return 0;
}
