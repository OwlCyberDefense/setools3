/**
 *  @file
 *
 *  Test boolean querying, introduced in SETools 3.4.
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

#include <polsearch/bool_query.hh>
#include <polsearch/test.hh>
#include <polsearch/criterion.hh>
#include <polsearch/regex_parameter.hh>
#include <polsearch/bool_parameter.hh>
#include <polsearch/result.hh>
#include <polsearch/proof.hh>

#include <vector>
#include <string>
#include <stdexcept>

#include <apol/policy.h>
#include <apol/policy-path.h>

using std::vector;
using std::string;

#define SOURCE_POLICY TEST_POLICIES "setools-3.0/apol/conditionals_testing_policy.conf"

static apol_policy_t *sp;

static void create_query(void)
{
	polsearch_bool_query *bq = new polsearch_bool_query(POLSEARCH_MATCH_ALL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bq);
	CU_ASSERT(bq->match() == POLSEARCH_MATCH_ALL);
	polsearch_test & nt = bq->addTest(POLSEARCH_TEST_NAME);
	CU_ASSERT(nt.testCond() == POLSEARCH_TEST_NAME);
	polsearch_criterion & nc = nt.addCriterion(POLSEARCH_OP_MATCH_REGEX);
	CU_ASSERT(nc.op() == POLSEARCH_OP_MATCH_REGEX);
	polsearch_regex_parameter *rxp = new polsearch_regex_parameter("^[a-m]");
	CU_ASSERT_PTR_NOT_NULL_FATAL(rxp);
	nc.param(rxp);
	CU_ASSERT(nt.isContinueable() == false);
	vector < polsearch_test_cond_e > valid = bq->getValidTests();
	CU_ASSERT(valid.size() == 2);
	polsearch_test & st = bq->addTest(POLSEARCH_TEST_STATE);
	CU_ASSERT(st.testCond() == POLSEARCH_TEST_STATE);
	polsearch_criterion & sc = st.addCriterion(POLSEARCH_OP_IS);
	CU_ASSERT(sc.op() == POLSEARCH_OP_IS);
	CU_ASSERT(sc.negated(true));
	polsearch_bool_parameter *bp = new polsearch_bool_parameter(true);
	CU_ASSERT_PTR_NOT_NULL_FATAL(bp);
	sc.param(bp);
	CU_ASSERT(bp == sc.param());

	vector < polsearch_result > res_v = bq->run(sp, NULL);
	CU_ASSERT(!res_v.empty());
	CU_ASSERT(res_v.size() == 3);
	//results should be ben_b claire_b jack_b
	for (vector < polsearch_result >::const_iterator i = res_v.begin(); i != res_v.end(); i++)
	{
		CU_ASSERT(i->proof().size() == 2);
		CU_ASSERT(i->proof()[0].testCond() == POLSEARCH_TEST_NAME || i->proof()[0].testCond() == POLSEARCH_TEST_STATE);
		CU_ASSERT(i->proof()[1].testCond() == POLSEARCH_TEST_NAME || i->proof()[1].testCond() == POLSEARCH_TEST_STATE);
		CU_ASSERT(i->proof()[0].testCond() != i->proof()[1].testCond());
		const polsearch_proof *pr = &(i->proof()[0]);
		if (pr->testCond() != POLSEARCH_TEST_NAME)
			pr = &(i->proof()[1]);
		string name(static_cast < const char *>(pr->element()));
		CU_ASSERT(name == "ben_b" || name == "claire_b" || name == "jack_b");
	}
	delete bq;
}

CU_TestInfo bool_query_tests[] = {
	{"create query", create_query},
	CU_TEST_INFO_NULL
};

int bool_query_init()
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, SOURCE_POLICY, NULL);
	if (ppath == NULL)
	{
		return 1;
	}

	if ((sp = apol_policy_create_from_policy_path(ppath, 0, NULL, NULL)) == NULL)
	{
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int bool_query_cleanup()
{
	apol_policy_destroy(&sp);
	return 0;
}
