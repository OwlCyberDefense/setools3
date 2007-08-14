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

#include <vector>
#include <string>
#include <stdexcept>

using std::vector;

static void create_query(void)
{
	polsearch_bool_query *bq = new polsearch_bool_query();
	CU_ASSERT_PTR_NOT_NULL_FATAL(bq);
	polsearch_test & nt = bq->addTest(POLSEARCH_TEST_NAME);
	CU_ASSERT(nt.testCond() == POLSEARCH_TEST_NAME);
	polsearch_criterion & nc = nt.addCriterion(POLSEARCH_OP_MATCH_REGEX);
	CU_ASSERT(nc.op() == POLSEARCH_OP_MATCH_REGEX);
	polsearch_regex_parameter *rxp = new polsearch_regex_parameter("foo");
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

	delete bq;
}

CU_TestInfo bool_query_tests[] = {
	{"create query", create_query},
	CU_TEST_INFO_NULL
};

int bool_query_init()
{
	return 0;
}

int bool_query_cleanup()
{
	return 0;
}
