/**
 *  @file
 *
 *  Test qpol iterators.
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
#include <qpol/policy.h>
#include <stdio.h>

#define SOURCE_POLICY TEST_POLICIES "/snapshots/fc4_targeted.policy.conf"

static qpol_policy_t *qp = NULL;

static void iterators_alias(void)
{
	qpol_iterator_t *iter = NULL;
	CU_ASSERT_FATAL(qpol_policy_get_type_iter(qp, &iter) == 0);
	while (!qpol_iterator_end(iter)) {
		void *v;
		CU_ASSERT_FATAL(qpol_iterator_get_item(iter, &v) == 0);
		qpol_type_t *type = (qpol_type_t *) v;

		qpol_iterator_t *alias_iter = NULL;
		size_t alias_size;
		unsigned char isalias = 0;
		CU_ASSERT_FATAL(qpol_type_get_isalias(qp, type, &isalias) == 0);
		CU_ASSERT_FATAL(qpol_type_get_alias_iter(qp, type, &alias_iter) == 0);
		CU_ASSERT_FATAL(qpol_iterator_get_size(alias_iter, &alias_size) == 0);

		if (alias_size > 0) {
			/* isalias could be 0 or 1, depending upon if
			   type is a primary or an alias */
			CU_ASSERT(!qpol_iterator_end(alias_iter));
		} else {
			/* impossible for isalias to be true if the
			   alias iterator is empty */
			CU_ASSERT(!isalias && qpol_iterator_end(alias_iter));
		}

		qpol_iterator_destroy(&alias_iter);
		CU_ASSERT_FATAL(qpol_iterator_next(iter) == 0);
	}
	qpol_iterator_destroy(&iter);
}

CU_TestInfo iterators_tests[] = {
	{"alias iterator", iterators_alias}
	,
	CU_TEST_INFO_NULL
};

int iterators_init()
{
	int policy_type = qpol_policy_open_from_file(SOURCE_POLICY, &qp, NULL, NULL, QPOL_POLICY_OPTION_NO_RULES);
	if (policy_type < 0) {
		return 1;
	}
	return 0;
}

int iterators_cleanup()
{
	qpol_policy_destroy(&qp);
	return 0;
}
