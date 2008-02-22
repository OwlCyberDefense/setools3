/**
 *  @file
 *
 *  Test qpol loading of special types of policies.
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
#include "../src/qpol_internal.h"
#include <stdio.h>

#define BROKEN_ALIAS_POLICY TEST_POLICIES "/setools-3.3/policy-features/broken-alias-mod.21"
#define NOT_BROKEN_ALIAS_POLICY TEST_POLICIES "/setools-3.3/policy-features/not-broken-alias-mod.21"
#define NOGENFS_POLICY TEST_POLICIES "/setools-3.3/policy-features/nogenfscon-policy.21"

static void policy_features_alias_count(void *varg, const qpol_policy_t * policy
					__attribute__ ((unused)), int level, const char *fmt, va_list va_args)
{
	if (level == QPOL_MSG_WARN) {
		int *num_removed_aliases = (int *)varg;
		(*num_removed_aliases)++;
	} else if (level == QPOL_MSG_ERR) {
		fprintf(stderr, "ERROR: ");
		vfprintf(stderr, fmt, va_args);
		fprintf(stderr, "\n");
	}
}

/**
 * If a module has any disabled aliases, test that libqpol removed them.
 */
static void policy_features_invalid_alias(void)
{
	qpol_policy_t *qp = NULL;
	int policy_features_removed_aliases = 0;
	void *v;
	unsigned char isalias = 0;
	const char *name;

	int policy_type = qpol_policy_open_from_file(NOT_BROKEN_ALIAS_POLICY, &qp, policy_features_alias_count,
						     &policy_features_removed_aliases, QPOL_POLICY_OPTION_NO_RULES);
	CU_ASSERT_FATAL(policy_type == QPOL_POLICY_KERNEL_BINARY);
	CU_ASSERT(policy_features_removed_aliases == 0)

	qpol_iterator_t *iter = NULL;
	CU_ASSERT_FATAL(qpol_policy_get_type_iter(qp, &iter) == 0);
	while (!qpol_iterator_end(iter)) {
		CU_ASSERT_FATAL(qpol_iterator_get_item(iter, &v) == 0);
		qpol_type_t *type = (qpol_type_t *) v;
		CU_ASSERT_FATAL(qpol_type_get_isalias(qp, type, &isalias) == 0);
		if (isalias) {
			CU_ASSERT_FATAL(qpol_type_get_name(qp, type, &name) == 0);
			CU_ASSERT_STRING_EQUAL(name, "fs_t");
		}
		CU_ASSERT_FATAL(qpol_iterator_next(iter) == 0);
	}
	qpol_iterator_destroy(&iter);
	qpol_policy_destroy(&qp);

	policy_features_removed_aliases = 0;
	policy_type =
		qpol_policy_open_from_file(BROKEN_ALIAS_POLICY, &qp, policy_features_alias_count, &policy_features_removed_aliases,
					   QPOL_POLICY_OPTION_NO_RULES);
	CU_ASSERT_FATAL(policy_type == QPOL_POLICY_KERNEL_BINARY);
	CU_ASSERT(policy_features_removed_aliases == 1)

		CU_ASSERT_FATAL(qpol_policy_get_type_iter(qp, &iter) == 0);
	while (!qpol_iterator_end(iter)) {
		CU_ASSERT_FATAL(qpol_iterator_get_item(iter, &v) == 0);
		qpol_type_t *type = (qpol_type_t *) v;
		CU_ASSERT_FATAL(qpol_type_get_isalias(qp, type, &isalias) == 0);
		CU_ASSERT(isalias == 0);
		CU_ASSERT_FATAL(qpol_iterator_next(iter) == 0);
	}
	qpol_iterator_destroy(&iter);
	qpol_policy_destroy(&qp);
}

/** Test that getting an iterator of genfscon statements does not
 *  fail if there are no genfscon statements. */
static void policy_features_nogenfscon_iter(void)
{
	qpol_policy_t *qp = NULL;

	/* open a policy with no genfscon statements */
	int policy_type = qpol_policy_open_from_file(NOGENFS_POLICY, &qp, NULL, NULL, QPOL_POLICY_OPTION_NO_RULES);
	CU_ASSERT_FATAL(policy_type == QPOL_POLICY_KERNEL_BINARY);

	qpol_iterator_t *iter = NULL;

	/* iterator should be safe to request but should be at end */
	CU_ASSERT_FATAL(qpol_policy_get_genfscon_iter(qp, &iter) == 0);
	CU_ASSERT(qpol_iterator_end(iter));
	qpol_iterator_destroy(&iter);
	qpol_policy_destroy(&qp);

	/* open a policy with genfscon statements */
	policy_type = qpol_policy_open_from_file(NOT_BROKEN_ALIAS_POLICY, &qp, NULL, NULL, QPOL_POLICY_OPTION_NO_RULES);
	CU_ASSERT_FATAL(policy_type == QPOL_POLICY_KERNEL_BINARY);

	/* iterator should be safe to request and not at end */
	CU_ASSERT_FATAL(qpol_policy_get_genfscon_iter(qp, &iter) == 0);
	CU_ASSERT(!qpol_iterator_end(iter));
	qpol_iterator_destroy(&iter);
	qpol_policy_destroy(&qp);
}

CU_TestInfo policy_features_tests[] = {
	{"invalid alias", policy_features_invalid_alias}
	,
	{"No genfscon", policy_features_nogenfscon_iter}
	,
	CU_TEST_INFO_NULL
};

int policy_features_init()
{
	return 0;
}

int policy_features_cleanup()
{
	return 0;
}
