/**
 *  @file
 *
 *  Test policy loading capabilities that were introduced in SETools
 *  3.2.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007-2008 Tresys Technology, LLC
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

#include <stdbool.h>

#define POLICY_ROOT TEST_POLICIES "/policy-versions"

struct capability_answer
{
	const char *policy_name;
	int policy_type;
	unsigned int policy_version;
	bool has_attributes;
	bool has_syn_rules;
	bool has_line_numbers;
	bool has_conditionals;
	bool has_mls;
	bool has_polcaps;
	bool has_source;
	bool has_modules;
};

static void capability_test(const struct capability_answer *ca)
{
	qpol_policy_t *q = NULL;
	int policy_type = qpol_policy_open_from_file(ca->policy_name, &q, NULL, NULL, QPOL_POLICY_OPTION_NO_NEVERALLOWS);
	CU_ASSERT_FATAL(policy_type >= 0);
	CU_ASSERT_EQUAL(policy_type, ca->policy_type);

	unsigned policy_version;
	int retval;
	retval = qpol_policy_get_policy_version(q, &policy_version);
	CU_ASSERT_EQUAL_FATAL(retval, 0);
	CU_ASSERT_EQUAL(policy_version, ca->policy_version);

	bool cap;

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_ATTRIB_NAMES);
	CU_ASSERT_EQUAL(cap, ca->has_attributes);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_SYN_RULES);
	CU_ASSERT_EQUAL(cap, ca->has_syn_rules);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_LINE_NUMBERS);
	CU_ASSERT_EQUAL(cap, ca->has_line_numbers);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_CONDITIONALS);
	CU_ASSERT_EQUAL(cap, ca->has_conditionals);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_MLS);
	CU_ASSERT_EQUAL(cap, ca->has_mls);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_POLCAPS);
	CU_ASSERT_EQUAL(cap, ca->has_polcaps);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_SOURCE);
	CU_ASSERT_EQUAL(cap, ca->has_source);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_MODULES);
	CU_ASSERT_EQUAL(cap, ca->has_modules);

	qpol_policy_destroy(&q);
}

static void capability_v12_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-12.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		12U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v15_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-15.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		15U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v15_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.15",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		15U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v16_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-16.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		16U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v16_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.16",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		16U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v17_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-17.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		17U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v17_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.17",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		17U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v18_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-18.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		18U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v18_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.18",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		18U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v19_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.19",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		19U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v19_binary_mls()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.19",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		19U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v20_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.20",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		20U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v20_binary_mls()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.20",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		20U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v21_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls-21.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		21U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v21_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.21",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		21U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v22_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls-22.conf",
		QPOL_POLICY_KERNEL_SOURCE,	// policy type
		22U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		true,		       // has policy capabilities
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v22_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.22",
		QPOL_POLICY_KERNEL_BINARY,	// policy type
		22U,		       // policy version
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		true,		       // has policy capabilities
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_modv6_base_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/base-6.pp",
		QPOL_POLICY_MODULE_BINARY,	// policy type
		6U,		       // policy version
		true,		       // has attributes
		true,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has policy capabilities
		false,		       // has source
		true		       // has modules
	};
	capability_test(&cap);
}

CU_TestInfo capabilities_tests[] = {
	{"v12, source", capability_v12_source},
	{"v15, source", capability_v15_source},
	{"v15, binary", capability_v15_binary},
	{"v16, source", capability_v16_source},
	{"v16, binary", capability_v16_binary},
	{"v17, source", capability_v17_source},
	{"v17, binary", capability_v17_binary},
	{"v18, source", capability_v18_source},
	{"v18, binary", capability_v18_binary},
	{"v19, binary", capability_v19_binary},
	{"v19, binary mls", capability_v19_binary_mls},
	{"v20, binary", capability_v20_binary},
	{"v20, binary mls", capability_v20_binary_mls},
	{"v21, source", capability_v21_source},
	{"v21, binary", capability_v21_binary},
	{"v22, source", capability_v22_source},
	{"v22, binary", capability_v22_binary},
	{"mod v6, base binary", capability_modv6_base_binary},
	CU_TEST_INFO_NULL
};

int capabilities_init()
{
	return 0;
}

int capabilities_cleanup()
{
	return 0;
}
