/**
 *  @file
 *
 *  Test policy loading capabilities that were introduced in SETools
 *  3.2.
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
#include <qpol/policy.h>

#include <stdbool.h>

#define POLICY_ROOT TEST_POLICIES "/policy-versions"

struct capability_answer
{
	const char *policy_name;
	const char *version_string;
	bool has_attributes;
	bool has_syn_rules;
	bool has_line_numbers;
	bool has_conditionals;
	bool has_mls;
	bool has_source;
	bool has_modules;
};

static void capability_test(const struct capability_answer *ca)
{
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, ca->policy_name, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ppath);

	apol_policy_t *p = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(p);

	apol_policy_path_destroy(&ppath);

	char *ver_str = apol_policy_get_version_type_mls_str(p);
	CU_ASSERT_PTR_NOT_NULL_FATAL(ver_str);

	CU_ASSERT_STRING_EQUAL(ver_str, ca->version_string);
	free(ver_str);

	const qpol_policy_t *q = apol_policy_get_qpol(p);
	CU_ASSERT_PTR_NOT_NULL_FATAL(q);

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

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_SOURCE);
	CU_ASSERT_EQUAL(cap, ca->has_source);

	cap = (bool) qpol_policy_has_capability(q, QPOL_CAP_MODULES);
	CU_ASSERT_EQUAL(cap, ca->has_modules);

	apol_policy_destroy(&p);
}

static void capability_v12_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-12.conf",
		"v.12 (source, non-mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v15_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-15.conf",
		"v.15 (source, non-mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v15_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.15",
		"v.15 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		false,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v16_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-16.conf",
		"v.16 (source, non-mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v16_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.16",
		"v.16 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v17_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-17.conf",
		"v.17 (source, non-mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v17_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.17",
		"v.17 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v18_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-18.conf",
		"v.18 (source, non-mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v18_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.18",
		"v.18 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v19_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.19",
		"v.19 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v19_binary_mls()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.19",
		"v.19 (binary, mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v20_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy.20",
		"v.20 (binary, non-mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		false,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v20_binary_mls()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.20",
		"v.20 (binary, mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v21_source()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls-21.conf",
		"v.21 (source, mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		true,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		true,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_v21_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/policy-mls.21",
		"v.21 (binary, mls)",
		false,		       // has attributes
		false,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
		false,		       // has source
		false		       // has modules
	};
	capability_test(&cap);
}

static void capability_modv6_base_binary()
{
	struct capability_answer cap = {
		POLICY_ROOT "/base-6.pp",
		"v.6 (modular, mls)",
		true,		       // has attributes
		true,		       // has syntactic rules
		false,		       // has line numbers
		true,		       // has conditionals
		true,		       // has mls
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
	{"mod v6, base binary", capability_modv6_base_binary},
	CU_TEST_INFO_NULL
};

int capabalities_init()
{
	return 1;
}

int capabalities_cleanup()
{
	return 1;
}
