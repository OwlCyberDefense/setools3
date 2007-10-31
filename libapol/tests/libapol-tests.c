/**
 *  @file
 *
 *  CUnit testing framework for libapol.
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
#include <CUnit/Basic.h>

#include "avrule-tests.h"
#include "dta-tests.h"
#include "infoflow-tests.h"
#include "policy-21-tests.h"
#include "role-tests.h"
#include "terule-tests.h"
#include "user-tests.h"

int main(void)
{
	if (CU_initialize_registry() != CUE_SUCCESS) {
		return CU_get_error();
	}

	CU_SuiteInfo suites[] = {
		{"Policy Version 21", policy_21_init, policy_21_cleanup, policy_21_tests}
		,
		{"AV Rule Query", avrule_init, avrule_cleanup, avrule_tests}
		,
		{"Domain Transition Analysis", dta_init, dta_cleanup, dta_tests}
		,
		{"Infoflow Analysis", infoflow_init, infoflow_cleanup, infoflow_tests}
		,
		{"Role Query", role_init, role_cleanup, role_tests}
		,
		{"TE Rule Query", terule_init, terule_cleanup, terule_tests}
		,
		{"User Query", user_init, user_cleanup, user_tests}
		,
		CU_SUITE_INFO_NULL
	};

	CU_register_suites(suites);
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	unsigned int num_failures = CU_get_number_of_failure_records();
	CU_cleanup_registry();
	return (int)num_failures;
}
