/**
 *  @file
 *
 *  Test libseaudit's filtering capabilities.
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
#include <apol/util.h>
#include <seaudit/log.h>
#include <seaudit/message.h>
#include <seaudit/model.h>
#include <seaudit/parse.h>

#include <stdbool.h>
#include <stdio.h>

#define MESSAGES_NOWARNS TEST_POLICIES "/setools-3.1/seaudit/messages-nowarns"

static seaudit_log_t *l = NULL;
static seaudit_model_t *m = NULL;

static void filters_simple()
{
	seaudit_filter_t *f = seaudit_filter_create("simple filter");
	CU_ASSERT_PTR_NOT_NULL_FATAL(f);

	int retval;
	apol_vector_t *v = apol_str_split("system_u", ":");
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	retval = seaudit_filter_set_source_user(f, v);
	CU_ASSERT(retval == 0);
	apol_vector_destroy(&v);

	retval = seaudit_model_append_filter(m, f);
	CU_ASSERT(retval == 0);

	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5 + 5);
	apol_vector_destroy(&v);

	retval = seaudit_filter_set_strict(f, true);
	CU_ASSERT(retval == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5);
	apol_vector_destroy(&v);

	retval = seaudit_filter_set_strict(f, false);
	CU_ASSERT(retval == 0);
	v = seaudit_model_get_messages(l, m);
	CU_ASSERT_PTR_NOT_NULL_FATAL(v);
	CU_ASSERT(apol_vector_get_size(v) == 5 + 5);
	apol_vector_destroy(&v);
}

CU_TestInfo filters_tests[] = {
	{"simple filter", filters_simple},
	CU_TEST_INFO_NULL
};

int filters_init()
{
	l = seaudit_log_create(NULL, NULL);
	if (l == NULL) {
		return 1;
	}
	m = seaudit_model_create("filters", l);
	if (m == NULL) {
		return 1;
	}

	FILE *f = fopen(MESSAGES_NOWARNS, "r");
	if (f == NULL) {
		return 1;
	}
	int retval;
	retval = seaudit_log_parse(l, f);
	if (retval != 0) {
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

int filters_cleanup()
{
	seaudit_log_destroy(&l);
	seaudit_model_destroy(&m);
	return 0;
}
