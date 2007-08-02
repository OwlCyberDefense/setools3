/**
 *  @file
 *
 *  Test libseaudit's log file parsing ability.
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
#include <seaudit/log.h>
#include <seaudit/parse.h>

#include <stdbool.h>
#include <stdio.h>

struct log_answer
{
	const char *log_name;
	bool has_warnings;
};

static void parse_file_test(const struct log_answer *la)
{
	seaudit_log_t *l = seaudit_log_create(NULL, NULL);
	CU_ASSERT_PTR_NOT_NULL_FATAL(l);

	FILE *f = fopen(la->log_name, "r");
	CU_ASSERT_PTR_NOT_NULL_FATAL(f);

	int retval;
	retval = seaudit_log_parse(l, f);
	if (la->has_warnings) {
		CU_ASSERT(retval > 0);
	} else {
		CU_ASSERT(retval == 0);
	}

	fclose(f);
	seaudit_log_destroy(&l);
}

static void parse_file_fc4()
{
	struct log_answer l = {
		TEST_POLICIES "/setools-3.0/seaudit/messages-FC4",
		false
	};
	parse_file_test(&l);
}

static void parse_file_fc5()
{
	struct log_answer l = {
		TEST_POLICIES "/setools-3.0/seaudit/messages-FC5",
		false
	};
	parse_file_test(&l);
}

static void parse_file_nowarns()
{
	struct log_answer l = {
		TEST_POLICIES "/setools-3.1/seaudit/messages-nowarns",
		false
	};
	parse_file_test(&l);
}

static void parse_file_warnings()
{
	struct log_answer l = {
		TEST_POLICIES "/setools-3.1/seaudit/messages-warnings",
		true
	};
	parse_file_test(&l);
}

CU_TestInfo parse_file_tests[] = {
	{"FC4 log", parse_file_fc4},
	{"FC5 log", parse_file_fc5},
	{"messages-nowarns", parse_file_nowarns},
	{"messages-warnings", parse_file_warnings},
	CU_TEST_INFO_NULL
};

int parse_file_init()
{
	return 0;
}

int parse_file_cleanup()
{
	return 0;
}
