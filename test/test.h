/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information
 */

/*
 * Author: kmacmillan@tresys.com
 */

/*
 * test.h
 *
 * This is some simple test infrastructure for creating
 * automated unit tests.
 */

#ifndef __APOL_TEST_H__
#define __APOL_TEST_H__

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

/* control how a program exits on test failure */
static int dump_core = 0;

/*
 * Test a condition. If it succeds a message is printed else the program
 * aborts. If abort is non-zero then abort is called to dump core, otherwise
 * exit is called.
 *
 */

#define TEST(name, expression) fprintf(stderr, "Testing %s . . . ", name); \
  if (expression) { fprintf(stderr, "pass.\n"); } \
  else { fprintf(stderr, "failed - in %s at %s:%d\n", __FUNCTION__, __FILE__, __LINE__); \
    if (dump_core) { abort(); } else { exit(1); } }

int get_rand_int(int min, int max);

void init_tests(int argc, char **argv);

#endif
