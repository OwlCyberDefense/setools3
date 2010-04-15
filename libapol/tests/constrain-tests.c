/**
 *  @file
 *
 *  Test the information flow analysis code.
 *
 *
 *  Copyright (C) 2010 Tresys Technology, LLC
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

#include <stdio.h>
#include <config.h>

#include <CUnit/CUnit.h>
#include <apol/perm-map.h>
#include <apol/policy.h>
#include <apol/policy-path.h>
#include <stdbool.h>
#include <string.h>
#include <apol/constraint-query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/constraint.h>
#include <libqpol/src/queue.h>

#define CONSTR_SOURCE TEST_POLICIES "/setools-3.3/apol/constrain_test_policy.conf"
#define CONSTR_BINARY TEST_POLICIES "/setools-3.3/apol/constrain_test_policy.21"
// Glob won't work, but this gives the idea of where we are trying to go
#define CONSTR_MODULAR TEST_POLICIES "/setools-3.1/modules/*.pp"

//#define DEBUGTRACE 1


/*	General concepts:  The constraints are stored in the policy by class,
 *	that is, the list of classes stored in the policy has attached to it
 *	whatever constraints affect that class.
 *	The "policy_iter" iterator is a structure which contains a pointer to the
 *	list of classes from the loaded policy, and another pointer to the list of
 *	constraints associated with the current class. This latter pointer is
 *	traversed to its end, at which point the class pointer is updated, and the
 *	new class' list of constraints is put in its place. The switch from one
 *	class to the next is done behind the scenes by the iterator. Thus each time
 *	a new item is retrieved from policy_iter, it needs to have all info (class,
 *	permissions, expression) extracted from it.
 *
 *	The input file must be a known file.  The class and permissions are used as
 *	a key by this test routine to determine what the expected expression will
 *	be. Thus, if the input file is modified, this test becomes invalid. The file
 *	(defined above) resides in the 'testing-policies' repository.
 *
 *	The statements validatetrans and mlsvalidatetrans, although similar to
 *	constrain and mlsconstrain, are not considered here.
 *
 */

// Define data for expected policy. This is a hack, but what I could think of
// on short notice.

// Similar to struct constraint_expr from sepol/policydb/constraint.h
// but want char * list of names, not internal representations.
typedef struct local_expr {
	uint32_t expr_type;
	uint32_t attr;
	uint32_t op;
	size_t   name_count;
	char 	**namelist;
} local_expr_t;

typedef struct constrain_test_list {
	char **class;
	char **permissions;	// Must end with NULL
	int test_found;
	int  expr_count;
	local_expr_t **expr_list;
} constrain_test_list_t;

// TODO Clean up memory leaks -- all iterators need to be destroyed, check other stuff


char *class0 = "file";
char *perm0[] = { "create", "relabelto", NULL };
local_expr_t expr00 = { CEXPR_ATTR, CEXPR_L2H2, CEXPR_EQ, 0, NULL };
local_expr_t *expr0[] = { &expr00, NULL };

char *class1 = "lnk_file";
char *perm1[10] = { "create", "relabelto", NULL };
local_expr_t expr10 = { CEXPR_ATTR, CEXPR_L2H2, CEXPR_NEQ, 0, NULL };
local_expr_t *expr1[] = { &expr10, NULL };

// This test (test 2) is not expected to be matched
char *class2 = "fifo_file";
char *perm2[] = { "create", "relabelto", NULL };
local_expr_t expr20 = { CEXPR_ATTR, CEXPR_L2H2, CEXPR_DOM, 0, NULL };
local_expr_t *expr2[] = { &expr20, NULL };

char *class3 = "node";
char *perm3[] = { "udp_send", NULL };
local_expr_t expr30 = { CEXPR_ATTR, CEXPR_L1L2, CEXPR_DOM, 0, NULL };
local_expr_t expr31 = { CEXPR_ATTR, CEXPR_L1H2, CEXPR_DOMBY, 0, NULL };
local_expr_t expr32 = { CEXPR_AND, 0, 0, 0, NULL };
local_expr_t *expr3[] = { &expr30, &expr31, &expr32, NULL };

char *class4 = "netif";
char *perm4[] = { "tcp_send", NULL };
local_expr_t expr40 = { CEXPR_ATTR, CEXPR_L1L2, CEXPR_DOM, 0, NULL };
local_expr_t expr41 = { CEXPR_ATTR, CEXPR_L1H2, CEXPR_DOMBY, 0, NULL };
local_expr_t expr42 = { CEXPR_OR, 0, 0, 0, NULL };
local_expr_t *expr4[] = { &expr40, &expr41, &expr42, NULL };

char *class5 = "dir";
char *perm5[] = { "read", NULL };
char *name50[] = { "sysadm_t", "secadm_t", NULL };
local_expr_t expr50 = { CEXPR_NAMES, CEXPR_TYPE, CEXPR_EQ, 2, name50 };
local_expr_t *expr5[] = { &expr50, NULL };

constrain_test_list_t test_list[] = {
	{ &class0, perm0, 0, 1, expr0 },
	{ &class1, perm1, 0, 1, expr1 },
	{ &class2, perm2, 0, 1, expr2 },
	{ &class3, perm3, 0, 3, expr3 },
	{ &class4, perm4, 0, 3, expr4 },
	{ &class5, perm5, 0, 3, expr5 }
};

typedef struct compare_perm_str {
	int list_length;
	int list_found;
	int q_elements_compared;
	char **list;
} compare_perm_str_t;

typedef struct compare_expr_str {
	int list_length;
	int list_found;
	local_expr_t **list;
} compare_expr_str_t;


static apol_policy_t *ps = NULL;	// Source policy
static apol_policy_t *pb = NULL;	// Binary policy
static apol_policy_t *pm = NULL;	// Modular policy


// Prototypes if needed
static int compare_item_to_list(void *e, void *v);




static int doprintstr (queue_element_t e, void *p)
{
	char *s = (char *)e;
	// Second arg is not used

	printf ("%s ", s);
	return 0;
}

static int compare_expr_list(qpol_policy_t *q, qpol_iterator_t *expr_iter, int expr_count, local_expr_t **le)
{
	const qpol_constraint_expr_node_t *expr;
	int sym_type;
	int op;
	int expr_type;
	int i;
	int err;

	for (i=0; qpol_iterator_end(expr_iter) == 0; i++, qpol_iterator_next(expr_iter))
	{
		expr_type = op = sym_type = 0;
		if (i >= expr_count)	// Hit the end of the list
			return 1;			// Not the right list

		err = qpol_iterator_get_item(expr_iter, (void **)&expr);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		err = qpol_constraint_expr_node_get_sym_type(q, expr, &sym_type);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		err = qpol_constraint_expr_node_get_op(q, expr, &op);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		err = qpol_constraint_expr_node_get_expr_type(q, expr, &expr_type);
		CU_ASSERT_EQUAL_FATAL(err, 0);

#ifdef DEBUGTRACE
		printf ("Expr compare: Policy:attr:%d, op:%d, expr_type:%d\n", sym_type, op, expr_type);
		printf ("Expr compare:   Test:attr:%d, op:%d, expr_type:%d\n", le[i]->attr, le[i]->op, le[i]->expr_type);
#endif
		if (sym_type != le[i]->attr)
		{
			return 1;
		}
		if (op != le[i]->op)
		{
			return 1;
		}
		if (expr_type != le[i]->expr_type)
		{
			return 1;
		}

		if (expr_type == CEXPR_NAMES) // Need compare name lists
		{
			qpol_iterator_t *names_iter=NULL;
			size_t name_size=0;
			compare_perm_str_t x;
			
#ifdef DEBUGTRACE
			printf ("Found CEXPR_NAMES expression\n");
#endif
			x.list_length = le[i]->name_count;
			x.list = le[i]->namelist;
			x.list_found = 0;
			x.q_elements_compared = 0;

			err = qpol_constraint_expr_node_get_names_iter (q, expr, &names_iter);
			CU_ASSERT_EQUAL_FATAL(err, 0);

			err = qpol_iterator_get_size(names_iter, &name_size);
			CU_ASSERT_EQUAL_FATAL(err, 0);
			CU_ASSERT_TRUE_FATAL(name_size > 0);

			if (name_size != x.list_length)	// Want exact match, 
			{
				qpol_iterator_destroy(&names_iter);
				return 1;
			}

			for (; qpol_iterator_end(names_iter) == 0; qpol_iterator_next(names_iter))
			{
				char *lname = NULL;

				err = qpol_iterator_get_item (names_iter, (void **)&lname);
				CU_ASSERT_EQUAL_FATAL(err, 0);

				compare_item_to_list (lname, &x);
				free (lname);
			}

#ifdef DEBUGTRACE
			printf ("name list length=%d, list_found=%d, q_elements_compared=%d\n", x.list_length, x.list_found, x.q_elements_compared);
#endif
			if ((x.list_length != x.list_found) || (x.list_length != x.q_elements_compared))
				return 1;
		}
	}
	return 0;
}

static int compare_item_to_list(void *e, void *v)
{
	char *pe = (char *)e;
	compare_perm_str_t *x = (compare_perm_str_t *)v;
	char **permlist = x->list;
	char *perm;

	CU_ASSERT_PTR_NOT_NULL(permlist);
	CU_ASSERT_PTR_NOT_NULL(pe);

	while ((perm=*permlist++) != NULL)
	{
#ifdef DEBUGTRACE
		printf ("pe = %s\n", pe);
		printf ("perm = %s\n", perm);
#endif
		if (strcmp(pe, perm) == 0)
			x->list_found++;
	}
	x->q_elements_compared++;
	return 0;
}

static int compare_perm_list(queue_t perm_q, char **permissions)
{
	compare_perm_str_t x;
	
	x.list_length = 0;
	x.list_found = 0;
	x.q_elements_compared = 0;
	x.list = permissions;

	while (*permissions++ != NULL)
		x.list_length++;

#ifdef DEBUGTRACE
	printf ("list_length = %d\n", x.list_length);
#endif
	if (queue_map(perm_q, compare_item_to_list, &x) != 0)
		return 1;

#ifdef DEBUGTRACE
	printf ("list length=%d, list_found=%d, q_elements_compared=%d\n", x.list_length, x.list_found, x.q_elements_compared);
#endif
	if ((x.list_length != x.list_found) || (x.list_length != x.q_elements_compared))
		return 1;

	return 0;
}

static void constrain_test(apol_policy_t *ap)
{
	int i;
	int err=0;
	const char *class_name = NULL;
	const char *constrain_type = "?constrain";
	char *perm_list = "No Perms Extracted";
	const qpol_constraint_expr_node_t *expr = NULL;
	qpol_iterator_t *policy_iter = NULL;	// Iterates over all constraints in a policy
	qpol_iterator_t *perm_iter = NULL;		// Iterates over permissions in a constraint
	qpol_iterator_t *expr_iter = NULL;		// Iterates over expression in a constraint
	qpol_policy_t *q = apol_policy_get_qpol(ap);
	qpol_constraint_t *constraint = NULL;
	const qpol_class_t *class;
	size_t n_constraints = 0;
	size_t counted_constraints = 0;
	size_t tests_not_found = 0;
	int test_count = sizeof(test_list) / sizeof(constrain_test_list_t);
	int tests_matched = 0;
	int constrains_matched = 0;

	queue_t perm_q;		// holds list of permissions, in case more than one

	err = qpol_policy_get_constraint_iter(q, &policy_iter);
	if (err != 0)
	{
		CU_FAIL("Policy iterator not accessible");
		goto cleanup;
	}
	err = qpol_iterator_get_size(policy_iter, &n_constraints);
	if (err != 0)
	{
		CU_FAIL("Policy size computation failed");
		goto cleanup;
	}

	CU_ASSERT_EQUAL(n_constraints, 7);	// Count of constraints split among all classes

	counted_constraints=0;
	for (i=0; i<test_count; i++)
	{
		test_list[i].test_found = 0;
	}

	// Iterate through constraints
	for (; qpol_iterator_end(policy_iter) == 0; qpol_iterator_next(policy_iter))
	{
		counted_constraints++;
		/* The qpol_constraint_t that is returned below consists of
		 * 	struct qpol_constraint	<<<from constraint_query.c
		 * 	{
		 * 		const qpol_class_t *obj_class;
		 * 		constraint_node_t *constr;
		 * 	};
		 * the qpol_class_t is a pseudonym for class_datum_t from policydb.h
		 * constraint_node_t is defined in sepol/policydb/constraint.h
		 */
		err = qpol_iterator_get_item(policy_iter, (void **)&constraint);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen

		err = qpol_constraint_get_class(q, constraint, &class);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen
		err = qpol_class_get_name(q, class, &class_name);
		CU_ASSERT_EQUAL_FATAL(err, 0);	// Should never happen

#ifdef DEBUGTRACE
		printf ("Found class %s\n", class_name);
#endif
		// get permission(s)
		err = qpol_constraint_get_perm_iter (q, constraint, &perm_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		perm_q = queue_create();
		for (; qpol_iterator_end(perm_iter) == 0; qpol_iterator_next(perm_iter))
		{
			err = qpol_iterator_get_item(perm_iter, (void **)&perm_list);
			CU_ASSERT_EQUAL_FATAL(err,0)

			err = queue_insert (perm_q, perm_list);
			CU_ASSERT_EQUAL_FATAL(err,0)
		}
#ifdef DEBUGTRACE
		printf ("perms: ");
		queue_map(perm_q, doprintstr, NULL);
		printf ("\n");
#endif

		// get RPN expressions
		err = qpol_constraint_get_expr_iter (q, constraint, &expr_iter);
		CU_ASSERT_EQUAL_FATAL(err, 0);

		// At this point, the class, permission list, and expression list (in
		// the iterator) have been identified. Based on expected class/permission
		// combinations, find one which matches, and note that it was found.
		// If not found, count that too.
		for (i=0; i<test_count; i++)
		{
			if (strcmp(*(test_list[i].class), class_name) == 0)
			{
				if (compare_perm_list(perm_q, test_list[i].permissions) == 0)
				{
					if (compare_expr_list(q, expr_iter, test_list[i].expr_count, test_list[i].expr_list) == 0)
					{
						test_list[i].test_found = 1;
						constrains_matched++;
						break;
					}
#ifdef DEBUGTRACE
					else
					{
						printf ("Mismatch comparing expression list\n");
					}
#endif
				}
#ifdef DEBUGTRACE
				else
				{
					printf ("Mismatch comparing permission list\n");
				}
#endif
			}
#ifdef DEBUGTRACE
			else
			{
				printf ("Mismatch comparing classes %s,%s\n", *(test_list[i].class),class_name);
			}
#endif
		}
		queue_destroy(perm_q);
	}
	for (i=0; i<test_count; i++)
	{
		if (test_list[i].test_found == 0)
		{
			CU_ASSERT_EQUAL(i, 2);
		}
		else
			tests_matched++;
	}
#ifdef DEBUGTRACE
	printf ("tests_matched: %d, constrains_matched: %d, counted_constraints: %d, n_constraints: %d\n", tests_matched, constrains_matched, counted_constraints, n_constraints);
#endif
	CU_ASSERT_EQUAL(tests_matched, 5);
	CU_ASSERT_EQUAL(constrains_matched, 5);
	CU_ASSERT_EQUAL(counted_constraints, 7);
	CU_ASSERT_EQUAL(n_constraints, 7);

	CU_PASS();

cleanup:
	return;
	// close and destroy iterators/policy pointers
}

static void constrain_source(void)
{
	constrain_test(ps);
}

static void constrain_binary(void)
{
	constrain_test(pb);
//	CU_PASS("Not yet implemented")
}


static void constrain_modular(void)
{
	CU_PASS("Not yet implemented")
}

CU_TestInfo constrain_tests[] = {
	{"constrain from source policy", constrain_source},
	{"constrain from binary policy", constrain_binary},
//	{"constrain from modular policy", constrain_modular},
	CU_TEST_INFO_NULL
};

int constrain_init()
{
	// Probably should move this to individual tests, just fstat policy to see if it is there!
	apol_policy_path_t *ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, CONSTR_SOURCE, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((ps = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	ppath = apol_policy_path_create(APOL_POLICY_PATH_TYPE_MONOLITHIC, CONSTR_BINARY, NULL);
	if (ppath == NULL) {
		return 1;
	}

	if ((pb = apol_policy_create_from_policy_path(ppath, QPOL_POLICY_OPTION_NO_NEVERALLOWS, NULL, NULL)) == NULL) {
		apol_policy_path_destroy(&ppath);
		return 1;
	}
	apol_policy_path_destroy(&ppath);

	return 0;
}

int constrain_cleanup()
{
	apol_policy_destroy(&ps);
	return 0;
}
