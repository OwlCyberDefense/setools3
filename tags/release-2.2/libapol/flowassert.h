/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jason Tang (jtang@tresys.com)
 */

/* A set of functions to perform information flow assertion analysis.
 * The user poses a series of assertions in the form of a struct
 * flow_assert_t.  The struct is then passed to flow_assert_execute(),
 * which determines if the assertions are valid or not.  The function
 * also populates a struct flow_assert_results_t with the specific
 * rules within the policy that break the assertions.
 */

#ifndef _FLOWASSERT_H_
#define _FLOWASSERT_H_

#include "policy.h"
#include "util.h"

enum assert_mode { FLOW_ASSERT_INVALID_MODE, FLOW_ASSERT_NOFLOW_MODE,
                   FLOW_ASSERT_MUSTFLOW_MODE, FLOW_ASSERT_ONLYFLOW_MODE };


/* -- these are passed into flow_assert_execute() -- */
typedef struct flow_assert {
        enum assert_mode assert_mode;
        llist_t *from_list; /* linked list of flow_assert_id_t (see below) */
        llist_t *to_list;
        llist_t *via_list;
        int min_weight;
} flow_assert_t;

typedef struct flow_assert_id {
        int type_id;
        int num_obj_classes;
        int *obj_classes;
        int flags;  /* used internally by assert executable */
} flow_assert_id_t;

#define FLOW_ASSERT_STAR -1


/* -- flow_assert_execute() then responds using these -- */
typedef struct flow_assert_results {
        enum assert_mode mode;
        unsigned long rule_lineno;  /* line number from assertion_contents */
        int assert_result;               /* see #defines below */
        int num_rules;
        struct flow_assert_rule *rules;  /* length is num_rules */
} flow_assert_results_t;

typedef struct flow_assert_rule {
        int start_type, end_type, via_type;
        int num_rules;     /* number of rules in rule_indices */
        int *rules;        /* list of indices suitable for get_rule_lineno() */
} flow_assert_rule_t;

/* codes allowed within a flow_assert_results_t->assert_result */
/* assertion correct */
#define FLOW_ASSERT_VALID 0
/* assertion failed */
#define FLOW_ASSERT_FAIL 1
/* statement not formatted correctly */
#define FLOW_ASSERT_BAD_FORMAT 2
/* statement has undeclared attribute or type */
#define FLOW_ASSERT_UNKNOWN_TYPE 3
/* statement has undeclared object class */
#define FLOW_ASSERT_UNKNOWN_CLASS 4
/* statement has undeclared variable */
#define FLOW_ASSERT_UNKNOWN_VARIABLE 5
/* for all types of syntactical errors */
#define FLOW_ASSERT_SYNTAX_ERROR 6
/* all other errors (e.g., out of memory) */
#define FLOW_ASSERT_ERROR -1

/* -- USE THIS FUNCTION HERE -- */
/* call this one to actually execute assertion statements.  it returns
   a linked list of flow_assert_results_t.  caller is responsible for
   free()ing the list; see flow_assert_results_destroy(). */
llist_t *execute_flow_assertion (char *assertion_contents, policy_t *policy,
                                 bool_t short_circuit_while_executing);

/* these provide low-level access to the assertion engine */
flow_assert_t *flow_assert_create (void);
void flow_assert_destroy (flow_assert_t *assert);
void flow_assert_id_destroy (void *ptr);
flow_assert_results_t *flow_assert_results_create (void);
void flow_assert_results_destroy (void *assert_results);
int flow_assert_execute (flow_assert_t *assert, policy_t *policy,
                         flow_assert_results_t *assert_results,
                         bool_t abort_after_first_conflict);
void flowassert_add_error_result (int error_code);

#endif
