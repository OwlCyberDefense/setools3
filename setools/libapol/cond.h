 /* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com
 *         kmacmillan@tresys.com
 */
/* cond.h */


#ifndef _APOLICY_COND_H_
#define _APOLICY_COND_H_
#include "util.h"

#define COND_BOOL	1 /* plain bool */
#define COND_NOT	2 /* !bool */
#define COND_OR		3 /* bool || bool */
#define COND_AND	4 /* bool && bool */
#define COND_XOR	5 /* bool ^ bool */
#define COND_EQ		6 /* bool == bool */
#define COND_NEQ	7 /* bool != bool */
#define COND_LAST	8

#define COND_EXPR_MAXDEPTH 10

/* policy DB structures */

/* Conditional Booleans */
typedef struct cond_bool {
	char	*name;
	bool_t  default_state; 	/* the state from the policy */
	bool_t	state;		/* current state (can be varied; init'd to default_state) */
} cond_bool_t;


/* A conditional expression is a list of operators and operands
 * in reverse polish notation. */
typedef struct cond_expr {
	unsigned int expr_type;
	int bool;
	struct cond_expr *next;
} cond_expr_t;

/* Each conditional has a true and fals list of allow, audit,
 * and/or type rules */
typedef struct cond_rule_list {
	int	num_av_access;
	int	num_av_audit;
	int	num_te_trans;
	int	*av_access;
	int	*av_audit;
	int	*te_trans;
} cond_rule_list_t;

/* This is base conditional expression struct */
typedef struct cond_expr_item {
	bool_t cur_state;		/* the current logical result of the expression */
	cond_expr_t *expr;
	cond_rule_list_t *true_list;
	cond_rule_list_t *false_list;
} cond_expr_item_t;


/* macros */

/* prototypes */
int cond_free_bool(cond_bool_t *b);
int cond_free_expr(cond_expr_t *expr);
int cond_free_rules_list(cond_rule_list_t *rl);
int cond_free_expr_item(cond_expr_item_t *c);
int cond_evaluate_expr(cond_expr_t *expr, struct policy *policy);
bool_t cond_exprs_equal(cond_expr_t *a, cond_expr_t *b);

#endif
