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

#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY

/* policy DB structures */

/* Conditional Booleans */
typedef struct cond_bool {
	char	*name;
	bool_t	val;
} cond_bool_t;


/* A conditional expression is a list of operators and operands
 * in reverse polish notation. */
typedef struct cond_expr {
	unsigned int expr_type;
	bool_t bool;
	struct cond_expr *next;
} cond_expr_t;

/* Each conditional has a true and fals list of allow, audit,
 * and/or type rules */
typedef struct cond_rule_list {
	int	num_access;
	int	num_audit;
	int	num_te;
	int	*av_access;
	int	*av_audit;
	int	*te_trans;
} cond_rule_list_t;

/* This is base conditional expression struct */
typedef struct cond_expr_item {
	bool_t cur_state;
	cond_expr_t *expr;
	cond_rule_list_t *true_list;
	cond_rule_list_t *false_list;
} cond_expr_item_t;


/* macros */

/* prototypes */
int cond_free_bool(cond_bool_t *b);
int cond_free_expr_item(cond_expr_item_t *c);

#endif
#endif 


