 /* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com
 */

/* cond.c */

/* Support functions for conditional policy language extensions 
 * some of this is borrowed directly from our work in conditional.c
 * for the checkpolicy extensions */


#include "util.h"
#include "cond.h"
#include "policy.h"


int cond_free_expr(cond_expr_t *expr)
{
	cond_expr_t *cur, *next;

	for (cur = expr; cur != NULL; cur = next) {
		next = cur->next;
		free(cur);
	}
	return 0;
}

int cond_free_rules_list(cond_rule_list_t *rl)
{
	if(rl == NULL)
		return 0;
	if(rl->av_access != NULL)
		free(rl->av_access);
	if(rl->av_audit != NULL)
		free(rl->av_audit);
	if(rl->te_trans != NULL)
		free(rl->te_trans);
	free(rl);
	return 0;
}

int cond_free_expr_item(cond_expr_item_t *c)
{
	if(c == NULL)
		return 0;
	cond_free_expr(c->expr);
	cond_free_rules_list(c->true_list);
	cond_free_rules_list(c->false_list);
	return 0;
}

int cond_free_bool(cond_bool_t *b)
{
	if(b != NULL) {
		if(b->name != NULL)
			free(b->name);
	}
	return 0;
}

/*
 * cond_evaluate_expr evaluates a conditional expr
 * in reverse polish notation. It returns true (1), false (0),
 * or undefined (-1). Undefined occurs when the expression
 * exceeds the stack depth of COND_EXPR_MAXDEPTH.
 */
int cond_evaluate_expr(cond_expr_t *expr, policy_t *policy)
{

	cond_expr_t *cur;
	int s[COND_EXPR_MAXDEPTH];
	int sp = -1;

	for (cur = expr; cur != NULL; cur = cur->next) {
		switch (cur->expr_type) {
		case COND_BOOL:
			if (sp == (COND_EXPR_MAXDEPTH - 1))
				return -1;
			sp++;
			s[sp] = policy->cond_bools[cur->bool].state;
			break;
		case COND_NOT:
			if (sp < 0)
				return -1;
			s[sp] = !s[sp];
			break;
		case COND_OR:
			if (sp < 1)
				return -1;
			sp--;
			s[sp] |= s[sp + 1];
			break;
		case COND_AND:
			if (sp < 1)
				return -1;
			sp--;
			s[sp] &= s[sp + 1];
			break;
		case COND_XOR:
			if (sp < 1)
				return -1;
			sp--;
			s[sp] ^= s[sp + 1];
			break;
		case COND_EQ:
			if (sp < 1)
				return -1;
			sp--;
			s[sp] = (s[sp] == s[sp + 1]);
			break;
		case COND_NEQ:
			if (sp < 1)
				return -1;
			sp--;
			s[sp] = (s[sp] != s[sp + 1]);
			break;
		default:
			return -1;
		}
	}
	return s[0];
}

/* Compare 2 conditional expressions for equality. This is a very basic compare and
 * the expressions need to be exactly the same in order to match (including order).
 *
 * TODO: Add semantic comparison.
 *
 * RETURNS:
 *	TRUE or FALSE if the conditional expressions match or not.
 */
bool_t cond_exprs_equal(cond_expr_t *a, cond_expr_t *b)
{
	cond_expr_t *cur_a, *cur_b;
	
	if (!a || !b)
		return FALSE;
	
	cur_a = a;
	cur_b = b;
	
	while (1) {
		if (!cur_a && !cur_b)
			return TRUE;
		if (!cur_a || !cur_b)
			return FALSE;
		if (cur_a->expr_type != cur_b->expr_type)
			return FALSE;
		if (cur_a->expr_type == COND_BOOL)
			if (cur_a->bool != cur_b->bool)
				return FALSE;
		cur_a = cur_a->next;
		cur_b = cur_b->next;
	}
	/* can't be reached */
	return TRUE;
}
