 /* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com
 */

/* cond.c */

/* Support functions for conditional policy language extensions 
 * some of this is borrowed directly from our work in conditional.c
 * for the checkpolicy extensions */

#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY

#include "util.h"
#include "cond.h"


static int cond_free_expr(cond_expr_t *expr)
{
	cond_expr_t *cur, *next;

	for (cur = expr; cur != NULL; cur = next) {
		next = cur->next;
		free(cur);
	}
	return 0;
}

static int cond_free_rules_list(cond_rule_list_t *rl)
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





#endif

