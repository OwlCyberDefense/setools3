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
#include <assert.h>
#include <string.h>
#include <sys/capability.h>

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

static int cond_evaluate_expr_helper(cond_expr_t *expr, bool_t *vals)
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
			s[sp] = vals[cur->bool];
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

int cond_evaluate_expr(cond_expr_t *expr, policy_t *policy)
{
	bool_t *vals;
	int i, rt; 
	
	if(expr == NULL || policy == NULL)
		return -1;
	
	vals = (bool_t *)malloc(sizeof(bool_t) * policy->num_cond_bools);
	if(vals == NULL ) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	for(i = 0; i < policy->num_cond_bools; i++) {
		vals[i] = policy->cond_bools[i].state;
	}
	rt = cond_evaluate_expr_helper(expr, vals);
	free(vals);
	return rt;
}

/* Compare 2 conditional expressions for equality. This is a very basic compare and
 * the expressions need to be exactly the same in order to match (including order).
 *
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

static int count_and_get_unique_bools(cond_expr_t *e, int **bools)
{
	int num = 0, rt;
	cond_expr_t *t;
	
	if(bools == NULL)
		return -1;
	*bools = NULL;
	
	for(t = e; t != NULL; t = t->next) {
		if(t->expr_type == COND_BOOL) {
			rt = find_int_in_array(t->bool, *bools, num);
			if(rt < 0) { /* means this is a new, unique bool */
				rt = add_i_to_a(t->bool, &num, bools);
				if(rt < 0)
					return -1;
			}
		}
	}
	return num;
}



/* assumes vals is of size sz (which is num of bools in policy; alloc's and returns pre computed values.
 * num is number of unique bools in expression e.  Returns in comp the pre comp and return the sz in bytes
 * of comp.  Returns -1 for error. */
static int pre_comp_helper(bool_t *vals, int sz, int *bools, int num, cond_expr_t *e, unsigned char **comp)
{
	int num_reqd_bytes, i, ans;
	uint32_t test, lnum;  
	
	if(vals == NULL || e == NULL || bools == NULL || comp == NULL)
		return -1;
		
	assert(num >= 0 && num <= COND_MAX_BOOLS);
	assert(sz > 0);
	num_reqd_bytes =  (0x1 << num)/8; 
	/* always need at least 1 byte */
	if (num_reqd_bytes == 0) num_reqd_bytes++;
	
	*comp = (unsigned char *) malloc(sizeof(unsigned char) * num_reqd_bytes); 
	if(*comp == NULL ) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(*comp, 0, sizeof(unsigned char) * num_reqd_bytes);
	
	lnum = num;
	for(test = 0x0; test < (0x1 << lnum); test++) {
		/* set the boolean vals */
		for(i = 0; i < num; i++) {
			vals[bools[i]] = (test & (0x1 << i) ) ? TRUE : FALSE;
		}
		ans = cond_evaluate_expr_helper(e, vals);
		if(ans < 0) {
			free(*comp);
			return -1;
		}
		if(ans) 
			(*comp)[test/8] |= (0x1 << (test & 0x7));
	}
	return num_reqd_bytes;
}


static bool_t is_inverse_comp(int sz, unsigned char *a, unsigned char *b)
{
	int i;
	assert(a != NULL && b!= NULL);
	
	for(i = 0; i < sz; i++) {
		if(a[i] & b[i])
			return FALSE;
	}
	return TRUE;
}


/* This function assumes taht both expressions have the exact same unique booleans, and that
 * num indicates how many unique bools.  Inverse indicates that the exprs are the inverse of each
 * other in which case just logically switch the TRUE and FALSE lists for the expr  */
static bool_t semantic_equal_helper(int num, int *abools, int *bbools, cond_expr_t *a, cond_expr_t *b, policy_t *p, bool_t *inverse)
{
	bool_t *vals = NULL, ans;	
	int sza, szb, rt;
	unsigned char *a_comp = NULL, *b_comp = NULL; /* buffer for pre-computed values */

	if(num <= 0 || a == NULL || b == NULL || p == NULL || abools == NULL || bbools == NULL || inverse == NULL) {
		assert(0);
		return FALSE;
	}
	*inverse = FALSE;

	/* allocated boolean value array for testing; size of all booleans in policy */
	assert(p->num_cond_bools > 0);
	vals = (bool_t *)malloc(sizeof(bool_t) * p->num_cond_bools);
	if(vals == NULL) {
		fprintf(stderr, "out of memory\n");
		return FALSE;
	}
	memset(vals, 0, sizeof(bool_t) * p->num_cond_bools);
	
	sza = pre_comp_helper(vals,  p->num_cond_bools, abools, num, a, &a_comp);
	if(sza < 1) {
		free(vals);
		assert(0);
		return FALSE;
	}
	szb = pre_comp_helper(vals,  p->num_cond_bools, bbools, num, b, &b_comp);
	if(szb < 1) {
		free(vals);
		free(a_comp);
		assert(0);
		return FALSE;
	}
	free(vals);

	assert(a_comp != NULL);
	assert(b_comp != NULL);
	assert(sza == szb);
	rt = memcmp(a_comp, b_comp, sza);
	if(rt == 0)
		ans = TRUE;
	else {
		if(is_inverse_comp(sza, a_comp, b_comp)) {
			*inverse = TRUE; /* this is the inverse expr */
			ans = TRUE;
		}
		else {
			ans = FALSE; /* not inverse either */
		}
	}

	free(a_comp);
	free(b_comp);
	return ans;
}



/* A semantic comaprison, that will determine if two expresions are equal under
 * most cases */
bool_t cond_exprs_semantic_equal(cond_expr_t *a, cond_expr_t *b, struct policy *p, bool_t *inverse)
{
	int i, rt, anum, bnum, *abools = NULL, *bbools = NULL;
	bool_t ans;

	if(a == NULL || b == NULL || p == NULL || inverse == NULL) {
		assert(0);
		return FALSE;
	}
	*inverse = FALSE;
	
	anum = count_and_get_unique_bools(a, &abools);
	bnum = count_and_get_unique_bools(b, &bbools);
	if(anum < 0 || bnum < 0){
		assert(0);
		ans = FALSE;
		goto return_ans;
	}
	assert(abools != NULL);
	assert(bbools != NULL);
		
	/* first check the # bools heuristic */
	if(anum != bnum) {
		ans = FALSE;
		goto return_ans;
	}
	/* then attempt to check for EXACT match */
	if(cond_exprs_equal(a, b)){
		ans = TRUE;
		goto return_ans;
	}
	/* see if the exact same booleans are used; if not they can't be semantically equal */
	for(i = 0; i < anum; i++) {
		rt = find_int_in_array(abools[i], bbools, bnum);
		if(rt < 0) {
			ans = FALSE;
			goto return_ans;
		}
	}
	/* otherwise go through the brute force semantic check */
	if(p == NULL) {
		assert(0);
		ans = FALSE;
		goto  return_ans;
	}
	ans = semantic_equal_helper(anum, abools, bbools, a, b, p, inverse);
return_ans:
	if(abools != NULL) free(abools);
	if(bbools != NULL) free(bbools);
	return ans;
}




