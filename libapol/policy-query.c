/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* policy-query.c
 *
 * policy query/search functions
 */
#include <stdlib.h>
#include <regex.h>
#include <assert.h>
#include "policy.h"
#include "util.h"
#include "policy-query.h"


int free_teq_results_contents(teq_results_t *r)
{
	if(r == NULL)
		return 0;
	if(r->av_access != NULL) free(r->av_access);
	if(r->av_access_lineno != NULL) free(r->av_access_lineno);
	if(r->av_audit != NULL) free(r->av_audit);
	if(r->av_audit_lineno != NULL) free(r->av_audit_lineno);
	if(r->type_rules != NULL) free(r->type_rules);
	if(r->type_lineno != NULL) free(r->type_lineno);
	if(r->clones != NULL) free(r->clones);
	if(r->clones_lineno != NULL) free(r->clones_lineno);
	if(r->errmsg != NULL) free(r->errmsg);
	return 0;
}

static int free_teq_search_type(teq_srch_type_t *s)
{
	assert(s != NULL);
	if(s->ta != NULL) free(s->ta);
	return 0;
}

int free_teq_query_contents(teq_query_t *q)
{
	if(q == NULL)
		return 0;
	if(q->classes != NULL) free(q->classes);
	if(q->perms != NULL) free(q->perms);
	free(q->bool_name);
	free_teq_search_type(&q->ta1);
	free_teq_search_type(&q->ta2);
	free_teq_search_type(&q->ta3);
	return 0;
}

static void init_teq_search_type(teq_srch_type_t *s)
{
	assert(s != NULL);
	s->indirect = FALSE;
	s->ta = NULL;		/* init to invalid type */
	s->t_or_a = IDX_INVALID;	/* assume type by default */
}

int init_teq_query(teq_query_t *q)
{
	if(q == NULL)
		return -1;
	q->classes = NULL;
	q->perms = NULL;
	q->num_classes = q->num_perms = 0;
	q->any = FALSE;
	q->rule_select = 0x0;
	q->use_regex = TRUE;
	q->only_enabled = FALSE;
	init_teq_search_type(&q->ta1);
	init_teq_search_type(&q->ta2);
	init_teq_search_type(&q->ta3);
	q->bool_name = NULL;
	return 0;
}

int init_teq_results(teq_results_t *r)
{
	if(r == NULL)
		return -1;
	r->av_access = NULL;
	r->av_access_lineno = NULL;
	r->av_audit = NULL;
	r->av_audit_lineno = NULL;
	r->type_rules = NULL;
	r->type_lineno = NULL;
	r->clones = NULL;
	r->clones_lineno = NULL;
	r->num_av_access = r->num_av_audit = r->num_type_rules = r->num_clones = 0;
	r->errmsg = NULL;
	r->err = 0;
	return 0;
}

static bool_t validate_teq_search_type(teq_srch_type_t *s)
{
	assert(s != NULL);
	if(!(s->t_or_a == IDX_BOTH || s->t_or_a == IDX_TYPE || s->t_or_a == IDX_ATTRIB ) )
		return FALSE;
	return TRUE;
}

bool_t validate_te_query(teq_query_t *q)
{
	if(q == NULL)
		return FALSE;
	
	/* if any, then must use ta1 (2-3 are ignored) */
	if(q->any && !is_ta_used(q->ta1))
		return FALSE;
	/* can't use ta3 if one of the type rules isn't selected */
	if(!q->any && is_ta_used(q->ta3) && !(q->rule_select & TEQ_TYPE))
		return FALSE;
	if(is_ta_used(q->ta1) && !validate_teq_search_type(&q->ta1))
		return FALSE;
	if(!q->any && is_ta_used(q->ta2) && !validate_teq_search_type(&q->ta2))
		return FALSE;
	if(!q->any && is_ta_used(q->ta3) && !validate_teq_search_type(&q->ta3))
		return FALSE;
	return TRUE;
}

int policy_query_add_type(int **types, int *num_types, int type)
{
	bool_t add = FALSE;

	/* we can't do anymore checking without the policy */
	if (type < 0) {
		fprintf(stderr, "type must be 0 or greater\n");
		return -1;
	}

	if (*types) {
		if (find_int_in_array(type, *types,
				      *num_types) < 0) {
			add = TRUE;
		}
	} else {
		add = TRUE;
	}
	if (add)
		if (add_i_to_a(type, &(*num_types), &(*types)) < 0)
			return -1;
	return 0;
}

/* find all rules that include a given type/attribute;
 * Doesn't set rules_b value to FALSE (assumed it has been
 * initialized), but rather only sets to TRUE if approporiate. 
 * In this way, you can call this function repeatedly with new
 * idx's building upon previous results */
/* FIX: address clone rules */
static int match_te_rules_idx(int  idx,
                          int  idx_type,
                          bool_t  include_audit, 
                          unsigned char whichlists,	/* indicates src, target, and/or default lists */	
                          bool_t do_indirect,
			  bool_t only_enabled,
                          rules_bool_t *rules_b,
                          policy_t *policy) 		
{
	int i;
	int ans;
	
	if(rules_b == NULL || policy == NULL)
		return -1;
	/* Note, DEFAULT_LIST is only used for type transition/change/member rules */
	
	if(whichlists & (SRC_LIST | TGT_LIST)) {
		for(i = 0; i < policy->num_av_access; i++) {
			if(rules_b->access[i])
				continue;
			if (only_enabled && !policy->av_access[i].enabled)
				continue;
			ans = does_av_rule_use_type(idx, idx_type, whichlists, do_indirect, 
					&(policy->av_access[i]), &(rules_b->ac_cnt), policy);
			if (ans == -1)
				return -1;
			else if (ans) {
				rules_b->access[i] = TRUE;
			}
		}
	}
	for(i = 0; i < policy->num_te_trans; i++) {
		if (rules_b->ttrules[i])
			continue;
		if (only_enabled && !policy->av_access[i].enabled)
				continue;
		ans = does_tt_rule_use_type(idx, idx_type, whichlists, do_indirect, 
				&(policy->te_trans[i]), &(rules_b->tt_cnt), policy);
		if (ans == -1)
			return -1;
		else if (ans) {
			rules_b->ttrules[i] = TRUE;
		}
	}
	if(whichlists & (SRC_LIST | TGT_LIST)) {
		for(i = 0; i < policy->rule_cnt[RULE_CLONE]; i++) {
			if(!rules_b->clone[i] && does_clone_rule_use_type(idx, idx_type, whichlists, &
					(policy->clones[i]), &(rules_b->cln_cnt), policy)) {
				rules_b->clone[i] = TRUE;
			}
		}
	}

	if(include_audit && (whichlists & (SRC_LIST | TGT_LIST))) {
		assert(rules_b->audit != NULL);
		for(i = 0; i < policy->num_av_audit; i++) {
			if (rules_b->audit[i])
				continue;
			if (only_enabled && !policy->av_audit[i].enabled)
				continue;
			ans = does_av_rule_use_type(idx, idx_type, whichlists, do_indirect, 
					&(policy->av_audit[i]), &(rules_b->au_cnt), policy);
			if (ans == -1)
				return -1;
			else if (ans) {
				rules_b->audit[i] = TRUE;
			}
		}
	}	
	return 0;
}



/* find all rules that include a given a regular expression*/
static int match_te_rules_regex(regex_t *preg,
			  int ta_opt,
                          bool_t  include_audit, 
                          unsigned char whichlists,	/* indicates src, target, and/or default lists */	
                          bool_t do_indirect,
			  bool_t only_enabled, 
                          rules_bool_t *rules_b,
                          policy_t *policy)	
{
	int i, idx_type, rt;
	char *name;
	if(rules_b == NULL || preg == NULL || policy == NULL)
		return -1;
	if(ta_opt == IDX_TYPE || ta_opt == IDX_BOTH) {
		idx_type = IDX_TYPE;
		for(i = 0; i < policy->num_types; i++) {
			_get_type_name_ptr(i, &name, policy);
			rt = regexec(preg, name, 0, NULL, 0);
			if(rt == 0) {
				rt = match_te_rules_idx(i, idx_type, include_audit, whichlists, do_indirect,
					only_enabled, rules_b, policy);
				if(rt != 0)
					return rt;
			}
		}
	}
	if(ta_opt == IDX_ATTRIB || ta_opt == IDX_BOTH) {
		idx_type = IDX_ATTRIB;
		for(i = 0; i < policy->num_attribs; i++) {
			_get_attrib_name_ptr(i, &name, policy);
			rt = regexec(preg, name, 0, NULL, 0);
			if(rt == 0) {
				rt = match_te_rules_idx(i, idx_type, include_audit, whichlists, do_indirect,
					only_enabled, rules_b, policy);
				if(rt != 0)
					return rt;
			}
		}
	}
	return 0;		
}


/* front-end function for two types of matches (index and regex) */
int match_te_rules(bool_t allow_regex,
			regex_t *preg,			/* regexp array (3 deep), ignore if !allow_regex */
			int ta_opt,			/* for regex, indicates type (0), attrib (1), either/both(2) */
                        int  idx,			/* ta idx, ignore if allow_regex */
                        int  idx_type,			/* ta idx type, for non-regex matches */
                        bool_t  include_audit, 
                        unsigned char whichlists,	/* indicates src, target, and/or default lists */	
                        bool_t do_indirect,
			bool_t only_enabled, 
                        rules_bool_t *rules_b,
                        policy_t *policy) 		
{
	if(allow_regex) { 
		if(!(ta_opt == IDX_TYPE || ta_opt == IDX_ATTRIB || ta_opt == IDX_BOTH))
			return -1;
		return match_te_rules_regex(preg, ta_opt, include_audit, whichlists, do_indirect,
			only_enabled, rules_b, policy);
	}
	else {
		return match_te_rules_idx(idx, idx_type, include_audit, whichlists, do_indirect,
			only_enabled, rules_b, policy);
	}
}

/* If !tgt_is_role and (whichlist & TGT_LIST), then this function will only
 * check role_transition rules, since we know that allow rules don't have
 * a type in their target.  Likewise, if tgt_is_role and (whichlist & TGT_LIST).
 * we only check allow rules since role_transition rules don't have roles
 * as their target.  We only check both rules if !(whichlist & TGT_LIST).
 */
int match_rbac_rules(int	idx,
                     int	type,
                     unsigned char whichlist,
                     bool_t	do_indirect,
                     bool_t	tgt_is_role,
                     rbac_bool_t *b,
                     policy_t	*policy)
{
	int i;
	int ans;
	
	if(b == NULL)
		return -1;
	
	/* Note, DEFAULT_LIST is only used for role_transition rules */
	if((whichlist & (SRC_LIST | TGT_LIST)) && !((whichlist & TGT_LIST) && !tgt_is_role) ) {
		for(i = 0; i < policy->num_role_allow; i++) {
			b->allow[i] = does_role_allow_use_role(idx, whichlist, do_indirect,  &(policy->role_allow[i]),
				&(b->a_cnt));
		}
	}
	if(!((whichlist & TGT_LIST) && tgt_is_role) ) {
		for(i = 0; i < policy->num_role_trans; i++) {
			if(whichlist & (SRC_LIST | DEFAULT_LIST)) {
				b->trans[i] = does_role_trans_use_role(idx, whichlist, do_indirect, 
					&(policy->role_trans[i]), &(b->t_cnt));
			}
			if(!(b->trans[i]) && (whichlist & TGT_LIST) && !tgt_is_role) {
				ans = does_role_trans_use_ta(idx, type, do_indirect, &(policy->role_trans[i]), 
						&(b->t_cnt), policy);
				if (ans == -1)
					return -1;
				b->trans[i] = ans;
			}
		}
	}
	
	return 0;
}

/* the behaviour of this function matches the above, however instead of returning a boolean array
 * with the indices matching rules the indices match roles.
 */

int match_rbac_roles(int	idx,
                     int	type,
                     unsigned char whichlist,
                     bool_t	do_indirect,
                     bool_t	tgt_is_role,
                     rbac_bool_t *b,
		     int *num_matched,
                     policy_t	*policy)
{
	int i;
	ta_item_t *ta;

	if(b == NULL)
		return -1;
	*num_matched = 0;
	if((whichlist & (SRC_LIST ^ TGT_LIST)) && !((whichlist & TGT_LIST) && !tgt_is_role) ) {
		for(i = 0; i < policy->num_role_allow; i++) {
			if (does_role_allow_use_role(idx, whichlist, do_indirect, &(policy->role_allow[i]), &(b->a_cnt))) {
				*num_matched += 1;
                                if (whichlist & TGT_LIST)
                                        ta = policy->role_allow[i].src_roles;
				else
					ta = policy->role_allow[i].tgt_roles;

				while (ta) {
					b->allow[ta->idx] = TRUE;
					ta = ta->next;
				}
			}
		}
	}

	if(!((whichlist & TGT_LIST) && tgt_is_role) ) {
		for(i = 0; i < policy->num_role_trans; i++) {
			if(whichlist & (SRC_LIST ^ DEFAULT_LIST)) {
				if (does_role_trans_use_role(idx, whichlist, do_indirect, &(policy->role_trans[i]), &(b->t_cnt))) {

					if (whichlist & SRC_LIST) {
						ta = policy->role_trans[i].src_roles;
						while (ta) {
							b->trans[ta->idx] = TRUE;
							ta = ta->next;
						}
					}
                                        else
						b->trans[policy->role_trans[i].trans_role.idx] = TRUE;

				}
			}
		}
	}
	
	return 0;
}


/* this function takes in the source role idx, the type/attribute idx
   and searches the role transitions in policy using those two items as
   the key.  If found it assigns rt_idx to the target role idx in policy and
   returns true.  If not found rt_idx is not modified and false is returned
*/
bool_t match_rbac_role_ta(int	rs_idx,
			  int	ta_idx,
			  int   *rt_idx,
			  policy_t	*policy)
{
	int cnt = 0;
	int i;
	int ans;
	/* got through all role trans in policy */
	for(i = 0; i < policy->num_role_trans; i++) {
		/* does this role trans use this role in the src */
		if (does_role_trans_use_role(rs_idx, SRC_LIST, TRUE, &(policy->role_trans[i]), &cnt)) {
			/* does this role trans use this type  */
			ans = does_role_trans_use_ta(ta_idx, IDX_TYPE, TRUE, &(policy->role_trans[i]), 
					     &cnt, policy);		        
			/* if the role trans uses this type */
			if (ans == TRUE) {
				*rt_idx = policy->role_trans[i].trans_role.idx;
				return TRUE;
			}
		}
	}
	return FALSE;
}

/* search and return type enforcement rules based on provided query critiera.  Results are return
 * as arrays of rules indicies 
 *
 * RETURNS:
 *	 0 success, results in r (call must free memory)
 *	-1 general unrecoverable error (bug!)
 *	-2 possible recoverable error, r->err will have error type and r->errmsg will have error message
 * 
 */
int search_te_rules(teq_query_t *q, teq_results_t *r, policy_t *policy)
{
	
	int i, j, rt, sz, ta1 = -1, ta2 = -1, ta3 = -1, ta1_type, ta2_type, ignore_cntr;
	char *err;
	regex_t reg[3];
	bool_t include_audit, use_1, use_2, use_3, *cexprs_b = NULL;
	rules_bool_t rules_src, rules_tgt, rules_default, rules_cond;

	
	if(q == NULL)
		return -1;
	
	if(!validate_te_query(q))
		return -1;
		
	if(init_teq_results(r) != 0)
		return -1;

	include_audit = (q->rule_select & TEQ_AV_AUDIT);
	use_1 = is_ta_used(q->ta1);
	use_2 = (!q->any && is_ta_used(q->ta2));
	use_3 = (!q->any && q->rule_select & TEQ_TYPE && is_ta_used(q->ta3));
	
	if(use_1) {
		if(!is_valid_str_sz(q->ta1.ta)) {
			r->err = TEQ_ERR_TA1_STRG_SZ;
			return -2;
		}
		if(q->use_regex) {
			rt = regcomp(&(reg[0]), q->ta1.ta, REG_EXTENDED|REG_NOSUB);
			if(rt != 0) {
				sz = regerror(rt, &(reg[0]), NULL, 0);
				if((err = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "out of memory");
					return -1;
				}
				regerror(rt, &(reg[0]), err, sz);
				r->err = TEQ_ERR_TA1_REGEX;
				r->errmsg = err;	/* call will free */
				regfree(&(reg[0]));
				return -2;
				
			}
		}
		else {
			ta1 = get_type_or_attrib_idx(q->ta1.ta, &ta1_type, policy);
			if(ta1 < 0 ) {
				r->err = TEQ_ERR_TA1_INVALID;
				return -2;			
			}
		}
	}

	if(use_2) {
		if(!is_valid_str_sz(q->ta2.ta)) {
			r->err = TEQ_ERR_TA2_STRG_SZ;
			if(use_1 && q->use_regex) {
				regfree(&(reg[0]));
				}
			return -2;
		}
		if(q->use_regex) {
			rt = regcomp(&(reg[1]), q->ta2.ta, REG_EXTENDED|REG_NOSUB);
			if(rt != 0) {
				sz = regerror(rt, &(reg[1]), NULL, 0);
				if((err = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "out of memory");
					return -1;
				}
				regerror(rt, &(reg[1]), err, sz);
				if(use_1 && q->use_regex){regfree(&(reg[1]));}
				r->err = TEQ_ERR_TA2_REGEX;
				r->errmsg = err;	/* call will free */
				return -2;
				
			}
		}
		else {
			ta2 = get_type_or_attrib_idx(q->ta2.ta, &ta2_type, policy);
			if(ta2 < 0 ) {
				r->err = TEQ_ERR_TA2_INVALID;
				return -2;			
			}
		}
	}

	if(use_3) {
		if(!is_valid_str_sz(q->ta3.ta)) {
			if(use_1 && q->use_regex) {regfree(&(reg[0]));}
			if(use_2 && q->use_regex) {regfree(&(reg[1]));}
			r->err = TEQ_ERR_TA3_STRG_SZ;
			return -2;
		}
		if(q->use_regex) {
			rt = regcomp(&(reg[2]), q->ta3.ta, REG_EXTENDED|REG_NOSUB);
			if(rt != 0) {
				sz = regerror(rt, &(reg[2]), NULL, 0);
				if((err = (char *)malloc(++sz)) == NULL) {
					fprintf(stderr, "out of memory");
					return -1;
				}
				regerror(rt, &(reg[2]), err, sz);
				r->err = TEQ_ERR_TA3_REGEX;
				r->errmsg = err;	/* call will free */
				if(use_1 && q->use_regex) {regfree(&(reg[0]));}
				if(use_2 && q->use_regex) {regfree(&(reg[1]));}
				return -2;
				
			}
		}
		else {
			/* ta3 can only ever be a type (not attrib) */
			ta3 = get_type_idx(q->ta3.ta, policy);
			if(ta3 < 0) {
				r->err = TEQ_ERR_TA3_INVALID;
				return -2;			
			}
		}
	}

	/* validate the provided classes */
	if(q->classes == NULL && q->num_classes != 0) {
		r->err = TEQ_ERR_INVALID_CLS_Q;
		return -2;
	}
	
	for(i = 0; i < q->num_classes; i++) {
		if(!is_valid_obj_class_idx(q->classes[i], policy)) {
			r->err = TEQ_ERR_INVALID_CLS_IDX;
			rt = -2;
			goto err_return1;
		}
	}
	
	/* validate provided perms */
	if(q->perms == NULL && q->num_perms != 0) {
		r->err = TEQ_ERR_INVALID_PERM_Q;
		return -2;
	}
	
	for(i = 0; i < q->num_perms; i++) {
		if(!is_valid_perm_idx(q->perms[i], policy)) {
			r->err = TEQ_ERR_INVALID_PERM_IDX;
			rt = -2;
			goto err_return1;		}
	}
		
	/* set up match structures */
	if(init_rules_bool(include_audit, &rules_src, policy) != 0) {
		rt = -1;
		goto err_return1;
	}
	if(init_rules_bool(include_audit, &rules_tgt, policy) != 0) {
		free_rules_bool(&rules_src);
		rt = -1;
		goto err_return1;
	}
	if(init_rules_bool(include_audit, &rules_default, policy) != 0) {
		free_rules_bool(&rules_src);
		free_rules_bool(&rules_tgt);
		rt = -1;
		goto err_return1;
	}
	if(init_rules_bool(include_audit, &rules_cond, policy) != 0) {
		free_rules_bool(&rules_src);
		free_rules_bool(&rules_tgt);
		free_rules_bool(&rules_default);
		rt = -1;
		goto err_return1;
	}

	if(use_1) {
		if(match_te_rules(q->use_regex, &(reg[0]), q->ta1.t_or_a, ta1, ta1_type, include_audit, SRC_LIST, q->ta1.indirect, q->only_enabled, &rules_src, policy) != 0) {
			rt = -1;
			goto err_return2;	
		}
	}
	else {
		all_true_rules_bool(&rules_src, policy);
	}
	
	if(use_1 && q->any) { 
		/* since "any", need to check target and default lists too */
		if(match_te_rules(q->use_regex, &(reg[0]), q->ta1.t_or_a, ta1, ta1_type, include_audit, TGT_LIST, q->ta1.indirect, q->only_enabled, &rules_tgt, policy) != 0) {
			rt = -1;
			goto err_return2;	
		}
		if(match_te_rules(q->use_regex, &(reg[0]), IDX_TYPE, ta1, ta1_type, include_audit, DEFAULT_LIST, q->ta1.indirect, q->only_enabled, &rules_default, policy) != 0) {
			rt = -1;
			goto err_return2;	
		}	
	}
	else {
		if(use_2) {
			if(match_te_rules(q->use_regex, &(reg[1]), q->ta2.t_or_a, ta2, ta2_type, include_audit, TGT_LIST, q->ta2.indirect, q->only_enabled, &rules_tgt, policy) != 0) {
				rt = -1;
				goto err_return2;	
			}	
		}
		else {
			all_true_rules_bool(&rules_tgt, policy);
		}
		if(use_3) {
			if(match_te_rules(q->use_regex, &(reg[2]),IDX_TYPE, ta3, IDX_TYPE, include_audit, DEFAULT_LIST, q->ta3.indirect, q->only_enabled, &rules_default, policy) != 0) {
				rt = -1;
				goto err_return2;	
			}	
		}
		else {
			all_true_rules_bool(&rules_default, policy);		
		}
	}

	if (q->bool_name) {
		cexprs_b = (bool_t*)calloc(policy->num_cond_exprs, sizeof(bool_t));
		if (!cexprs_b) {
			rt = -1;
			goto err_return2;
		}
		rt = search_conditional_expressions(1, q->bool_name, q->use_regex, cexprs_b, &err, policy);
		if (rt) {
			rt = -1;
			goto err_return2;
		}
		rt = match_cond_rules(&rules_cond, cexprs_b, include_audit, policy);
	} else {
		all_true_rules_bool(&rules_cond, policy);
	}
	
	/* further select and output matching rules */
	if(q->rule_select & TEQ_AV_ACCESS) {
		for(i = 0, j = 0; i < policy->num_av_access; i++) {
			if(
			   ((q->rule_select & TEQ_ALLOW && (policy->av_access[i].type == RULE_TE_ALLOW)) ||
			   (q->rule_select & TEQ_NEVERALLOW && (policy->av_access[i].type == RULE_NEVERALLOW))) 
			   &&			   
			   ((!q->any && (rules_src.access[i] && rules_tgt.access[i])) ||
			   (q->any && (rules_src.access[i] || rules_tgt.access[i])))
			  &&
			   ( (q->num_classes < 1) || ((q->num_classes > 0) && does_av_rule_use_classes(i, 1, q->classes, q->num_classes, policy)) )
			  &&
			   ( (q->num_perms < 1) || ((q->num_perms > 0) && does_av_rule_use_perms(i, 1, q->perms, q->num_perms, policy)) )
			  &&
				( !q->bool_name || (q->bool_name && rules_cond.access[i]) )
			  )	{
			  	if (q->only_enabled && !policy->av_access[i].enabled)
					continue;
				/* Have a matching AV rule */
				/* first the rule idx */
				if(add_i_to_a(i, &r->num_av_access, &r->av_access) != 0) {
					rt = -1;
					goto err_return2;
				}
				/* and then the rule line #; ignore the counter in this case */
				ignore_cntr = r->num_av_access - 1;
				if(add_i_to_a(policy->av_access[i].lineno, &ignore_cntr, &r->av_access_lineno) != 0) {
					rt = -1;
					goto err_return2;
				}
			}
		}
	}
	if(q->rule_select & TEQ_CLONE ) {
		for(i = 0, j = 0; i < policy->rule_cnt[RULE_CLONE]; i++) {
			if(
			   ((!q->any && (rules_src.clone[i] && rules_tgt.clone[i])) ||
			   (q->any && (rules_src.clone[i] || rules_tgt.clone[i])))
			  ) {
				/* first the rule idx */
				if(add_i_to_a(i, &r->num_clones, &r->clones) != 0) {
					rt = -1;
					goto err_return2;
				}
				/* and then the rule line #; ignore the counter in this case */
				ignore_cntr = r->num_clones - 1;
				if(add_i_to_a(policy->clones[i].lineno, &ignore_cntr, &r->clones_lineno) != 0) {
					rt = -1;
					goto err_return2;
				}
			}
		}
	}
	if(q->rule_select & TEQ_TYPE) { 
		/* only case to use third (default) list */
		for(i = 0, j = 0; i < policy->num_te_trans; i++) {
			if(
			   ((q->rule_select & TEQ_TYPE_TRANS && (policy->te_trans[i].type == RULE_TE_TRANS)) ||
			    (q->rule_select & TEQ_TYPE_MEMBER && (policy->te_trans[i].type == RULE_TE_MEMBER)) ||
			    (q->rule_select & TEQ_TYPE_CHANGE && (policy->te_trans[i].type == RULE_TE_CHANGE)))
			   &&
			   ((!q->any && (rules_src.ttrules[i] && rules_tgt.ttrules[i] && rules_default.ttrules[i])) ||
			    (q->any && (rules_src.ttrules[i] || rules_tgt.ttrules[i] || rules_default.ttrules[i])))
	  		   &&
			   ( (q->num_classes < 1) || ((q->num_classes > 0) && does_tt_rule_use_classes(i, q->classes, q->num_classes, policy)) )
			  &&
				( !q->bool_name || (q->bool_name && rules_cond.ttrules[i]) )
			  ) {
			  	if (q->only_enabled && !policy->te_trans[i].enabled)
					continue;
				/* first the rule idx */
				if(add_i_to_a(i, &r->num_type_rules, &r->type_rules) != 0) {
					rt = -1;
					goto err_return2;
				}
				/* and then the rule line #; ignore the counter in this case */
				ignore_cntr = r->num_type_rules - 1;
				if(add_i_to_a(policy->te_trans[i].lineno, &ignore_cntr, &r->type_lineno) != 0) {
					rt = -1;
					goto err_return2;
				}
			}
		}
	}
	if(include_audit) {
		for(i = 0, j = 0; i < policy->num_av_audit; i++) {
			if(
			   ((q->rule_select & TEQ_AUDITALLOW && (policy->av_audit[i].type == RULE_AUDITALLOW)) ||
			   (q->rule_select & TEQ_AUDITDENY  && (policy->av_audit[i].type == RULE_AUDITDENY)) ||
			   (q->rule_select & TEQ_DONTAUDIT  && (policy->av_audit[i].type == RULE_DONTAUDIT))) 
			   &&
			   ((!q->any && (rules_src.audit[i] && rules_tgt.audit[i])) ||
			   (q->any && (rules_src.audit[i] || rules_tgt.audit[i])))
	  		   &&
			    ( (q->num_classes < 1) || ((q->num_classes > 0) && does_av_rule_use_classes(i, 0, q->classes, q->num_classes, policy)) )
			   &&
			    ( (q->num_perms < 1) || ((q->num_perms > 0) && does_av_rule_use_perms(i, 0, q->perms, q->num_perms, policy)) )
			  &&
				( !q->bool_name || (q->bool_name && rules_cond.audit[i]) )
			  )	{
			  	if (q->only_enabled && !policy->av_audit[i].enabled)
					continue;
				/* first the rule idx */
				if(add_i_to_a(i, &r->num_av_audit, &r->av_audit) != 0) {
					rt = -1;
					goto err_return2;
				}
				/* and then the rule line #; ignore the counter in this case */
				ignore_cntr = r->num_av_audit - 1;
				if(add_i_to_a(policy->av_audit[i].lineno, &ignore_cntr, &r->av_audit_lineno) != 0) {
					rt = -1;
					goto err_return2;
				}
			}
		}
	}

	/* free up temp stuff and return */
	if(use_1 && q->use_regex){regfree(&(reg[0]));}
	if(use_2 && q->use_regex){regfree(&(reg[1]));}
	if(use_3 && q->use_regex){regfree(&(reg[2]));}	
	free_rules_bool(&rules_src);	
	free_rules_bool(&rules_tgt);	
	free_rules_bool(&rules_default);	
	free_rules_bool(&rules_cond);
	
	return 0;	
	
err_return2:
	free_rules_bool(&rules_src);	
	free_rules_bool(&rules_tgt);	
	free_rules_bool(&rules_default);
	free_rules_bool(&rules_cond);
err_return1:
	if(use_1 && q->use_regex) {regfree(&(reg[0]));}
	if(use_2 && q->use_regex) {regfree(&(reg[1]));}
	if(use_3 && q->use_regex) {regfree(&(reg[2]));}
	return rt;
}

/* Search the conditional expressions in the policy. This works like the functions above in that
 * it takes an initialized array of booleans and only marks the indexes in the array true for
 * the conditional expressions that match the boolean name (or regex). The array expr_b should
 * be the same size as policy->num_cond_bool_exprs.
 *
 * RETURNS:
 *	-1 on error
 *	0 on success
 */
int search_conditional_expressions(bool_t use_bool, char *bool, bool_t regex, bool_t *exprs_b, char **error_msg, policy_t *policy)
{
	int i, rt;
	cond_expr_t *cur;
	size_t sz;
	regex_t reg;
	
	if (regex) {
		rt = regcomp(&reg, bool, REG_EXTENDED | REG_NOSUB);
		if (rt != 0) {
			char *err;
			sz = regerror(rt, &reg, NULL, 0);
			if((err = (char *)malloc(++sz)) == NULL) {
				fprintf(stderr, "out of memory");
				return -1;
			}
			regerror(rt, &reg, err, sz);
			*error_msg = err;	/* call will free */
			regfree(&reg);
			return -1;
		}
	}
	
	for (i = 0; i < policy->num_cond_exprs; i++) {
		for (cur = policy->cond_exprs[i].expr; cur != NULL; cur = cur->next) {
			if (cur->expr_type != COND_BOOL)
				continue;
			if (use_bool && regex) {
				rt = regexec(&reg, policy->cond_bools[cur->bool].name, 0, NULL, 0);
				if (rt == 0)
					exprs_b[i] = TRUE;
			} else if (use_bool) {
				if (strcmp(bool, policy->cond_bools[cur->bool].name) == 0)
					exprs_b[i] = TRUE;
			} else {
				exprs_b[i] = TRUE;
			}
		}
	}

	if (regex)
		regfree(&reg);
	return 0;
}

int match_cond_rules(rules_bool_t *rules_b, bool_t *exprs_b, bool_t include_audit, policy_t *policy)
{
	int i;

	if (!policy || !rules_b || !exprs_b)
		return -1;

	for (i = 0; i < policy->num_av_access; i++) {
		if (policy->av_access[i].cond_expr != -1 && exprs_b[policy->av_access[i].cond_expr])
			rules_b->access[i] = TRUE;
	}
	for (i = 0; i < policy->num_te_trans; i++) {
		if (policy->te_trans[i].cond_expr != -1 && exprs_b[policy->te_trans[i].cond_expr])
			rules_b->ttrules[i] = TRUE;
	}

	if (include_audit) {
		assert(rules_b->audit != NULL);
		for (i = 0; i < policy->num_av_audit; i++) {
			if (policy->av_audit[i].cond_expr != -1 && exprs_b[policy->av_audit[i].cond_expr]) 
				rules_b->audit[i] = TRUE;
		}
	}

	return 0;
}

