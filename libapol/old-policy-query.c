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
#include "old-policy-query.h"



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

int free_rtrans_results_contents(rtrans_results_t *r)
{
	if(r == NULL)
		return 0;
	if(r->range_rules != NULL) free(r->range_rules);
	if(r->errmsg != NULL) free(r->errmsg);
	return 0;
}

static int free_search_type(srch_type_t *s)
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
	if(q->bool_name != NULL) free(q->bool_name);
	free_search_type(&q->ta1);
	free_search_type(&q->ta2);
	free_search_type(&q->ta3);
	return 0;
}

static void init_search_type(srch_type_t *s)
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
	init_search_type(&q->ta1);
	init_search_type(&q->ta2);
	init_search_type(&q->ta3);
	q->bool_name = NULL;
	return 0;
}

int init_rtrans_query(rtrans_query_t *q)
{
	if(q == NULL)
		return -1;
	q->src.indirect = q->tgt.indirect = FALSE;
	q->src.ta = q->tgt.ta = NULL;
	q->src.t_or_a = q->tgt.t_or_a = IDX_BOTH;
	q->range = NULL;
	q->use_regex = TRUE;
	q->search_type = 0;
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

int init_rtrans_results(rtrans_results_t *r)
{
	if(r == NULL)
		return -1;
	r->range_rules = NULL;
	r->num_range_rules = 0;
	r->err = 0;
	r->errmsg = NULL;
	return 0;
}

static bool_t validate_search_type(srch_type_t *s)
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
	if(is_ta_used(q->ta1) && !validate_search_type(&q->ta1))
		return FALSE;
	if(!q->any && is_ta_used(q->ta2) && !validate_search_type(&q->ta2))
		return FALSE;
	if(!q->any && is_ta_used(q->ta3) && !validate_search_type(&q->ta3))
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

		/* match against aliases */
		char *alias_name;
		for(i = 0; i < policy->num_aliases; i++) { 
			alias_name =  policy->aliases[i].name;
			rt = regexec(preg, alias_name, 0, NULL, 0); 

			/* if match, add to list for search */
			if (rt == 0) {
				int alias_type_idx = get_type_idx_by_alias_name(alias_name,
						 policy);
				rt = match_te_rules_idx(alias_type_idx, idx_type, include_audit,
						whichlists, do_indirect, only_enabled, rules_b, policy);
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



/************
* Collects the type and attribute indexes that match the search name input.
* Handles regular expression comparison as well as aliases on type. Expands
* attribute names to include all type names in the attribute.
* 
* Input Params:
*  srch_name - string to search to locate index
*  query - range transition query structure; contains search data(i.e. type
*          of search, use regex, etc)
*  reg - location to place compiled regular expression, if any
*  idx_array - location to place found indexes
*  num_idx - number of indexes foundin search
*  results - location for error code and/or string for error handling
*  policy - policy representation
*
* RETURNS:
*	-1 on error or 
*  -2 on error with error string in the rtrans_results_t structure
*	0 on success
*/
static int get_search_type_attrib_idxs (srch_type_t srch,
		int** type_array, int* num_type, int** attrib_array, int* num_attrib, 
		bool_t use_regex,  int* err_value, char** err_msg, policy_t* policy)
{
	int rt, i, j = 0;
	size_t sz = 0;
	char* srch_name = NULL;
	regex_t reg;

	if (use_regex) {
		/* compile regular expression for expression comparison*/
		rt = regcomp(&reg, srch.ta, REG_EXTENDED|REG_NOSUB);
		if (rt != 0) {
			if ((*err_msg == NULL) || (err_msg == NULL)) {
				fprintf(stderr, "Error in regular expression compilation\n ");
				return -1;
			}

			regerror(rt, &reg, *err_msg, sz);
			if (err_value != NULL)
				*err_value = RTRANS_ERR_REGCOMP;  
			regfree(&reg);
			return -2;
		}

		/* for regex, add index of all TYPE regexec matches by index */
		if ((srch.t_or_a == IDX_TYPE) || (srch.t_or_a == IDX_BOTH)) {
			/* compare each type to the compiled regular expressions */
			for(i = 0; i < policy->num_types; i++) { 
				/* get string name of corresponding type id */
				_get_type_name_ptr(i, (char**)&srch_name, policy); 
				rt = regexec(&reg, srch_name, 0, NULL, 0); 

				/* if match, add to src list for search */
				if (rt == 0) {
					if (find_int_in_array(i, *type_array, *num_type) == -1) {
						if (add_i_to_a(i, num_type, type_array) != 0) {
							printf("Out of memory!\n");
							return -1;
						}
					}
				}
			}

			/* compare each alias to the compiled regular expressions */
			char *alias_name;
			for(i = 0; i < policy->num_aliases; i++) { 
				alias_name =  policy->aliases[i].name;
				rt = regexec(&reg, alias_name, 0, NULL, 0); 

				/* if match, add to list for search */
				if (rt == 0) {
					int alias_type_idx = get_type_idx_by_alias_name(alias_name,
							 policy); 
					if (find_int_in_array(alias_type_idx, *type_array, *num_type) == -1) {
						if (add_i_to_a(alias_type_idx, num_type, type_array) != 0) {
							printf("Out of memory!\n");
							return -1;
						}
					}
				}
			}
		}

		if ((srch.t_or_a == IDX_ATTRIB) || (srch.t_or_a == IDX_BOTH))
		{
			for(i = 0; i < policy->num_attribs; i++) { 
				/* get attribute string name */
				_get_attrib_name_ptr(i, (char**)&srch_name, policy); 
				rt = regexec(&reg, srch_name, 0, NULL, 0); 

				/* if match, add to src list for search */
				if (rt == 0) {
					if (find_int_in_array(i, *attrib_array, *num_attrib) == -1) {
						if (add_i_to_a(i, num_attrib, attrib_array) != 0) {
							printf("Out of memory!\n");
							return -1;
						}
					}
				}
			}
		}
		if (!(*num_attrib) && !(*num_type)) {
			if (err_value != NULL)
				*err_value = RTRANS_ERR_SRC_INVALID;
			if ((err_msg != NULL) && (*err_msg != NULL))
				sprintf(*err_msg, "\nError: %s is not a valid type or attribute"
						"\n", srch.ta);
			else
				printf("\nError: %s is not a valid type or attribute"
						"\n", srch.ta);
			return -2;
		}
		regfree(&reg);
	}

	/* no regex, just find index of passed source name */
	else {
		int idx_value = 0;
		int idx_type = 0;
		if ((idx_value = get_type_or_attrib_idx(srch.ta, &idx_type, policy))
				 < 0) {
			if (err_value != NULL)
				*err_value = RTRANS_ERR_SRC_INVALID;
			if ((err_msg != NULL) && (*err_msg != NULL))
				sprintf(*err_msg, "\nError: %s is not a valid type or attribute"
						"\n", srch.ta);
			else
				printf("\nError: %s is not a valid type or attribute"
						"\n", srch.ta);

			return -2;
		}

		if (idx_type == IDX_ATTRIB) {
			if (find_int_in_array(idx_value, *attrib_array, *num_attrib) == -1) {
				if (add_i_to_a(idx_value, num_attrib, attrib_array) != 0) {
					printf("Out of memory!\n");
					return -1;
				}
			}
		} else {
			if (find_int_in_array(idx_value, *type_array, *num_type) == -1) {
				if (add_i_to_a(idx_value, num_type, type_array) != 0) {
					printf("Out of memory!\n");
					return -1;
				}
			}
		}
	}

	/* for each collected type, if indirect get corresponding attributes */
	if (srch.indirect && *num_type) {
		for (i = 0; i < *num_type; i++) {
			type_item_t type_info = policy->types[(*type_array)[i]];
   			for(j = 0; j < type_info.num_attribs; j++) {
           		if (find_int_in_array(type_info.attribs[j], *attrib_array, 
						*num_attrib) == -1) {
					if (add_i_to_a(type_info.attribs[j], num_attrib, 
						attrib_array) != 0) {
		   				printf("Out of memory!\n");
			     		return -1;
					}
				}
			}
		}
	}

	return 0;
}



/************
 * Search range transition rules in the policy.  rtrans_query_t contains any src
 * and target names that may have been supplied for filtering.  The input names
 * are identified by index and expanded into types if it is an attribute, and 
 * compared against the corresponding src and tgt of the range transition rule.
*
*  Input:
*  query - range transition query structure; contains search data(i.e. type
*          of search, use regex, etc)
*  results - location for return results, error code and/or string for error 
*          handling, etc
*  policy - policy representation
 *
 * RETURNS:
 *	-1 on error or 
 *	-2 on error with error string in the rtrans_results_t structure
 *	0 on success
 */
int search_range_transition_rules(rtrans_query_t* query, 
		rtrans_results_t* results, policy_t* policy)
{
	int rt = 0;
	int i = 0;
	int* src_types = 0;
	int* src_attribs =  0;
	int* tgt_types = 0;
	int* tgt_attribs = 0;
	int num_src_types = 0;
	int num_src_attribs = 0;
	int num_tgt_types = 0;
	int num_tgt_attribs = 0;
	int num_rules = 0;
	int num_total_rules = 0;
	int* search_results = 0;

	if (results->errmsg == NULL) {
		if ((results->errmsg = (char*) malloc(200)) == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
	}

	if (query->src.ta == 0 && query->tgt.ta == 0) {
		for (i = 0; i < policy->num_rangetrans; i++) {
			add_i_to_a(i, &(results->num_range_rules), &(results->range_rules));
		}
		return 0;
	}


	if (query->src.ta != 0) {
		rt = get_search_type_attrib_idxs(query->src,
				&src_types, &num_src_types, &src_attribs, 
				&num_src_attribs, query->use_regex, &(results->err), 
				&(results->errmsg), policy);	
		if (rt != 0){
			return (rt);
		}
	}

	if (query->tgt.ta) {
		rt = get_search_type_attrib_idxs(query->tgt, 
				&tgt_types, &num_tgt_types, &tgt_attribs, 
				&num_tgt_attribs, query->use_regex, &(results->err), 
				&(results->errmsg), policy);	
		if (rt != 0){
			return (rt);
		}
	}

	/* TODO: add mls range types and set the high and low of the range */
	/* match against src and tgt types */

	if (num_src_types || num_src_attribs ) {
		/* if not target search input then just run search for src types
		   and attributes */
		if (!num_tgt_types && !num_tgt_attribs) {
			if (num_src_types > 0) {
				num_rules = ap_mls_range_transition_search(src_types, 
					num_src_types, IDX_TYPE, 0, 0, 0, query->range,
					query->search_type, &search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}

				else 
					goto return_error;
			}

			/* run for src attribute matches with no target input */
			if (num_src_attribs > 0) {
				num_rules = ap_mls_range_transition_search(src_attribs, 
					num_src_attribs, IDX_ATTRIB, 0, 0, 0, query->range,
					query->search_type, &search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}
				else 
					goto return_error;
			}
		}
		/* else there is at least one tgt list to run with at least one */
		else {
			if (num_src_types && num_tgt_types) {
				num_rules = ap_mls_range_transition_search(src_types, 
					num_src_types, IDX_TYPE, tgt_types, num_tgt_types, IDX_TYPE,
					query->range, query->search_type, &search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}
				else
					goto return_error;
			}

			if (num_src_types && num_tgt_attribs) {
				num_rules = ap_mls_range_transition_search(src_types, 
			    	num_src_types, IDX_TYPE, tgt_attribs, num_tgt_attribs, 
			    	IDX_ATTRIB, query->range, query->search_type, 
			    	&search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}
				else
					goto return_error;
			}

			if (num_src_attribs && num_tgt_types) {
				num_rules = ap_mls_range_transition_search(src_attribs, 
			    	num_src_attribs, IDX_ATTRIB, tgt_types, num_tgt_types, 
			    	IDX_TYPE, query->range, query->search_type, 
			    	&search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}
				else
					goto return_error;
			}

			if (num_src_attribs && num_tgt_attribs) {
				num_rules = ap_mls_range_transition_search(src_attribs, 
			    	num_src_attribs, IDX_ATTRIB, tgt_attribs, num_tgt_attribs, 
			    	IDX_ATTRIB, query->range, query->search_type, 
			    	&search_results, policy);
				if (num_rules >= 0) {
					for (i = 0; i < num_rules; i++)
						add_i_to_a(search_results[i], &num_total_rules, 
							&(results->range_rules));
					free(search_results);
					search_results = NULL;
				}
				else
					goto return_error;
			}
		}
	} /* else no src input and ony target input to search */
	else {
		if (num_tgt_types) {
			num_rules = ap_mls_range_transition_search(0, 
				0, 0, tgt_types, num_tgt_types, IDX_TYPE, query->range,
				query->search_type, &search_results, policy);
			if (num_rules >= 0) {
				for (i = 0; i < num_rules; i++)
					add_i_to_a(search_results[i], &num_total_rules, 
						&(results->range_rules));
					free(search_results);
					search_results = NULL;
			}
			else 
				goto return_error;
		}

		if (num_tgt_attribs) {
			num_rules = ap_mls_range_transition_search(0, 0, 0, tgt_attribs, 
				num_tgt_attribs, IDX_ATTRIB, query->range, query->search_type, 
				&search_results, policy);
			if (num_rules >= 0) {
				for (i = 0; i < num_rules; i++)
					add_i_to_a(search_results[i], &num_total_rules, 
						&(results->range_rules));
					free(search_results);
					search_results = NULL;
			}
			else 
				goto return_error;
		}
	}


	results->num_range_rules = num_total_rules;
	
	free(src_types);
	free(src_attribs);
	free(tgt_types);
	free(tgt_attribs);
	return 0;

return_error: 
	printf("Error in range transition search; returning\n");
	results->err = rt;
	if (results->errmsg == NULL) {
		if ((results->errmsg = (char*) malloc(200)) == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
	}
	if (rt == -1 || rt == -2) {
		strcpy(results->errmsg, "No valid types for target input\n");
	}
	else if (rt == -3 || rt == -4){
		strcpy(results->errmsg, "No valid types for src input search\n");
	}
	else if (rt == -5 ){
		strcpy(results->errmsg, "Invalid range\n");
	}
	else if (rt == -6 ){
		strcpy(results->errmsg, "Invalid search type\n");
	}
	free(src_types);
	free(src_attribs);
	free(tgt_types);
	free(tgt_attribs);
	return -2;
}

int search_rbac_rules(rbac_query_t *query, rbac_results_t *results, policy_t *policy)
{
	rbac_bool_t master, secondary, tmp;
	int idx = -1, type, i, retv = 0, error = 0;
	regex_t reg;

	if (!query || !results || !policy) {
		errno = EINVAL;
		return -1;
	}

	init_rbac_bool(&master, policy, 0);
	init_rbac_bool(&secondary, policy, 0);
	init_rbac_bool(&tmp, policy, 0);

	all_true_rbac_bool(&master, policy);
	all_false_rbac_bool(&secondary, policy);

	if (query->use_regex) {
		if (query->src) {
			if (regcomp(&reg, query->src, REG_EXTENDED|REG_NOSUB)) {
				error = errno;
				results->err = RBAC_ERR_REGCOMP;
				results->errmsg = strdup("Invalid regular expression");
				retv = -2;
				goto err;
			}
			for (i = 0; i < policy->num_roles; i++) {
				if (!regexec(&reg,  policy->roles[i].name, 0, NULL, 0)) {
					match_rbac_rules(i, IDX_ROLE, SRC_LIST, 0, 0, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			rbac_bool_and_eq(&master, &secondary, policy);
			all_false_rbac_bool(&secondary, policy);
			regfree(&reg);
		}
		if (query->tgt_ta && (query->rule_select & RBACQ_RTRANS)) {
			if (regcomp(&reg, query->tgt_ta, REG_EXTENDED|REG_NOSUB)) {
				error = errno;
				results->err = RBAC_ERR_REGCOMP;
				results->errmsg = strdup("Invalid regular expression");
				retv = -2;
				goto err;
			}
			for (i = 0; i < policy->num_types; i++) {
				if (!regexec(&reg,  policy->types[i].name, 0, NULL, 0)) {
					match_rbac_rules(i, IDX_TYPE, TGT_LIST, query->indirect, 0, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			for (i = 0; i < policy->num_aliases; i++) {
				if (!regexec(&reg,  policy->aliases[i].name, 0, NULL, 0)) {
					match_rbac_rules(policy->aliases[i].type, IDX_TYPE, TGT_LIST, query->indirect, 0, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			for (i = 0; i < policy->num_attribs; i++) {
				if (!regexec(&reg,  policy->attribs[i].name, 0, NULL, 0)) {
					match_rbac_rules(i, IDX_ATTRIB, TGT_LIST, query->indirect, 0, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			/* set all role allows to true since they don't the default list */
			memset(secondary.allow, 1, policy->num_role_allow * sizeof(bool_t));
			rbac_bool_and_eq(&master, &secondary, policy);
			all_false_rbac_bool(&secondary, policy);
			regfree(&reg);
		}
		if (query->tgt_role && (query->rule_select & RBACQ_RALLOW)) {
			if (regcomp(&reg, query->tgt_role, REG_EXTENDED|REG_NOSUB)) {
				error = errno;
				results->err = RBAC_ERR_REGCOMP;
				results->errmsg = strdup("Invalid regular expression");
				retv = -2;
				goto err;
			}
			for (i = 0; i < policy->num_roles; i++) {
				if (!regexec(&reg,  policy->roles[i].name, 0, NULL, 0)) {
					match_rbac_rules(i, IDX_ROLE, TGT_LIST, 0, 1, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			/* set all role transitions to true since they don't use roles as targets */
			memset(secondary.trans, 1, policy->num_role_trans * sizeof(bool_t));
			rbac_bool_and_eq(&master, &secondary, policy);
			all_false_rbac_bool(&secondary, policy);
			regfree(&reg);
		}
		if (query->dflt && (query->rule_select & RBACQ_RTRANS)) {
			if (regcomp(&reg, query->dflt, REG_EXTENDED|REG_NOSUB)) {
				error = errno;
				results->err = RBAC_ERR_REGCOMP;
				results->errmsg = strdup("Invalid regular expression");
				retv = -2;
				goto err;
			}
			for (i = 0; i < policy->num_roles; i++) {
				if (!regexec(&reg,  policy->roles[i].name, 0, NULL, 0)) {
					match_rbac_rules(i, IDX_ROLE, DEFAULT_LIST, 0, 0, &tmp, policy);
					rbac_bool_or_eq(&secondary, &tmp, policy);
					all_false_rbac_bool(&tmp, policy);
				}
			}
			/* set all role allows to true since they don't the default list */
			memset(secondary.allow, 1, policy->num_role_allow * sizeof(bool_t));
			rbac_bool_and_eq(&master, &secondary, policy);
			all_false_rbac_bool(&secondary, policy);
			regfree(&reg);
		}
	} else {
		if (query->src) {
			idx = get_role_idx(query->src, policy);
			if (idx == -1) {
				results->err = RBAC_ERR_SRC_INV;
				results->errmsg = strdup("Invalid source role");
				error = ENOENT;
				retv = -2;
				goto err;
			}
			match_rbac_rules(idx, IDX_ROLE, SRC_LIST, 0, 0, &tmp, policy);
			rbac_bool_and_eq(&master, &tmp, policy);
			all_false_rbac_bool(&tmp, policy);
		}
		if (query->tgt_ta && (query->rule_select & RBACQ_RTRANS)) {
			idx = get_type_or_attrib_idx(query->tgt_ta, &type, policy);
			if (idx == -1) {
				results->err = RBAC_ERR_TGTT_INV;
				results->errmsg = strdup("Invalid target type/attribute");
				error = ENOENT;
				retv = -2;
				goto err;
			}
			match_rbac_rules(idx, type, TGT_LIST, query->indirect, 0, &tmp, policy);
			/* set all role allows to true since they don't use types as targets */
			memset(tmp.allow, 1, policy->num_role_allow * sizeof(bool_t));
			rbac_bool_and_eq(&master, &tmp, policy);
			all_false_rbac_bool(&tmp, policy);
		}
		if (query->tgt_role && (query->rule_select & RBACQ_RALLOW)) {
			idx = get_role_idx(query->tgt_role, policy);
			if (idx == -1) {
				results->err = RBAC_ERR_TGTR_INV;
				results->errmsg = strdup("Invalid target role");
				error = ENOENT;
				retv = -2;
				goto err;
			}
			match_rbac_rules(idx, IDX_ROLE, TGT_LIST, 0, 1, &tmp, policy);
			/* set all role transitions to true since they don't use roles as targets */
			memset(tmp.trans, 1, policy->num_role_trans * sizeof(bool_t));
			rbac_bool_and_eq(&master, &tmp, policy);
			all_false_rbac_bool(&tmp, policy);
		}
		if (query->dflt && (query->rule_select & RBACQ_RTRANS)) {
			idx = get_role_idx(query->dflt, policy);
			if (idx == -1) {
				results->err = RBAC_ERR_DFLT_INV;
				results->errmsg = strdup("Invalid default role");
				error = ENOENT;
				retv = -2;
				goto err;
			}
			match_rbac_rules(idx, IDX_ROLE, DEFAULT_LIST, 0, 0, &tmp, policy);
			/* set all role allows to true since they don't the default list */
			memset(tmp.allow, 1, policy->num_role_allow * sizeof(bool_t));
			rbac_bool_and_eq(&master, &tmp, policy);
			all_false_rbac_bool(&tmp, policy);
		}
	}

	for (i = 0; i < policy->num_role_allow && (query->rule_select & RBACQ_RALLOW); i++) {
		if (master.allow[i]) {
			if (add_i_to_a(i, &results->num_role_allows, &results->role_allows)) {
				error = errno;
				retv = -1;
				goto err;
			}
		}
	}

	for (i = 0; i < policy->num_role_trans && (query->rule_select & RBACQ_RTRANS); i++) {
		if (master.trans[i]) {
			if (add_i_to_a(i, &results->num_role_trans, &results->role_trans)) {
				error = errno;
				retv = -1;
				goto err;
			}
		}
	}

	free_rbac_bool(&master);
	free_rbac_bool(&secondary);
	free_rbac_bool(&tmp);
	return 0;

err:
	free_rbac_bool(&master);
	free_rbac_bool(&secondary);
	free_rbac_bool(&tmp);
	errno = error;
	return retv;
}

int init_rbac_query(rbac_query_t *q)
{
	if (!q) {
		errno = EINVAL;
		return -1;
	}

	q->src = NULL;
	q->tgt_ta = NULL;
	q->tgt_role = NULL;
	q->dflt = NULL;
	q->use_regex = FALSE;
	q->indirect = FALSE;
	q->rule_select = RBACQ_NONE;

	return 0;
}

int init_rbac_results(rbac_results_t *r)
{
	if (!r) {
		errno = EINVAL;
		return -1;
	}

	r->role_allows = NULL;
	r->num_role_allows = 0;
	r->role_trans = NULL;
	r->num_role_trans = 0;
	r->err = 0;
	r->errmsg = NULL;

	return 0;
}

int free_rbac_query(rbac_query_t *q)
{
	if (!q)
		return 0;

	free(q->src);
	free(q->tgt_ta);
	free(q->tgt_role);
	free(q->dflt);

	return 0;
}

int free_rbac_results(rbac_results_t *r)
{
	if (!r)
		return 0;

	free(r->role_allows);
	free(r->role_trans);
	free(r->errmsg);

	return 0;
}
