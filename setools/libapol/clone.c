 /* Copyright (C) 2001 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* apolicy 
 *
 * Functions to resolve clone rules dynamically */
#include "policy.h"
#include "util.h"
#include <stdio.h>
#include <assert.h>


/* Find TE rules that match as a result of clone rules.  For our analysis policy DB,
 * we don't expand the DB to add rules cloned....rather we store the clone rule and
 * then resolve cloned rules when asked for matches (using this function).  The clone
 * rule has some specical cases, and there are some tricky differences between
 * checkpolicy and here.  Some of the interesting cases are:
 *
 * 1. If the rule is RULE_TE_TRANS (type_transition) and the object class is 'process',
 *    checkpolicy does not clone the rule if the 'default' type in the type_transition
 *    rule is equal to either the clone rule's src or tgt types.
 *
 * 2. For all AV rules, checkpolicy does not clone the rule if the AV's rule tgt type is
 *    is equal to either the clone rule's src or tgt types.
 *
 * 3. Since we don't expand our rules to remove attributes (unlike checkpolicy), we have to 
 *    deal with attribute resolution when searching for matches.  However, we have to be 
 *    mindful of the two special cases above.  Since attributes usually match more than
 *    one type, we can't simply throw out a clone if the clone rule's src or tgt types
 *    mactch per case 1 or 2 above.  If the attribute has more than one associated type,
 *    then we would treat it as a "cloned" rule.
 *
 * NOTE: Rules are cloned only if the clone's src type is equal to the rule's src type (i.e.,
 * the clone's type refers to "DOMAINS" which are always represented by the src type.
 */

/* return 1 on match, 0 otherwise */ 
static bool_t attrib_has_single_matching_type(int idx, name_a_t *attrib)
{
	if(attrib->num == 1 && attrib->a[0] == idx)
		return 1;
	else
		return 0;
}


/* return 1 if the special rules didn't prevent a match, 0 otherwise */ 
static bool_t check_clone_specials_av(int src_idx, int tgt_idx, av_item_t *av_rule, policy_t *policy)
{
	ta_item_t *ptr;
	bool_t ans1, ans2;

	/* we go through attribs/types ensuring that they are not just the src and tgt
	 * types (or single attributes for those types).  I.e., we're looking for an idication that a type other 
	 * than just the src and/or idx types are used in the rule's target field. */
	for(ptr = av_rule->tgt_types; ptr != NULL; ptr = ptr->next) {
		if(ptr->type == IDX_TYPE) {
			if(ptr->idx != src_idx && ptr->idx != tgt_idx)
				return 1;
		}
		else {
			ans1 = attrib_has_single_matching_type(src_idx, &(policy->attribs[ptr->idx]));
			ans2 = attrib_has_single_matching_type(tgt_idx, &(policy->attribs[ptr->idx]));
			if(!ans1 && !ans2)
				return 1;
		}		
	}
	
	return 0; /* i.e., the AV rule's target field relates ONLY to the clone's src and/or tgt types */
}

/* return 1 if the special rules didn't prevent a match, 0 otherwise */ 
/* for TT rules, all we care about is the default type.  Since clone's src and tgt, and TT's default
 * are all ONLY types, we don't have to worry about resolving attributes! */
static bool_t check_clone_specials_tt(int src_idx, int tgt_idx, tt_item_t *tt_rule, policy_t *policy)
{
	bool_t ans;
	/* only type transition rules */
	if(tt_rule->type != RULE_TE_TRANS)
		return 1;
	
	/* only if they relate to process object class */
	ans = is_name_in_list("process", tt_rule->classes, policy);
	if(!ans)
		return 1;
	
	if(tt_rule->dflt_type.idx == src_idx || tt_rule->dflt_type.idx == tgt_idx)
		return 0;
	
	return 1;
}

/* FIX: BUG....need to address '~' and '*', and test the logic here more...clones are tricky
 * when we aren't expanding rules! */
int match_cloned_rules(int  idx,			
                             bool_t include_audit,
                             rules_bool_t *rules_b,
                             policy_t *policy
                             )
{
	int i, cnt;
	int ans;
	cln_item_t *ptr;
	if(rules_b == NULL || policy == NULL || idx >= policy->num_types)
		return -1;
		
	for(ptr = policy->clones; ptr != NULL; ptr = ptr->next) {
		/* A clone rule copies the rules for the src type to the tgt type, except 
		 * for the special cases above; so we check if the clone rule's tgt matches our idx */
		if(idx == ptr->tgt) {
			/* access AV rules */
			for(i = 0; i < policy->num_av_access; i++) {
				/* if the rule is already recorded as a match, don't waste time checking again */
				if(rules_b->access[i])
					break;
				/* Since the clone's tgt relates to our idx, we have to see if the clone's
				 * src is in the src type/attrib list for all rules, and if so and if special
				 * checks don't say otherwise, we record that rule as being "cloned" for the 
				 * provided type 'idx' */
				ans = does_av_rule_use_type(ptr->src, IDX_TYPE, SRC_LIST, 1, &(policy->av_access[i]),
						&cnt, policy);
				if (ans == -1)
					return -1;
				else if(ans) {
					ans = check_clone_specials_av(ptr->src, ptr->tgt, &(policy->av_access[i]), policy);
					if(ans) {
						rules_b->access[i] = 1;
						(rules_b->ac_cnt)++;
					}
				}
			}
			/* TT rules */
			for(i = 0; i < policy->num_te_trans; i++) {
				if(rules_b->ttrules[i])
					break;
				ans = does_tt_rule_use_type(ptr->src, IDX_TYPE, SRC_LIST, 1,
						&(policy->te_trans[i]), &cnt, policy);
				if (ans == -1)
					return -1;
				else if(ans) {
					ans = check_clone_specials_tt(ptr->src, ptr->tgt, &(policy->te_trans[i]), policy);
					if(ans) {
						rules_b->ttrules[i] = 1;
						(rules_b->tt_cnt)++;
					}
				}
			}
			/* audit AV rules */
			if(include_audit) {
				for(i = 0; i < policy->num_av_audit; i++) {
					/* if the rule is already recorded as a match, don't waste time checking again */
					if(rules_b->audit[i])
						break;
					/* Since the clone's tgt relates to our idx, we have to see if the clone's
					 * src is in the src type/attrib list for all rules, and if so and if special
					 * checks don't say otherwise, we record that rule as being "cloned" for the 
					 * provided type 'idx' */
					ans = does_av_rule_use_type(ptr->src, IDX_TYPE, SRC_LIST, 1, &(policy->av_audit[i]),
							&cnt, policy);
					if (ans == -1)
						return -1;
					else if (ans) {
						ans = check_clone_specials_av(ptr->src, ptr->tgt, &(policy->av_audit[i]), policy);
						if(ans) {
							rules_b->audit[i] = 1;
							(rules_b->au_cnt)++;
						}
					}
				}				
			}		
		}
	}
	
	return 0;
}
