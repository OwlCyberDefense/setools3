/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * avsemantics.c
 *
 * Support for semantically examining the TE rules for a policy
 * via a hash table.
 */

#include "avhash.h"
#include "avsemantics.h"
#include "../policy.h"

#include <stdio.h>
#include <assert.h>


bool_t avh_is_enabled(avh_node_t *node, policy_t *p)
{
	if(node == NULL || p == NULL) {
		assert(0);
		return FALSE;
	}
	
	assert(node->rules != NULL);
	/* the enabled state should be the same for all associated rules, so
	 * we can simply take the state of the first rule */
	switch(node->key.rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		assert(is_valid_av_rule_idx(node->rules->rule, 1, p));
		return p->av_access[node->rules->rule].enabled;
		break;
	case RULE_AUDITALLOW:
	case RULE_AUDITDENY:
	case RULE_DONTAUDIT:
		assert(is_valid_av_rule_idx(node->rules->rule, 0, p));
		return p->av_audit[node->rules->rule].enabled;
		break;
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		assert(is_valid_tt_rule_idx(node->rules->rule, p));
		return p->te_trans[node->rules->rule].enabled;
		break;
	default:
		assert(0);
		return FALSE;
		break;
	}
	/* shouldn't get here */
	assert(0);
	return FALSE;
}

 
/* Determine is a provided conditional type rule is valid for exntry into the hash
 * table.  Valid means that there is NOT an unconditional type rule with the same
 * key, AND there is NOT a conditional type rule with the same key UNLESS it's in the
 * same conditional BUT on the opposite true/false list */
static bool_t avh_is_valid_cond_type_rule(avh_key_t *key, int cond_expr, bool_t cond_list, policy_t *p) 
{
	//TODO:
	return TRUE;	
}


/* if(is_av), then it is a access/audit rule, otherwise a type rule */
static int avh_load_avrules( void *r, int num, bool_t is_av, policy_t *p)
{
	int i, j, k, x, y, rt, start;
	int num_src, num_tgt, num_src_tilda = 0, num_tgt_tilda = 0, num_cls, num_perm, pidx, *src_a, *tgt_a, *cls_a, *perm_a, dflt = -1, cond_expr = -1;
	bool_t all_src, all_tgt, all_cls, all_perms = FALSE, is_cond, cond_list = FALSE, self = FALSE, src_tilda, tgt_tilda;
	avh_key_t  key;
	avh_node_t *node;
	
	if(r == NULL) {
		assert(num == 0);
		return 0;
	}
		
	if(p == NULL)
		return -1;
	
	
	for(i = 0; i < num ; i++) {
		if(is_av) {
			/* TODO: As of now, we cannot handle neverallow rules in the hash table.  
			 * They expand too greatly, and they are not in binary policies in any case. */
			if(((av_item_t *)r)[i].type ==  RULE_NEVERALLOW)
				continue;
			
			src_tilda = (((av_item_t *)r)[i].flags & AVFLAG_SRC_TILDA);
			tgt_tilda = (((av_item_t *)r)[i].flags & AVFLAG_TGT_TILDA);
			if(is_cond_rule(((av_item_t *)r)[i]) ) {
				is_cond = TRUE;
				cond_expr = ((av_item_t *)r)[i].cond_expr;
				cond_list = ((av_item_t *)r)[i].cond_list;
			}
			else {
				is_cond = FALSE;
			}
		}
		else {
			src_tilda = (((tt_item_t *)r)[i].flags & AVFLAG_SRC_TILDA);
			tgt_tilda = (((tt_item_t *)r)[i].flags & AVFLAG_TGT_TILDA);
			if(is_cond_rule(((tt_item_t *)r)[i]) ) {
				is_cond = TRUE;
				cond_expr = ((tt_item_t *)r)[i].cond_expr;
				cond_list = ((tt_item_t *)r)[i].cond_list;
			}
			else {
				is_cond = FALSE;
			}
		}
				
		src_a = tgt_a = cls_a = perm_a = NULL;
		
		if(is_av) {
			key.rule_type = ((av_item_t *)r)[i].type;
			assert(key.rule_type >= 0 && key.rule_type <= RULE_MAX_AV);
		}
		else {
			key.rule_type = ((tt_item_t *)r)[i].type;
			assert(key.rule_type >= RULE_TE_TRANS && key.rule_type <= RULE_MAX_TE);
		}
		
		/* extract all the rule elements */
		rt = extract_types_from_te_rule(i, key.rule_type, SRC_LIST, &src_a, &num_src, &self, p);
		if(rt == -1)
			goto err_return;
		else if(rt == 2) {
			all_src = TRUE;
		}
		else {
			all_src = FALSE;
			if(src_tilda) {
				num_src_tilda = num_src;
				num_src = num_types(p);
			}
		}
			
		rt = extract_types_from_te_rule(i, key.rule_type, TGT_LIST, &tgt_a, &num_tgt, &self, p);
		if(rt == -1)
			goto err_return;
		else if (rt == 2) {
			all_tgt = TRUE;
		}
		else {
			all_tgt = FALSE;
			if(tgt_tilda) {
				num_tgt_tilda = num_tgt;
				num_tgt = num_types(p);
			}
		}
		/* if the target type is self, we have some more work; in this case, the returned list is the same
		 * as the source list.  We won't need the target list since all we do is add every source to themselves;
		 */
		if(!all_tgt && self) {
			num_tgt = 1; /* always 1 for self, since it is just the current source */
			free(tgt_a);
			tgt_a = NULL;
		}
			
		rt = extract_obj_classes_from_te_rule(i, key.rule_type, &cls_a, &num_cls, p);
		if(rt == -1) 
			goto err_return;
		else if(rt == 2)
			all_cls = TRUE;
		else 
			all_cls = FALSE;
		
		if(is_av) {
			rt = extract_perms_from_te_rule(i, key.rule_type, &perm_a, &num_perm, p);
			if(rt == -1) 
				goto err_return;
			else if(rt == 2) 
				all_perms = TRUE;
			else
				all_perms = FALSE;
		}
		else {
			dflt = ((tt_item_t *)r)[i].dflt_type.idx;
			assert(is_valid_type_idx(dflt, p));
		}
		
		/* iterate thru all rule key combinations and perms */
		if(all_src || src_tilda) 
			start = 1; /* skip over self type */
		else
			start = 0;
		for(j = start; j < num_src; j++) {
			if(all_src)
				key.src = j;
			else if(src_tilda) {
				if(find_int_in_array(j, src_a, num_src_tilda) < 0) 
					key.src = j; /* a type not in the src */
				else
					continue;
			}
			else
				key.src = src_a[j];
			assert(is_valid_type_idx(key.src, p));
			
			if(all_tgt || tgt_tilda) 
				start = 1; /* skip over self type */
			else
				start = 0;
			for(k = start; k < num_tgt; k++) {
				if(all_tgt)
					key.tgt = k;
				else if(tgt_tilda) {
					if(find_int_in_array(k, tgt_a, num_tgt_tilda) < 0) 
						key.tgt = k; /* a type not in the tgt */
					else
						continue;
				}
				else {
					if(self) 
						key.tgt = key.src;
					else
						key.tgt = tgt_a[k];
				}
				assert(is_valid_type_idx(key.tgt, p));
				
				for(x = 0; x < num_cls; x++) { 
					if(all_cls)
						key.cls = x;
					else
						key.cls = cls_a[x];
					assert(is_valid_obj_class_idx(key.cls, p));
					
					/* We now need to enforce the semantic for conditional type rules 
					 * where there can only be two matching keys for type rules iff 
					 * the two rules are in the SAME conditional, but DIFFERENT true/false list.  
					 * So if there is a non-conditional type rule of the same key, the conditional 
					 * type rule is invalid.  Likewise if there are two conditional type rules with 
					 * the same key, they are only valid if their conditionals are the same and the 
					 * reside in opposite lists */
					if(is_cond && !is_av && !avh_is_valid_cond_type_rule(&key, cond_expr, cond_list, p)) {
						fprintf(stderr, "Warning: invalid conditional type_ rule; skipped\n");
						continue;
					}
					
					/* at this point, we have a complete key */
					for(node = avh_find_first_node(&p->avh, &key); node != NULL; node = avh_find_next_node(node) ) {
						if(node->flags & AVH_FLAG_COND) {
							if(!is_cond)
								continue;
							/* for conditional rules, we need to check whether the
							 * same conditional and rule within the conditional
							 * are used for the match; otherwise it really isn't a 
							 * match */
							if(!(node->cond_expr == cond_expr && node->cond_list == cond_list))
								continue;
							/* at this point it is a matching conditional node associated
							 * with same cond expression on the same rule list */

							break;
						}							
						else if(!is_cond)
							break; /* found a matching node */
						else
							continue;
					}
							
					if(node == NULL) {
						/* key doesn't exist; add it */
						node = avh_insert(&p->avh, &key);
						if(node == NULL) {
							assert(0);
							goto err_return;
						}
						if(is_cond) {
							node->flags |= AVH_FLAG_COND;
							node->cond_expr = cond_expr;
							node->cond_list = cond_list;
						}
					}
					if(is_av) {
						if(all_perms) {
							num_perm = get_num_perms_for_obj_class(key.cls, p);
						}
						/* add our perm list */
						for(y = 0; y < num_perm; y++) {
							if(all_perms)
								pidx = get_obj_class_nth_perm_idx(key.cls, y, p);
							else
								pidx = perm_a[y];
							assert(is_valid_perm_idx(pidx, p));
	
							rt = avh_add_datum(node, pidx);
							if(rt < 0) {
								assert(0);
								goto err_return;
							}
						}
					}
					else {
						/* add the default type */
						rt = avh_add_datum(node, dflt);
							if(rt < 0) {
								assert(0);
								goto err_return;
							}
					}
					/* note this rule in the node's list of rule */
					/* TODO: set the hint for this rule */
					rt = avh_add_rule(node, i, 0);
				}
			}
		}
		if(src_a != NULL) free(src_a);
		if(tgt_a != NULL) free(tgt_a);
		if(cls_a != NULL) free(cls_a);
		if(perm_a != NULL) free(perm_a);
	}
	
	return 0;
	
err_return:
	avh_free(&p->avh);
	if(src_a != NULL) free(src_a);
	if(tgt_a != NULL) free(tgt_a);
	if(cls_a != NULL) free(cls_a);
	if(perm_a != NULL) free(perm_a);
	return -1;
}


int avh_build_hashtab(policy_t *p)
{
	int rt;
	if(p == NULL || avh_hash_table_present(p->avh)) 
		return -1;
	
	assert(p->avh.num == 0);
	rt = avh_new(&p->avh);
	if(rt < 0) return rt;
	
	
	/* first add all the unconditional rules */
	/* allow and neverallow */
	rt  = avh_load_avrules(p->av_access, p->num_av_access, TRUE, p);
	if(rt < 0)
		return -1;
	/* audit rules */
	rt  = avh_load_avrules(p->av_audit, p->num_av_audit, TRUE, p);
	if(rt < 0)
		return -1;
	/* typerules */
	rt  = avh_load_avrules(p->te_trans, p->num_te_trans, FALSE, p);
	if(rt < 0)
		return -1;
	
	return 0;

}



