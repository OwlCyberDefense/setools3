/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com
 * Modified by: don.patterson@tresys.com (6-17-2003)
 * Modified by: kmacmillan@tresys.com (7-18-2003) - added
 *   information flow analysis.
 */

/* analysis.c
 *
 * Analysis routines for libapol
 */
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include "policy.h"
#include "util.h"
#include "analysis.h"
#include "policy-query.h"
#include "queue.h"

/*************************************************************************
 * domain transition analysis
 */
 
/* all the "free" fns below have a prototype just like free() so that
 * ll_free() in util.c can use them.  This makes us have to cast the
 * pointer, which can also cause run-time errors since someone could
 * mistakenly pass the wrong data type!  BE CAREFUL!.
 */
void free_entrypoint_type(void *t)
{
	entrypoint_type_t *p = (entrypoint_type_t *)t;
	if(p == NULL)
		return;
	if(p->ep_rules != NULL) 
		free(p->ep_rules);
	if(p->ex_rules != NULL) 
		free(p->ex_rules);
	free(p);
	return;
}

void free_trans_domain(void *t)
{
	trans_domain_t *p = (trans_domain_t *)t;
	if(p == NULL)
		return;
	ll_free(p->entry_types, free_entrypoint_type);
	if(p->pt_rules != NULL) 
		free(p->pt_rules);
	free(p);
	return;
}

void free_domain_trans_analysis(domain_trans_analysis_t *p)
{
	if(p == NULL)
		return;
	ll_free(p->trans_domains, free_trans_domain);
	free(p);
	return;
}

entrypoint_type_t *new_entry_point_type(void)
{
	entrypoint_type_t *t;
	t = (entrypoint_type_t *)malloc(sizeof(entrypoint_type_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(t, 0, sizeof(entrypoint_type_t));
	return t;
}

trans_domain_t *new_trans_domain(void)
{
	trans_domain_t *t;
	t = (trans_domain_t *)malloc(sizeof(trans_domain_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(t, 0, sizeof(trans_domain_t));
	t->entry_types = ll_new();
	return t;
}

domain_trans_analysis_t *new_domain_trans_analysis(void)
{
	domain_trans_analysis_t *t;
	t = (domain_trans_analysis_t *)malloc(sizeof(domain_trans_analysis_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(t, 0, sizeof(domain_trans_analysis_t));
	t->trans_domains = ll_new();

	return t;
}


/* INTERNAL */
static int dta_add_rule_to_trans_type(int start_idx, int trans_idx, int rule_idx, 
		domain_trans_analysis_t *dta)
{	
	llist_node_t *t;
	trans_domain_t *t_data = NULL;
	/* 1. find the type in the dta->trans_domains list */
	/*TODO: Need to fix the list; right now unsorted so this will can become painful*/
	for(t = dta->trans_domains->head; t != NULL; t = t->next) {
		t_data = (trans_domain_t *) t->data;
		assert(t_data->start_type == start_idx);
		if(t_data->trans_type == trans_idx)
			break;
	}
	if(t == NULL)
		return -1; /* trans_idx doesn't currently exist in the dta! */
	assert(t_data != NULL);
	
	/* 2. add the rule to pt_rules list for that t_ptr type */
	return add_i_to_a(rule_idx ,&(t_data->num_pt_rules), &(t_data->pt_rules));
}

/* INTERNAL */
static int dta_add_trans_type(bool_t reverse, int start_idx, int trans_idx, int rule_idx, 
		domain_trans_analysis_t *dta)
{
	trans_domain_t *t;
	
	/* allocate and initialize new target type struct (we may undo this later) */
	t = new_trans_domain();
	if(t == NULL) 
		return -1;
	t->start_type = start_idx;
	t->trans_type = trans_idx;
	t->reverse= reverse;
	
	/* add the rule to the new target type */
	if(add_i_to_a(rule_idx ,&(t->num_pt_rules), &(t->pt_rules)) != 0) {
		free_trans_domain(t);
		return -1;
	}
	/* and link the target into the dta struct */
	/* TODO: need to do an insertion sort */
	if(ll_append_data(dta->trans_domains, t) != 0 ) {
		free_trans_domain(t);
		return -1;
	}
			
	return 0;
}

/* INTERNAL: add process trans allowed trans types to dta result */
static int dta_add_process_trans_rule(bool_t reverse, int start_idx, int rule_idx, bool_t *b_type, domain_trans_analysis_t *dta, 
		policy_t *policy)
{
	int *types = NULL, num_types, rt, i, idx;
	assert(b_type != NULL && dta != NULL && policy != NULL && is_valid_av_rule_idx(rule_idx, 1, policy));
	
	/* Check to see if this is a reverse DT analysis and if so, then extract the type from the SOURCE field. */ 
	/* Otherwise, extract the type from the TARGET field */
	if(reverse) {
		rt = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, SRC_LIST, &types, &num_types, policy);
	} 
	else {
		rt = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, TGT_LIST, &types, &num_types, policy);
	}
	
	if(rt < 0)
		return -1;
	if(rt == 2) {
		/* add all types 
		 * NOTE: Start from i = 1 since we know that type index 0 is 'self' and
		 * 	we don't want to include the pdeudo type self
		 */
		for(i = 1; i < policy->num_types; i++) {
			if(!b_type[i]) {
				/* add new trans type and record its rules */
				if(dta_add_trans_type(reverse, start_idx, i, rule_idx, dta) != 0) 
					return -1;
				b_type[i] = TRUE;
			}
			else {
				/* type already added just added, include this pt rule */
				if(dta_add_rule_to_trans_type(start_idx, i, rule_idx, dta) != 0)
					return -1;
			}
		}
	} 
	else {
		/* add types and rules returned in list to trans_domains list*/
		for(i = 0; i < num_types; i++) {
			/* NOTE: We have a special case if types[i] == 0.  This is the pseudo
			 *	type 'self'.  In this case we really don't want to add self, but
			 *	rather the start_idx.  So in that case we'll change the idx
			 * 	the start_idx.
			 */
			if(types[i] == 0)
				idx = start_idx;
			else
				idx = types[i];

			if(!b_type[idx]) {
				/* add new trans type and record its rules */
				if(dta_add_trans_type(reverse, start_idx, idx, rule_idx, dta) != 0) {
					if(types != NULL) free(types);
					return -1;
				}
				b_type[idx] = TRUE;
			}
			else {
				/* type already added just added, include this pt rule */
				if(dta_add_rule_to_trans_type(start_idx, idx, rule_idx, dta) != 0) {
					if(types != NULL) free(types);
					return -1;
				}
			}
		}
		if(types != NULL) free(types);
	}
	
	return 0;
}



/* INTERNAL */
static int dta_add_rule_to_entry_point_type(bool_t reverse, int rule_idx, entrypoint_type_t *ep)
{
	if(ep != NULL) {
		if(reverse) {
			return add_i_to_a(rule_idx, &(ep->num_ep_rules), &(ep->ep_rules));	
		}
		else {
			return add_i_to_a(rule_idx, &(ep->num_ex_rules), &(ep->ex_rules));
		}
	}
	else 
		return -1;
}

/* INTERNAL */
static int dta_add_rule_to_ep_file_type(bool_t reverse, int file_idx, int rule_idx, trans_domain_t *t_ptr)
{	
	llist_node_t *t;
	entrypoint_type_t *t_data = NULL;
	/* 1. find the file type in the t_ptr */
	/*TODO: Need to fix the list; right now unsorted so this will can become painful*/
	for(t = t_ptr->entry_types->head; t != NULL; t = t->next) {
		t_data = (entrypoint_type_t *) t->data;
		if(t_data->file_type == file_idx)
			break;
	}
	if(t == NULL)
		return -1; /* file_idx doesn't currently exist in the t_ptr! */
	assert(t_data != NULL);
	
	/* 2. add the rule  */
	if(reverse) {
		return add_i_to_a(rule_idx ,&(t_data->num_ex_rules), &(t_data->ex_rules));
	}
	else {
		return add_i_to_a(rule_idx ,&(t_data->num_ep_rules), &(t_data->ep_rules));
	}
}

/* INTERNAL */
static int dta_add_ep_type(bool_t reverse, int file_idx, int rule_idx, trans_domain_t *t_ptr)
{
	entrypoint_type_t *t;
	
	/* allocate and initialize new target type struct (we may undo this later) */
	t = new_entry_point_type();
	if(t == NULL) 
		return -1;
	t->start_type = t_ptr->start_type;
	t->trans_type = t_ptr->trans_type;
	t->file_type = file_idx;

	/* add the rule to the new trans type */
	if(reverse) {
		if(add_i_to_a(rule_idx, &(t->num_ex_rules), &(t->ex_rules)) != 0) {
			free_entrypoint_type(t);
			return -1;
		}
	}
	else {
		if(add_i_to_a(rule_idx, &(t->num_ep_rules), &(t->ep_rules)) != 0) {
			free_entrypoint_type(t);
			return -1;
		}
	}
	
	/* link in new file type */
	/* TODO: need to do an insertion sort */
	if(ll_append_data(t_ptr->entry_types, t) != 0 ) {
		free_entrypoint_type(t);
		return -1;
	}
			
	return 0;
}


/* INTERNAL */ 
/* TODO: This is very similar to dta_add_process_trans_rule(); should consolidate */
static int dta_add_file_entrypoint_type(bool_t reverse, int rule_idx, bool_t *b_types, trans_domain_t *t_ptr, policy_t *policy)
{
	int rt, i, idx, *types, num_types; 
	assert(policy != NULL &&is_valid_av_rule_idx(rule_idx,1,policy) && b_types != NULL && t_ptr != NULL);
	/* In either a reverse or forward DT analysis, the entry point type is extracted from the TARGET field of the rule */
	rt = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, TGT_LIST, &types, &num_types, policy);

	if(rt < 0)
		return -1;
	if(rt == 2) {
		/* add all types 
		 * NOTE: Start from i = 1 since we know that type index 0 is 'self' and
		 * 	we don't want to include the pdeudo type self 
		 */
		for(i = 1; i < policy->num_types; i++) {
			if(!b_types[i]) {
				/* new */
				if(dta_add_ep_type(reverse, i, rule_idx, t_ptr) != 0)
					return -1;
				b_types[i] = TRUE;
			}
			else {
				/* existing; add rule to existing one */
				if(dta_add_rule_to_ep_file_type(reverse, i, rule_idx, t_ptr) != 0)
					return -1;
			}
		}
	}
	else {
		/* adding new file type */
		/* add types and rules returned in list to target domains list */
		for(i = 0; i < num_types; i++) {
			/* NOTE: We have a special case if types[i] == 0.  This is the pseudo
			 *	type 'self'.  In this case we really don't want to add self, but
			 *	rather the target's index (which is the source for these rules).
			 *	So in that case we'll change the idx the t_ptr->trans_type.
			 */
			if(types[i] == 0)
				idx = t_ptr->trans_type;
			else
				idx = types[i];	
			if(!b_types[idx]) {
				/* new */
				if(dta_add_ep_type(reverse, idx, rule_idx, t_ptr) != 0) {
					if(types != NULL) free(types);
					return -1;
				}
				b_types[idx] = TRUE;
			}
			else {
				/* existing; add rule to existing one */
				if(dta_add_rule_to_ep_file_type(reverse, idx, rule_idx, t_ptr) != 0) {
					if(types != NULL) free(types);
					return -1;
				}
			}
		}
		if(types != NULL) free(types);
	}				
				

	return 0;
}


/* main domain trans analysis function.
 * 	dta must be allocated and initialized
 *
 *	returns:	
 *		-1 general error
 *		-2 start_domain invalid type
 */

int determine_domain_trans(bool_t reverse, char *start_domain, domain_trans_analysis_t **dta, policy_t *policy)
{
	int start_idx, i, classes[1], perms[1], perms2[1], rt;
	rules_bool_t b_start, b_trans; 	/* structures are used for passing TE rule match booleans */
	bool_t *b_type;			/* scratch pad arrays to keep track of types that have already been added */
	trans_domain_t *t_ptr;
	entrypoint_type_t *ep;
	llist_node_t *ll_node, *ll_node2;
	int ans;

	if(policy == NULL || dta == NULL)
		return -1;
	/* Retrieve the index of the specified starting domain from our policy database. */
	if((start_idx = get_type_idx(start_domain, policy)) < 0)
		return -2;
	*dta = NULL;
	
	/* initialize our bool rule structures...free before leaving function */
	b_type = (bool_t *)malloc(sizeof(bool_t) * policy->num_types);
	if(b_type == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	memset(b_type, 0, policy->num_types * sizeof(bool_t));
	/* b_start (all rules that have start_type as SOURCE for a forward   
	 * DT analysis or start_type as TARGET for a reverse DT analysis). 
	 * This structure is set in step 1 below. 
	 */
	if(init_rules_bool(0, &b_start, policy) != 0) 
		goto err_return;
	/* b_trans (similar but used by t_ptr as SOURCE) */
	if(init_rules_bool(0, &b_trans, policy) != 0) 
		goto err_return;		
	
	/* initialize the results structure (caller must free if successful) */
	*dta = new_domain_trans_analysis();
	if(*dta == NULL) {
		fprintf(stderr, "out of memory");
		goto err_return;
	}
	(*dta)->start_type = start_idx;
	(*dta)->reverse = reverse;
	if((*dta)->trans_domains == NULL)
		goto err_return;
		
	/* At this point, we begin our domain transition analysis. 
	 * Based upon the type of DT analysis (forward or reverse), populate dta structure  
	 * with candidate trans domains by collecting all allow rules that give process 
	 * transition access and that:
	 * 	- forward DT analysis - contain start_type in the SOURCE field
	 * 	- reverse DT analysis - contain start_type in the TARGET field
	 * Then:
	 *	- forward DT analysis - select all the target types from those rules.
	 * 	- reverse DT analysis - select all the source types from those rules. 
	 */
 
	/* Step 1. select all rules that:
		- forward DT analysis - contain start_type in the SOURCE field
	 	- reverse DT analysis - contain start_type in the TARGET field
	  (keep this around; we use it later when down-selecting candidate entry point file types in step 3.c) */
	if(reverse) {
		if(match_te_rules(FALSE, NULL, 0, start_idx, IDX_TYPE, FALSE, TGT_LIST, TRUE, TRUE,
			&b_start, policy) != 0)
			goto err_return;
	} 
	else {
		if(match_te_rules(FALSE, NULL, 0, start_idx, IDX_TYPE, FALSE, SRC_LIST, TRUE, TRUE,
			&b_start, policy) != 0)
			goto err_return;	
	}
	
	
	/* 2. Extract the trans domain types for process transition perm, and add to our result 
	      keeping track if type already added in to b_type (i.e. our types scratch pad array)  */
	classes[0] = get_obj_class_idx("process", policy);
	assert(classes[0] >= 0);
	perms[0] = get_perm_idx("transition", policy);
	assert(perms[0] >= 0);
	for(i = 0; i < policy->num_av_access; i++) {
		if(b_start.access[i] && (policy->av_access)[i].type == RULE_TE_ALLOW && 
				does_av_rule_use_classes(i, 1, classes, 1, policy) &&
				does_av_rule_use_perms(i, 1, perms, 1, policy)) {
			/* 2.a we have a rule that allows process tran access, add it for now */
			rt = dta_add_process_trans_rule(reverse, start_idx, i, b_type, *dta, policy);
			if(rt != 0)
				goto err_return;
		}
	}
	
	/* At this point, we have a list of all trans types (and associated list of rules) that
	 * allow process transition permission ...
	 * 	- reverse DT analysis - to the start_domain
	 *	- forward DT analysis - from the start_domain
	 * Now we need to take each trans type, and look for file types that provide:
	 *	- forward DT analysis - the start_domain file execute and the trans type file entrypoint access.
	 *	- reverse DT analysis - the start_domain file entrypoint and the trans type file execute access.
	 */
	 
	/* 3. get all the file types for the candidate trans types */
	
	/* set up some temporary structure for our search. */
	classes[0] = get_obj_class_idx("file", policy);
	assert(classes[0] >= 0);
	if(reverse) {
		perms[0] = get_perm_idx("execute", policy);
		perms2[0] = get_perm_idx("entrypoint", policy);
	} 
	else {
		perms[0] = get_perm_idx("entrypoint", policy);
		perms2[0] = get_perm_idx("execute", policy);
	}
	assert(perms[0] >= 0);
	assert(perms2[0] >= 0);
	
	/* Loop through each trans type and find all allow rules that provide:
	 *	- forward DT analysis - the start_domain file execute and the trans type file entrypoint access.
	 *	- reverse DT analysis - the start_domain file entrypoint and the trans type file execute access.
	 */
	for(ll_node = (*dta)->trans_domains->head; ll_node != NULL; ) {
		t_ptr = (trans_domain_t *)ll_node->data;
		assert(t_ptr != NULL);
		all_false_rules_bool(&b_trans, policy);
		memset(b_type, 0, policy->num_types * sizeof(bool_t));
		
		/* 3.a Retrieve all rules that provide trans_type access as SOURCE
		 * 	- forward DT analysis - then filter out rules that provide file execute access.
		 * 	- reverse DT analysis - then filter our rules that provide file entrypoint access.
		 */
		if(match_te_rules(FALSE, NULL, 0, t_ptr->trans_type, IDX_TYPE, FALSE, SRC_LIST, TRUE,
			TRUE, &b_trans, policy) != 0)
			goto err_return;
		
		/* 3.b Filter out rules that allow the current trans_type ...
		 * 	- forward DT analysis - file entrypoint access.
	 	 *	- reverse DT analysis - file execute access. 
		 *     Then extract candidate entrypoint file types from those rules. 
		*/
		for(i = 0; i < policy->num_av_access; i++) {
			if(b_trans.access[i] && (policy->av_access)[i].type == RULE_TE_ALLOW && 
					does_av_rule_use_classes(i, 1, classes, 1, policy) &&
					does_av_rule_use_perms(i, 1, perms, 1, policy)) {
				rt = dta_add_file_entrypoint_type(reverse, i, b_type, t_ptr, policy);
				if(rt != 0)
					goto err_return;
			}
		}
		
		/* If this is a reverse DT analysis, we need to re-run match_te_rules to  
		 * retrieve all rules with start_idx in the SOURCE field. */						
		if(reverse) {
			all_false_rules_bool(&b_start, policy);
			if(match_te_rules(FALSE, NULL, 0, start_idx, IDX_TYPE, FALSE, SRC_LIST, TRUE,
				TRUE, &b_start, policy) != 0)
				goto err_return;
		} 
				
		/* 3.c for each candidate entrypoint file type, now look for rules that provide:
		 * 	- forward DT analysis - the start_type with file execute access to the entrypoint file.
	 	 *	- reverse DT analysis - the start_type with file entrypoint access to the entrypoint file.
	 	 */
		for(ll_node2 = t_ptr->entry_types->head; ll_node2 != NULL;) {
			ep = (entrypoint_type_t *) ll_node2->data;
			assert(ep != NULL);
			for(i = 0; i < policy->num_av_access; i++) {
				/* To be of interest, rule must have SOURCE field as start_type (b_start), be an allow
				 * rule, provide file execute (forward DT) or file entrypoint (reverse DT) access 
				 * to the current entrypoint file type, and relate to file class objects. */
				ans = does_av_rule_idx_use_type(i, 0, ep->file_type, IDX_TYPE, TGT_LIST, TRUE, policy);
				if (ans == -1)
					return -1;
				if(b_start.access[i] && policy->av_access[i].type == RULE_TE_ALLOW && ans &&
				  does_av_rule_use_classes(i, 1, classes, 1, policy) &&
				  does_av_rule_use_perms(i, 1, perms2, 1, policy)) {	
				rt = dta_add_rule_to_entry_point_type(reverse, i, ep);
				if(rt != 0)
					goto err_return;
				}		
			}
			/* 3.d At this point if a candidate file type does not have any ...
			 * 		- forward DT analysis - file execute rules
			 *		- reverse DT analysis - file entrypoint rules
			 * 	then it fails all 3 criteria and we remove it from the trans_type. 
			 *	We don't have to check for ...
			 * 		- forward DT analysis - file entrypoint rules
			 *		- reverse DT analysis - file execute rules 
			 *	because the file type would not even be in the list if it didn't 
			 *	already have at least one ...
			 * 		- forward DT analysis - file entrypoint rule.
			 *		- reverse DT analysis - file execute rule.
			 */
			if(reverse) {
				if(ep->num_ep_rules < 1) {
					assert(ep->ep_rules == NULL);
					if(ll_unlink_node(t_ptr->entry_types, ll_node2) != 0) 
						goto err_return;
					ll_node2 = ll_node_free(ll_node2, free_entrypoint_type);
				}
				else {
					/* interate */
					ll_node2 = ll_node2->next;
				}
			}
			else {
				if(ep->num_ex_rules < 1) {
					assert(ep->ex_rules == NULL);
					if(ll_unlink_node(t_ptr->entry_types, ll_node2) != 0) 
						goto err_return;
					ll_node2 = ll_node_free(ll_node2, free_entrypoint_type);
				}
				else {
					/* interate */
					ll_node2 = ll_node2->next;
				}
			}
		}
		/* 3.e at this point, if a candidate trans_types do not have any entrypoint file types,
		 *	remove it since it fails the criteria */
		if(t_ptr->entry_types->num < 1) {
			if(ll_unlink_node((*dta)->trans_domains, ll_node) !=0)
				goto err_return;
			ll_node = ll_node_free(ll_node, free_trans_domain);
		}
		else {
			/* interate */
			ll_node = ll_node->next;
		}
		
	}
	
	if(b_type != NULL) free(b_type);
	free_rules_bool(&b_trans);	
	free_rules_bool(&b_start);	
	return 0;	
err_return:	
	free_domain_trans_analysis(*dta);
	if(b_type != NULL) free(b_type);
	free_rules_bool(&b_trans);
	free_rules_bool(&b_start);
	return -1;
}


