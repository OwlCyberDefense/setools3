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
		if(match_te_rules(0, NULL, 0, start_idx, IDX_TYPE, 0, TGT_LIST, 1, &b_start, policy) != 0)
			goto err_return;
	} 
	else {
		if(match_te_rules(0, NULL, 0, start_idx, IDX_TYPE, 0, SRC_LIST, 1, &b_start, policy) != 0)
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
		if(match_te_rules(0, NULL, 0, t_ptr->trans_type, IDX_TYPE, 0, SRC_LIST, 1, &b_trans, policy) != 0)
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
			if(match_te_rules(0, NULL, 0, start_idx, IDX_TYPE, 0, SRC_LIST, 1, &b_start, policy) != 0)
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


/* end domain transition analysis
*************************************************************************/

/*************************************************************************
 * Information flow analysis */

/* iflow_query_t */

iflow_query_t *iflow_query_create(void)
{
	iflow_query_t* q = (iflow_query_t*)malloc(sizeof(iflow_query_t));
	if (q == NULL) {
		fprintf(stderr, "Memory error!\n");
		return NULL;
	}
	memset(q, 0, sizeof(iflow_query_t));
	q->start_type = -1;
	q->direction = IFLOW_IN;

	return q;
}

static int iflow_obj_options_copy(iflow_obj_options_t *dest, iflow_obj_options_t *src)
{
        dest->obj_class = src->obj_class;
        dest->num_perms = src->num_perms;
        if (src->num_perms) {
                assert(src->perms);
                if (copy_int_array(&dest->perms, src->perms, src->num_perms))
                        return -1;
        }
        return 0;
}

/* perform a deep copy of an iflow_query_t - dest should be
 * a newly created iflow_query */
static int iflow_query_copy(iflow_query_t *dest, iflow_query_t *src)
{
        int i;

        assert(dest && src);
        dest->start_type = src->start_type;
        dest->direction = src->direction;
        if (src->num_end_types) {
                assert(src->end_types);
                if (copy_int_array(&dest->end_types, src->end_types, src->num_end_types))
                        return -1;
                dest->num_end_types = src->num_end_types;
        }
        
        if (src->num_types) {
                assert(src->types);
                if (copy_int_array(&dest->types, src->types, src->num_types))
                        return -1;
                dest->num_types = src->num_types;
        }

        if (src->num_obj_options) {
                assert(src->obj_options);
                dest->obj_options = (iflow_obj_options_t*)malloc(sizeof(iflow_obj_options_t) * 
                                                                 src->num_obj_options);
                if (!dest->obj_options) {
                        fprintf(stderr, "Memory error\n");
                        return -1;
                }
                memset(dest->obj_options, 0, sizeof(iflow_obj_options_t) * src->num_obj_options);
                for (i = 0; i < src->num_obj_options; i++) {
                        if (iflow_obj_options_copy(dest->obj_options + i, src->obj_options + i))
                                return -1;
                }
                dest->num_obj_options = src->num_obj_options;
        }
        return 0;
}

void iflow_query_destroy(iflow_query_t *q)
{
	int i;

	if (q->end_types)
		free(q->end_types);
	if (q->types)
		free(q->types);

	for (i = 0; i < q->num_obj_options; i++) {
		if (q->obj_options[i].perms)
			free(q->obj_options[i].perms);
	}
	if (q->obj_options)
		free(q->obj_options);
	free(q);
}

static int iflow_query_find_obj_class(iflow_query_t *q, int obj_class)
{
	int i;

	assert(q);
	assert(obj_class >= 0);

	for (i = 0; i < q->num_obj_options; i++) {
		if (q->obj_options[i].obj_class == obj_class) {
			return i;
		}
	}
	return -1;
}

/*
 * Add an object class to ignore to an iflow_query_t - returns the index of
 * the iflow_obj_options_t on success or -1 on failure. Checks to
 * prevent the addition of duplicate or contradictory object classes.
 */
int iflow_query_add_obj_class(iflow_query_t *q, int obj_class)
{
	int obj_idx, cur;

	assert(q);
	assert(obj_class >= 0);

	/* find an existing entry for the object class */
	obj_idx = iflow_query_find_obj_class(q, obj_class);
	if (obj_idx != -1) {
			/* make certain that the entire object class is ignored */
			if (q->obj_options[obj_idx].perms) {
				free(q->obj_options[obj_idx].perms);	
				q->obj_options[obj_idx].perms = NULL;
				q->obj_options[obj_idx].num_perms = 0;
			}
			return obj_idx;
	}

	/* add a new entry */
	cur = q->num_obj_options;
	q->num_obj_options++;
	q->obj_options = (iflow_obj_options_t*)realloc(q->obj_options,
						      sizeof(iflow_obj_options_t)
						      * q->num_obj_options);
	if (!q->obj_options) {
		fprintf(stderr, "Memory error!\n");
		return -1;
	}
	memset(&q->obj_options[cur], 0, sizeof(iflow_obj_options_t));
	q->obj_options[cur].obj_class = obj_class;

	return cur;
}

/*
 * Add an object class and perm to ignore to an iflow_query_t - returns the index of
 * the iflow_obj_options_t on success or -1 on failure. Checks to
 * prevent the addition of duplicate or contradictory object classes.
 */
int iflow_query_add_obj_class_perm(iflow_query_t *q, int obj_class, int perm)
{
	int cur;
	bool_t add = FALSE;

	/* find an existing entry for the object class */
	cur = iflow_query_find_obj_class(q, obj_class);

        /* add a new entry */
	if (cur == -1) {
		cur = q->num_obj_options;
		q->num_obj_options++;
		q->obj_options = (iflow_obj_options_t*)realloc(q->obj_options,
							       sizeof(iflow_obj_options_t)
							       * q->num_obj_options);
		if (!q->obj_options) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}
		memset(&q->obj_options[cur], 0, sizeof(iflow_obj_options_t));
		q->obj_options[cur].obj_class = obj_class;
		
	}

	if (!q->obj_options[cur].perms) {
		add = TRUE;
	} else {
		if (find_int_in_array(perm, q->obj_options[cur].perms,
				      q->obj_options[cur].num_perms) == -1)
			add = TRUE;
	}

	if (add) {
		if (add_i_to_a(perm, &q->obj_options[cur].num_perms,
			       &q->obj_options[cur].perms) == -1)
			return -1;
	}
	return 0;
}

int iflow_query_add_end_type(iflow_query_t *q, int end_type)
{
	bool_t add = FALSE;

	assert(q);
	/* we can't do anymore checking without the policy */
	if (end_type < 0) {
		fprintf(stderr, "end type must be 0 or greater\n");
		return -1;
	}

	if (q->end_types) {
		if (find_int_in_array(end_type, q->end_types,
				      q->num_end_types) < 0) {
			add = TRUE;
		}
	} else {
		add = TRUE;
	}
	if (add)
		if (add_i_to_a(end_type, &q->num_end_types, &q->end_types) < 0)
			return -1;
	return 0;
}

int iflow_query_add_type(iflow_query_t *q, int type)
{
	bool_t add = FALSE;

	assert(q);
	/* we can't do anymore checking without the policy */
	if (type < 0) {
		fprintf(stderr, "end type must be 0 or greater\n");
		return -1;
	}

	if (q->types) {
		if (find_int_in_array(type, q->types,
				      q->num_types) < 0) {
			add = TRUE;
		}
	} else {
		add = TRUE;
	}
	if (add)
		if (add_i_to_a(type, &q->num_types, &q->types) < 0)
			return -1;
	return 0;
}

/*
 * Check that the iflow_obj_option_t is valid for the graph/policy.
 */
bool_t iflow_obj_option_is_valid(iflow_obj_options_t *o, policy_t *policy)
{
	int i;

	assert(o && policy);

	if (!is_valid_obj_class(policy, o->obj_class))
		return FALSE;

	if (o->num_perms) {
		if (!o->perms) {
			fprintf(stderr, "query with num_perms %d and perms is NULL\n", o->num_perms);
			return FALSE;
		}
		for (i = 0; i < o->num_perms; i++) {
			if (!is_valid_perm_for_obj_class(policy, o->obj_class, o->perms[i])) {
				fprintf(stderr, "query with invalid perm %d for object class %d\n",
					o->perms[i], o->obj_class);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/* check to make certain that a query is consistent and makes
 * sense with the graph/policy */
bool_t iflow_query_is_valid(iflow_query_t *q, policy_t *policy)
{
	int i;

#ifdef DEBUG_QUERIES
	printf("start type: %s\n", policy->types[q->start_type].name);
	printf("types[%d]:\n", q->num_types);
	for (i = 0; i < q->num_types; i++)
		printf("\t%s\n", policy->types[q->types[i]].name);
	printf("end types[%d]: \n", q->num_end_types);
	for (i = 0; i < q->num_end_types; i++)
		printf("\t%s\n", policy->types[q->end_types[i]].name);
	printf("obj options[%d]: \n", q->num_obj_options);
	for (i = 0; i < q->num_obj_options; i++) {
		int j;
		printf("\tobj class [%d]%s perms [%d]:\n", q->obj_options[i].obj_class,
		       policy->obj_classes[q->obj_options[i].obj_class].name,
		       q->obj_options[i].num_perms);
		for (j = 0; j < q->obj_options[i].num_perms; j++)
			printf("\t\t%s\n", policy->perms[q->obj_options[i].perms[j]]);
	}
#endif

	/* check the start type - we don't allow self (which is always 0) */
	if (!is_valid_type(policy, q->start_type, FALSE)) {
		fprintf(stderr, "invalid start type %d in query\n", q->start_type);
		return FALSE;
	}
	
	/* transitive analysis will have to do further checks */
	if (!(q->direction == IFLOW_IN || q->direction == IFLOW_OUT
	      || q->direction == IFLOW_BOTH || q->direction == IFLOW_EITHER)) {
		fprintf(stderr, "invalid direction %d in query\n", q->direction);
		return FALSE;		
	}
	
	if (q->num_end_types) {
		if (!q->end_types) {
			fprintf(stderr, "query num_end_types was %d but end_types was NULL\n",
				q->num_end_types);
			return FALSE;
		}
		for (i = 0; i < q->num_end_types; i++) {
			if (!is_valid_type(policy, q->end_types[i], FALSE)) {
				fprintf(stderr, "Invalid end type %d in query\n", q->end_types[i]);
				return FALSE;
			}
		}
	}

	if (q->num_types) {
		if (!q->types) {
			fprintf(stderr, "query num_types was %d but types was NULL\n",
				q->num_types);
			return FALSE;
		}
		for (i = 0; i < q->num_types; i++) {
			if (!is_valid_type(policy, q->types[i], FALSE)) {
				fprintf(stderr, "Invalid end type %d in query\n", q->types[i]);
				return FALSE;
			}
		}
	}
	
	if (q->num_obj_options) {
		if (!q->obj_options) {
			fprintf(stderr, "query num_obj_options was %d by obj_options was NULL\n",
				q->num_obj_options);
			return FALSE;
		}
		for (i = 0; i < q->num_obj_options; i++) {
			if (!iflow_obj_option_is_valid(&q->obj_options[i], policy)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

/* iflow_t */

int iflow_init(iflow_graph_t *g, iflow_t *flow)
{
	memset(flow, 0, sizeof(iflow_t));
	flow->num_obj_classes = g->policy->num_obj_classes;
	flow->obj_classes = (iflow_obj_class_t*)malloc(sizeof(iflow_obj_class_t) *
						       flow->num_obj_classes);
	if (!flow->obj_classes) {
		fprintf(stderr, "Memory Error\n");
		return -1;
	}
	memset(flow->obj_classes, 0, sizeof(iflow_obj_class_t) *
	       flow->num_obj_classes);
	return 0;
}

static void iflow_destroy_data(iflow_t *flow)
{
	int i;
	
	if (flow->obj_classes) {
		for (i = 0; i < flow->num_obj_classes; i++) {
			if (flow->obj_classes[i].rules)
				free(flow->obj_classes[i].rules);
		}
		free(flow->obj_classes);
	}
}

void iflow_destroy(iflow_t *flow)
{
	if (!flow)
		return;
	
	iflow_destroy_data(flow);

	free(flow);
}

/* iflow_transitive_t */

static void iflow_path_destroy(iflow_path_t *path)
{
	int i;

	if (!path)
		return;
	for (i = 0; i < path->num_iflows; i++) {
		iflow_destroy_data(&path->iflows[i]);
	}
	if (path->iflows)
		free(path->iflows);
	free(path);
}

static void iflow_path_destroy_list(iflow_path_t *path)
{
	iflow_path_t *next;

	while (path) {
		next = path->next;
		iflow_path_destroy(path);
		path = next;
	}
}

void iflow_transitive_destroy(iflow_transitive_t *flow)
{
	int i;

	if (!flow)
		return;

	if (flow->end_types)
		free(flow->end_types);
	for (i = 0; i < flow->num_end_types; i++) {
		iflow_path_destroy_list(flow->paths[i]);
	}
	if (flow->paths)
		free(flow->paths);
	if (flow->num_paths)
		free(flow->num_paths);
	free(flow);
}

/* iflow_node_t */

static void iflow_node_destroy_data(iflow_node_t *node)
{
	if (!node)
		return;
	if (node->in_edges)
		free(node->in_edges);
	if (node->out_edges)
		free(node->out_edges);
}

/* iflow_graph_t */

#define get_src_index(type) type
#define get_tgt_index(g, type, obj_class) ((type * g->policy->num_obj_classes) + obj_class)

static iflow_graph_t *iflow_graph_alloc(policy_t *policy)
{
	iflow_graph_t *g;
	int index_size;

	g = (iflow_graph_t*)malloc(sizeof(iflow_graph_t));
	if (!g) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g, 0, sizeof(iflow_graph_t));

	index_size = policy->num_types;
	g->src_index = (int*)malloc(sizeof(int) * index_size);
	if (!g->src_index) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g->src_index, -1, sizeof(int) * index_size);
	
	index_size = policy->num_types * policy->num_obj_classes;
	g->tgt_index = (int*)malloc(sizeof(int) * index_size);
	if (!g->tgt_index) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(g->tgt_index, -1, sizeof(int) * index_size);
	
	g->policy = policy;
	return g;
}

void iflow_graph_destroy(iflow_graph_t *g)
{
	int i;

	if (!g)
		return;

	for (i = 0; i < g->num_nodes; i++)
		iflow_node_destroy_data(&g->nodes[i]);

	if (g->src_index)
		free(g->src_index);
	if (g->tgt_index)
		free(g->tgt_index);

	if (g->nodes)
		free(g->nodes);
	if (g->edges) {
		for (i = 0; i < g->num_edges; i++) {
			if (g->edges[i].rules)
				free(g->edges[i].rules);
		}
		free(g->edges);
	}
}

static int iflow_graph_get_nodes_for_type(iflow_graph_t *g, int type, int *len, int **types)
{
	int i;

	*len = 0;
	*types = NULL;

	if (g->src_index[get_src_index(type)] >= 0)
		if (add_i_to_a(g->src_index[get_src_index(type)], len, types) < 0)
			return -1;
	for (i = 0; i < g->policy->num_obj_classes; i++) {
		if (g->tgt_index[get_tgt_index(g, type, i)] >= 0)
			if (add_i_to_a(g->tgt_index[get_tgt_index(g, type, i)], len, types) < 0)
				return -1;
	}
	return 0;
}

static int iflow_graph_connect(iflow_graph_t *g, int start_node, int end_node)
{

	iflow_node_t* start, *end;
	int i;

	start = &g->nodes[start_node];
	end = &g->nodes[end_node];

	for (i = 0; i < start->num_out_edges; i++) {
		if (g->edges[start->out_edges[i]].end_node == end_node)
			return start->out_edges[i];
	}

	g->edges = (iflow_edge_t*)realloc(g->edges, (g->num_edges + 1)
					  * sizeof(iflow_edge_t));
	if (g->edges == NULL) {
		fprintf(stderr, "Memory error!\n");
		return -1;
	}

	memset(&g->edges[g->num_edges], 0, sizeof(iflow_edge_t));
	
	g->edges[g->num_edges].start_node = start_node;
	g->edges[g->num_edges].end_node = end_node;
	
	if (add_i_to_a(g->num_edges, &start->num_out_edges, &start->out_edges) != 0) {
		return -1;
	}	

	if (add_i_to_a(g->num_edges, &end->num_in_edges, &end->in_edges) != 0) {
		return -1;
	}

	g->num_edges++;
	return g->num_edges - 1;
}

static int iflow_graph_add_node(iflow_graph_t *g, int type, int node_type, int obj_class)
{
	assert(node_type == IFLOW_SOURCE_NODE || node_type == IFLOW_TARGET_NODE);

	/* check for an existing node and update the indexes if not */
	if (node_type == IFLOW_SOURCE_NODE) {
		if (g->src_index[get_src_index(type)] >= 0)
			return g->src_index[get_src_index(type)];
		else
			g->src_index[type] = g->num_nodes;
	} else {
		if (g->tgt_index[get_tgt_index(g, type, obj_class)] >= 0) {
			return g->tgt_index[get_tgt_index(g, type, obj_class)];
		} else {
			g->tgt_index[get_tgt_index(g, type, obj_class)] = g->num_nodes;
		}
	}
	
	/* create a new node */
	g->nodes = (iflow_node_t*)realloc(g->nodes, sizeof(iflow_node_t) * (g->num_nodes + 1));
	if (!g->nodes) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	memset(&g->nodes[g->num_nodes], 0, sizeof(iflow_node_t));
	g->nodes[g->num_nodes].node_type = node_type;
	g->nodes[g->num_nodes].type = type;
	g->nodes[g->num_nodes].obj_class = obj_class;
	
	g->num_nodes++;
	return g->num_nodes - 1;
}

/* helper for iflow_graph_create */
static int add_edges(iflow_graph_t* g, int obj_class, int rule_idx, bool_t found_read, bool_t found_write) {
	int i, j, k, ret;
	int src_node, tgt_node;

	bool_t all_src_types = FALSE;
	int cur_src_type;
	int num_src_types = 0;
	int* src_types = NULL;

	bool_t all_tgt_types = FALSE;
	int cur_tgt_type;
	int num_tgt_types = 0;
	int* tgt_types = NULL;

	av_item_t* rule;

	/* extract all of the rules */
	rule = &g->policy->av_access[rule_idx];

	ret = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, SRC_LIST, &src_types, &num_src_types, g->policy);
	if (ret == -1)
		return -1;
	if (ret == 2)
		all_src_types = TRUE;

	ret = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, TGT_LIST, &tgt_types, &num_tgt_types, g->policy);
	if (ret == -1)
		return -1;
	if (ret == 2)
		all_tgt_types = TRUE;
	
	for (i = 0; i < num_src_types; i++) {
		if (all_src_types)
			cur_src_type = i;
		else
			cur_src_type = src_types[i];

		if (g->query->num_types) {
			bool_t filter_type = FALSE;
			for (k = 0; k < g->query->num_types; k++) {
				if (g->query->types[k] == cur_src_type) {
					filter_type = TRUE;
					break;
				}
			}
			if (filter_type) {
				continue;
			}
		}

		/* add the source type */
		src_node = iflow_graph_add_node(g, cur_src_type, IFLOW_SOURCE_NODE, -1);
		if (src_node < 0)
			return -1;
		
		for (j = 0; j < num_tgt_types; j++) {
			int edge;
			
			if (all_tgt_types)
				cur_tgt_type = j;
			else
				cur_tgt_type = tgt_types[j];
			
			if (g->query->num_types) {
				bool_t filter_type = FALSE;
				for (k = 0; k < g->query->num_types; k++) {
					if (g->query->types[k] == cur_tgt_type) {
						filter_type = TRUE;
						break;
					}
				}
				if (filter_type) {
					continue;
				}
			}
			
			/* add the target type */
			tgt_node = iflow_graph_add_node(g, cur_tgt_type, IFLOW_TARGET_NODE, obj_class);
			if (tgt_node < 0)
				return -1;
			
			if (found_read) {
				edge = iflow_graph_connect(g, tgt_node, src_node);
				if (edge < 0) {
					fprintf(stderr, "Could not add edge!\n");
					return -1;
				}
				
				if (add_i_to_a(rule_idx, &g->edges[edge].num_rules,
					       &g->edges[edge].rules) != 0) {
					fprintf(stderr, "Could not add rule!\n");
					return -1;
				}
			}
			if (found_write) {
				edge = iflow_graph_connect(g, src_node, tgt_node);
				if (edge < 0) {
					fprintf(stderr, "Could not add edge!\n");
					return -1;
				}
				if (add_i_to_a(rule_idx, &g->edges[edge].num_rules,
					       &g->edges[edge].rules) != 0) {
					fprintf(stderr, "Could not add rule!\n");
					return -1;
				}
			}
			
		}
	}
	if (!all_src_types) {
		free(src_types);
	}
	if (!all_tgt_types) {
		free(tgt_types);
	}
	return 0;
}

/*
 * Create an information flow graph of a policy.
 */
iflow_graph_t *iflow_graph_create(policy_t* policy, iflow_query_t *q)
{
	int i, j, k, l, ret;
	unsigned char map;
	iflow_graph_t* g;
	bool_t perm_error = FALSE;

	assert(policy && q);

	if (policy->pmap == NULL) {
		fprintf(stderr, "Perm map must be loaded first.\n");
		return NULL;
	}
	
	g = iflow_graph_alloc(policy);
	if (g == NULL)
		return NULL;
	g->query = q;

	for (i = 0; i < policy->num_av_access; i++) {
		av_item_t* rule;
		int cur_obj_class, num_obj_classes = 0, *obj_classes = NULL;
		bool_t all_obj_classes = FALSE, all_perms = FALSE;
		int cur_perm, num_perms = 0, *perms = NULL;

		rule = &policy->av_access[i];
		if (rule->type != RULE_TE_ALLOW)
			continue;
		
		/* get the object classes for this rule */
		ret = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &obj_classes, &num_obj_classes, policy);
		if (ret == -1) {
			iflow_graph_destroy(g);
			return NULL;
		} else if (ret == 2) {
			all_obj_classes = TRUE;
		}
		
		ret = extract_perms_from_te_rule(i, RULE_TE_ALLOW, &perms, &num_perms, policy);
		if (ret == -1) {
			iflow_graph_destroy(g);
			if (!all_obj_classes)
				free(obj_classes);
			return NULL;
		} else if (ret == 2) {
			all_perms = TRUE;
		}

		/* find read or write flows for each object class */
		for (j = 0; j < num_obj_classes; j++ ) {
			class_perm_map_t* cur_pmap;
			bool_t found_read = FALSE, found_write = FALSE;
			int cur_obj_options = -1;

			if (all_obj_classes)
				cur_obj_class = j;
			else
				cur_obj_class = obj_classes[j];

			/* Check to see if we should filter this object class. If we find
			 * the object class in the obj_options and it doesn't list specific
			 * perms then we filter. If we find the object class in the obj_options
			 * but it has specific perms we save the index into obj_options and
			 * check the perms below */
			if (q->num_obj_options != 0) {
				bool_t filter_obj_class = FALSE;
				for (k = 0; k < q->num_obj_options; k++) {
					if (q->obj_options[k].obj_class == cur_obj_class) {
						if (q->obj_options[k].num_perms == 0)
							filter_obj_class = TRUE;
						else
							cur_obj_options = k;
						break;
					}
				}
				if (filter_obj_class)
					continue;
			}

			cur_pmap = &policy->pmap->maps[cur_obj_class];
			if (all_perms) {
				ret = get_obj_class_perms(cur_obj_class, &num_perms, &perms, policy);
				if (ret != 0) {
					iflow_graph_destroy(g);	
					if (!all_obj_classes)
						free(obj_classes);
					return NULL;
				}
			}

			for (k = 0; k < num_perms; k++) {
				cur_perm = perms[k];

				/* Check to see if we should ignore this permission */
				if (cur_obj_options >= 0) {
					bool_t filter_perm = FALSE;
					for (l = 0; l < q->obj_options[cur_obj_options].num_perms; l++) {
						if (q->obj_options[cur_obj_options].perms[l] == cur_perm) {
							filter_perm = TRUE;
							break;
						}
					}
					if (filter_perm)
						continue;
				}

				/* get the mapping for the perm */
				map = 0;
				for (l = 0; l < cur_pmap->num_perms; l++) {
					if (cur_pmap->perm_maps[l].perm_idx == cur_perm) {
						map = cur_pmap->perm_maps[l].map;
						break;
					}
				}
				if (map == 0) {
					perm_error = TRUE;
					continue;
				}
				if (map & PERMMAP_READ)
					found_read = TRUE;
				if (map & PERMMAP_WRITE)
					found_write = TRUE;
				if (found_read && found_write)
					break;
			}
			if (all_perms)
				free(perms);

			if (!found_read && !found_write) {
				continue;
			}

			/* if we have found any flows add the edge */
			if (add_edges(g, cur_obj_class, i, found_read, found_write) != 0) {
				iflow_graph_destroy(g);
				if (!all_perms)
					free(perms);
				if (!all_obj_classes)
					free(obj_classes);
				return NULL;
			}

			
		}
		if (!all_perms)
			free(perms);
		if (!all_obj_classes)
			free(obj_classes);
	}

	if (perm_error)
		fprintf(stderr, "Not all of the permissions found had associated permission maps.\n");

	return g;
}

/* direct information flow */

/* helper for iflow_direct_flows */
static bool_t edge_matches_query(iflow_graph_t* g, iflow_query_t* q, int edge)
{
	int end_type, ending_node;
	
	if (g->nodes[g->edges[edge].start_node].type == q->start_type) {
		ending_node = g->edges[edge].end_node;
	} else {
		ending_node = g->edges[edge].start_node;
	}

	if (q->num_end_types != 0) {
		end_type = g->nodes[ending_node].type;
		if (find_int_in_array(end_type, q->end_types, q->num_end_types) == -1)
			return FALSE;
	}

	return TRUE;
}

static int iflow_define_flow(iflow_graph_t *g, iflow_t *flow, int direction, int start_node, int edge)
{
	int i, end_node, obj_class;
	iflow_edge_t *edge_ptr;
	
	edge_ptr = &g->edges[edge];

	if (edge_ptr->start_node == start_node) {
		end_node = edge_ptr->end_node;
	} else {
		end_node = edge_ptr->start_node;
	}

	flow->direction |= direction;
	flow->start_type = g->nodes[start_node].type;
	flow->end_type = g->nodes[end_node].type;
	
	obj_class = g->nodes[edge_ptr->start_node].obj_class;
	if (obj_class == -1)
		obj_class = g->nodes[edge_ptr->end_node].obj_class;
	for (i = 0; i < edge_ptr->num_rules; i++) {
		if (find_int_in_array(edge_ptr->rules[i], flow->obj_classes[obj_class].rules,
				      flow->obj_classes[obj_class].num_rules) == -1) {
			if (add_i_to_a(edge_ptr->rules[i], &flow->obj_classes[obj_class].num_rules,
				       &flow->obj_classes[obj_class].rules) < 0) {
					return 	-1;
			}
		}
	}

	return 0;
}

static int direct_find_flow(iflow_graph_t *g, int start_node, int end_node, int *num_answers, iflow_t **answers)
{
	iflow_t *cur;
	int i;

	assert(num_answers);

	/* see if a flow already exists */
	if (*answers) {
		for (i = 0; i < *num_answers; i++) {
			cur = &(*answers)[i];
			if (cur->start_type == g->nodes[start_node].type &&
			    cur->end_type == g->nodes[end_node].type) {
				return i;
			}
		}
	}

	/* if we didn't find a matching flow make space for a new one */
	*answers = (iflow_t*)realloc(*answers, (*num_answers + 1)
				     * sizeof(iflow_t));
	if (*answers == NULL) {
		fprintf(stderr,	"Memory error!\n");
		return -1;
	}
	if (iflow_init(g, &(*answers)[*num_answers])) {
		return -1;
	}

	(*num_answers)++;
	return *num_answers - 1;
}

int iflow_direct_flows(policy_t *policy, iflow_query_t *q, int *num_answers,
		       iflow_t **answers)
{
	int i, j, edge, ret = 0;
	iflow_node_t* node;
	bool_t edge_matches;
	int num_nodes, *nodes;
	int flow, end_node;
	iflow_graph_t *g;

	if (!iflow_query_is_valid(q, policy))
		return -1;

	g = iflow_graph_create(policy, q);
	if (!g) {
		fprintf(stderr, "Error creating graph\n");
		return -1;
	}
	
	*num_answers = 0;
	*answers = NULL;
	
	if (iflow_graph_get_nodes_for_type(g, q->start_type, &num_nodes, &nodes) < 0)
		return -1;
	/*
	 * Because the graph doesn't contain every type (i.e. it is possible that the query
	 * made a type not match), not finding a node means that there are no flows. This
	 * used to indicate an error.
	 */
	if (num_nodes == 0) {
		return 0;
	}
	
	if (q->direction == IFLOW_IN || q->direction == IFLOW_EITHER || q->direction == IFLOW_BOTH) {
		for (i = 0; i < num_nodes; i++) {
			node = &g->nodes[nodes[i]];
			for (j = 0; j < node->num_in_edges; j++) {
				edge = node->in_edges[j];
				edge_matches = edge_matches_query(g, q, edge);
				if (!edge_matches)
					continue;

				if (g->edges[edge].start_node == nodes[i])
					end_node = g->edges[edge].end_node;
				else
					end_node = g->edges[edge].start_node;

				flow = direct_find_flow(g, nodes[i], end_node, num_answers, answers);
				if (flow < 0) {
					ret = -1;
					goto out;
				}
				if (iflow_define_flow(g, &(*answers)[flow], IFLOW_IN, nodes[i], edge)) {
					ret = -1;
					goto out;
				}
			}
		}
	}
	if (q->direction == IFLOW_OUT || q->direction == IFLOW_EITHER || q->direction == IFLOW_BOTH) {
		for (i = 0; i < num_nodes; i++) {
			node = &g->nodes[nodes[i]];
			for (j = 0; j < node->num_out_edges; j++) {
				edge = node->out_edges[j];
				edge_matches = edge_matches_query(g, q, edge);
				if (!edge_matches)
					continue;

				if (g->edges[edge].start_node == nodes[i])
					end_node = g->edges[edge].end_node;
				else
					end_node = g->edges[edge].start_node;

				flow = direct_find_flow(g, nodes[i], end_node, num_answers, answers);
				if (flow < 0) {
					ret = -1;
					goto out;
				}
				if (iflow_define_flow(g, &(*answers)[flow], IFLOW_OUT, nodes[i], edge)) {
					ret = -1;
					goto out;
				}
			}
		}
	}

	if (*num_answers == 0)
		goto out;

	/* do some extra checks for both */
	if (q->direction == IFLOW_BOTH) {
		int tmp_num_answers = *num_answers;
		iflow_t *tmp_answers = *answers;

		*num_answers = 0;
		*answers = NULL;

		for (i = 0; i < tmp_num_answers; i++) {
			if (tmp_answers[i].direction != IFLOW_BOTH) {
				iflow_destroy_data(&tmp_answers[i]);
				continue;
			}
			*answers = (iflow_t*)realloc(*answers, (*num_answers + 1)
						     * sizeof(iflow_t));
			if (*answers == NULL) {
				fprintf(stderr,	"Memory error!\n");
				goto out;
			}
			(*answers)[*num_answers] = tmp_answers[i];
			*num_answers += 1;
		}
		free(tmp_answers);
	}

out:
	if (nodes)
		free(nodes);
	iflow_graph_destroy(g);
	return ret;
}

/* helper for iflow_transitive_flows */
static int transitive_answer_append(iflow_graph_t *g, iflow_query_t *q, iflow_transitive_t* a,
				    int end_node, int path_len, int* path)
{
	int i, j, cur_type, cur;
	iflow_path_t *p, *last_path = NULL;
	bool_t found_dup, new_path = FALSE;

	p = (iflow_path_t*)malloc(sizeof(iflow_path_t));
	if (!p) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	memset(p, 0, sizeof(iflow_path_t));

	/* build the path */
	for (i = 0; i < path_len - 1; i++) {
		int edge = -1;
		/* find the edge */
		if (q->direction == IFLOW_OUT) {
			for (j = 0; j < g->nodes[path[i]].num_out_edges; j++) {
				edge = g->nodes[path[i]].out_edges[j];
				if (g->edges[edge].start_node == path[i] &&
				    g->edges[edge].end_node == path[i + 1])
					break;
			}
			if (j == g->nodes[path[i]].num_out_edges) {
				fprintf(stderr, "Did not find an edge\n");
				return -1;
			}
		} else {
			for (j = 0; j < g->nodes[path[i]].num_in_edges; j++) {
				edge = g->nodes[path[i]].in_edges[j];
				if (g->edges[edge].end_node == path[i] &&
				    g->edges[edge].start_node == path[i + 1])
					break;
			}
			if (j == g->nodes[path[i]].num_in_edges) {
				fprintf(stderr, "Did not find an edge\n");
				return -1;
			}
		}
		assert(edge >= 0);
		p->num_iflows++;
		/* TODO - we should preallocate this since we know the length ahead of time */
		p->iflows = (iflow_t*)realloc(p->iflows, sizeof(iflow_t) * p->num_iflows);
		if (!p->iflows) {
			fprintf(stderr, "Memory error\n");
			return -1;
		}
		if (iflow_init(g, &p->iflows[p->num_iflows - 1])) {
			fprintf(stderr, "Memory error\n");
			return -1;
		}
		if (q->direction == IFLOW_OUT) {
			if (iflow_define_flow(g, &p->iflows[p->num_iflows - 1], IFLOW_OUT,
					      path[i], edge))
				return -1;
		} else {
			if (iflow_define_flow(g, &p->iflows[p->num_iflows - 1], IFLOW_IN,
					      path[i + 1], edge))
				return -1;
		}
	}

	/* see if we've already seen this type */
	cur_type = g->nodes[end_node].type;
	for (i = 0; i < a->num_end_types; i++) {
		if (a->end_types[i] == cur_type) {
			last_path = a->paths[i];
			/* find the last path while checking for duplicates */
			while (1) {
				if (last_path->num_iflows == p->num_iflows) {
					found_dup = TRUE;
					for (j = 0; j < last_path->num_iflows; j++) {
						if (last_path->iflows[j].start_type != p->iflows[j].start_type
						    || last_path->iflows[j].start_type != p->iflows[j].start_type
						    || last_path->iflows[j].direction != p->iflows[j].direction) {
							found_dup = FALSE;
							break;
						}
					}
					/* found a dup TODO - make certain all of the object class / rules are kept */
					if (found_dup) {
						iflow_path_destroy(p);
						return 0;
					}
				}
				if (!last_path->next)
					break;
				last_path = last_path->next;
			}
			new_path = TRUE;
			a->num_paths[i]++;
			last_path->next = p;
			break;
		}
	}

	/* this is a new type */
	if (!last_path) {
		new_path = TRUE;
		cur = a->num_end_types;
		if (add_i_to_a(cur_type, &a->num_end_types, &a->end_types))
			return -1;
		a->paths = (iflow_path_t**)realloc(a->paths, a->num_end_types
							* sizeof(iflow_path_t*));
		if (a->paths == NULL) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}

		a->num_paths = (int*)realloc(a->num_paths, a->num_end_types
					     * sizeof(int));
		if (a->num_paths == NULL) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}
		new_path = TRUE;
		a->paths[cur] = p;
		a->num_paths[cur] = 1;
	}

	if (new_path)
		return 1;
	return 0;
}

static int breadth_first_find_path(iflow_graph_t *g, int node, int *path)
{
	int next_node = node;
	int path_len = g->nodes[node].distance + 1;
	int i = path_len - 1;
	
	while (i >= 0) {
		path[i] = next_node;
		next_node = g->nodes[next_node].parent;
		i--;
	}

	return path_len;
}

static int do_breadth_first_search(iflow_graph_t *g, queue_t queue, iflow_query_t *q,
				   iflow_transitive_t *a)
{
	int i, ret = 0, path_len, *path;
	int num_edges;
	bool_t skip_node;

	path = (int*)malloc(g->num_nodes * sizeof(int));
	if (!path) {
		ret = -1;
		goto out;
	}

	while (queue_head(queue)) {
		void *cur_ptr;
		int cur;
		cur_ptr = queue_remove(queue);
		if (cur_ptr == NULL) {
			ret = -1;
			goto out;
		}
		cur = ((int)cur_ptr) - 1;
		
		if (g->nodes[cur].color == IFLOW_COLOR_RED) {
			skip_node = FALSE;
			if (q->num_end_types) {
				if (find_int_in_array(g->nodes[cur].type, q->end_types, q->num_end_types) == -1) {
					skip_node = TRUE;
				}
			}
			if (!skip_node) {
				path_len = breadth_first_find_path(g, cur, path);
				if (path_len == -1) {
					ret = -1;
					goto out;
				}
				if (transitive_answer_append(g, q, a, cur, path_len, path) == -1) {
					ret = -1;
					goto out;
				}
			}
		}
			
		g->nodes[cur].color = IFLOW_COLOR_BLACK;
		if (q->direction == IFLOW_OUT)
			num_edges = g->nodes[cur].num_out_edges;
		else
			num_edges = g->nodes[cur].num_in_edges;
		for (i = 0; i < num_edges; i++) {
			int cur_edge, cur_node;
			if (q->direction == IFLOW_OUT) {
				cur_edge = g->nodes[cur].out_edges[i];
				cur_node = g->edges[cur_edge].end_node;
			} else {
				cur_edge = g->nodes[cur].in_edges[i];
				cur_node = g->edges[cur_edge].start_node;
			}
			if (g->nodes[cur_node].color == IFLOW_COLOR_WHITE) {
				if (g->nodes[cur_node].distance == -1)
					g->nodes[cur_node].color = IFLOW_COLOR_RED;
				else
					g->nodes[cur_node].color = IFLOW_COLOR_GREY;
				g->nodes[cur_node].distance = g->nodes[cur].distance + 1;
				g->nodes[cur_node].parent = cur;
				if (queue_insert(queue, (void*)(cur_node + 1)) < 0) {
					fprintf(stderr, "Error inserting into queue\n");
					ret = -1;
					goto out;
				}
			}
		}
	}

out:
	if (path)
		free(path);
	return ret;
}

iflow_transitive_t *iflow_transitive_flows(policy_t *policy, iflow_query_t *q)
{
	queue_t queue = NULL;
	int num_nodes, *nodes;
	int i, j, start_node;
	iflow_transitive_t *a;
	iflow_graph_t *g;

	if (!iflow_query_is_valid(q, policy))
		return NULL;
	
	if (!((q->direction == IFLOW_OUT ) || (q->direction == IFLOW_IN))) {
		fprintf(stderr, "Direction must be IFLOW_IN or IFLOW_OUT\n");
		return NULL;
	}

	g = iflow_graph_create(policy, q);
	if (!g) {
		fprintf(stderr, "Error creating graph\n");
		return NULL;
	}

	a = (iflow_transitive_t*)malloc(sizeof(iflow_transitive_t));
	if (a == NULL) {
		fprintf(stderr, "Memory error!\n");
		goto err;
	}
	memset(a, 0, sizeof(iflow_transitive_t));

	queue = queue_create();
	if (!queue) {
		fprintf(stderr, "Error creating queue\n");
		goto err;
	}

	if (iflow_graph_get_nodes_for_type(g, q->start_type, &num_nodes, &nodes) < 0)
		return NULL;

	if (num_nodes == 0) {
		goto out;
	}

	/* paint all nodes white */
	for (i = 0; i < g->num_nodes; i++) {
		g->nodes[i].color = IFLOW_COLOR_WHITE;
		g->nodes[i].parent = -1;
		g->nodes[i].distance = -1;
	}

	start_node = nodes[0];

	g->nodes[start_node].color = IFLOW_COLOR_GREY;
	g->nodes[start_node].distance = 0;
	g->nodes[start_node].parent = -1;

	if (queue_insert(queue, (void*)(start_node + 1)) < 0) {
		fprintf(stderr, "Error inserting into queue\n");
		goto err;
	}

	if (do_breadth_first_search(g, queue, q, a) < 0)
		goto err;

	for (i = 1; i < num_nodes; i++) {

		/* paint all nodes white */
		for (j = 0; j < g->num_nodes; j++) {
			g->nodes[j].color = IFLOW_COLOR_WHITE;
			g->nodes[j].parent = -1;
		}

		start_node = nodes[i];

		g->nodes[start_node].color = IFLOW_COLOR_GREY;
		g->nodes[start_node].distance = 0;
		g->nodes[start_node].parent = -1;

		if (queue_insert(queue, (void*)(start_node + 1)) < 0) {
			fprintf(stderr, "Error inserting into queue\n");
			goto err;
		}

		if (do_breadth_first_search(g, queue, q, a) < 0)
			goto err;
	}
out:
	iflow_graph_destroy(g);
	free(g);
	if (nodes)
		free(nodes);
	queue_destroy(queue);
	return a;
err:
	iflow_transitive_destroy(a);
	a = NULL;
	goto out;
}

/* Random shuffle from Knuth Seminumerical Algorithms p. 139 */
static void shuffle_list(int len, int *list)
{	
	float U;
	int j, k, tmp;

	srand((int)time(NULL));

	for (j = len - 1; j > 0; j--) {
		/* get a random number between 1 and j */
		U = rand() / (float)RAND_MAX;
		k = ((int)(j * U)) + 1;
		tmp = list[k];
		list[k] = list[j];
		list[j] = tmp;
	}
}

static int get_random_edge_list(int edges_len, int **edge_list)
{	

	int i;

	*edge_list = (int*)malloc(sizeof(int) * edges_len);
	if (!*edge_list) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	for (i = 0; i < edges_len; i++)
		(*edge_list)[i] = i;

	shuffle_list(edges_len, *edge_list);

	return 0;
}

typedef struct bfs_random_state {
	iflow_graph_t *g;
	queue_t queue;
	iflow_query_t *q;
	policy_t *policy;
	iflow_transitive_t *a;
	int *path;
	int num_nodes;
	int *nodes;
	int num_enodes;
	int *enodes;
	int cur;
} bfs_random_state_t;

void bfs_random_state_destroy(bfs_random_state_t *s)
{
	if (s->g) {
		iflow_graph_destroy(s->g);
		free(s->g);
	}

	if (s->q)
		iflow_query_destroy(s->q);
	
	if (s->queue) {
		queue_destroy(s->queue);
	}

	if (s->path)
		free(s->path);
	if (s->nodes)
		free(s->nodes);
	if (s->enodes)
		free(s->enodes);
}

int bfs_random_state_init(bfs_random_state_t *s, policy_t *p, iflow_query_t *q, iflow_transitive_t *a)
{
	assert(s);
	memset(s, 0, sizeof(bfs_random_state_t));
	s->policy = p;
	s->a = a;

	s->q = iflow_query_create();
	if (!s->q) {
		fprintf(stderr, "Error creating query\n");
		return -1;
	}

	if (iflow_query_copy(s->q, q)) {
		fprintf(stderr, "Error copy query\n");
		return -1;
	}

	if (!iflow_query_is_valid(q, p))
		return -1;

	if (q->num_end_types != 1) {
		fprintf(stderr, "You must provide exactly 1 end type\n");
		return -1;
	}


	s->g = iflow_graph_create(p, q);
	if (!s->g) {
		fprintf(stderr, "Error creating graph\n");
		return -1;
	}

	s->queue = queue_create();
	if (!s->queue) {
		fprintf(stderr, "Error creating queue\n");
		goto err;
	}

	if (iflow_graph_get_nodes_for_type(s->g, q->start_type, &s->num_nodes, &s->nodes) < 0)
		goto err;
	if (iflow_graph_get_nodes_for_type(s->g, q->end_types[0], &s->num_enodes, &s->enodes) <0)
		goto err;

	s->path = (int*)malloc(sizeof(int) * s->g->num_nodes);
	if (!s->path) {
		fprintf(stderr, "Memory error\n");
		goto err;
	}
		       
	return 0;
err:
	bfs_random_state_destroy(s);
	return -1;
}



static int do_breadth_first_search_random(bfs_random_state_t *s)
{
	int i, ret = 0, path_len, *edge_list = NULL;
	int num_edges, cur;
	void *cur_ptr;
	bool_t found_new_path = FALSE;

	while (queue_head(s->queue)) {
	
		cur_ptr = queue_remove(s->queue);
		if (cur_ptr == NULL) {
			ret = -1;
			goto out;
		}
		cur = ((int)cur_ptr) - 1;
	
		if (find_int_in_array(cur, s->enodes, s->num_enodes) != -1) {
			path_len = breadth_first_find_path(s->g, cur, s->path);
			if (path_len == -1) {
				ret = -1;
				goto out;
			}
			ret = transitive_answer_append(s->g, s->q, s->a, cur, path_len, s->path);
			if (ret == -1) {
				fprintf(stderr, "Error in transitive answer append\n");
				goto out;
			} else if (ret > 0) {
				found_new_path = TRUE;
			}
		}
		
		s->g->nodes[cur].color = IFLOW_COLOR_BLACK;
		if (s->q->direction == IFLOW_OUT)
			num_edges = s->g->nodes[cur].num_out_edges;
		else
			num_edges = s->g->nodes[cur].num_in_edges;
		if (num_edges) {
			if (get_random_edge_list(num_edges, &edge_list) < 0) {
				ret = -1;
				goto out;
			}
		}
		for (i = 0; i < num_edges; i++) {
			int cur_edge, cur_node;
			if (s->q->direction == IFLOW_OUT) {
				cur_edge = s->g->nodes[cur].out_edges[edge_list[i]];
				cur_node = s->g->edges[cur_edge].end_node;
			} else {
				cur_edge = s->g->nodes[cur].in_edges[edge_list[i]];
				cur_node = s->g->edges[cur_edge].start_node;
			}
			if (s->g->nodes[cur_node].color == IFLOW_COLOR_WHITE) {
				s->g->nodes[cur_node].color = IFLOW_COLOR_GREY;
				s->g->nodes[cur_node].distance = s->g->nodes[cur].distance + 1;
				s->g->nodes[cur_node].parent = cur;
				if (queue_insert(s->queue, (void*)(cur_node + 1)) < 0) {
					fprintf(stderr, "Error inserting into queue\n");
					ret = -1;
					goto out;
				}
			}
		}
		if (edge_list) {
			free(edge_list);
			edge_list = NULL;
		}
	}

	if (found_new_path)
		ret = 1;
out:
	if (edge_list)
		free(edge_list);
	return ret;
}

int iflow_find_paths_next(void *state)
{
	int j, start_node;
	bfs_random_state_t *s = (bfs_random_state_t*)state;
	int num_paths;

	/* paint all nodes white */
	for (j = 0; j < s->g->num_nodes; j++) {
		s->g->nodes[j].color = IFLOW_COLOR_WHITE;
		s->g->nodes[j].parent = -1;
		s->g->nodes[j].distance = -1;
	}

	start_node = s->nodes[s->cur];
	
	s->g->nodes[start_node].color = IFLOW_COLOR_GREY;
	s->g->nodes[start_node].distance = 0;
	s->g->nodes[start_node].parent = -1;
	
	if (queue_insert(s->queue, (void*)(start_node + 1)) < 0) {
		fprintf(stderr, "Error inserting into queue\n");
		return -1;
	}
	
	if (do_breadth_first_search_random(s) < 0)
		return -1;

	s->cur++;
	if (s->cur >= s->num_nodes) {
		s->cur = 0;
		shuffle_list(s->num_nodes, s->nodes);
	}

	if (s->a->num_paths)
		num_paths = s->a->num_paths[0];
	else
		num_paths = 0;

	return num_paths;
}

/* caller does not need to free the query */
void *iflow_find_paths_start(policy_t *policy, iflow_query_t *q)
{
	bfs_random_state_t *s;
	iflow_transitive_t *a;

	s = (bfs_random_state_t*)malloc(sizeof(bfs_random_state_t));
	if (!s) {
		fprintf(stderr, "Memory error\n");
		return NULL;
	}

	a = (iflow_transitive_t*)malloc(sizeof(iflow_transitive_t));
	if (!a) {
		free(s);
		fprintf(stderr, "Memory error\n");
		return NULL;
	}
	memset(a, 0, sizeof(iflow_transitive_t));

	if (bfs_random_state_init(s, policy, q, a)) {
		fprintf(stderr, "Random state init error\n");
		free(s);
		free(a);
		return NULL;
	}
	return (void*)s;
}

iflow_transitive_t *iflow_find_paths_end(void *state)
{
	bfs_random_state_t *s = (bfs_random_state_t*)state;
	iflow_transitive_t *a;

	a = s->a;
	bfs_random_state_destroy(s);
	free(s);
	return a;
}

void iflow_find_paths_abort(void *state)
{
	bfs_random_state_t *s = (bfs_random_state_t*)state;

	bfs_random_state_destroy(s);
	free(s);
	iflow_transitive_destroy(s->a);
}

/* end information flow analysis 
*************************************************************************/
