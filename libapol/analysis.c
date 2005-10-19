/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com
 * Modified by: don.patterson@tresys.com
 *		6-17-2003: Added reverse DTA. 
 *		6-04-2004: Enhanced forward DTA to select by  
 *			   object class perm and/or object type. 
 *		6-23-2004: Added types relationship analysis.
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
#include <errno.h>

#include "policy.h"
#include "util.h"
#include "analysis.h"
#include "policy-query.h"
#include "infoflow.h"
#include "queue.h"
#include "dta.h"

/* Select by object class/permissions.	
 * Forward domain transition - limits the query to to find transitions to domains  
 *	that have specific permissions on object classes or entire object classes.  
 */
int dta_query_add_obj_class(dta_query_t *q, int obj_class)
{
	return apol_add_class_to_obj_perm_set_list(&q->obj_options, &q->num_obj_options, obj_class);
}

int dta_query_add_obj_class_perm(dta_query_t *q, int obj_class, int perm)
{
	return apol_add_perm_to_obj_perm_set_list(&q->obj_options, &q->num_obj_options, obj_class, perm);
}

/* Select by object type.	
 * Forward domain transition - limits the query to find transitions to domains
 * 	that have access to specific object types.
 */
int dta_query_add_end_type(dta_query_t *q, int end_type)
{
	return policy_query_add_type(&q->end_types, &q->num_end_types, end_type);
}

/*************************************************************************
 * domain transition analysis
 */
 
/* all the "free" fns below have a prototype just like free() so that
 * ll_free() in util.c can use them.  This makes us have to cast the
 * pointer, which can also cause run-time errors since someone could
 * mistakenly pass the wrong data type!  BE CAREFUL!.
 */
 
dta_query_t *dta_query_create(void)
{
	dta_query_t* q = (dta_query_t*)malloc(sizeof(dta_query_t));
	if (q == NULL) {
		fprintf(stderr, "Memory error!\n");
		return NULL;
	}
	memset(q, 0, sizeof(dta_query_t));
	q->start_type = -1;
	q->reverse = FALSE;
	
	return q;
}

void dta_query_destroy(dta_query_t *q)
{
	int i;
	
	assert(q != NULL);
	if (q->end_types)
		free(q->end_types);
	if (q->filter_types)
		free(q->filter_types);
	for (i = 0; i < q->num_obj_options; i++) {
		if (q->obj_options[i].perms)
			free(q->obj_options[i].perms);
	}
	if (q->obj_options)
		free(q->obj_options);
	free(q);
}

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
	if(p->other_rules != NULL) 
		free(p->other_rules);
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

/* main domain trans analysis function.
 * 	dta_results must be allocated and initialized
 *
 *	returns:	
 *		-1 general error
 *		-2 start_domain invalid type
 */

int determine_domain_trans(dta_query_t *dta_query, 
			   domain_trans_analysis_t **dta_results, 
			   policy_t *policy)
{
	dta_table_t *table = NULL;
	dta_trans_t *transitions = NULL;
	domain_trans_analysis_t *dta_res = NULL;
	int retv;

	if (!dta_query || !policy || !dta_results) {
		errno = EINVAL;
		perror("Domain Transition Analysis");
		return -1;
	}

	/* create the lookup table*/
	table = dta_table_new(policy);
	if (!table) {
		perror("Error creating DTA lookup table");
		return -1;
	}

	/* build the table (builds hash table if not yet done) */
	retv = dta_table_build(table, policy);
	if (retv) {
		perror("Error building DTA lookup table");
		goto exit_error;
	}

	/* get list of transitions */
	if (dta_query->reverse) {
		retv = dta_table_get_all_reverse_trans(table, &transitions, dta_query->start_type);
		if (retv) {
			perror("DTA Reverse Analysis");
			goto exit_error;
		}
	} else {
		retv = dta_table_get_all_trans(table, &transitions, dta_query->start_type);
		if (retv) {
			perror("DTA Forward Analysis");
			goto exit_error;
		}
	}

	/* filter list to contain only valid transitions */
	retv = dta_trans_filter_valid(&transitions, 1);
	if (retv) {
		perror("DTA filter out invalid transitions");
		goto exit_error;
	}

	/* optional end type filtering */
	if (dta_query->use_endtype_filters) {
		if (dta_query->reverse)
			retv = dta_trans_filter_start_types(&transitions, dta_query->filter_types, dta_query->num_filter_types);
		else
			retv = dta_trans_filter_end_types(&transitions, dta_query->filter_types, dta_query->num_filter_types);
		if (retv) {
			perror("DTA filter result types");
			goto exit_error;
		}
	}

	/* optional object access filtering (forward only) */
	if (dta_query->use_object_filters && !dta_query->reverse) {
		retv = dta_trans_filter_access_types(&transitions, dta_query->end_types, dta_query->num_end_types, dta_query->obj_options, dta_query->num_obj_options, policy);
		if (retv) {
			perror("DTA filter by object access");
			goto exit_error;
		}
	}

	/* if all results are filtered out or no results give this dummy to
	 * the conversion function to make an empty set */
	if (!transitions) {
		transitions = dta_trans_new();
		transitions->start_type = transitions->end_type = dta_query->start_type;
	}

	/* convert to struct used by other analysis modules and apol_tcl */
	dta_res = dta_trans_convert(transitions, dta_query->reverse);
	if (!dta_res) {
		perror("DTA convert to standard result format");
		goto exit_error;
	}

	/* results are valid at this point assign to passed in pointer */
	*dta_results = dta_res;

	dta_table_free(table);
	dta_trans_destroy(&transitions);

	return 0;

exit_error:
	free_domain_trans_analysis(dta_res);
	dta_table_free(table);
	dta_trans_destroy(&transitions);
	return -1;
}

/*
 * Starts Types Relationship Analysis functions:
 */
types_relation_query_t *types_relation_query_create(void)
{
	types_relation_query_t *q = (types_relation_query_t*)malloc(sizeof(types_relation_query_t));
	if (q == NULL) {
		fprintf(stderr, "Memory error!\n");
		return NULL;
	}
	memset(q, 0, sizeof(types_relation_query_t));
	q->type_A = -1;
	q->type_B = -1;
	q->options = TYPES_REL_NO_OPTS;
					
	return q;
}

void types_relation_query_destroy(types_relation_query_t *q)
{
	assert(q != NULL);
	if (q->type_name_A)
		free(q->type_name_A);
	if (q->type_name_B)
		free(q->type_name_B);
	if (q->dta_query)
		dta_query_destroy(q->dta_query);
	if (q->direct_flow_query)
		iflow_query_destroy(q->direct_flow_query);
	if (q->trans_flow_query)
		iflow_query_destroy(q->trans_flow_query);
	free(q);
}

static types_relation_obj_access_t *types_relation_obj_access_create(void)
{
	types_relation_obj_access_t *t = 
		(types_relation_obj_access_t*)malloc(sizeof(types_relation_obj_access_t));
	if (t == NULL) {
		fprintf(stderr, "Memory error!\n");
		return NULL;
	}
	memset(t, 0, sizeof(types_relation_obj_access_t));

	return t;
}

static void types_relation_obj_access_destroy(types_relation_obj_access_t *t)
{
	assert(t != NULL);
	if (t->objs_A)
		free(t->objs_A);
	if (t->objs_B)
		free(t->objs_B);
	
	free(t);
}

types_relation_results_t *types_relation_create_results(void)
{
	types_relation_results_t *tra;
	
	tra = (types_relation_results_t *)malloc(sizeof(types_relation_results_t));
	if (tra == NULL) {
		fprintf(stderr, "out of memory");
		return NULL;
	}
	memset(tra, 0, sizeof(types_relation_results_t));
	tra->type_A = -1;
	tra->type_B = -1;
	
	return tra;
}

static void types_relation_destroy_type_access_pool(types_relation_type_access_pool_t *p)
{	
	int i;
	
	assert(p != NULL);
	for (i = 0; i < p->num_types; i++) {
		if (p->type_rules[i]->rules)
			free(p->type_rules[i]->rules);
	}
	free(p->type_rules);
	if (p->types) free(p->types);
	free(p);
}

void types_relation_destroy_results(types_relation_results_t *tra)
{
	assert(tra != NULL);
	if (tra->common_attribs) {
		free(tra->common_attribs);
	}
	if (tra->common_roles) {
		free(tra->common_roles);
	}
	if (tra->common_users) {
		free(tra->common_users);
	}
	
	if (tra->dta_results_A_to_B)
		free_domain_trans_analysis(tra->dta_results_A_to_B);
	if (tra->dta_results_B_to_A)
		free_domain_trans_analysis(tra->dta_results_B_to_A);
	if (tra->direct_flow_results)
		iflow_destroy(tra->direct_flow_results);
	if (tra->trans_flow_results_A_to_B)
		iflow_transitive_destroy(tra->trans_flow_results_A_to_B);
	if (tra->trans_flow_results_B_to_A)
		iflow_transitive_destroy(tra->trans_flow_results_B_to_A);
		
	if (tra->tt_rules_results)
		free(tra->tt_rules_results);
	if (tra->allow_rules_results)
		free(tra->allow_rules_results);
			
	if (tra->common_obj_types_results)
		types_relation_obj_access_destroy(tra->common_obj_types_results);
	if (tra->unique_obj_types_results)
		types_relation_obj_access_destroy(tra->unique_obj_types_results);
	
	if (tra->typeA_access_pool) types_relation_destroy_type_access_pool(tra->typeA_access_pool);
	if (tra->typeB_access_pool) types_relation_destroy_type_access_pool(tra->typeB_access_pool);
	
	free(tra);
	
	return;
}

static int types_relation_find_common_attributes(types_relation_query_t *tra_query, 
			   			 types_relation_results_t **tra_results,
			   			 policy_t *policy) 
{
	int attrib_idx, rt;
	int *attribs_A = NULL, *attribs_B = NULL;
	int num_attribs_A = 0, num_attribs_B = 0;

	assert(policy != NULL || tra_query != NULL || tra_results != NULL);
	/* Get attribs for type A */
	rt = get_type_attribs(tra_query->type_A, &num_attribs_A, &attribs_A, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting attributes for type A.\n\n");
		return -1;
	}
	/* Get attribs for type B */
	rt = get_type_attribs(tra_query->type_B, &num_attribs_B, &attribs_B, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting attributes for type B.\n\n");
		goto err;
	}

	/* Get the intersection of both attribute sets (i.e. members which are in both sets) */
	if (num_attribs_A && num_attribs_B) {
		for (attrib_idx = 0; attrib_idx < policy->num_attribs; attrib_idx++) {
			if ((find_int_in_array(attrib_idx, attribs_A, num_attribs_A) >= 0) &&
			    (find_int_in_array(attrib_idx, attribs_B, num_attribs_B) >= 0)) {
				if (add_i_to_a(attrib_idx, &(*tra_results)->num_common_attribs, 
				    &(*tra_results)->common_attribs) != 0) {
					goto err;
				}	
			}
		}
	}

	if (attribs_A) free(attribs_A);
	if (attribs_B) free(attribs_B);
	return 0;	
err:
	if (attribs_A) free(attribs_A);
	if (attribs_B) free(attribs_B);
	return -1;
}

static int types_relation_find_common_roles(types_relation_query_t *tra_query, 
			   		    types_relation_results_t **tra_results,
			   		    policy_t *policy) 
{	
	int role_idx, rt;
	int *roles_A = NULL, *roles_B = NULL;
	int num_roles_A = 0, num_roles_B = 0;
	
	assert(policy != NULL || tra_query != NULL || tra_results != NULL);
	/* Get roles for type A */
	rt = get_type_roles(tra_query->type_A, &num_roles_A, &roles_A, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting roles for type A.\n\n");
		return -1;
	}
	/* Get roles for type B */
	rt = get_type_roles(tra_query->type_B, &num_roles_B, &roles_B, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting roles for type B.\n\n");
		goto err;
	}

	/* Get the intersection of both role sets (i.e. members which are in both sets) */
	if (num_roles_A && num_roles_B) {
		for (role_idx = 0; role_idx < policy->num_roles; role_idx++) {
			if ((find_int_in_array(role_idx, roles_A, num_roles_A) >= 0) &&
			    (find_int_in_array(role_idx, roles_B, num_roles_B) >= 0)) {
				if (add_i_to_a(role_idx, &(*tra_results)->num_common_roles, 
				    &(*tra_results)->common_roles) != 0) {
					goto err;
				}	
			}
		}
	}
	
	if (roles_A) free(roles_A);
	if (roles_B) free(roles_B);
	return 0;
err:	
	if (roles_A) free(roles_A);
	if (roles_B) free(roles_B);
	return -1;
}

static int types_relation_find_common_users(types_relation_query_t *tra_query, 
			   		    types_relation_results_t **tra_results,
			   		    policy_t *policy) 
{	
	int user_idx, rt;
	int *users_A = NULL, *users_B = NULL;
	int num_users_A = 0, num_users_B = 0;
		
	assert(policy != NULL || tra_query != NULL || tra_results != NULL);
	/* Get users for type A */
	rt = get_type_users(tra_query->type_A, &num_users_A, &users_A, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting users for type A.\n\n");
		return -1;
	}
	/* Get users for type B */
	rt = get_type_users(tra_query->type_B, &num_users_B, &users_B, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting users for type B.\n\n");
		goto err;
	}

	/* Get the intersection of both user sets (i.e. members which are in both sets) */
	if (num_users_A && num_users_B) {
		for (user_idx = 0; user_idx < policy->num_users; user_idx++) {
			if ((find_int_in_array(user_idx, users_A, num_users_A) >= 0) &&
			    (find_int_in_array(user_idx, users_B, num_users_B) >= 0)) {
				if (add_i_to_a(user_idx, &(*tra_results)->num_common_users, 
				    &(*tra_results)->common_users) != 0) {
					goto err;
				}	
			}
		}
	}
	
	if (users_A) free(users_A);
	if (users_B) free(users_B);
	return 0;	
err:
	if (users_A) free(users_A);
	if (users_B) free(users_B);
	return -1;
}

/* This function finds any FORWARD DOMAIN TRANSITIONS from typeA->typeB and from typeB->typeA. 
 * It will configure all necessary query paramters, except for any optional object 
 * classes/permissions and object types. */
static int types_relation_find_domain_transitions(types_relation_query_t *tra_query, 
			   		          types_relation_results_t **tra_results,
			   		    	  policy_t *policy) 
{	
	int rt;
	
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	/* Set direction paramter for both queries. */
	tra_query->dta_query->reverse = FALSE;
	tra_query->dta_query->use_endtype_filters = TRUE;
	/* Find transitions from typeA->typeB. First we configure the  
	 * DTA query arguments to have typeA as the starting domain and type B as the only end type. */
	tra_query->dta_query->start_type = tra_query->type_A;
	if (add_i_to_a(tra_query->type_B, &tra_query->dta_query->num_filter_types, 
		       &tra_query->dta_query->filter_types) != 0) {
		fprintf(stderr, "Error adding Type B to end type filter for domain transition.\n");
		return -1;
	}
	rt = determine_domain_trans(tra_query->dta_query, 
				    &(*tra_results)->dta_results_A_to_B, 
				    policy);
	/* Free endtype filter array and reset number to zero so we can run the analysis in the opposite direction. */
	free(tra_query->dta_query->filter_types);
	tra_query->dta_query->filter_types = NULL;
	tra_query->dta_query->num_filter_types = 0;
	if (rt == -2) {
		fprintf(stderr, "Type A is not a valid type\n");
		return -1;
	} else if (rt < 0) {
		fprintf(stderr, "Error with domain transition analysis\n");
		return -1;
	}
	
	/* Find transitions from typeB->typeA. First we configure the
	 * DTA query arguments to have typeB as the starting domain and type A as the only end type. */
	tra_query->dta_query->start_type = tra_query->type_B;
	if (add_i_to_a(tra_query->type_A, &tra_query->dta_query->num_filter_types, 
		       &tra_query->dta_query->filter_types) != 0) {
		fprintf(stderr, "Error adding Type A to end type filter for domain transition.\n");
		return -1;
	}
	rt = determine_domain_trans(tra_query->dta_query, 
				    &(*tra_results)->dta_results_B_to_A, 
				    policy);
	/* Free endtype filter array */
	free(tra_query->dta_query->filter_types);
	tra_query->dta_query->filter_types = NULL;
	if (rt == -2) {
		fprintf(stderr, "Type B is not a valid type\n");
		return -1;
	} else if (rt < 0) {
		fprintf(stderr, "Error with domain transition analysis\n");
		return -1;
	}

	return 0;
}

/* This function finds any DIRECT FLOWS from typeA->typeB and from typeB->typeA. It will
 * configure all necessary query parameters, except for any optional filters on object 
 * classes/permissions. */
static int types_relation_find_direct_flows(types_relation_query_t *tra_query, 
			   		    types_relation_results_t **tra_results,
			   		    policy_t *policy) 
{	
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	/* Set direction paramter to BOTH, in order to find direct  
	 * flows both into and out of typeA [from/to] typeB. */
	tra_query->direct_flow_query->direction = IFLOW_EITHER;
	
	/* Configure the query arguments to have typeA as  
	 * the starting domain and the end type as typeB. */
	tra_query->direct_flow_query->start_type = tra_query->type_A;
	tra_query->direct_flow_query->num_end_types = 0;
	if (tra_query->direct_flow_query->end_types) 
		free(tra_query->direct_flow_query->end_types);
		
	if (iflow_query_add_end_type(tra_query->direct_flow_query, tra_query->type_B) != 0) {
		fprintf(stderr, "Error adding end type to query!\n");
		return -1;
	}
	
	/* Get direct flows from typeA->typeB and from typeB->typeA. */									
	if (iflow_direct_flows(policy, tra_query->direct_flow_query, 
			       &(*tra_results)->num_dirflows, 
			       &(*tra_results)->direct_flow_results) < 0) {
		fprintf(stderr, "There were errors in the direct information flow analysis\n");
		return -1;
	}
				
	return 0;
}

/* This function finds any TRANSITIVE FLOWS from typeA->typeB and from typeB->typeA. 
 * All necessary query parameters will be configured, except for any optional filters 
 * on object classes/permissions and intermediate types. */
static int types_relation_find_trans_flows(types_relation_query_t *tra_query, 
			   		   types_relation_results_t **tra_results,
			   		   policy_t *policy) 
{		
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	       
	tra_query->trans_flow_query->direction = IFLOW_OUT;
	
	/* Configure the query arguments to have typeA as  
	 * the starting domain and the end type as typeB. */
	tra_query->trans_flow_query->start_type = tra_query->type_A;
	tra_query->trans_flow_query->num_end_types = 0;
	if (tra_query->trans_flow_query->end_types) 
		free(tra_query->trans_flow_query->end_types);
		
	if (iflow_query_add_end_type(tra_query->trans_flow_query, tra_query->type_B) != 0) {
		fprintf(stderr, "Error adding end type to query!\n");
		return -1;
	}
	
	if (((*tra_results)->trans_flow_results_A_to_B = 
	    iflow_transitive_flows(policy, tra_query->trans_flow_query)) == NULL) {
		fprintf(stderr, "There were errors in the information flow analysis\n");
		return -1;
	}
	
	/* Configure the query arguments to have typeB as  
	 * the starting domain and the end type as typeA. */
	tra_query->trans_flow_query->start_type = tra_query->type_B;
	tra_query->trans_flow_query->num_end_types = 0;
	if (tra_query->trans_flow_query->end_types) {
		free(tra_query->trans_flow_query->end_types);
		tra_query->trans_flow_query->end_types = NULL;
	}
		
	if (iflow_query_add_end_type(tra_query->trans_flow_query, tra_query->type_A) != 0) {
		fprintf(stderr, "Error adding end type to query!\n");
		return -1;
	}
	
	if (((*tra_results)->trans_flow_results_B_to_A = 
	    iflow_transitive_flows(policy, tra_query->trans_flow_query)) == NULL) {
		fprintf(stderr, "There were errors in the information flow analysis\n");
		return -1;
	}
			
	return 0;
}

static int types_relation_search_te_rules(teq_query_t *query, 
					  teq_results_t *results, 
			   		  char *ta1, char *ta2,
			   		  policy_t *policy) 
{
	int rt;
	
	assert(query != NULL && results != NULL && policy != NULL);
	
	if (ta1 != NULL) {
		(*query).ta1.ta = (char *)malloc((strlen(ta1) + 1) * sizeof(char));
		if ((*query).ta1.ta == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		strcpy((*query).ta1.ta, ta1);	/* The ta1 string */
	}
	if (ta2 != NULL) {
		(*query).ta2.ta = (char *)malloc((strlen(ta2) + 1) * sizeof(char));
		if ((*query).ta2.ta == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		strcpy((*query).ta2.ta, ta2);	/* The ta2 string */ 
	}
	
	/* search rules */
	rt = search_te_rules(query, results, policy);
	if (rt < 0) {
		if ((*results).errmsg) {
			fprintf(stderr, "%s", (*results).errmsg);
			free((*results).errmsg);
		} else {
			fprintf(stderr, "Unrecoverable error when searching TE rules.");
		}
		return -1;
	}
				       	        
	return 0;
}

/* This function finds all type transition rules that relate typeA<->typeB.
 * It starts by searching type transition/change/member rules with typeA as
 * the source and then flips the query to search for typeB as the source*/
static int types_relation_find_type_trans_rules(types_relation_query_t *tra_query, 
			   		     	types_relation_results_t **tra_results,
			   		   	policy_t *policy) 
{	
	teq_query_t query;
	teq_results_t results;
	int i, rt, tt_rule_idx, rule_pass, is_typeA_rule, is_typeB_rule;
	int cnt = 0; 	/* Variable needed for the does_tt_rule_use_type() function we will call. */
		
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	       
	init_teq_query(&query);
	init_teq_results(&results);	
	query.rule_select |= TEQ_TYPE_TRANS;
	query.rule_select |= TEQ_TYPE_MEMBER;
	query.rule_select |= TEQ_TYPE_CHANGE;
	query.use_regex = FALSE;
	query.only_enabled = 1;
	
	/* Query for all type trans/change/member rules */				
	rt = types_relation_search_te_rules(&query, &results, NULL, NULL, policy);
	if (rt != 0) {
		fprintf(stderr, "Problem searching TE rules");
		goto err;
	}
	free_teq_query_contents(&query);
	for (i = 0; i < results.num_type_rules; i++) {	
		tt_rule_idx = results.type_rules[i];
		/* Does this rule have typeA in its' source types list? */					
		is_typeA_rule = does_tt_rule_use_type(tra_query->type_A, IDX_TYPE, SRC_LIST, 
						      TRUE, &(policy->te_trans[tt_rule_idx]), 
						      &cnt, policy);
		if (is_typeA_rule == -1)
			goto err;
		/* Does this rule have typeB in its' source types list? */
		is_typeB_rule = does_tt_rule_use_type(tra_query->type_B, IDX_TYPE, SRC_LIST, 
					      	      TRUE, &(policy->te_trans[tt_rule_idx]), 
					      	      &cnt, policy);
		if (is_typeB_rule == -1)
			goto err;
		/* Skip this rule if it contains neither typeA or typeB in source list */
		if (!is_typeA_rule && !is_typeB_rule) 
			continue;
		if (is_typeA_rule) {
			/* Does this rule have typeB in its' target or default type list? */					
			rule_pass = does_tt_rule_use_type(tra_query->type_B, IDX_TYPE, (TGT_LIST | DEFAULT_LIST), 
								    TRUE, &(policy->te_trans[tt_rule_idx]), 
								    &cnt, policy);
			if (rule_pass == -1)
				goto err;
			if (rule_pass) {
				if (find_int_in_array(tt_rule_idx, (*tra_results)->tt_rules_results, 
				    (*tra_results)->num_tt_rules) < 0) {
					if (add_i_to_a(tt_rule_idx, &(*tra_results)->num_tt_rules, 
						       &(*tra_results)->tt_rules_results) != 0) {
						goto err;
					}
				}
			}
		} 
		if (is_typeB_rule) {
			/* Does this rule have typeA in its' target or default type list? */					
			rule_pass = does_tt_rule_use_type(tra_query->type_A, IDX_TYPE, (TGT_LIST | DEFAULT_LIST), 
								    TRUE, &(policy->te_trans[tt_rule_idx]), 
								    &cnt, policy);
			if (rule_pass == -1)
				goto err;
			if (rule_pass) {
				if (find_int_in_array(tt_rule_idx, (*tra_results)->tt_rules_results, 
				    (*tra_results)->num_tt_rules) < 0) {
					if (add_i_to_a(tt_rule_idx, &(*tra_results)->num_tt_rules, 
						       &(*tra_results)->tt_rules_results) != 0) {
						goto err;
					}
				}
			}
		}
	}
	free_teq_results_contents(&results);
	
	return 0;
err:
	free_teq_query_contents(&query);
	free_teq_results_contents(&results);
	return -1;
}

/* This function finds all te rules that relate TypeA and TypeB. */
static int types_relation_find_te_rules(types_relation_query_t *tra_query, 
	   		     	        types_relation_results_t **tra_results,
	   		   	        policy_t *policy) 
{		
	int rule_idx, rule_pass, is_typeA_rule, is_typeB_rule; 
		
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	/* Loop throough all av access rules and check for a rule that has typeA or typeB as source.
	 * If so, the perform further analysis on the target type of the rule. */
	for (rule_idx = 0; rule_idx < policy->num_av_access; rule_idx++) {	
		/* Skip neverallow rules */
		if ((policy->av_access)[rule_idx].type != RULE_TE_ALLOW)
			continue;	
		/* Does this rule have typeA in its' source types list? */					
		is_typeA_rule = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_A, 
					      		  IDX_TYPE, SRC_LIST, TRUE, 
					      		  policy);
		if (is_typeA_rule == -1)
			return -1;
		/* Does this rule have typeB in its' source types list? */
		is_typeB_rule = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_B, 
					      		  IDX_TYPE, SRC_LIST, TRUE, 
					      		  policy);
		if (is_typeB_rule == -1)
			return -1;
		/* Skip this rule if it contains neither typeA or typeB in source list */
		if (!(is_typeA_rule || is_typeB_rule)) 
			continue;
		if (is_typeA_rule) {
			/* Does this rule have typeB in its' target list? */					
			rule_pass = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_B, 
					      		  IDX_TYPE, TGT_LIST, TRUE, 
					      		  policy);
			if (rule_pass == -1)
				return -1;
			if (rule_pass) {
				if (find_int_in_array(rule_idx, (*tra_results)->allow_rules_results, 
				    (*tra_results)->num_allow_rules) < 0) {
					if (add_i_to_a(rule_idx, &(*tra_results)->num_allow_rules, 
						       &(*tra_results)->allow_rules_results) != 0) {
						return -1;
					}
				}
			}
		} 
		if (is_typeB_rule) {
			/* Does this rule have typeA in its' target list? */					
			rule_pass = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_A, 
					      		  IDX_TYPE, TGT_LIST, TRUE, 
					      		  policy);
			if (rule_pass == -1)
				return -1;
			if (rule_pass) {
				if (find_int_in_array(rule_idx, (*tra_results)->allow_rules_results, 
				    (*tra_results)->num_allow_rules) < 0) {
					if (add_i_to_a(rule_idx, &(*tra_results)->num_allow_rules, 
						       &(*tra_results)->allow_rules_results) != 0) {
						return -1;
					}
				}
			}
		}
	}		
	
	return 0;
}
			
static types_relation_type_access_pool_t *types_relation_create_type_access_pool(policy_t *policy)
{	
	int k;
	types_relation_type_access_pool_t *all_unique_rules_pool = 
		(types_relation_type_access_pool_t *)malloc(sizeof(types_relation_type_access_pool_t));
		
	if (all_unique_rules_pool == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	memset(all_unique_rules_pool, 0, sizeof(types_relation_type_access_pool_t));
	all_unique_rules_pool->type_rules = 
		(types_relation_rules_t **)malloc(policy->num_types * sizeof(types_relation_rules_t*));
	
	for (k = 0; k < policy->num_types; k++) {
		all_unique_rules_pool->type_rules[k] = (types_relation_rules_t *)malloc(sizeof(types_relation_rules_t));
		if (all_unique_rules_pool->type_rules[k] == NULL) {
			fprintf(stderr, "out of memory\n");
			types_relation_destroy_type_access_pool(all_unique_rules_pool);
			return NULL;
		}
		memset(all_unique_rules_pool->type_rules[k], 0, sizeof(types_relation_rules_t));
		all_unique_rules_pool->num_types = all_unique_rules_pool->num_types + 1;
	}
	
	return all_unique_rules_pool;
}

static int types_relation_add_to_type_access_pool(types_relation_type_access_pool_t *p, int rule_idx, int type_idx, policy_t *policy)
{	
	assert(p != NULL && policy != NULL);
	assert(is_valid_type_idx(type_idx, policy) && is_valid_av_rule_idx(rule_idx, 1, policy));
	
	/* Only add to the list if the type doesn't already exist */
	if (find_int_in_array(type_idx, p->types, p->num_types) < 0) {
		if (add_i_to_a(type_idx, &p->num_types, &p->types) != 0) {
			return -1;
		 }
	}
	/* Only add to the list if the rule doesn't already exist */
	if (find_int_in_array(rule_idx, 
	    p->type_rules[type_idx]->rules, 
	    p->type_rules[type_idx]->num_rules) < 0) {					
		if (add_i_to_a(rule_idx, &p->type_rules[type_idx]->num_rules, &p->type_rules[type_idx]->rules) != 0) {
			return -1;
		}
	}
	return 0;
}

/* This function finds all common object types to which both typeA and typeB have access. 
 * Additionally, the allow rules are included in the results. */
static int types_relation_find_obj_types_access(types_relation_query_t *tra_query, 
			   		     	types_relation_results_t **tra_results,
			   		   	policy_t *policy) 
{		
	int *tgt_types = NULL, num_tgt_types = 0;
	int rule_idx, type_idx, j, rt;
	int typeA_accesses_type, typeB_accesses_type;
	types_relation_type_access_pool_t *tgt_type_access_pool_A = NULL; 
	types_relation_type_access_pool_t *tgt_type_access_pool_B = NULL; 
	
	assert(tra_query != NULL && tra_results != NULL 
	       && *tra_results != NULL && policy != NULL);
	if (!(tra_query->options & 
	    (TYPES_REL_COMMON_ACCESS | TYPES_REL_UNIQUE_ACCESS))) {
		return 0;
	}
			
	/* The following are seperate databases to hold rules for typeA and typeB respectively. 
	 * The database holds an array of pointers to types_relation_rules_t structs. The
	 * indices of this array correspond to type indices in the policy database. So for example, 
	 * if we need to get the rules for typeA that have a specific type in its' target type
	 * list, we will be able to do so by simply specifying the index of the type we are 
	 * interested in as the array index for tgt_type_access_pool_A. The same is true if we
	 * wanted to get rules for typeB that have a specific type in it's target type list, except
	 * we would specify the types index to tgt_type_access_pool_B. This is better for the performance
	 * of this analysis, as opposed to looping through all of the access rules more than once.
	 * Instead, the end result are 2 local databases which contain all of the information we need.
	 * We can then compare target types list for typeA and typeB, determine common and unique access 
	 * and have easy access to the relevant rules. */
	tgt_type_access_pool_A = types_relation_create_type_access_pool(policy);
	if (tgt_type_access_pool_A == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	tgt_type_access_pool_B = types_relation_create_type_access_pool(policy);
	if (tgt_type_access_pool_B == NULL) {
		types_relation_destroy_type_access_pool(tgt_type_access_pool_A);
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	/* Parse all allow rules that have typeA and typeB as the source type argument and 
	 * grow the seperate databases for typeA and typeB as needed. */		
	for (rule_idx = 0; rule_idx < policy->num_av_access; rule_idx++) {	
		/* Skip neverallow rules */
		if ((policy->av_access)[rule_idx].type != RULE_TE_ALLOW)
			continue;
		/* Does this rule have typeA in its' source types list? */					
		typeA_accesses_type = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_A, 
					      IDX_TYPE, SRC_LIST, TRUE, 
					      policy);
		if (typeA_accesses_type == -1)
			goto err;
		/* Does this rule have typeB in its' source types list? */			
		typeB_accesses_type = does_av_rule_idx_use_type(rule_idx, 0, tra_query->type_B, 
					      IDX_TYPE, SRC_LIST, TRUE, 
					      policy);
		if (typeB_accesses_type == -1)
			goto err;
		
		/* Make sure this is a rule that has either typeA or typeB as the source. */
		if (!(typeA_accesses_type || typeB_accesses_type)) 
			continue;
				 
		/* Extract target type(s) from the rule */
		rt = extract_types_from_te_rule(rule_idx, RULE_TE_ALLOW, 
					        TGT_LIST, &tgt_types, &num_tgt_types, 
					        policy);
		if (rt < 0)
			goto err;
		
		if (rt == 2) {
			/* encountered '*', so add all types 
			 * NOTE: Start from j = 1 since we know that type index 0 is 'self' and
			 * 	we don't want to include the pdeudo type self
			 */
			for (j = 1; j < policy->num_types; j++) {
				if (add_i_to_a(j, &num_tgt_types, &tgt_types) == -1) {
					goto err;
				}
			}
		}
		
		
		/* Check to see if the rule has typeA or typeB as the source argument. */
		if (typeA_accesses_type){						
			for (j = 0; j < num_tgt_types; j++) {
				/* We don't want the pseudo type 'self' */
				if (tgt_types[j] == 0) {
					type_idx = tra_query->type_A;
				} else {
					type_idx = tgt_types[j];
				}
				
				/* Add this target type and the associated rule index to our database. */
				if (types_relation_add_to_type_access_pool(tgt_type_access_pool_A, rule_idx, type_idx, policy) != 0)
						goto err;
			}
						
		} 
		if (typeB_accesses_type) {
			for (j = 0; j < num_tgt_types; j++) {
				/* We don't want the pseudo type 'self' */
				if (tgt_types[j] == 0) {
					type_idx = tra_query->type_B;
				} else {
					type_idx = tgt_types[j];
				}
				/* Add this target type and the associated rule index to our database. */
				if (types_relation_add_to_type_access_pool(tgt_type_access_pool_B, rule_idx, type_idx, policy) != 0)
						goto err;
			}
		} 
		if (tgt_types != NULL) {
			free(tgt_types);
			tgt_types = NULL;
			num_tgt_types = 0;
		}
	}
	
	if (tra_query->options & TYPES_REL_COMMON_ACCESS) {
		(*tra_results)->common_obj_types_results = types_relation_obj_access_create();
		if ((*tra_results)->common_obj_types_results == NULL) {
			fprintf(stderr, "Out of memory\n");
			goto err;
		}

	}
	if (tra_query->options & TYPES_REL_UNIQUE_ACCESS) {
		(*tra_results)->unique_obj_types_results = types_relation_obj_access_create();
		if ((*tra_results)->unique_obj_types_results == NULL) {
			fprintf(stderr, "Out of memory\n");
			goto err;
		}
	}		
	
	/* We now have seperate databases for typeA and typeB which consists of:
	 *	- list of target types to which it has access. 
	 * 	- list of rule records indexed by each type index in the policy. We will
	 *	  use the index for each target type to get the relative rules. 
	 * Next, we will:
	 *	1. loop through each type in the policy
	 *	2. Determine if typeA and/or typeB have access to this particular type
	 *	3. If they have access to the type, then we will add this type to the common
	 *	   types list in our results. We also, add the relative rules to our results. 
	 *	4. If either typeA or typeB has unique access to this type, then we add this
	 *	   type to the appropriate unique types list in our results. We also, add the 
	 *	   relative rules to our results.
	 *	5. If neither typeA nor typeB have access to this type, we just skip and move
	 *	   on.
	 *
	 * Start from index 1, since index 0 is the pseudo type 'self'
	 */
	for (type_idx = 1; type_idx < policy->num_types; type_idx++) {
		/* Determine if this is a type that typeA has access to */
		typeA_accesses_type = find_int_in_array(type_idx, 
		    				    tgt_type_access_pool_A->types, 
		    				    tgt_type_access_pool_A->num_types);
		
		/* Determine if this is a type that typeB has access to */
		typeB_accesses_type = find_int_in_array(type_idx, 
		    				    tgt_type_access_pool_B->types, 
		    				    tgt_type_access_pool_B->num_types);
		    				    
		/* Neither typeA nor typeB have access to this type, so move on.*/		    				    
		if (typeA_accesses_type < 0 && typeB_accesses_type < 0) 
			continue;
			
		/* There can only be 3 cases here:
		 * 	1. Both typeA and typeB have access to this type, hence indicating common access. 
		 *	2. TypeA alone has access to this type, hence indicating unique access.
		 *	3. TypeB alone has access to this type, hence indicating unique access. */
		if ((tra_query->options & TYPES_REL_COMMON_ACCESS) && 
		    (typeA_accesses_type >= 0) && 
		    (typeB_accesses_type >= 0)) {
			/* Add as common target type for typeA within our results */
			if (add_i_to_a(type_idx, 
			    	       	&(*tra_results)->common_obj_types_results->num_objs_A, 
			    		&(*tra_results)->common_obj_types_results->objs_A) != 0) {
				return -1;
			}
			/* Add as common target type for typeA within our results */
			if (add_i_to_a(type_idx, 
			    		&(*tra_results)->common_obj_types_results->num_objs_B, 
			    		&(*tra_results)->common_obj_types_results->objs_B) != 0) {
				return -1;
			}
		} else if ((tra_query->options & TYPES_REL_UNIQUE_ACCESS) && (typeA_accesses_type >= 0)) {		
			/* Add the unique type to typeA's unique results */			
			if (add_i_to_a(type_idx, 
			    	&(*tra_results)->unique_obj_types_results->num_objs_A, 
			    	&(*tra_results)->unique_obj_types_results->objs_A) != 0) {
				return -1;
			}
		} else if ((tra_query->options & TYPES_REL_UNIQUE_ACCESS) && (typeB_accesses_type >= 0)) {
			/* Add the unique type to typeB's unique results */					
			if (add_i_to_a(type_idx, 
			    	&(*tra_results)->unique_obj_types_results->num_objs_B, 
			    	&(*tra_results)->unique_obj_types_results->objs_B) != 0) {
				return -1;
			}
		}
	}

	/* Set pointer to access pools within results */
	(*tra_results)->typeA_access_pool = tgt_type_access_pool_A;
	(*tra_results)->typeB_access_pool = tgt_type_access_pool_B;
					
	return 0;
err:
	if ((*tra_results)->common_obj_types_results) 
		types_relation_obj_access_destroy((*tra_results)->common_obj_types_results);
	if ((*tra_results)->unique_obj_types_results) 
		types_relation_obj_access_destroy((*tra_results)->unique_obj_types_results);
	if (tgt_types != NULL) free(tgt_types); 
	if (tgt_type_access_pool_A) types_relation_destroy_type_access_pool(tgt_type_access_pool_A);
	if (tgt_type_access_pool_B) types_relation_destroy_type_access_pool(tgt_type_access_pool_B);
	return -1;
}

/***************************************************************************************
 * Types Relationship Analysis (a.k.a. TRA) main function:
 * 
 * The purpose of the types relationship analysis is to determine if there exists 
 * any relationship (or interactions) between typeA and typeB and exactly what 
 * makes up that relationship. You can control the analysis to search for any of  
 * the following:
 *	- the attribute(s) to which both types are assigned (common attribs)
 *	- the role(s) which have access to both TypeA and TypeB (common roles)
 *	- the users which have access to both TypeA and TypeB (common users)
 *	- any direct information flows between TypeA and TypeB (DIF analysis)
 *	- any transitive information flows between TypeA and TypeB (TIF analysis)
 *	- any domain transitions from TypeA to TypeB or from TypeB to TypeA. 
 *	  (DTA analysis)
 *	- all type transition rules from TypeA to TypeB or from 
 *	   TypeB to TypeA. (TE rules query)
 *	- object types to which both types share access. 
 *	- any process interactions between TypeA and TypeB (e.g., allow rules that 
 *	   allow TypeA and TypeB to send signals to each other). (TE rules query)
 *	- types to which each TypeA and TypeB have special access. (TE rules query)
 */
int types_relation_determine_relationship(types_relation_query_t *tra_query, 
				   	  types_relation_results_t **tra_results,
				   	  policy_t *policy) 
{
	assert(policy != NULL || tra_query != NULL || tra_results != NULL);	
	if (tra_query->options & TYPES_REL_NO_OPTS) {
		fprintf(stderr, "No options specified.");
		return -1;
	}
	
	tra_query->type_A = get_type_idx(tra_query->type_name_A, policy);
	if (tra_query->type_A < 0) {
		fprintf(stderr, "Invalid type A");
		return -1;
	}
	tra_query->type_B = get_type_idx(tra_query->type_name_B, policy);
	if (tra_query->type_B < 0) {
		fprintf(stderr, "Invalid type B");
		return -1;
	}
				
	*tra_results = types_relation_create_results();
	if (*tra_results == NULL) {
		fprintf(stderr, "Error creating results data structure.");
		return -1;
	}
	/* Find common attributes */
	if ((tra_query->options & TYPES_REL_COMMON_ATTRIBS) && 
	    types_relation_find_common_attributes(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	/* Find common roles */
	if ((tra_query->options & TYPES_REL_COMMON_ROLES) && 
	    types_relation_find_common_roles(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	/* Find common users */
	if ((tra_query->options & TYPES_REL_COMMON_USERS) && 
	    types_relation_find_common_users(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}	
	/* Find domain transitions */
	if ((tra_query->options & TYPES_REL_DOMAINTRANS) && 
	    types_relation_find_domain_transitions(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	/* Find direct information flows */
	if ((tra_query->options & TYPES_REL_DIRFLOWS) && 
	    types_relation_find_direct_flows(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	/* Find transitive information flows */
	if ((tra_query->options & TYPES_REL_TRANSFLOWS) && 
	    types_relation_find_trans_flows(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	
	/* This function finds all te rules that relate TypeA and TypeB. */
	if ((tra_query->options & TYPES_REL_ALLOW_RULES) && 
	    types_relation_find_te_rules(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	
	/* This function finds all type transition/member/change rules that relate TypeA and TypeB. */
	if ((tra_query->options & TYPES_REL_TTRULES) && 
	    types_relation_find_type_trans_rules(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	
	/* Find either common or unique object types to which typeA and typeB have access. */
	if (types_relation_find_obj_types_access(tra_query, tra_results, policy) != 0) {
	    	types_relation_destroy_results(*tra_results);
		return -1;
	}
	
	return 0;						 	
}
