/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 * Modified by: don.patterson@tresys.com
 *		6-17-2003: Added reverse DTA 
 *		6-04-2004: Enhanced forward DTA to select by  
 *			   object class perm and/or object type. 
 *		6-23-2004: Added types relationship analysis.
 * Modified by: kmacmillan@tresys.com (7-18-2003) - added
 *   information flow analysis.
 */

/* analysis.h
 *
 * Analysis routines for libapol
 */

#ifndef _APOLICY_ANALYSIS_H_
#define _APOLICY_ANALYSIS_H_

#include "policy.h"
#include "old-policy-query.h"
#include "infoflow.h"
#include "util.h"



/*
 * DOMAIN TRANSITION ANALYSIS
 */

/* These structures are used to return domain transition information.
 *
 * This struucture only captures one level of domain transition...
 * repeated calls are required to build a tree.
 */
 
/* file (program) types that allow appropriate execute and entrypoint perms */
/* In the case of a forward DT analysis, the start_type and trans_type */
/* members would be the index of the starting domain and the domain it has */
/* transitioned to, respectively. In the case of a reverse DT analysis, */
/* start_type and trans_type would be the index of the ending domain */
/* and the domain it has transitioned from, respectively. */
typedef struct entrypoint_type {
	int	start_type;		
	int	trans_type;		
	int	file_type;		/* index of file type */
	int	num_ep_rules;		/* # of file entrypoint rules for tgt type */
	int	num_ex_rules;		/* # of execute rules for src type */
	int	*ep_rules;		/* array */
	int	*ex_rules;		/* array */
} entrypoint_type_t;
	

/* Capture all info for a domain in a domain trans analysis  */
/* In the case of a forward DT analysis, the start_type and trans_type members */
/* would be the index of the starting domain and the domain it has */
/* transitioned to, respectively. In the case of a reverse DT analysis, */
/* start_type and trans_type would be the index of the ending domain */
/* and the domain it has transitioned from, respectively. */
typedef struct trans_domain {
	int	start_type;		
	int	trans_type;		
	int	num_pt_rules;		/* # of process transition rules */
	int	*pt_rules;		/* dynamic array of pt rules */
	int	num_other_rules;	/* # of other transition rules */
	int	*other_rules;		/* dynamic array of other rules */
	llist_t *entry_types;		/* list of entrypoint types */
	bool_t	reverse;		/* reverse direction (0 is non-reverse, anything else is reverse) */
} trans_domain_t;

/* top level domain analysis list */ 
typedef struct domain_trans_analysis {
	int	start_type;		/* specified type used to start the DT analysis */
	llist_t *trans_domains;		/* list of target domains */
	bool_t	reverse;		/* reverse direction (0 is non-reverse, anything else is reverse) */
} domain_trans_analysis_t;

/*
 * dta_query_t encapsulates all of the paramaters of a dta query. It should
 * always be allocated with dta_query_create() and deallocated with
 * dta_query_destroy(). 
 *
 * Limiting by object_types, obj_classes and obj_class permissions is optional.
 * If the list is empty then no limiting is done. All of the list should contain 
 * the items that you want to appear in the results. 
 */
typedef struct dta_query {
	int start_type; 		/* index into policy->types */
	bool_t	reverse;		/* reverse direction (0 is non-reverse, anything else is reverse) */
	bool_t use_object_filters;	/* indicates whether to filter the result types by object class access.*/
	bool_t use_endtype_filters;	/* indicates whether to filter the result types by end type.*/
	int num_end_types;
	int *end_types; 		/* indices into policy->types; this array is used for filtering object type access */
	int num_filter_types;
	int *filter_types; 		/* indices into policy->types; this array is used for filtering the result domains */
	int num_obj_options; 		/* number of permission options */
	obj_perm_set_t *obj_options;
} dta_query_t;

/*
 * types_relation_query_t encapsulates all of the query paramaters for a types relationship 
 * analysis. It should always be allocated with types_relation_query_create() and deallocated 
 * with types_relation_query_destroy(). 
 */
typedef struct types_relation_query {
	/* masks used for specifying which aspects of types relationship analysis to query. */ 
	#define	TYPES_REL_NO_OPTS		0x0		/* no opts specifically used at initialization. */
	#define	TYPES_REL_COMMON_ATTRIBS	0x00000001	/* search common attributes */
	#define TYPES_REL_COMMON_ROLES		0x00000002	/* search common roles */
	#define TYPES_REL_COMMON_USERS		0x00000004	/* search common users */
	#define TYPES_REL_DOMAINTRANS		0x00000008	/* search domain transitions */
	#define TYPES_REL_DIRFLOWS		0x00000010	/* search direct flows */
	#define TYPES_REL_TRANSFLOWS		0x00000020	/* search transitive flows */
	#define TYPES_REL_TTRULES		0x00000040	/* search additional type transition rules */
	#define TYPES_REL_COMMON_ACCESS		0x00000080	/* search access to common object types */	
	#define TYPES_REL_ALLOW_RULES		0x00000100	/* search process interactions */
	#define TYPES_REL_UNIQUE_ACCESS		0x00000200	/* search unique object type access */
	char *type_name_A;
	char *type_name_B;
	int type_A; 		/* index into policy->types for first type */
	int type_B; 		/* index into policy->types for second type */
	unsigned int options;	/* bit mask for getting which aspects of analysis to query */
	/* The following are encapsulated within this struct b/c the user 
	 * can configure certain query parameters for each query type. */
	dta_query_t *dta_query;		   /* domain transitions */
	iflow_query_t *direct_flow_query;  /* direct flows */
	iflow_query_t *trans_flow_query;   /* transitive flows */
} types_relation_query_t;

typedef struct types_relation_rules {
	int num_rules;
	int *rules;
} types_relation_rules_t;

/* This struct is basically a database for a particular type, which in the types relationship
 * analysis would be considered the start type. This structure contains an array of 
 * types_relation_rules_t structs, each of which maps 'allow' rules from the policy which 
 * give a starting type access to a particular target type. So for example, this would 
 * be used to store all 'allow' rule indices from the main policy database which allow typeA 
 * access to let's say...passwd_t. By having seperate instances of this structure for a
 * typeA and typeB, we can then determine the access to types that they have in common, 
 * as well as any unique access. */
typedef struct types_relation_type_access_pool {	
	int num_types;				/* This corresponds to the number of types in the policy */
	int *types;				
	types_relation_rules_t **type_rules; 	/* each array index corresponds to a type index from the policy */
} types_relation_type_access_pool_t;

typedef struct types_relation_obj_access {
	int num_objs_A;	
	int *objs_A;
	int num_objs_B;
	int *objs_B;
} types_relation_obj_access_t;
				  
/*
 * types_relation_results_t encapsulates all of the results of a types relationship analysis. 
 * It should always be allocated with types_relation_create_results() and deallocated with
 * types_relation_destroy_results(). 
 */
typedef struct types_relation_results {
	int type_A; 		/* index into policy->types for first type */
	int type_B; 		/* index into policy->types for second type */
	int num_common_attribs;
	int num_common_roles;
	int num_common_users;
	int *common_attribs;	/* indices into policy->attribs */
	int *common_roles;	/* indices into policy->roles */
	int *common_users;	/* indices into policy->users */
	domain_trans_analysis_t *dta_results_A_to_B;
	domain_trans_analysis_t *dta_results_B_to_A;
	int num_dirflows;
	iflow_t *direct_flow_results;
	iflow_transitive_t *trans_flow_results_A_to_B;
	iflow_transitive_t *trans_flow_results_B_to_A;
	int num_tt_rules;
	int *tt_rules_results;
	int num_allow_rules;
	int *allow_rules_results;
	types_relation_type_access_pool_t *typeA_access_pool;
	types_relation_type_access_pool_t *typeB_access_pool;
	types_relation_obj_access_t *common_obj_types_results;
	types_relation_obj_access_t *unique_obj_types_results;
} types_relation_results_t;

/* exported prototypes */

/* dta_query_t */
void free_entrypoint_type(void *t);
void free_trans_domain(void *t);
void free_domain_trans_analysis(domain_trans_analysis_t *p);
dta_query_t* dta_query_create(void);
void dta_query_destroy(dta_query_t *q);
int dta_query_add_type(dta_query_t *q, int type);
int dta_query_add_end_type(dta_query_t *q, int end_type);
int dta_query_add_obj_class(dta_query_t *q, int obj_class);
int dta_query_add_obj_class_perm(dta_query_t *q, int obj_class, int perm);
domain_trans_analysis_t *new_domain_trans_analysis(void);
trans_domain_t *new_trans_domain(void); 
entrypoint_type_t *new_entry_point_type(void);
int determine_domain_trans(dta_query_t *dta_query, 
			   domain_trans_analysis_t **dta, 
			   policy_t *policy);

/* Types relationship analysis function prototypes. */
types_relation_query_t *types_relation_query_create(void);
void types_relation_query_destroy(types_relation_query_t *q);
types_relation_results_t *types_relation_create_results(void);
void types_relation_destroy_results(types_relation_results_t *tra);
int types_relation_determine_relationship(types_relation_query_t *tra_query,
				   types_relation_results_t **tra_results,
				   policy_t *policy);
				   
#endif /*_APOLICY_ANALYSIS_H_*/
