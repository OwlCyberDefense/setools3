/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 * Modified by: don.patterson@tresys.com (6-17-2003)
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
#include "util.h"

/*
 * analysis_obj_options_t allows the inclusion/exclusion of individual permissions
 * on object classes or entire object classes. 
 *
 *	Transitive information flow - if perms is non-NULL then only those 
 *	permissions are ignored, otherwise the entire object class is ignored. 
 *
 *	Forward domain transition - limits the query to select individual permissions 
 *	on object classes or entire object classes.  
 *
 */
typedef struct analysis_obj_options {
	int obj_class;   	/* index policy->obj_classes */
	int num_perms;
	int *perms;    		/* index of an object class' permission */
} analysis_obj_options_t;

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
	int num_end_types;
	int *end_types; 		/* indices into policy->types */
	int num_obj_options; 		/* number of permission options */
	analysis_obj_options_t *obj_options;
} dta_query_t;

/* exported prototypes */

/* Generic function prototypes for adding object class options and end types to an analysis query. */
int analysis_query_add_obj_class(analysis_obj_options_t **obj_options, 
				 int *num_obj_options, int obj_class);
int analysis_query_add_obj_class_perm(analysis_obj_options_t **obj_options, 
				      int *num_obj_options, int obj_class, 
				      int perm);
int analysis_query_add_end_type(int **end_types, int *num_end_types, int end_type);

/* dta_query_t */
void free_entrypoint_type(void *t);
void free_trans_domain(void *t);
void free_domain_trans_analysis(domain_trans_analysis_t *p);
dta_query_t* dta_query_create(void);
void dta_query_destroy(dta_query_t *q);
int dta_query_add_type(dta_query_t *q, int type);
int dta_query_add_obj_class(dta_query_t *q, int obj_class);
int dta_query_add_obj_class_perm(dta_query_t *q, int obj_class, int perm);
domain_trans_analysis_t *new_domain_trans_analysis(void);
trans_domain_t *new_trans_domain(void); 
int determine_domain_trans(dta_query_t *dta_query, 
			   domain_trans_analysis_t **dta, 
			   policy_t *policy);
#endif /*_APOLICY_ANALYSIS_H_*/
