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
#include "perm-map.h"
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
	llist_t *entry_types;		/* list of entrypoint types */
	bool_t	reverse;		/* reverse direction (0 is non-reverse, anything else is reverse) */
} trans_domain_t;

/* top level domain analysis list */ 
typedef struct domain_trans_analysis {
	int	start_type;		/* specified type used to start the DT analysis */
	llist_t *trans_domains;		/* list of target domains */
	bool_t	reverse;		/* reverse direction (0 is non-reverse, anything else is reverse) */
} domain_trans_analysis_t;


void free_entrypoint_type(void *t);
void free_trans_domain(void *t);
void free_domain_trans_analysis(domain_trans_analysis_t *p);
domain_trans_analysis_t *new_domain_trans_analysis(void);
trans_domain_t *new_trans_domain(void); 
int determine_domain_trans(bool_t reverse, char *start_domain, domain_trans_analysis_t **dta, policy_t *policy);

/*
 * Information Flow Analysis
 */

/*
 * All operations are mapped in either an information flow
 * in or an information flow out (using the permission map).
 * These defines are for the two flow directions plus
 * flows in both or either direction for queries and query
 * results.
 */
#define IFLOW_IN        	0x01
#define IFLOW_OUT       	0x02
#define IFLOW_BOTH      	(IFLOW_IN | IFLOW_OUT)
#define IFLOW_EITHER    	0x04

/*
 * Nodes in the graph represent either a type used in the source
 * of an allow rule or the target: these defines are used to
 * represent which.
 */
#define IFLOW_SOURCE_NODE 	0x0
#define IFLOW_TARGET_NODE 	0x1

/*
 * iflow_obj_options_t allows the exclusion of individual permissions
 * on object classes or entire object classes. If perms is non-NULL then
 * only those permissions are ignored, otherwise the entire object class
 * is ignored.
 */
typedef struct iflow_obj_options {
	int obj_class;   /* index policy->obj_classes */
	int num_perms;
	int *perms;    /* index of an object class' permission */
} iflow_obj_options_t;

/*
 * iflow_query_t encapsulates all of the paramaters of a query. It should
 * always be allocated with iflow_query_create and deallocated with
 * iflow_query_destroy. Limiting by ending_types, obj_classes, intermed types,
 * obj_class permissions is optional - if the list is empty then no limiting
 * is done.
 *
 * All of the list except end_types should contain the items that you want to
 * not appear in the results. end_types lists the types that you do want to
 * appear.
 */
typedef struct iflow_query {
	int start_type; /* index into policy->types */
	unsigned char direction; /* IFLOW_IN/OUT/BOTH/EITHER */
	int num_end_types;
	int *end_types; /* indices into policy->types */
	int num_types; /* number of intermediate types */
	int *types; /* indices of intermediate types in policy->types */
	int num_obj_options; /* number of permission options */
	iflow_obj_options_t *obj_options;
} iflow_query_t;

/*
 * iflow_obj_clsas is used to represent an object class in the iflow_t (see below).
 */
typedef struct iflow_obj_class {
	int obj_class; /* index into policy->obj_classes. */
	int num_rules;
	int *rules;
} iflow_obj_class_t;

/*
 * iflow represents an information flow from a
 * start type to an end type in terms of the
 * object classes and rules in the obj_classes array.
 */
typedef struct iflow {
	int start_type;
	int end_type;
	int direction;
	int num_obj_classes;
	iflow_obj_class_t *obj_classes;
} iflow_t;

typedef struct iflow_path {
	int start_type;
	int end_type;
	int num_iflows;
	iflow_t *iflows;
	struct iflow_path *next;
} iflow_path_t;

typedef struct iflow_transitive {
	int start_type;
	int num_end_types;
	int *end_types;
	iflow_path_t **paths; /* length is num_end_types */
	int *num_paths; /* length is num_end_types */
} iflow_transitive_t;

typedef struct iflow_edge {
	int num_obj_classes;
	iflow_obj_class_t *obj_classes;
	int start_node; /* index into iflow_graph->nodes */
	int end_node; /* index into iflow_graph->nodes */
	int length;
} iflow_edge_t;

typedef struct iflow_node {
	int type;
	int node_type;
	int obj_class;
	int num_in_edges;
	int *in_edges;
	int num_out_edges;
	int *out_edges;
#define IFLOW_COLOR_WHITE 0
#define IFLOW_COLOR_GREY  1
#define IFLOW_COLOR_BLACK 2
#define IFLOW_COLOR_RED   3
	unsigned char color;
	int parent;
	int distance;
} iflow_node_t;

typedef struct iflow_graph {
	int num_nodes; /* the number of slots used in nodes */
	iflow_node_t *nodes;
	int *src_index;
	int *tgt_index;
	int num_edges;
	iflow_edge_t *edges;
	policy_t *policy;
	iflow_query_t *query;
} iflow_graph_t;

/* exported prototypes */

/* iflow_query_t */
iflow_query_t* iflow_query_create(void);
void iflow_query_destroy(iflow_query_t *q);
bool_t iflow_query_is_valid(iflow_query_t *q, policy_t *policy);
int iflow_query_add_obj_class(iflow_query_t *q, int obj_class);
int iflow_query_add_obj_class_perm(iflow_query_t *q, int obj_class, int perm);
int iflow_query_add_end_type(iflow_query_t *q, int end_type);
int iflow_query_add_type(iflow_query_t *q, int type);

void iflow_destroy(iflow_t *flow);
void iflow_transitive_destroy(iflow_transitive_t *flow);

iflow_graph_t *iflow_graph_create(policy_t* policy, iflow_query_t *q);
void iflow_graph_destroy(iflow_graph_t *g);

int iflow_direct_flows(policy_t *policy, iflow_query_t *q, int *num_answers,
		       iflow_t **answers);

iflow_transitive_t *iflow_transitive_flows(policy_t *policy, iflow_query_t *q);
int iflow_all_paths(policy_t *policy, iflow_query_t *q, int end_type);

void *iflow_find_paths_start(policy_t *policy, iflow_query_t *q);
int iflow_find_paths_next(void *state);
iflow_transitive_t *iflow_find_paths_end(void *state);
void iflow_find_paths_abort(void *state);

#endif /*_APOLICY_ANALYSIS_H_*/
