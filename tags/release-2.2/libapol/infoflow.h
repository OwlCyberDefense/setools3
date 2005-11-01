/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kmacmillan@tresys.com
 * Modified by: mayerf@tresys.com (Apr 2004) - separated information
 *   flow from main analysis.c file, and added noflow/onlyflow batch
 *   capabilitiy.
 */

/* infoflow.h
 *
 * Information Flow analysis routines for libapol
 */

#ifndef _APOLICY_INFOFLOW_H_
#define _APOLICY_INFOFLOW_H_

#include "policy.h"
#include "policy-query.h"
#include "perm-map.h"
#include "util.h"

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
	int start_type; 			/* index into policy->types */
	unsigned char direction; 		/* IFLOW_IN/OUT/BOTH/EITHER */
	int num_end_types;
	int *end_types; 			/* indices into policy->types */
	int num_types; 				/* number of intermediate types */
	int *types; 				/* indices of intermediate types in policy->types */
	int num_obj_options; 			/* number of permission options */
	obj_perm_set_t *obj_options; 		/* Allows the exclusion of individual permissions 
					      	 * or entire object classes. This struct is defined 
					      	 * in policy.h */
        int min_weight;				/* minimum weight for nodes to be considered */
} iflow_query_t;

/*
 * iflow_obj_class is used to represent an object class in the iflow_t (see below).
 */
typedef struct iflow_obj_class {
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
	int length;
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

int iflow_direct_flows(policy_t *policy, iflow_query_t *q, int *num_answers,
		       iflow_t **answers);

iflow_transitive_t *iflow_transitive_flows(policy_t *policy, iflow_query_t *q);

void *iflow_find_paths_start(policy_t *policy, iflow_query_t *q);
int iflow_find_paths_next(void *state);
iflow_transitive_t *iflow_find_paths_end(void *state);
void iflow_find_paths_abort(void *state);

#endif /*_APOLICY_INFOFLOW_H_*/
