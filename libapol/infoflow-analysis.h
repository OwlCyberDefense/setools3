/**
 * @file infoflow-analysis.h
 *
 * Routines to perform an information flow analysis, both direct and
 * transitive flows.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2003-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef APOL_INFOFLOW_ANALYSIS_H
#define APOL_INFOFLOW_ANALYSIS_H

#include "policy.h"
#include "vector.h"

/*
 * All operations are mapped in either an information flow in or an
 * information flow out (using the permission map).  These defines are
 * for the two flow directions plus flows in both or either direction
 * for queries and query results.
 */
#define APOL_INFOFLOW_IN      0x01
#define APOL_INFOFLOW_OUT     0x02
#define APOL_INFOFLOW_BOTH    (APOL_INFOFLOW_IN|APOL_INFOFLOW_OUT)
#define APOL_INFOFLOW_EITHER  0x04

typedef struct apol_infoflow_analysis apol_infoflow_analysis_t;
typedef struct apol_infoflow_result apol_infoflow_result_t;

/********** functions to do information flow analysis **********/

/**
 * Execute an information flow analysis against a particular policy.
 * The policy must have had a permission map loaded via
 * apol_permmap_load(), else this analysis will abort immediately.
 *
 * @param p Policy within which to look up allow rules.
 * @param ia A non-NULL structure containing parameters for analysis.
 * @param v Reference to a vector of apol_infoflow_result_t.  The
 * vector will be allocated by this function.  The caller must call
 * apol_vector_destroy() afterwards, <b>passing
 * apol_infoflow_result_free() as the second parameter</b>.  This will
 * be set to NULL upon no results or upon error.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_infoflow_analysis_do(apol_policy_t *p,
				     apol_infoflow_analysis_t *ia,
				     apol_vector_t **v);

/**
 * Allocate and return a new information analysis structure.  All
 * fields are cleared; one must fill in the details of the analysis
 * before running it.  The caller must call
 * apol_infoflow_analysis_destroy() upon the return value afterwards.
 *
 * @return An initialized information flow analysis structure, or NULL
 * upon error.
 */
extern apol_infoflow_analysis_t *apol_infoflow_analysis_create(void);

/**
 * Deallocate all memory associated with the referenced information
 * flow analysis, and then set it to NULL.  This function does nothing
 * if the analysis is already NULL.
 *
 * @param ia Reference to an infoflow analysis structure to destroy.
 */
extern void apol_infoflow_analysis_destroy(apol_infoflow_analysis_t **ia);

/**
 * Set an information flow analysis to search in a specific direction.
 * This must be one of the values APOL_INFOFLOW_IN, APOL_INFOFLOW_OUT,
 * APOL_INFOFLOW_BOTH, or APOL_INFOFLOW_EITHER.  This function must be
 * called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param dir Direction to analyze, using one of the APOL_INFOFLOW_*
 * defines.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_infoflow_analysis_set_dir(apol_policy_t *p,
					  apol_infoflow_analysis_t *ia,
					  unsigned int dir);

/**
 * Set an information flow analysis to begin searching using a given
 * type.  This function must be called prior to running the analysis.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow anlysis to set.
 * @param name Begin searching types with this non-NULL name.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_infoflow_analysis_set_type(apol_policy_t *p,
					   apol_infoflow_analysis_t *ia,
					   const char *name);

/**
 * Set an information flow analysis to return rules with this object
 * (non-common) class.  If more than one class are appended to the
 * query, the rule's class must be one of those appended.  (I.e., the
 * rule's class must be a member of the analysis's classes.)  Pass a
 * NULL to clear all classes.
 *
 * @param p Policy handler, to report errors.
 * @param ia Infoflow analysis to set.
 * @param class Name of object class to add to search set, or NULL to
 * clear all classes.
 *
 * @return 0 on success, negative on error.
 */
extern int apol_infoflow_analysis_append_class(apol_policy_t *p,
					       apol_infoflow_analysis_t *ia,
					       const char *obj_class);

/**
 * Set an information flow analysis to return only types matching a
 * regular expression.  Note that the regexp will also match types'
 * aliases.
 *
 * @param p Policy handler, to report errors.
 * @param ia Information flow anlysis to set.
 * @param result Only return types matching this regular expression, or
 * NULL to return all types
 *
 * @return 0 on success, negative on error.
 */
extern int apol_infoflow_analysis_set_result_regexp(apol_policy_t *p,
						    apol_infoflow_analysis_t *ia,
						    const char *result);


#endif

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
#if 0
#ifndef _APOLICY_INFOFLOW_H_
#define _APOLICY_INFOFLOW_H_

#include "policy.h"
#include "old-policy-query.h"
#include "perm-map.h"
#include "util.h"

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

/* iflow_query_t */
int iflow_query_add_obj_class_perm(iflow_query_t *q, int obj_class, int perm);

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
#endif
