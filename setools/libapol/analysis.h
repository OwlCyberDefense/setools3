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


#endif /*_APOLICY_ANALYSIS_H_*/
