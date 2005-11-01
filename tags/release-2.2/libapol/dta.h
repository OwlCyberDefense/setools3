/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jmowery@tresys.com 
 */

#ifndef AP_DTA_H
#define AP_DTA_H

#include "policy.h"
#include "analysis.h"

typedef struct dta_rule {
	/* index of relavant type 
	 * for domains either the transition target or the entrypoint type
	 * for exec types the either the entered or calling domain */
	int	type_idx;
	int	dflt_idx; /* only for type_transition rules */
	/* all rules with same relavant type */
	int	*rules;
	int	num_rules;
	bool_t	used;
	bool_t	has_no_trans; /* for exec_rules domain also has execute_no_trans permission */
} dta_rule_t;

typedef struct dta_dom_node {
	dta_rule_t	*proc_trans_rules;
	dta_rule_t	*ep_rules;
	dta_rule_t	*type_trans_rules;
	int		num_proc_trans_rules;
	int		num_ep_rules;
	int		num_type_trans_rules;
} dta_dom_node_t;

typedef struct dta_exec_node {
	dta_rule_t	*exec_rules;
	dta_rule_t	*ep_rules;
	int		num_exec_rules;
	int		num_ep_rules;
} dta_exec_node_t;

typedef struct dta_table {
	int		size;			/* size == policy->num_types */
	dta_dom_node_t	*dom_list;		/* array of dom_node arrays */
	dta_exec_node_t	*exec_list;		/* array of exec_node arrays */
} dta_table_t;

typedef struct dta_trans {
	int	start_type;
	int	ep_type;
	int	end_type;
	int	*proc_trans_rules;
	int	num_proc_trans_rules;
	int	*ep_rules;
	int	num_ep_rules;
	int	*exec_rules;
	int	num_exec_rules;
	int	type_trans_rule;	/* can only be one, set to -1 if not found */
	bool_t	valid;
	int	*access_rules;	/* used for access filtering, this is only populated on demand */
	int	num_access_rules;
	struct dta_trans *next;
} dta_trans_t;

/* constructors */
dta_table_t *dta_table_new(policy_t *policy);
dta_trans_t *dta_trans_new();

/* free functions */
void dta_table_free(dta_table_t *table);
void dta_dom_node_free(dta_dom_node_t *node);
void dta_exec_node_free(dta_exec_node_t *node);
void dta_rule_free(dta_rule_t *rule);
void dta_trans_destroy(dta_trans_t **trans);

/* building functions */
int dta_table_build(dta_table_t *table, policy_t *policy);

/* define the following for rule_type */
#define AP_DTA_RULE_PROC_TRANS		0x01
#define AP_DTA_RULE_EXEC			0x02
#define AP_DTA_RULE_EXEC_NO_TRANS	0x04
#define AP_DTA_RULE_ENTRYPOINT		0x08
#define AP_DTA_RULE_TYPE_TRANS		0x10
int dta_table_add_rule(dta_table_t *table, unsigned char rule_type, int src, int tgt, int dflt, int idx);

/* searching functions */
void dta_table_reset_used_flags(dta_table_t *table);

/* verify_trans returns 0 if valid,
 * an or'ed set of flags for the missing rules if invalid,
 * and -1 on error */
int dta_table_verify_trans(dta_table_t *table, int start_dom, int ep_type, int end_dom);

/* fills trans array with trans structs for all (possible) transitions for start/end point */
int dta_table_get_all_trans(dta_table_t *table, dta_trans_t **trans, int start_idx);
int dta_table_get_all_reverse_trans(dta_table_t *table, dta_trans_t **trans, int end_idx);

/* filter functions */
/* filter list of transitions to include only transitions 
 * with a matching valid flag */
int dta_trans_filter_valid(dta_trans_t **trans, bool_t valid);

/* filter list of transitions to include only transitions
 * with an end type in the provided list */
int dta_trans_filter_end_types(dta_trans_t **trans, int *end_types, int num_end_types);

/* filter list of transitions to include only transitions
 * with a start type in the provided list */
int dta_trans_filter_start_types(dta_trans_t **trans, int *start_types, int num_start_types);

/* filter list of transitions to include only transitions
 * with an end type that has access to at least one of the provided 
 * access_types for at least one of the object & permission sets */
int dta_trans_filter_access_types(dta_trans_t **trans, int *access_types, int num_access_types, obj_perm_set_t *obj_perm_sets, int num_obj_perm_sets, policy_t *policy);

/* the convert function turns the linked list of transitions 
 * into the domain_trans_analysis structure used by apol_tcl and
 * other callers in analysis.c 
 * Note: only valid transitions will be placed in the new struct
 * but the linked list will remain unchanged
 * it is an error to give this function a list with no valid transitions */
domain_trans_analysis_t *dta_trans_convert(dta_trans_t *trans, bool_t reverse);

#endif /* AP_DTA_H */

