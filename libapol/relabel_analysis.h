/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>

#ifndef __RELABEL_ANALYSIS_H_FILE__
#define __RELABEL_ANALYSIS_H_FILE__

/* internal error code defines */
#define NOTHERE -6 /* could not find requested element */

/* list choice codes */
#define TOLIST   0
#define FROMLIST 1
#define BOTHLIST 2
#define ANYLIST  3

/* name of relabeling permissions */
#define RELABELTO "relabelto"
#define RELABELFROM "relabelfrom"

/* search mode definitions */
#define MODE_TO   1
#define MODE_FROM 2
#define MODE_DOM  3

typedef struct type_obj {
	int type;
	obj_perm_set_t *perm_sets;
	int num_perm_sets;
} type_obj_t;

typedef struct relabel_set {
	int domain_type_idx;
	type_obj_t *to_types;
	type_obj_t *from_types;
	int num_to_types;
	int num_from_types;
	int *to_rules;
	int *from_rules;
	int num_to_rules;
	int num_from_rules;

} relabel_set_t;

typedef struct relabel_result {
	int *types;
	int num_types;
	int **domains;
	int *num_domains; /* num_types is size */
	int *rules;
	int num_rules;
	int mode;
	relabel_set_t *set;
} relabel_result_t;

typedef struct relabel_mode {
	int mode; 
	bool_t filter;
	bool_t transitive;
	unsigned int trans_steps;
} relabel_mode_t;

typedef struct relabel_filter {
	obj_perm_set_t *perm_sets;
	int num_perm_sets;
} relabel_filter_t;

int apol_type_obj_init(type_obj_t *obj);
int apol_relabel_set_init(relabel_set_t *set);
int apol_relabel_result_init(relabel_result_t *res);
int apol_relabel_mode_init(relabel_mode_t *mode);
int apol_relabel_filter_init(relabel_filter_t *fltr);

void apol_free_type_obj_data(type_obj_t *obj);
void apol_free_relabel_set_data(relabel_set_t *set);
void apol_free_relabel_result_data(relabel_result_t *res);
void apol_free_relabel_filter_data(relabel_filter_t *fltr);

int apol_do_relabel_analysis(relabel_set_t **sets, policy_t *policy);
int apol_query_relabel_analysis(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, relabel_mode_t *mode, relabel_filter_t *filter);

#endif /* __RELABEL_ANALYSIS_H_FILE__ */
