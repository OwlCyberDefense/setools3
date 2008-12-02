/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jeremy A. Mowery jmowery@tresys.com
 */

#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>

#ifndef __RELABEL_ANALYSIS_H_FILE__
#define __RELABEL_ANALYSIS_H_FILE__

/* internal error code defines */
#define NOTHERE -6 /* could not find requested element */

/* list choice codes */
#define NOLIST   0
#define TOLIST   1
#define FROMLIST 2
#define BOTHLIST 3
#define ANYLIST  4

/* name of relabeling permissions */
#define RELABELTO "relabelto"
#define RELABELFROM "relabelfrom"

/* search mode definitions */
#define MODE_TO   1
#define MODE_FROM 2
#define MODE_BOTH 3
#define MODE_DOM  4

typedef struct type_obj {
	int type;
	obj_perm_set_t *perm_sets;
	int num_perm_sets;
	int *rules;
	int num_rules;
	int list;
} type_obj_t;

typedef struct relabel_set {
	int subject_type;
	type_obj_t *types;
	int num_types;
} relabel_set_t;

typedef struct relabel_mode {
	int mode; 
	bool_t filter;
	bool_t transitive;
	unsigned int trans_steps;
} relabel_mode_t;

typedef struct relabel_result {
	int *types;
	int num_types;
	int **subjects;
	int *num_subjects; /* num_types is size */
	relabel_mode_t *mode;
	relabel_set_t *set;
} relabel_result_t;

typedef struct relabel_filter {
	obj_perm_set_t *perm_sets; /* Anything in here is what is displayed. */
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

int apol_where_is_type_in_list(relabel_set_t *set, int type, int list);

int apol_fill_filter_set (char *object_class, char *permission, relabel_filter_t *filter, policy_t *policy);
int apol_do_relabel_analysis(relabel_set_t **sets, policy_t *policy);
int apol_query_relabel_analysis(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, relabel_mode_t *mode, relabel_filter_t *filter);

#endif /* __RELABEL_ANALYSIS_H_FILE__ */
