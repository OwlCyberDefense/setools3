#include <policy.h>
#include <policy-io.h>
#include <policy-query.h>

#ifndef __RELABEL_ANALYSIS_H_FILE__
#define __RELABEL_ANALYSIS_H_FILE__

/* internal error code defines */
#define NOERROR 0  /* no error */
#define INVNULL -1 /* invalid null pointer */
#define OOMEMER -2 /* out of memory error */
#define INVAIDX -3 /* invalid array index */
#define INVLIST -4 /* invalid list choice code */
#define UNEXPTD -5 /* unexpected exit point for function */
#define NOTHERE -6 /* could not find requested element */

/* list choice codes */
#define TOLIST   0
#define FROMLIST 1
#define BOTHLIST 2
#define ANYLIST  3

typedef policy_query_obj_options_t obj_perm_set_t;

typedef struct type_obj
{
	int idx;
	obj_perm_set_t *perm_sets;
	int num_perm_sets;
} type_obj_t;

typedef struct relabel_set
{
	int domain_type_idx;
	type_obj_t *to_types;
	type_obj_t *from_types;
	int num_to;
	int num_from;
} relabel_set_t;

typedef struct relabel_result
{
	int *domains;
	int **types;
	int num_domains;
	int *num_types;
	int to_from;
} relabel_result_t;

int init_obj_perm_set(obj_perm_set_t *it);
int init_type_obj(type_obj_t *obj);
int init_relabel_set(relabel_set_t *set);
int init_relabel_result(relabel_result_t *res);

void free_obj_perm_set_data(obj_perm_set_t *it);
void free_type_obj_data(type_obj_t *obj);
void free_relabel_set_data(relabel_set_t *set);
void free_relabel_result_data(relabel_result_t *res);

int fill_relabel_sets(relabel_set_t **sets, policy_t *policy);
int add_type_to_list(relabel_set_t *set, int idx, int list);
int add_obj_to_set_member(relabel_set_t *set, int type_idx, int obj_idx);
int add_perm_to_set_member(relabel_set_t *set, int type_idx, int obj_idx, int perm);
int add_domain_to_result(relabel_result_t *res, int domain, int *types, int num_types);
int where_is_type_in_list(relabel_set_t *set, int type, int list);
int where_is_obj_in_type(type_obj_t *type, int obj_idx);

bool_t is_type_in_list(relabel_set_t *set, int type, int list);
bool_t does_type_obj_have_class(type_obj_t *type, int obj_idx);
bool_t does_type_obj_have_perm(type_obj_t *type, int obj_idx, int perm);

int single_type_relabel_to(relabel_set_t *sets, int domain, int type, int **array, int *size, policy_t *policy);
int single_type_relabel_from(relabel_set_t *sets, int domain, int type, int **array, int *size, policy_t *policy);
int type_relabels_what(relabel_set_t *sets, int domain, relabel_set_t **result, policy_t *policy);

int type_relabel_to(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy);
int type_relabel_from(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy);
int domain_relabel_types(relabel_set_t *sets, int domain, relabel_result_t *res, policy_t *policy);
int perm_filter(relabel_set_t *sets, obj_perm_set_t *perm_sets, int num_perm_sets, relabel_result_t *res, policy_t *policy);
#endif /* __RELABEL_ANALYSIS_H_FILE__ */
