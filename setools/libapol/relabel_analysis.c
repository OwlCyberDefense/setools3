/* Copyright (C) 2003-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "policy.h"
#include "policy-query.h"
#include "relabel_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <util.h>

int apol_type_obj_init(type_obj_t *obj)
{
	if (!obj) return -1;
	obj->type = -1;
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
	return 0;
}

int apol_relabel_set_init(relabel_set_t *set)
{
	if (!set) 
		return -1;
	set->domain_type_idx = -1;
	set->to_types = NULL;
	set->from_types = NULL;
	set->num_to_types = 0;
	set->num_from_types = 0;
	set->to_rules = NULL;
	set->from_rules = NULL;
	set->num_to_rules = 0;
	set->num_from_rules = 0;
	return 0;
}

int apol_relabel_result_init(relabel_result_t *res)
{
	if (!res) 
		return -1;

	res->types = NULL;
	res->num_types = 0;
	res->domains = NULL;
	res->num_domains = NULL; 
	res->rules = NULL;
	res->num_rules = 0;
	res->mode = 0;
	res->set = NULL;

	return 0;
}

int apol_relabel_mode_init(relabel_mode_t *mode) 
{
	if (!mode)
		return -1;

	mode->mode = 0; /* NOTE: must set mode later 0 is not valid */
	mode->filter = 0;
	mode->transitive = 0;
	mode->trans_steps = 0;

	return 0;
}

int apol_relabel_filter_init(relabel_filter_t *fltr)
{
	if (!fltr)
		return -1;

	fltr->perm_sets = NULL;
	fltr->num_perm_sets = 0;

	return 0;
}

void apol_free_type_obj_data(type_obj_t *obj)
{
	if (!obj) 
		return;
	if (obj->perm_sets) 
		free(obj->perm_sets);
	obj->type = -1;
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
}

void apol_free_relabel_set_data(relabel_set_t *set)
{
	if (!set) 
		return;
	if (set->to_types) 
		free(set->to_types);
	if (set->from_types) 
		free(set->from_types);
	if (set->to_rules)
		free(set->to_rules);
	if (set->from_rules)
		free(set->from_rules);
	set->domain_type_idx = -1;
	set->num_to_types = 0;
	set->num_from_types = 0;
	set->num_to_rules = 0;
	set->num_from_rules = 0;
}

void apol_free_relabel_result_data(relabel_result_t *res)
{
	int i;
	if (!res) 
		return;

	if (res->types)
		free(res->types);
	res->types = NULL;

	if (res->domains) {
		for (i = 0; i < res->num_types; i++) {
			if (res->domains[i])
				free(res->domains[i]);
		}
		free(res->domains);
	}
	res->domains = NULL;

	if (res->num_domains)
		free(res->num_domains);
	res->num_domains = NULL; 

	if (res->rules)
		free(res->rules);
	res->rules = NULL;
	
	if(res->set)
		free(res->set);

	res->num_rules = 0;
	res->mode = 0;
	res->num_types = 0;

}

void apol_free_relabel_filter_data(relabel_filter_t *fltr)
{
	int i;
	
	if (!fltr)
		return;

	for(i = 0; i < fltr->num_perm_sets; i++) {
		apol_free_obj_perm_set_data(&(fltr->perm_sets[i]));
	}

	if (fltr->perm_sets)
		free(fltr->perm_sets);
	fltr->num_perm_sets = 0;
}

/* where is type in list returns index in list for found or a number < 0 on error or not found*/
/* only TOLIST and FROMLIST are valid */
static int apol_where_is_type_in_list(relabel_set_t *set, int type, int list)
{
	int i;

	if (!set) 
		return -1;
	if (list != TOLIST && list != FROMLIST) 
		return -1;

	switch (list){
	case TOLIST:
		for (i = 0; i < set->num_to_types; i++){
			if(set->to_types[i].type == type) return i;
		}
		break;
	case FROMLIST:
		for (i = 0; i < set->num_from_types; i++){
			if(set->from_types[i].type == type) return i;
		}
		break;
	default:
		return -1;
		break;
	}	
	return NOTHERE;
};

static int apol_where_is_obj_in_type(type_obj_t *type, int obj_idx)
{
	int i;

	for (i = 0; i < type->num_perm_sets; i++){
		if (type->perm_sets[i].obj_class == obj_idx)
			return i;
	}

	return NOTHERE;
};

static bool_t apol_is_type_in_list(relabel_set_t *set, int idx, int list)
{
	int i;
	if (!set) 
		return 0;
	switch (list){
	case TOLIST:
		for (i = 0; i < set->num_to_types; i++){
			if (set->to_types[i].type == idx) 
				return 1;
		}
		break;
	case FROMLIST:
		for (i = 0; i < set->num_from_types; i++){
			if (set->from_types[i].type == idx) 
				return 1;
		}
		break;
	case BOTHLIST:
		return (apol_is_type_in_list(set, idx, TOLIST) && apol_is_type_in_list(set, idx, FROMLIST));
		break;
	case ANYLIST:
		return (apol_is_type_in_list(set, idx, TOLIST) || apol_is_type_in_list(set, idx, FROMLIST));
		break;
	default:
		return 0;
		break;
	}
	return 0;
};

static bool_t apol_does_type_obj_have_class(type_obj_t *type, int obj_idx)
{
	int i;

	if (!type) 
		return 0;
	
	for (i = 0; i < type->num_perm_sets; i++){
		if (obj_idx == type->perm_sets[i].obj_class) 
			return 1;
	}

	return 0;
};

static bool_t apol_does_type_obj_have_perm(type_obj_t *type, int obj_idx, int perm)
{
	int i, j;

	if (!type) 
		return 0;
	if (!apol_does_type_obj_have_class(type, obj_idx)) 
		return 0;

	for (i = 0; i < type->num_perm_sets; i++) {
		if (type->perm_sets[i].obj_class == obj_idx){
			for (j = 0; j < type->perm_sets[i].num_perms; j++){
				if (perm == type->perm_sets[i].perms[j]) 
					return 1;
			}
		}
	}

	return 0;
};

/* the ANYLIST option is not used for this function */
static int apol_add_type_to_list(relabel_set_t *set, int idx, int list)
{
	type_obj_t *temp;
	int retv;

	if (!set) 
		return -1;
	if (list != TOLIST && list != FROMLIST && list != BOTHLIST) 
		return -1;

	switch (list){
	case TOLIST:
		if (apol_is_type_in_list(set, idx, TOLIST)) 
			return 0;
		temp = (type_obj_t *)realloc(set->to_types, (set->num_to_types + 1) * sizeof(type_obj_t));
		if (temp)
			set->to_types = temp;
		else
			return -1;
		retv = apol_type_obj_init(&( set->to_types[set->num_to_types] ));
		if (retv != 0) 
			return retv;
		set->to_types[set->num_to_types].type = idx;
		(set->num_to_types)++;
		return 0;
		break;
	case FROMLIST:
		if (apol_is_type_in_list(set, idx, FROMLIST)) return 0;
		temp = (type_obj_t *)realloc(set->from_types, (set->num_from_types + 1) * sizeof(type_obj_t));
		if (temp)
			set->from_types = temp;
		else
			return -1;
		retv = apol_type_obj_init(&( set->from_types[set->num_from_types] ));
		if (retv) 
			return retv;
		set->from_types[set->num_from_types].type = idx;
		(set->num_from_types)++;
		return 0;
		break;
	case BOTHLIST:
		retv = apol_add_type_to_list(set, idx, TOLIST);
		if (retv) 
			return retv;
		retv = apol_add_type_to_list(set, idx, FROMLIST);
		if(retv) 
			return retv;
		return 0;
		break;
	default:
		return -1;
		break;
	}
	return -1;
};

static int apol_add_obj_to_set_member(relabel_set_t *set, int type_idx, int obj_idx)
{
	int to_idx, from_idx;
	obj_perm_set_t *temp = NULL;

	if (!set) 
		return -1;
	if (!apol_is_type_in_list(set, type_idx, ANYLIST)) 
		return NOTHERE;

	to_idx = apol_where_is_type_in_list(set, type_idx, TOLIST);
	from_idx = apol_where_is_type_in_list(set, type_idx, FROMLIST);

	if (to_idx != NOTHERE && to_idx >= 0){
		temp = (obj_perm_set_t*)realloc(set->to_types[to_idx].perm_sets, (set->to_types[to_idx].num_perm_sets + 1) * sizeof(obj_perm_set_t));
		if (!temp) 
			return -1;
		set->to_types[to_idx].perm_sets = temp;
		apol_obj_perm_set_init(&(set->to_types[to_idx].perm_sets[set->to_types[to_idx].num_perm_sets]));
		set->to_types[to_idx].perm_sets[(set->to_types[to_idx].num_perm_sets)++].obj_class = obj_idx;
	}
	if (from_idx != NOTHERE && from_idx >= 0){
		temp = (obj_perm_set_t*)realloc(set->from_types[from_idx].perm_sets, (set->from_types[from_idx].num_perm_sets + 1) * sizeof(obj_perm_set_t));
		if (!temp) return -1;
		set->from_types[from_idx].perm_sets = temp;
		apol_obj_perm_set_init(&(set->from_types[from_idx].perm_sets[set->from_types[from_idx].num_perm_sets]));
		set->from_types[from_idx].perm_sets[(set->from_types[from_idx].num_perm_sets)++].obj_class = obj_idx;
	}

	return 0;
};

/* if object class is not present calls add obj to set */
static int apol_add_perm_to_set_member(relabel_set_t *set, int type_idx, int obj_idx, int perm)
{
	int to_idx, from_idx, retv, where;

	if (!set) 
		return -1;
	if (!apol_is_type_in_list(set, type_idx, ANYLIST)) 
		return NOTHERE;

	to_idx = apol_where_is_type_in_list(set, type_idx, TOLIST);
	from_idx = apol_where_is_type_in_list(set, type_idx, FROMLIST);

	if (to_idx != NOTHERE && to_idx >= 0){
		if (!apol_does_type_obj_have_perm(&(set->to_types[to_idx]), obj_idx, perm)){
			where = apol_where_is_obj_in_type(&(set->to_types[to_idx]), obj_idx);
			if (where < 0 && where != NOTHERE) 
				return where;
			if (where == NOTHERE) {
				retv = apol_add_obj_to_set_member(set, type_idx, obj_idx);
				if (retv) 
					return retv;
				where = set->to_types[to_idx].num_perm_sets - 1;
			}
			retv = add_i_to_a(perm, &(set->to_types[to_idx].perm_sets[where].num_perms), &(set->to_types[to_idx].perm_sets[where].perms));
			if (retv == -1) 
				return -1;
		}
	}
	if (from_idx != NOTHERE && from_idx >= 0){
		if (!apol_does_type_obj_have_perm(&(set->from_types[from_idx]), obj_idx, perm)){	
			where = apol_where_is_obj_in_type(&(set->from_types[from_idx]), obj_idx);
			if (where < 0 && where != NOTHERE) 
				return where;
			if (where == NOTHERE) {
				retv = apol_add_obj_to_set_member(set, type_idx, obj_idx);
				if (retv) 
					return retv;
				where = set->from_types[from_idx].num_perm_sets - 1;
			}
			retv = add_i_to_a(perm, &(set->from_types[from_idx].perm_sets[where].num_perms), &(set->from_types[from_idx].perm_sets[where].perms));
			if (retv == -1) 
				return -1;
		}
	}

	return 0;
};

static int apol_add_domain_to_result(relabel_result_t *res, int domain, int *types, int num_types, int *rules, int num_rules)
{
	int i, retv, where;

	if (!res || !types || !rules) 
		return -1;

	/* add any new types */
	for (i = 0; i < num_types; i++) {
		where = find_int_in_array(types[i], res->types, res->num_types);
		if (where == -1) {
			retv = add_i_to_a(types[i], &(res->num_types), &(res->types));
			if (retv)
				return -1;
			if (res->domains) {
				res->domains = (int**)realloc(res->domains, res->num_types * sizeof(int*));
				if (!res->domains)
					return -1;
				res->domains[res->num_types - 1] = NULL;
			} else {
				res->domains = (int**)calloc(1, sizeof(int*));
				if (!res->domains)
					return -1;
			}
			if (res->num_domains) {
				res->num_domains = (int*)realloc(res->num_domains, res->num_types * sizeof(int));
				if (!res->num_domains)
					return -1;
				res->num_domains[res->num_types - 1] = 0;
			} else {
				res->num_domains = (int*)calloc(1, sizeof(int));
				if (!res->num_domains)
					return -1;
			}
			where = res->num_types - 1;
		}
		retv = add_i_to_a(domain, &(res->num_domains[where]), &(res->domains[where]));
		if (retv) 
			return -1;
		
	}

	/* do rules */
	for (i = 0; i < num_rules; i++) {
		retv = find_int_in_array(rules[i], res->rules, res->num_rules);
		if (retv == -1) {
			retv = add_i_to_a(rules[i], &(res->num_rules), &(res->rules));
			if (retv)
				return -1;
		}
	}

	return 0;
};

#define ALL_TYPES 1
#define ALL_OBJS  2
#define ALL_PERMS 3
static int apol_fill_array_with_all(int **array, int content, policy_t *policy) 
{
	int i, max;
	
	switch (content) {
	case ALL_TYPES:
		max = policy->num_types;
		break;
	case ALL_OBJS:
		max = policy->num_obj_classes;
		break;
	case ALL_PERMS:
		max = policy->num_perms;
		break;
	default:
		return -1;
	}
	
	*array = (int*)malloc(max * sizeof(int));
	if (!( *array ))
		return -1;

	for (i = 0; i < max; i++) {
		(*array)[i] = i;
	}
	if (content == ALL_TYPES)
		(*array)[0] = 1; // 0 is for self duplicates handled elsewhere
	
	return 0;
};

int apol_do_relabel_analysis(relabel_set_t **sets, policy_t *policy) 
{
	int i, j, k, x, y, retv, relabelto_idx, relabelfrom_idx;  
	int num_subjects, num_targets, num_objects, num_perms;
	int *subjects = NULL, *targets = NULL, *objects = NULL, *perms = NULL;
	bool_t dummy[1] = {0};

	if (!sets || !policy) 
		return -1;

	/* ititialize sets */
	if (!( *sets = (relabel_set_t *)malloc(sizeof(relabel_set_t) * policy->num_types) )) {
		return -1;
	}
	for (i = 0; i < policy->num_types; i++){
		retv = apol_relabel_set_init(&((*sets)[i]));
		if (retv) 
			return retv;
		(*sets)[i].domain_type_idx = i;
	}

	/* get indices of relabeling permissions */
	relabelto_idx = get_perm_idx(RELABELTO, policy);
	relabelfrom_idx = get_perm_idx(RELABELFROM, policy);

	/* the following two loops loop over the number of accesss rules populate the relabel sets */

	/* LOOP 1 : add all types with relabel permissions */
	for (i = 0; i < policy->num_av_access; i++) {
		if (!policy->av_access[i].type == RULE_TE_ALLOW) 
			continue; /* only allow rules matter, skip all others */

		/* extract rule parts to arrays */
		/* if any of these fail, abort */
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, SRC_LIST, &subjects, &num_subjects, dummy, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&subjects, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, TGT_LIST, &targets, &num_targets, dummy, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&targets, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &objects, &num_objects, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&objects, ALL_OBJS, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_perms_from_te_rule(i, RULE_TE_ALLOW, &perms, &num_perms, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&perms, ALL_PERMS, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}

		for (j = 0; j < num_perms; j++) {
			if (perms[j] == relabelto_idx) {
				for (k = 0; k < num_subjects; k++) {
					for (x = 0; x < num_targets; x++) {
						/* add tgt x to to_list of k */
						retv = apol_add_type_to_list(&((*sets)[subjects[k]]), targets[x], TOLIST);
						if (retv)
							goto bail_point;
						for (y = 0; y < num_objects; y++) {
							apol_add_perm_to_set_member(&((*sets)[subjects[k]]), targets[x], objects[y], perms[j]);
						}
					}
					/* if rule not here add it */
					retv = find_int_in_array(i, (*sets)[subjects[k]].to_rules, (*sets)[subjects[k]].num_to_rules);
					if (retv == -1){
						retv = add_i_to_a(i, &((*sets)[subjects[k]].num_to_rules), &((*sets)[subjects[k]].to_rules));
						if (retv)
							goto bail_point;
					}
					
				}
			} else if (perms[j] == relabelfrom_idx) {
				for (k = 0; k < num_subjects; k++) {
					for (x = 0; x < num_targets; x++) {
						/* add tgt x to from_list of k */
						retv = apol_add_type_to_list(&((*sets)[subjects[k]]), targets[x], FROMLIST);
						if (retv)
							goto bail_point;
						for (y = 0; y < num_objects; y++) {
							apol_add_perm_to_set_member(&((*sets)[subjects[k]]), targets[x], objects[y], perms[j]);
						}
					}
					/* if rule not here add it */
					retv = find_int_in_array(i, (*sets)[subjects[k]].from_rules, (*sets)[subjects[k]].num_from_rules);
					if (retv == -1){
						retv = add_i_to_a(i, &((*sets)[subjects[k]].num_from_rules), &((*sets)[subjects[k]].from_rules));
						if (retv)
							goto bail_point;
					}
				}
			} /* no else */
		}
		
		/* free and reset rule part arrays */
		if (subjects) {
			free(subjects);
			subjects = NULL;
		}
		num_subjects = 0;

		if (targets) {
			free(targets);
			targets = NULL;
		}
		num_targets = 0;

		if (objects) {
			free(objects);
			objects = NULL;
		}
		num_objects = 0;

		if (perms) {
			free(perms);
			perms = NULL;
		}
		num_perms = 0;
	}

	/* LOOP 2 : add all permissions given to any type from previous loop */
	for (i = 0; i < policy->num_av_access; i++) {
		if (!policy->av_access[i].type == RULE_TE_ALLOW)
			continue;

		/* extract rule parts to arrays */
		/* if any of these fail, abort */
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, SRC_LIST, &subjects, &num_subjects, dummy, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&subjects, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, TGT_LIST, &targets, &num_targets, dummy, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&targets, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &objects, &num_objects, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&objects, ALL_OBJS, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_perms_from_te_rule(i, RULE_TE_ALLOW, &perms, &num_perms, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&perms, ALL_PERMS, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}

		for (j = 0; j < num_perms; j++) {
			for (k = 0; k < num_subjects; k++) {
				for (x = 0; x < num_targets; x++) {
					if (apol_is_type_in_list(&((*sets)[subjects[k]]), targets[x], ANYLIST)) {
						for (y = 0; y < num_objects; y++) {
							apol_add_perm_to_set_member(&((*sets)[subjects[k]]), targets[x], objects[y], perms[j]);
						}
					}
				}
			}
		}

		/* free and reset rule part arrays */
		if (subjects) {
			free(subjects);
			subjects = NULL;
		}
		num_subjects = 0;

		if (targets) {
			free(targets);
			targets = NULL;
		}
		num_targets = 0;

		if (objects) {
			free(objects);
			objects = NULL;
		}
		num_objects = 0;

		if (perms) {
			free(perms);
			perms = NULL;
		}
		num_perms = 0;
	}

	return 0;

bail_point:
		/* free and reset rule part arrays */
		if (subjects)
			free(subjects);
		if (targets) 
			free(targets);
		if (objects) 
			free(objects);
		if (perms) 
			free(perms);
	
	return -1;
}

static int apol_single_type_relabel(relabel_set_t *sets, int domain, int type, int **array, int *size, int **rules, int *num_rules, policy_t *policy, int mode)
{
	int i, retv;

	if (!array || !size || !policy || !sets) 
		return -1;
	if (!is_valid_type(policy, domain, 0) || !is_valid_type(policy, type, 0)) 
		return -1;
	if (mode != MODE_TO && mode != MODE_FROM)
		return -1;
	*array = NULL;
	*size = 0;
	if(mode == MODE_TO){
		if (!apol_is_type_in_list(&(sets[domain]), type, FROMLIST)) 
			return NOTHERE;
		for (i = 0; i < sets[domain].num_to_types; i++){
			retv = add_i_to_a(sets[domain].to_types[i].type, size, array);
			if (retv == -1) 
				return -1;
		}
		for (i = 0; i < sets[domain].num_to_rules; i++) {
			retv = does_av_rule_idx_use_type(sets[domain].to_rules[i], RULE_TE_ALLOW, type, IDX_TYPE, TGT_LIST, 1, policy);
			if (retv) {
				retv = add_i_to_a(sets[domain].to_rules[i], num_rules, rules);
				if (retv == -1)
					return -1;
			}
		}
	} else {
		if (!apol_is_type_in_list(&(sets[domain]), type, TOLIST))
			return NOTHERE;
		for (i = 0; i < sets[domain].num_from_types; i++){
			retv = add_i_to_a(sets[domain].from_types[i].type, size, array);
			if(retv == -1) 
				return -1;
		}
		for (i = 0; i < sets[domain].num_from_types; i++) {
			retv = does_av_rule_idx_use_type(sets[domain].from_rules[i], RULE_TE_ALLOW, type, IDX_TYPE, TGT_LIST, 1, policy);
			if (retv) {
				retv = add_i_to_a(sets[domain].from_rules[i], num_rules, rules);
				if (retv == -1)
					return -1;
			}
		}
	}


	return 0;
};

static int apol_type_relabels_what(relabel_set_t *sets, int domain, relabel_set_t **result, policy_t *policy)
{
	if (!result || !policy || !sets) 
		return -1;
	if (!is_valid_type(policy, domain, 0)) 
		return -1;

	*result = &(sets[domain]);

	return 0;
};

static int apol_domain_relabel_types(relabel_set_t *sets, int domain, relabel_result_t *res, policy_t *policy, relabel_filter_t *filter)
{
	int retv, here, i, j, k, next;
	relabel_set_t *temp, *clone;

	if (!sets || !policy) 
		return -1;
	if (res){
		apol_free_relabel_result_data(res);
	}
	apol_relabel_result_init(res);

	temp = (relabel_set_t*)malloc(1 * sizeof(relabel_set_t));
	if (!temp) 
		return -1;
	apol_relabel_set_init(temp);

	retv = apol_type_relabels_what(sets, domain, &clone, policy);
	if (retv) 
		return retv;

	res->mode = MODE_DOM;
	

	/* do filtering */ 
	next = 0;
	for (i = 0; i < clone->num_to_types; i++) {
		here = 1;
		if (filter && filter->num_perm_sets > 0) {
			here = 0; /* must include at least one of the specified object classes */ 
			for (j = 0; j < filter->num_perm_sets; j++) {
				if (apol_does_type_obj_have_class(&(clone->to_types[i]), filter->perm_sets[j].obj_class)) {
					here = 1;
					if (filter->perm_sets[j].num_perms) { 
						here = 0;
						for (k = 0; k < filter->perm_sets[j].num_perms; k++) {
							if( apol_does_type_obj_have_perm(&(clone->to_types[i]), filter->perm_sets[j].obj_class, filter->perm_sets[j].perms[k]))
								here = 1; /* must include at least specified permissions */
						}
					}
				}
			}
		} 
		if (here) {
			++(temp->num_to_types);
			temp->to_types = (type_obj_t*) realloc(temp->to_types, temp->num_to_types * sizeof(type_obj_t));
			if (!temp->to_types)
				return -1;

			temp->to_types[next] = clone->to_types[i];
			next++;
		}
	}

	next = 0;
	for (i = 0; i < clone->num_from_types; i++) {
		here = 1;
		if (filter && filter->num_perm_sets > 0) {
			here = 0;
			for (j = 0; j < filter->num_perm_sets; j++) {
				if (apol_does_type_obj_have_class(&(clone->from_types[i]), filter->perm_sets[j].obj_class)) {
					here = 1;
					if (filter->perm_sets[j].num_perms) {
						here = 0;
						for (k = 0; k < filter->perm_sets[j].num_perms; k++) {
							if( apol_does_type_obj_have_perm(&(clone->from_types[i]), filter->perm_sets[j].obj_class, filter->perm_sets[j].perms[k]))
								here = 1;
						}
					}
				}
			}
		}
 		if (here) {
			++(temp->num_from_types);
			temp->from_types = (type_obj_t*) realloc(temp->from_types, temp->num_from_types * sizeof(type_obj_t));
			if (!temp->from_types)
				return -1;

			temp->from_types[next] = clone->from_types[i];
			next++;
		}
	}
	
	/* check rules */
	for (i = 0; i < clone->num_to_rules; i++) {
		here = 0;
		for (j = 0; j < clone->num_to_types; j++) {
			if (does_av_rule_idx_use_type(clone->to_rules[i], RULE_TE_ALLOW, clone->to_types[j].type, IDX_TYPE, TGT_LIST, 1, policy)) {
				here = 1;
			}
			if (here) {
				retv = add_i_to_a(clone->to_rules[i], &(temp->num_to_rules), &(temp->to_rules));
				if (retv == -1)
					return retv;
				if (find_int_in_array(clone->to_rules[i], res->rules, res->num_rules) == -1) {
					retv = add_i_to_a(clone->to_rules[i], &(res->num_rules), &(res->rules));
					if (retv)
						return -1;
				}
				break;
			}
		}
	}

	for (i = 0; i < clone->num_from_rules; i++) {
		here = 0;
		for (j = 0; j < clone->num_from_types; j++) {
			if (does_av_rule_idx_use_type(clone->from_rules[i], RULE_TE_ALLOW, temp->from_types[j].type, IDX_TYPE, TGT_LIST, 1, policy)) {
				here = 1;
			}
			if (here) {
				retv = add_i_to_a(clone->from_rules[i], &(temp->num_from_rules), &(temp->from_rules));
				if (retv == -1)
					return retv;
				if (find_int_in_array(clone->from_rules[i], res->rules, res->num_rules) == -1) {
					retv = add_i_to_a(clone->from_rules[i], &(res->num_rules), &(res->rules));
					if (retv)
						return -1;
				}
				break;
			}
		}
	}

	temp->domain_type_idx = clone->domain_type_idx;

	res->set = temp;
	return 0;
};

static int apol_type_relabel(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, int mode, relabel_filter_t *filter)
{
	int i, j, k, x, retv, size = 0, size2 = 0, num_rules = 0, here;
	int *temp_array = NULL, *temp_array2 = NULL;
	int *rules = NULL;
	type_obj_t *it = NULL;

	if (!sets || !policy)
		return -1;

	if (mode != MODE_TO && mode != MODE_FROM) {
		if (mode != MODE_DOM) {
			return -1;
		} else { 
			retv = apol_domain_relabel_types(sets, type, res, policy, filter);
			return retv;
		}
	}
	if (res){
		apol_free_relabel_result_data(res);
	}
	apol_relabel_result_init(res);

	for (i = 1; i < policy->num_types; i++) { /* zero is self, skip */
		size = 0;
		temp_array = NULL;
		retv = apol_single_type_relabel(sets, i, type, &temp_array, &size, &rules, &num_rules, policy, mode);
		if (retv && retv != NOTHERE) 
			return retv;

		if (filter && filter->num_perm_sets > 0) {
			for (j = 0; j < size; j++) {
				here = 0;
				if (mode == MODE_TO) {
					retv = apol_where_is_type_in_list(&(sets[i]), temp_array[j], TOLIST);
					if (retv < 0)
						return -1;
					it = &(sets[i].to_types[retv]);
				} else {
					retv = apol_where_is_type_in_list(&(sets[i]), temp_array[j], FROMLIST);
					if (retv < 0)
						return -1;
					it = &(sets[i].from_types[retv]);
				}
				for (k = 0; k < filter->num_perm_sets; k++) {
					if (apol_does_type_obj_have_class(it, filter->perm_sets[k].obj_class))
						here = 1;
					if (here && filter->perm_sets[k].num_perms) {
						here = 0;
						for (x = 0; x < filter->perm_sets[k].num_perms; x++) {
							if (apol_does_type_obj_have_perm(it, filter->perm_sets[k].obj_class, filter->perm_sets[k].perms[x]))
								here = 1;
							if (here) 
								break;
						}
					}
					if (here) 
						break;
				}
				if (here) {
					retv = add_i_to_a(temp_array[j], &size2, &temp_array2);
					if (retv == -1)
						return -1;
				}
			}
			free(temp_array);	
			temp_array = temp_array2;
			size = size2;
			temp_array2 = NULL;
			size2 = 0;
		}

		
		if (size) {
			retv = apol_add_domain_to_result(res, i, temp_array, size, rules, num_rules);
			if (retv) 
				return retv;
			if (mode == MODE_TO) {
				for (j = 0; j < sets[i].num_to_rules; j++) {
					for (k = 0; k < res->num_types; k++) {
						if (does_av_rule_idx_use_type(sets[i].to_rules[j], RULE_TE_ALLOW, res->types[k], IDX_TYPE, TGT_LIST, 1, policy)) {
							retv = add_i_to_a(sets[i].to_rules[j], &(res->num_rules), &(res->rules));
							if (retv == -1)
								return -1;
							break;
						}
					}
				}
			} else {
				for (j = 0; j < sets[i].num_from_rules; j++) {
					for (k = 0; k < res->num_types; k++) {
						if (does_av_rule_idx_use_type(sets[i].from_rules[j], RULE_TE_ALLOW, res->types[k], IDX_TYPE, TGT_LIST, 1, policy)) {
							retv = add_i_to_a(sets[i].from_rules[j], &(res->num_rules), &(res->rules));
							if (retv == -1)
								return -1;
							break;
						}
					}
				}
			}
		}
	}

	res->mode = (mode == MODE_TO ? TOLIST : FROMLIST);

	return 0;
};

static int apol_filter_rules_list(relabel_result_t *res, policy_t *policy, relabel_filter_t *filter)
{
	int i, j, k, retv, temp_array_size = 0, here;
	int *temp_array = NULL;

	if (!res || !policy || !filter || filter->num_perm_sets < 1)
		return -1;
	if (!res->rules)
		return -1;

	for (i = 0; i < res->num_rules; i++) {
		here = 0;
		for (j = 0; j < filter->num_perm_sets; j++) {
			if (does_av_rule_use_classes(res->rules[i], 1, &(filter->perm_sets[j].obj_class), 1, policy)) {
				for (k = 0; k < filter->perm_sets[j].num_perms; k++) {
					if (does_av_rule_use_perms(res->rules[i], 1, &(filter->perm_sets[j].perms[k]), 1, policy)) {
						here = 1;
					}
					if (here) 
						break;
				}
			}
			if (here) 
				break;
		}
		if (here) {
			retv = add_i_to_a(res->rules[i], &temp_array_size, &temp_array);
			if (retv)
				return -1;
		}
	}

	free(res->rules);
	res->rules = temp_array;
	res->num_rules = temp_array_size;

	return 0;
}

int apol_query_relabel_analysis(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, relabel_mode_t *mode, relabel_filter_t *filter)
{
	int retv;

	if ( !sets || !policy || !mode )
		return -1;

	if (!mode->mode)
		return -1;
 
	if (mode->filter && !filter)
		return -1;

	if (mode->transitive && !mode->trans_steps)
		mode->transitive = 0; /* if 0 steps of transitive, turn transitive off */

	if (res) {
		apol_free_relabel_result_data(res);
	}
	else {
		return -1;
	}
	apol_relabel_result_init(res);

	/* XXX there is currently no transitive analysis code
	   XXX the trans flag is therefore ignored at this point */
	retv = apol_type_relabel(sets, type, res, policy, mode->mode, filter);
	if (retv)
		return retv;

	if (filter && filter->num_perm_sets > 0)
		retv = apol_filter_rules_list(res, policy, filter);

	return retv;
}
