/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: Jeremy A. Mowery jmowery@tresys.com
 */

#include "policy.h"
#include "policy-query.h"
#include "relabel_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <util.h>

int apol_type_obj_init(type_obj_t *obj)
{
	if (!obj) 
		return -1;

	obj->type = -1;
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
	obj->rules = NULL;
	obj->num_rules = 0;
	obj->list = NOLIST;
	return 0;
}

int apol_relabel_set_init(relabel_set_t *set)
{
	if (!set) 
		return -1;

	set->subject_type = -1;
	set->types = NULL;
	set->num_types = 0;
	return 0;
}

int apol_relabel_result_init(relabel_result_t *res)
{
	if (!res) 
		return -1;

	res->types = NULL;
	res->num_types = 0;
	res->subjects = NULL;
	res->num_subjects = NULL; 
	res->mode = NULL;
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
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
	if (obj->rules)
		free(obj->rules);
	obj->rules = NULL;
	obj->num_rules = 0;
	obj->type = -1;
	obj->list = NOLIST;
}

void apol_free_relabel_set_data(relabel_set_t *set)
{
	if (!set) 
		return;
	if (set->types) 
		free(set->types);
	set->types = NULL;
	set->subject_type = -1;
	set->num_types = 0;
}

void apol_free_relabel_result_data(relabel_result_t *res)
{
	int i;
	if (!res) 
		return;

	if (res->types)
		free(res->types);
	res->types = NULL;

	if (res->subjects) {
		for (i = 0; i < res->num_types; i++) {
			if (res->subjects[i])
				free(res->subjects[i]);
		}
		free(res->subjects);
	}
	res->subjects = NULL;

	if (res->num_subjects)
		free(res->num_subjects);
	res->num_subjects = NULL; 

	if(res->set)
		free(res->set);

	if (res->mode)
		free(res->mode);
	res->mode = NULL;
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
	fltr->perm_sets = NULL;
	fltr->num_perm_sets = 0;
}

static int find_obj_in_array(obj_perm_set_t *perm_sets, int num_perm_sets, int obj_idx)
{
	int i;

	if (!perm_sets) return -1;
	if (obj_idx < 0) return -1;

	for (i = 0; i < num_perm_sets; i++) {
		if (perm_sets[i].obj_class == obj_idx) {
			return i;
		}
	}

	return NOTHERE;
};

/* where is type in list returns index in list for found or a number < 0 on error or not found*/
int apol_where_is_type_in_list(relabel_set_t *set, int type, int list)
{
	int i;

	if (!set) 
		return -1;
	if (list != TOLIST && list != FROMLIST && list != ANYLIST) {
		if (list == BOTHLIST)
			list = ANYLIST;
		else
			return -1;
	}

	for (i = 0; i < set->num_types; i++){
		if(set->types[i].type == type) {
			if (set->types[i].list == BOTHLIST || set->types[i].list == list)
				return i;
			if (list == ANYLIST && (set->types[i].list == TOLIST || set->types[i].list == FROMLIST || set->types[i].list == BOTHLIST))
				return i;
		}
	}
	return NOTHERE;
}

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
	for (i = 0; i < set->num_types; i++){
		if (set->types[i].type == idx) {
			if (set->types[i].list == list)
				return 1;
			if (set->types[i].list == BOTHLIST && (list == TOLIST || list == FROMLIST))
				return 1;
			if (list == ANYLIST && (set->types[i].list == TOLIST || set->types[i].list == FROMLIST || set->types[i].list == BOTHLIST))
				return 1;
		}
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
			break;
		}
	}

	return 0;
};

/* the ANYLIST option is not used for this function */
static int apol_add_type_to_list(relabel_set_t *set, int idx, int list)
{
	type_obj_t *temp;
	int retv, where;

	if (!set) 
		return -1;
	if (list != TOLIST && list != FROMLIST && list != BOTHLIST) 
		return -1;

	/* check to see if it is here */
	if ((where = apol_where_is_type_in_list(set, idx, ANYLIST)) != NOTHERE) {
		if (set->types[where].list == BOTHLIST || set->types[where].list == list) {
			return 0;
		} else if ((list == TOLIST && set->types[where].list == FROMLIST) || (list == FROMLIST && set->types[where].list == TOLIST)) {
			set->types[where].list = BOTHLIST;
			return 0;
		}
		
	} 

	temp = (type_obj_t *)realloc(set->types, (set->num_types + 1) * sizeof(type_obj_t));
	if (temp)
		set->types = temp;
	else
		return -1;
	retv = apol_type_obj_init(&( set->types[set->num_types] ));
	if (retv) 
		return retv;
	set->types[set->num_types].type = idx;
	set->types[set->num_types].list = list;
	(set->num_types)++;
	
	return 0;
};

static int apol_add_rule_to_type_obj(type_obj_t *type, int rule)
{
	int retv = -1;

	if (!type)
		return -1;

	if (type->rules)
		retv = find_int_in_array(rule, type->rules, type->num_rules);
	if (retv > -1) {
		retv =  0;
	} else {
		retv = add_i_to_a(rule, &type->num_rules, &type->rules);
	}

	return retv;
}

static int apol_add_obj_to_set_member(relabel_set_t *set, int type_idx, int obj_idx)
{
	int where;
	obj_perm_set_t *temp = NULL;

	if (!set) 
		return -1;
	where = apol_where_is_type_in_list(set, type_idx, ANYLIST);
	if (where == NOTHERE)
		return NOTHERE;

	if (where != NOTHERE && where >= 0){
		temp = (obj_perm_set_t*)realloc(set->types[where].perm_sets, (set->types[where].num_perm_sets + 1) * sizeof(obj_perm_set_t));
		if (!temp) 
			return -1;
		set->types[where].perm_sets = temp;
		apol_obj_perm_set_init(&(set->types[where].perm_sets[set->types[where].num_perm_sets]));
		set->types[where].perm_sets[(set->types[where].num_perm_sets)++].obj_class = obj_idx;
	}
	return 0;
};

/* if object class is not present calls add obj to set */
static int apol_add_perm_to_set_member(relabel_set_t *set, int type_idx, int obj_idx, int perm)
{
	int there, retv, where;

	if (!set) 
		return -1;

	there = apol_where_is_type_in_list(set, type_idx, ANYLIST);
	if (there == NOTHERE)
		return NOTHERE;

	if (there != NOTHERE && there >= 0){
		if (!apol_does_type_obj_have_perm(&(set->types[there]), obj_idx, perm)){
			where = apol_where_is_obj_in_type(&(set->types[there]), obj_idx);
			if (where < 0 && where != NOTHERE) 
				return where;
			if (where == NOTHERE) {
				retv = apol_add_obj_to_set_member(set, type_idx, obj_idx);
				if (retv) 
					return retv;
				where = set->types[there].num_perm_sets - 1;
			}
			retv = add_i_to_a(perm, &(set->types[there].perm_sets[where].num_perms), &(set->types[there].perm_sets[where].perms));
			if (retv == -1) 
				return -1;
		}
	}

	return 0;
};

static int apol_add_domain_to_result(relabel_result_t *res, int domain, int *types, int num_types)
{
	int i, retv, where;

	if (!res || !types) 
		return -1;

	/* add any new types */
	for (i = 0; i < num_types; i++) {
		where = find_int_in_array(types[i], res->types, res->num_types);
		if (where == -1) {
			retv = add_i_to_a(types[i], &(res->num_types), &(res->types));
			if (retv)
				return -1;
			if (res->subjects) {
				res->subjects = (int**)realloc(res->subjects, res->num_types * sizeof(int*));
				if (!res->subjects)
					return -1;
				res->subjects[res->num_types - 1] = NULL;
			} else {
				res->subjects = (int**)calloc(1, sizeof(int*));
				if (!res->subjects)
					return -1;
			}
			if (res->num_subjects) {
				res->num_subjects = (int*)realloc(res->num_subjects, res->num_types * sizeof(int));
				if (!res->num_subjects)
					return -1;
				res->num_subjects[res->num_types - 1] = 0;
			} else {
				res->num_subjects = (int*)calloc(1, sizeof(int));
				if (!res->num_subjects)
					return -1;
			}
			where = res->num_types - 1;
		}
		retv = add_i_to_a(domain, &(res->num_subjects[where]), &(res->subjects[where]));
		if (retv) 
			return -1;
		
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

int apol_fill_filter_set (char *object_class, char *permission, relabel_filter_t *filter, policy_t *policy) 
{
        int obj_idx, perm_idx, retv = NOTHERE;
        
        obj_idx = get_obj_class_idx(object_class, policy);
        
        if (*permission == '*')
                perm_idx = -2;
        else
                perm_idx = get_perm_idx(permission, policy);
        
        if (!is_valid_obj_class_idx(obj_idx, policy) )
                return -1;
        if (perm_idx >= 0) {
                if (!(is_valid_perm_idx(perm_idx, policy) && is_valid_perm_for_obj_class(policy, obj_idx, perm_idx)))
                        return -1;
        } else {
                if (perm_idx != -2)
                        return -1;
        }
        if (filter->perm_sets)
                retv = find_obj_in_array(filter->perm_sets, filter->num_perm_sets, obj_idx);
        if (retv == NOTHERE) {
                retv = apol_add_class_to_obj_perm_set_list(&(filter->perm_sets), &(filter->num_perm_sets), obj_idx);
                if (retv == -1)
                        return -1;
        } else if (retv < 0) {
                return retv;
        }
        
        if (perm_idx >= 0) {
                retv = apol_add_perm_to_obj_perm_set_list(&(filter->perm_sets), &(filter->num_perm_sets), obj_idx, perm_idx);
                if (retv == -1) 
                        return -1;
        } else {
                retv = find_obj_in_array(filter->perm_sets, filter->num_perm_sets, obj_idx);
                if (retv != NOTHERE && filter->perm_sets[retv].perms) {
                        free(filter->perm_sets[retv].perms);
                        filter->perm_sets[retv].perms = NULL;
                }
                filter->perm_sets[retv].num_perms = 0;
        }
        return 0;
}

int apol_do_relabel_analysis(relabel_set_t **sets, policy_t *policy) 
{
	int i, j, k, x, y, retv, relabelto_idx, relabelfrom_idx, temp;  
	int num_subjects, num_targets, num_objects, num_perms;
	int *subjects = NULL, *targets = NULL, *objects = NULL, *perms = NULL;

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
		(*sets)[i].subject_type = i;
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
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, SRC_LIST, &subjects, &num_subjects, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&subjects, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, TGT_LIST, &targets, &num_targets, policy);
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
						if (!targets[x]) 
							retv = apol_add_type_to_list(&((*sets)[subjects[k]]), subjects[k], TOLIST);
						else
							retv = apol_add_type_to_list(&((*sets)[subjects[k]]), targets[x], TOLIST);
						if (retv)
							goto bail_point;
						for (y = 0; y < num_objects; y++) {
							apol_add_perm_to_set_member(&((*sets)[subjects[k]]), targets[x], objects[y], perms[j]);
						}
						/* if rule not here add it */
						temp = apol_where_is_type_in_list(&((*sets)[subjects[k]]), targets[x], TOLIST );
						if (temp < 0)
							return -1;
						retv = apol_add_rule_to_type_obj(&((*sets)[subjects[k]].types[temp]), i);
						if (retv)
							return retv;
					}
				}
			} else if (perms[j] == relabelfrom_idx) {
				for (k = 0; k < num_subjects; k++) {
					for (x = 0; x < num_targets; x++) {
						/* add tgt x to from_list of k */
						if (!targets[x])
							retv = apol_add_type_to_list(&((*sets)[subjects[k]]), subjects[k], FROMLIST);
						else
							retv = apol_add_type_to_list(&((*sets)[subjects[k]]), targets[x], FROMLIST);
						if (retv)
							goto bail_point;
						for (y = 0; y < num_objects; y++) {
							apol_add_perm_to_set_member(&((*sets)[subjects[k]]), targets[x], objects[y], perms[j]);
						}
						/* if rule not here add it */
						temp = apol_where_is_type_in_list(&((*sets)[subjects[k]]), targets[x], FROMLIST );
						if (temp < 0)
							return -1;
						retv = apol_add_rule_to_type_obj(&((*sets)[subjects[k]].types[temp]), i);
						if (retv)
							return retv;
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
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, SRC_LIST, &subjects, &num_subjects, policy);
		if (retv) {
			if(retv == 2){
				retv = apol_fill_array_with_all(&subjects, ALL_TYPES, policy);
				if (retv)
					return -1;
			} else
				goto bail_point;
		}
		retv = extract_types_from_te_rule(i, RULE_TE_ALLOW, TGT_LIST, &targets, &num_targets, policy);
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

static int apol_single_type_relabel(relabel_set_t *sets, int domain, int type, int **array, int *size, policy_t *policy, int mode)
{
	int i, retv;

	if (!array || !size || !policy || !sets) 
		return -1;
	if (!is_valid_type(policy, domain, 0) || !is_valid_type(policy, type, 0)) 
		return -1;
	if (mode != MODE_TO && mode != MODE_FROM && mode != MODE_BOTH)
		return -1;
	*array = NULL;
	*size = 0;
	if(mode == MODE_FROM){
		if (!apol_is_type_in_list(&(sets[domain]), type, FROMLIST)) 
			return NOTHERE;
		for (i = 0; i < sets[domain].num_types; i++){
			if (apol_is_type_in_list(&(sets[domain]), sets[domain].types[i].type, TOLIST)) {
				retv = add_i_to_a(sets[domain].types[i].type, size, array);
				if (retv == -1) 
					return -1;
			}
		}
	} else if (mode == MODE_TO) {
		if (!apol_is_type_in_list(&(sets[domain]), type, TOLIST))
			return NOTHERE;
		for (i = 0; i < sets[domain].num_types; i++){
			if (apol_is_type_in_list(&(sets[domain]), sets[domain].types[i].type, FROMLIST)) {
				retv = add_i_to_a(sets[domain].types[i].type, size, array);
				if(retv == -1) 
					return -1;
			}
		}
	} else if (mode == MODE_BOTH) {
		if (!apol_is_type_in_list(&(sets[domain]), type, ANYLIST))
			return NOTHERE;
		for (i = 0; i < sets[domain].num_types; i++){
			if (apol_is_type_in_list(&(sets[domain]), sets[domain].types[i].type, ANYLIST)) {
				retv = add_i_to_a(sets[domain].types[i].type, size, array);
				if(retv == -1) 
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

	res->mode = (relabel_mode_t*)calloc(1, sizeof(relabel_mode_t));
	if (!res->mode)
		return -1;
	res->mode->mode = MODE_DOM;
	res->mode->filter = filter?1:0;
	
	/* do filtering */ 
	next = 0;
	for (i = 0; i < clone->num_types; i++) {
		here = 1;
		if (filter && filter->num_perm_sets > 0) {
			here = 0; /* must include at least one of the specified object classes */ 
			for (j = 0; j < filter->num_perm_sets; j++) {
				if (apol_does_type_obj_have_class(&(clone->types[i]), filter->perm_sets[j].obj_class)) {
					here = 1;
					if (filter->perm_sets[j].num_perms) { 
						here = 0;
						for (k = 0; k < filter->perm_sets[j].num_perms; k++) {
							if( apol_does_type_obj_have_perm(&(clone->types[i]), filter->perm_sets[j].obj_class, filter->perm_sets[j].perms[k]))
								here = 1; /* must include at least specified permissions */
							if (here)
								break;
						}
					}
					if (here)
						break;

				}
			}
		} 
		if (here) {
			++(temp->num_types);
			temp->types = (type_obj_t*) realloc(temp->types, temp->num_types * sizeof(type_obj_t));
			if (!temp->types)
				return -1;
			apol_type_obj_init(&(temp->types[temp->num_types - 1]));

			temp->types[next].type = clone->types[i].type;
			temp->types[next].list = clone->types[i].list;
			for (j = 0; j < clone->types[i].num_rules ; j++) {
				if (filter) {
					for (k = 0; k < filter->num_perm_sets; k++) {
						if (does_av_rule_use_classes(clone->types[i].rules[j], 1, &filter->perm_sets[k].obj_class, 1, policy)) {
							retv = apol_add_rule_to_type_obj(&(temp->types[next]), clone->types[i].rules[j]);
							if (retv)
								return retv;
							break;
						}
					}
				} else {
					retv = apol_add_rule_to_type_obj(&(temp->types[next]), clone->types[i].rules[j]);
					if (retv)
						return retv;
				}
			}
			next++;
		}
	}

	temp->subject_type = clone->subject_type;

	res->set = temp;
	return 0;
};

static int apol_type_relabel(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, int mode, relabel_filter_t *filter)
{
	int i, j, k, x, retv, size = 0, size2 = 0, here;
	int *temp_array = NULL, *temp_array2 = NULL;
	type_obj_t *it = NULL;

	if (!sets || !policy)
		return -1;

	if (mode != MODE_TO && mode != MODE_FROM && mode != MODE_BOTH) {
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
		size = size2 = 0;
		temp_array = temp_array2 = NULL;
		retv = apol_single_type_relabel(sets, i, type, &temp_array, &size, policy, mode);
		if (retv && retv != NOTHERE) 
			return retv;

		if (filter && filter->num_perm_sets > 0) {
			for (j = 0; j < size; j++) {
				here = 0;
				retv = apol_where_is_type_in_list(&(sets[i]), temp_array[j], ANYLIST);
				if (retv < 0)
					return -1;
				it = &(sets[i].types[retv]);
				for (k = 0; k < filter->num_perm_sets; k++) {
					here = 0;
					if (apol_does_type_obj_have_class(it, filter->perm_sets[k].obj_class)) {
						if (filter->perm_sets[k].num_perms) {
							for (x = 0; x < filter->perm_sets[k].num_perms; x++) {
								if (apol_does_type_obj_have_perm(it, filter->perm_sets[k].obj_class, filter->perm_sets[k].perms[x]))
									here = 1;
								if (here) 
									break;
							}
						} else {
							here = 1;
						}
					}
					if (here) 
						break;
				}
				if (here) {
					for (k = 0; k < it->num_rules; k++) {
						for (x = 0; x < filter->num_perm_sets; x++) {
							if (does_av_rule_use_classes(it->rules[k], 1, &(filter->perm_sets[x].obj_class), 1, policy)) {
								retv = add_i_to_a(temp_array[j], &size2, &temp_array2);
								if (retv == -1)
									return -1;
								break;
							}
						}
					}
				}
			}
			free(temp_array);	
			temp_array = temp_array2;
			size = size2;
		}
		
		if (size) {
			retv = apol_add_domain_to_result(res, i, temp_array, size);
			if (retv) 
				return retv;
		}
	}

	res->mode = (relabel_mode_t*)calloc(1, sizeof(relabel_mode_t));
	res->mode->mode = mode;
	res->mode->filter = filter?1:0;
	
	return 0;
};

int apol_query_relabel_analysis(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy, relabel_mode_t *mode, relabel_filter_t *filter)
{
	int retv;
	relabel_filter_t *temp = NULL;

	if ( !sets || !policy || !mode )
		return -1;

	if (!mode->mode)
		return -1;
 
	if (mode->filter && !filter)
		return -1;

	if(!mode->filter)
		temp = NULL;
	else
		temp = filter;

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
	retv = apol_type_relabel(sets, type, res, policy, mode->mode, temp);

	return retv;
}
