#include <policy.h>
#include <policy-query.h>
#include "relabel_analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <util.h>

int init_obj_perm_set(obj_perm_set_t *it)
{
	if(!it) return INVNULL;
	
	it->obj_class = -1;
	it->num_perms = 0;
	it->perms = NULL;
	return NOERROR;
}

int init_type_obj(type_obj_t *obj)
{
	if(!obj) return INVNULL;
	obj->idx = -1;
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
	return NOERROR;
}

int init_relabel_set(relabel_set_t *set)
{
	if(!set) return INVNULL;
	set->domain_type_idx = -1;
	set->to_types = NULL;
	set->from_types = NULL;
	set->num_to = 0;
	set->num_from = 0;
	return NOERROR;
}

int init_relabel_result(relabel_result_t *res)
{
	if(!res) return INVNULL;
	res->domains = NULL;
	res->types = NULL;
	res->num_domains = 0;
	res->num_types = NULL;
	res->to_from = 0; /* use TOLIST, FROMLIST, and BOTHLIST for domain's to and from */ 
	return NOERROR;
}

void free_obj_perm_set_data(obj_perm_set_t *it)
{
	if(!it) return;
	if(it->perms) free(it->perms);
	init_obj_perm_set(it);
}

void free_type_obj_data(type_obj_t *obj)
{
	if(!obj) return;
	if(obj->perm_sets) free(obj->perm_sets);
	obj->idx = -1;
	obj->perm_sets = NULL;
	obj->num_perm_sets = 0;
}

void free_relabel_set_data(relabel_set_t *set)
{
	if(!set) return;
	if(set->to_types) free(set->to_types);
	if(set->from_types) free(set->from_types);
	set->domain_type_idx = -1;
	set->num_to = 0;
	set->num_from = 0;
}

void free_relabel_result_data(relabel_result_t *res)
{
	int i;
	if(!res) return;

	if(res->domains) free(res->domains);
	if(res->types){
		for(i = 0; i < res->num_domains; i++){
			if(res->types[i]) free(res->types[i]);
		}
		free(res->types);
	}
	if(res->num_types) free(res->num_types);
}

/* where is type in list returns index in list for found or a number < 0 on error or not found*/
/* only TOLIST and FROMLIST are valid */
int where_is_type_in_list(relabel_set_t *set, int type, int list)
{
	int i;

	if(!set) return INVNULL;
	if(list != TOLIST && list != FROMLIST) return INVLIST;

	switch(list){
	case TOLIST:
		for(i = 0; i < set->num_to; i++){
			if(set->to_types[i].idx == type) return i;
		}
		break;
	case FROMLIST:
		for(i = 0; i < set->num_from; i++){
			if(set->from_types[i].idx == type) return i;
		}
		break;
	default:
		return INVLIST;
		break;
	}	
	return NOTHERE;
}

int where_is_obj_in_type(type_obj_t *type, int obj_idx)
{
	int i;

	for(i = 0; i < type->num_perm_sets; i++){
		if(type->perm_sets[i].obj_class == obj_idx)
			return i;
	}

	return NOTHERE;
}

bool_t is_type_in_list(relabel_set_t *set, int idx, int list)
{
	int i;
	if(!set) return 0;
	switch(list){
	case TOLIST:
		for(i = 0; i < set->num_to; i++){
			if(set->to_types[i].idx == idx) return 1;
		}
		break;
	case FROMLIST:
		for(i = 0; i < set->num_from; i++){
			if(set->from_types[i].idx == idx) return 1;
		}
		break;
	case BOTHLIST:
		return (is_type_in_list(set, idx, TOLIST) && is_type_in_list(set, idx, FROMLIST));
		break;
	case ANYLIST:
		return (is_type_in_list(set, idx, TOLIST) || is_type_in_list(set, idx, FROMLIST));
		break;
	default:
		return 0;
		break;
	}
	return 0;
}

/* the ANYLIST option is not used for this function */
int add_type_to_list(relabel_set_t *set, int idx, int list)
{	
	type_obj_t *temp;
	int retv;

	if(!set) return INVNULL;
	if(list != TOLIST && list != FROMLIST && list != BOTHLIST) return INVLIST;

	switch(list){
	case TOLIST:
		if(is_type_in_list(set, idx, TOLIST)) return NOERROR;
		temp = (type_obj_t *)realloc(set->to_types, (set->num_to + 1) * sizeof(type_obj_t));
		if(temp)
			set->to_types = temp;
		else
			return OOMEMER;
		retv = init_type_obj(&( set->to_types[set->num_to] ));
		if(retv != NOERROR) return retv;
		set->to_types[set->num_to].idx = idx;
		(set->num_to)++;
		return NOERROR;
		break;
	case FROMLIST:
		if(is_type_in_list(set, idx, FROMLIST)) return NOERROR;
		temp = (type_obj_t *)realloc(set->from_types, (set->num_from + 1) * sizeof(type_obj_t));
		if(temp)
			set->from_types = temp;
		else
			return OOMEMER;
		retv = init_type_obj(&( set->from_types[set->num_from] ));
		if(retv != NOERROR) return retv;
		set->from_types[set->num_from].idx = idx;
		(set->num_from)++;
		return NOERROR;
		break;
	case BOTHLIST:
		retv = add_type_to_list(set, idx, TOLIST);
		if(retv != NOERROR) return retv;
		retv = add_type_to_list(set, idx, FROMLIST);
		if(retv != NOERROR) return retv;
		return NOERROR;
		break;
	default:
		return INVLIST;
		break;
	}
	return UNEXPTD;
}

int add_obj_to_set_member(relabel_set_t *set, int type_idx, int obj_idx)
{
	int to_idx, from_idx;
	obj_perm_set_t *temp = NULL;

	if(!set) return INVNULL;
	if(!is_type_in_list(set, type_idx, ANYLIST)) return NOTHERE;

	to_idx = where_is_type_in_list(set, type_idx, TOLIST);
	from_idx = where_is_type_in_list(set, type_idx, FROMLIST);

	if(to_idx != NOTHERE && to_idx >= 0){
		temp = (obj_perm_set_t*)realloc(set->to_types[to_idx].perm_sets, (set->to_types[to_idx].num_perm_sets + 1) * sizeof(obj_perm_set_t));
		if(!temp) return OOMEMER;
		set->to_types[to_idx].perm_sets = temp;
		init_obj_perm_set(&(set->to_types[to_idx].perm_sets[set->to_types[to_idx].num_perm_sets]));
		set->to_types[to_idx].perm_sets[(set->to_types[to_idx].num_perm_sets)++].obj_class = obj_idx;
	}
	if(from_idx != NOTHERE && from_idx >= 0){
		temp = (obj_perm_set_t*)realloc(set->from_types[from_idx].perm_sets, (set->from_types[from_idx].num_perm_sets + 1) * sizeof(obj_perm_set_t));
		if(!temp) return OOMEMER;
		set->from_types[from_idx].perm_sets = temp;
		init_obj_perm_set(&(set->from_types[from_idx].perm_sets[set->from_types[from_idx].num_perm_sets]));
		set->from_types[from_idx].perm_sets[(set->from_types[from_idx].num_perm_sets)++].obj_class = obj_idx;
	}

	return NOERROR;
}

int add_perm_to_set_member(relabel_set_t *set, int type_idx, int obj_idx, int perm)
{
	int to_idx, from_idx, retv, where;

	if(!set) return INVNULL;
	if(!is_type_in_list(set, type_idx, ANYLIST)) return NOTHERE;

	to_idx = where_is_type_in_list(set, type_idx, TOLIST);
	from_idx = where_is_type_in_list(set, type_idx, FROMLIST);

	if(to_idx != NOTHERE && to_idx >= 0){
		if(!does_type_obj_have_perm(&(set->to_types[to_idx]), obj_idx, perm)){
			where = where_is_obj_in_type(&(set->to_types[to_idx]), obj_idx);
			if(where < 0 && where != NOTHERE) return where;
			if(where == NOTHERE) {
				retv = add_obj_to_set_member(set, type_idx, obj_idx);
				if(retv != NOERROR) return retv;
				where = set->to_types[to_idx].num_perm_sets - 1;
			}
			retv = add_i_to_a(perm, &(set->to_types[to_idx].perm_sets[where].num_perms), &(set->to_types[to_idx].perm_sets[where].perms));
			if(retv == -1) return OOMEMER;
		}
	}
	if(from_idx != NOTHERE && from_idx >= 0){
		if(!does_type_obj_have_perm(&(set->from_types[from_idx]), obj_idx, perm)){	
			where = where_is_obj_in_type(&(set->from_types[from_idx]), obj_idx);
			if(where < 0 && where != NOTHERE) return where;
			if(where == NOTHERE) {
				retv = add_obj_to_set_member(set, type_idx, obj_idx);
				if(retv != NOERROR) return retv;
				where = set->from_types[from_idx].num_perm_sets - 1;
			}
			retv = add_i_to_a(perm, &(set->from_types[from_idx].perm_sets[where].num_perms), &(set->from_types[from_idx].perm_sets[where].perms));
			if(retv == -1) return OOMEMER;
		}
	}

	return NOERROR;
}

int add_domain_to_result(relabel_result_t *res, int domain, int *types, int num_types)
{
	int retv;
	int **temp = NULL;

	retv = find_int_in_array(domain, res->domains, res->num_domains);
	if(retv != -1) return NOERROR; /* already inserted, do nothing */

	if(!res || !types) return INVNULL;
	
	retv = add_i_to_a(domain, &(res->num_domains), &(res->domains));
	if(retv == -1) return OOMEMER;

	(res->num_domains)--;
	retv = add_i_to_a(num_types, &(res->num_domains), &(res->num_types));
	if(retv == -1) return OOMEMER;
	
	if(res->types){
		temp = (int**)realloc(res->types, sizeof(int*) * res->num_domains);
		if(!temp) return OOMEMER;
		res->types = temp;
	} else {
		temp = (int**)calloc(1, sizeof(int*));
		if(!temp) return OOMEMER;
		res->types = temp;
	}
	res->types[res->num_domains -1] = types;

	return NOERROR;
}

int fill_relabel_sets(relabel_set_t **sets, policy_t *policy)
{
	int i, j, retv, relabelto_idx, relabelfrom_idx, num_classes;
	int *classes = NULL;
	ta_item_t *cur = NULL;
	if(!sets || !policy) return INVNULL;
	if(!( *sets = (relabel_set_t *)malloc(sizeof(relabel_set_t) * policy->num_types) )) {
		return OOMEMER;
	}
	relabelto_idx = get_perm_idx("relabelto", policy);
	relabelfrom_idx = get_perm_idx("relabelfrom", policy);

	for(i = 0; i < policy->num_types; i++){
		retv = init_relabel_set(&((*sets)[i]));
		if(retv != NOERROR) return retv;
		(*sets)[i].domain_type_idx = i;
	}
	for(i = 0; i < policy->num_av_access; i++){
		/* is allow && does permit relabel*/
		if(policy->av_access[i].type == RULE_TE_ALLOW) {
			cur = policy->av_access[i].perms;
			while(cur){
				if(cur->idx == relabelto_idx){
					retv = add_type_to_list(&((*sets)[policy->av_access[i].src_types->idx]),
								policy->av_access[i].tgt_types->idx, TOLIST);
					if(retv != NOERROR) return retv;
					retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &(classes), &(num_classes), policy);
					if(retv != 0) return retv;
					for(j = 0; j < num_classes; j++){
						retv = add_perm_to_set_member(&((*sets)[policy->av_access[i].src_types->idx]), policy->av_access[i].tgt_types->idx, classes[j], cur->idx);
						if(retv != NOERROR) return retv;
					}
				} else if(cur->idx == relabelfrom_idx){
					retv = add_type_to_list(&((*sets)[policy->av_access[i].src_types->idx]),
								policy->av_access[i].tgt_types->idx, FROMLIST);
					if(retv != NOERROR) return retv;
					retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &(classes), &(num_classes), policy);
					if(retv != 0) return retv;
					for(j = 0; j< num_classes; j++){
						retv = add_perm_to_set_member(&((*sets)[policy->av_access[i].src_types->idx]), policy->av_access[i].tgt_types->idx, classes[j], cur->idx);
						if(retv != NOERROR) return retv;
					}
				}
				cur = cur->next;
				if(classes) free(classes);
				classes = NULL;
				num_classes = 0;
			}
		}
	}
	for(i = 0; i < policy->num_av_access; i++){
		if(policy->av_access[i].type == RULE_TE_ALLOW) {
			cur = policy->av_access[i].perms;
			while(cur){
				if(is_type_in_list( &((*sets)[policy->av_access[i].src_types->idx]),
						    policy->av_access[i].tgt_types->idx, ANYLIST)) {
					retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &(classes), &(num_classes), policy);
					if(retv != 0) return retv;
					for(j = 0; j< num_classes; j++){
						retv = add_perm_to_set_member(&((*sets)[policy->av_access[i].src_types->idx]), policy->av_access[i].tgt_types->idx, classes[j], cur->idx);
						if(retv != NOERROR) return retv;
					}

				}
				cur = cur->next;
				if(classes) free(classes);
				classes = NULL;
				num_classes = 0;
			}
		}
	}
	return NOERROR;
}

bool_t does_type_obj_have_class(type_obj_t *type, int obj_idx)
{
	int i;

	if(!type) return 0;
	
	for(i = 0; i < type->num_perm_sets; i++){
		if(obj_idx == type->perm_sets[i].obj_class) return 1;
	}

	return 0;
}

bool_t does_type_obj_have_perm(type_obj_t *type, int obj_idx, int perm)
{	
	int i, j;

	if(!type) return 0;
	if(!does_type_obj_have_class(type, obj_idx)) return 0;

	for (i = 0; i < type->num_perm_sets; i++) {
		if(type->perm_sets[i].obj_class == obj_idx){
			for(j = 0; j < type->perm_sets[i].num_perms; j++){
				if(perm == type->perm_sets[i].perms[j]) return 1;
			}
		}
	}

	return 0;
}

int single_type_relabel_to(relabel_set_t *sets, int domain, int type, int **array, int *size, policy_t *policy)
{
	int i, retv;

	if(!array || !size || !policy || !sets) return INVNULL;
	if(!is_valid_type(policy, domain, 0) || !is_valid_type(policy, type, 0)) return INVAIDX;

	*array = NULL;
	*size = 0;
	
	if(!is_type_in_list(&(sets[domain]), type, FROMLIST)) return NOTHERE;
	for(i = 0; i < sets[domain].num_to; i++){
		retv = add_i_to_a(sets[domain].to_types[i].idx, size, array);
		if(retv == -1) return OOMEMER;
	}

	return NOERROR;
}

int single_type_relabel_from(relabel_set_t *sets, int domain, int type, int **array, int *size, policy_t *policy)
{
	int i, retv;

	if(!array || !size || !policy || !sets) return INVNULL;
	if(!is_valid_type(policy, domain, 0) || !is_valid_type(policy, type, 0)) return INVAIDX;

	*array = NULL;
	*size = 0;
	
	if(!is_type_in_list(&(sets[domain]), type, TOLIST)) return NOTHERE;
	for(i = 0; i < sets[domain].num_from; i++){
		retv = add_i_to_a(sets[domain].from_types[i].idx, size, array);
		if(retv == -1) return OOMEMER;
	}

	return NOERROR;
}

int type_relabels_what(relabel_set_t *sets, int domain, relabel_set_t **result, policy_t *policy)
{
	if(!result || !policy || !sets) return INVNULL;
	if(!is_valid_type(policy, domain, 0)) return INVAIDX;

	*result = &(sets[domain]);

	return NOERROR;
}

int type_relabel_to(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy)
{
	int i, retv, size = 0;
	int *temp_array = NULL;

	if(!sets || !policy) return INVNULL;
	if(res){
		free_relabel_result_data(res);
	}
	init_relabel_result(res);

	for(i = 1; i < policy->num_types; i++){
		size = 0;
		retv = single_type_relabel_to(sets, i, type, &temp_array, &size, policy);
		if(retv != NOERROR && retv != NOTHERE) return retv;
		if(size){
			retv = add_domain_to_result(res, i, temp_array, size);
			if(retv != NOERROR) return retv;
		}
	}
	res->to_from = TOLIST;

	return NOERROR;
}

int type_relabel_from(relabel_set_t *sets, int type, relabel_result_t *res, policy_t *policy)
{
	int i, retv, size = 0;
	int *temp_array = NULL;

	if(!sets || !policy) return INVNULL;
	if(res){
		free_relabel_result_data(res);
	}
	init_relabel_result(res);

	for(i = 1; i < policy->num_types; i++){
		size = 0;
		retv = single_type_relabel_from(sets, i, type, &temp_array, &size, policy);
		if(retv != NOERROR && retv != NOTHERE) return retv;
		if(size){
			retv = add_domain_to_result(res, i, temp_array, size);
			if(retv != NOERROR) return retv;
		}
	}

	res->to_from = FROMLIST;

	return NOERROR;

}

int domain_relabel_types(relabel_set_t *sets, int domain, relabel_result_t *res, policy_t *policy)
{
	int retv, i;
	relabel_set_t *temp;

	if(!sets || !policy) return INVNULL;
	if(res){
		free_relabel_result_data(res);
	}
	init_relabel_result(res);

	temp = (relabel_set_t*)malloc(1 * sizeof(relabel_set_t));
	if(!temp) return OOMEMER;
	init_relabel_set(temp);

	retv = type_relabels_what(sets, domain, &temp, policy);
	if(retv != NOERROR) return retv;

	res->to_from = BOTHLIST;
	res->types = (int **)calloc(2, sizeof(int*));
	if(!(res->types)) return OOMEMER;
	res->num_types = (int*)calloc(2, sizeof(int));
	if(!(res->num_types)) return OOMEMER;
	res->domains = (int*)malloc(1 * sizeof(int));
	if(!(res->domains)) return OOMEMER;
	res->domains[0] = domain;
	
	for(i = 0; i < temp->num_to; i++){
		retv = add_i_to_a(sets[domain].to_types[i].idx, &(res->num_types[0]), &(res->types[0]));
		if(retv == -1) return OOMEMER;
	}
	
	for(i = 0; i < temp->num_from; i++){
		retv = add_i_to_a(sets[domain].from_types[i].idx, &(res->num_types[1]), &(res->types[1]));
		if(retv == -1) return OOMEMER;
	}

	return NOERROR;
}

int perm_filter(relabel_set_t *sets, obj_perm_set_t *perm_sets, int num_perm_sets, relabel_result_t *res, policy_t *policy)
{
	int i, j, k, x, retv, temp_size = 0, there = 1;
	int *temp_array = NULL;

	if(!sets || !perm_sets || !res || !policy) return INVNULL;
	if(res->to_from == BOTHLIST){
		for(i = 0; i < num_perm_sets; i++){
			for(j = 0; j < res->num_types[0]; j++){
				temp_size = 0;	
				temp_array = NULL;
				there = 1;
				for(k = 0; k < perm_sets[i].num_perms; k++){
					if(!there) break;
					retv = where_is_type_in_list(&(sets[res->domains[0]]),res->types[0][j], TOLIST);
					if(retv < 0) return retv;
					if(!does_type_obj_have_perm(&(sets[res->domains[0]].to_types[retv]), perm_sets[i].obj_class, perm_sets[i].perms[k])){
						there = 0;
					}
				}
				if(there && find_int_in_array(res->types[j][k], temp_array, temp_size) == -1){
					retv = add_i_to_a(res->types[0][j], &temp_size, &temp_array);
					if(retv == -1) return OOMEMER;
				}

				free(res->types[0]);
				res->types[0] = temp_array;
				res->num_types[0] = temp_size;
			}
			for(j = 0; j < res->num_types[1]; j++){
				temp_size = 0;	
				temp_array = NULL;
				there = 1;
				for(k = 0; k < perm_sets[i].num_perms; k++){
					if(!there) break;
					retv = where_is_type_in_list(&(sets[res->domains[0]]),res->types[0][j], FROMLIST);
					if(retv < 0) return retv;
					if(!does_type_obj_have_perm(&(sets[res->domains[0]].from_types[retv]), perm_sets[i].obj_class, perm_sets[i].perms[k])){
						there = 0;
					}
				}
				if(there && find_int_in_array(res->types[j][k], temp_array, temp_size) == -1){
					retv = add_i_to_a(res->types[0][j], &temp_size, &temp_array);
					if(retv == -1) return OOMEMER;
				}

				free(res->types[1]);
				res->types[1] = temp_array;
				res->num_types[1] = temp_size;
			}

			if(res->num_types[0] == 0 && res->num_types[1] == 0) break;
		}
	} else {
		if(res->to_from != TOLIST && res->to_from != FROMLIST) return INVLIST;
		for(i = 0; i < num_perm_sets; i++){
			for(j = 0; j < res->num_domains; j++){
				for(k = 0; k < res->num_types[j]; k++){
					temp_size = 0;
					temp_array = NULL;
					there = 1;
					for(x = 0; x < perm_sets[i].num_perms; x++){
						if(!does_type_obj_have_perm(res->to_from == TOLIST ? 
&(sets[res->domains[j]].to_types[where_is_type_in_list(&(sets[res->domains[j]]), res->types[j][k], TOLIST)]) : 
&(sets[res->domains[j]].from_types[where_is_type_in_list(&(sets[res->domains[j]]), res->types[j][k], FROMLIST)]), 
perm_sets[i].obj_class, perm_sets[i].perms[x])){
							there = 0;
						}
						if(there && find_int_in_array(res->types[j][k], temp_array, temp_size) == -1){
							retv = add_i_to_a(res->types[j][k], &temp_size, &temp_array);
							if(retv == -1) return OOMEMER;
						}
					}
					free(res->types[j]);
					res->types[j] = temp_array;
					res->num_types[j] = temp_size;
				}
			}
		}
	}

	return NOERROR;
}

