/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * poldiff.c
 *
 * Support for semantically diff'ing two policies 
 */
 
#include "poldiff.h"
#include "policy.h"
#include "policy-query.h"
#include "policy-io.h"
#include "semantic/avhash.h"
#include "semantic/avsemantics.h"
#include <assert.h>

static apol_diff_t *apol_new_diff()
{
	apol_diff_t *t;
	
	t = (apol_diff_t *)malloc(sizeof(apol_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
		
	memset(t, 0, sizeof(apol_diff_t));
	return t;
}

static void free_inta_diff(int_a_diff_t *nad)
{
	int_a_diff_t *t, *n;
	if(nad == NULL)
		return;
		
	for(t = nad; t != NULL; ) {
		if(t->a != NULL)
			free(t->a);
		n = t->next;
		free(t);
		t = n;
	}
	return;
}

static void free_bool_diff(bool_diff_t *bd)
{
	bool_diff_t *t, *n;
	if(bd == NULL)
		return;
		
	for(t = bd; t != NULL; ) {
		n = t->next;
		free(t);
		t = n;
	}
	return;
}

static void apol_free_diff(apol_diff_t *ad)
{
	if(ad == NULL)
		return;
		
	if(ad->types != NULL)
		free(ad->types);
	if(ad->perms != NULL)
		free(ad->perms);
	
	free_inta_diff(ad->attribs);
	free_inta_diff(ad->roles);
	free_inta_diff(ad->users);
	free_inta_diff(ad->classes);
	free_inta_diff(ad->common_perms);
	free_bool_diff(ad->booleans);
	avh_free(&ad->te);
	
	return;
}

void apol_free_diff_result(bool_t close_pols, apol_diff_result_t *adr)
{
	if(adr == NULL);
		return;
		
	apol_free_diff(adr->diff1);
	apol_free_diff(adr->diff2);
	if(close_pols) {
		close_policy(adr->p1);
		close_policy(adr->p2);
	}
	return;
}


static int find_type_in_p2(const char *name, name_item_t *aliases, policy_t *p2)
{
	int idx;
	name_item_t *t;
	
	/* first check if type name is in p2 as type name */
	idx = get_type_idx(name, p2);
	if(idx >= 0)
		return idx;
	/* else as a p2 type alias name */
	idx = get_type_idx_by_alias_name(name, p2);
	if(idx >= 0)
		return idx;
	/* else check all of type's aliases if they're p2 types or aliases */
	for(t = aliases; t != NULL; t = t->next) {
		idx = get_type_idx(t->name, p2);
		if(idx >= 0)
			return idx;
		idx = get_type_idx_by_alias_name(t->name, p2);
		if(idx >= 0)
			return idx;
	}
	return -1; /* not in p2 */		
}


static int add_i_to_inta(int i, int *num, int_a_diff_t **inta)
{
	int_a_diff_t *t;
	if(num == NULL || inta == NULL)
		return -1;
		
	/* since we don't care about ordering, and we have only single linked lists,
	 * we always PREpend new nodes into an int_a_diff struct */
	t = (int_a_diff_t *)malloc(sizeof(int_a_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(t, 0, sizeof(int_a_diff_t));
	t->idx = i;
	t->next = *inta;
	*inta = t;
	(*num)++;

	return 0;
}

static int add_bool_diff(int idx, bool_t state_diff, apol_diff_t *diff)
{
	bool_diff_t *t;
	
	if(diff == NULL)
		return -1;
	
	t = (bool_diff_t *)malloc(sizeof(bool_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(t, 0, sizeof(bool_diff_t));
	t->idx = idx;
	t->state_diff = state_diff;
	t->next = diff->booleans;
	diff->booleans = t;
	diff->num_booleans++;
	return 0;
}

static int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2)
{
	assert(p1key != NULL && p2key != NULL && p1 != NULL && p2 != NULL);
	assert(is_valid_type_idx(p1key->src, p1));
	assert(is_valid_type_idx(p1key->tgt, p1));
	assert(is_valid_obj_class(p1, p1key->cls));
	
	p2key->src = get_type_idx(p1->types[p1key->src].name, p2);
	p2key->tgt = get_type_idx(p1->types[p1key->tgt].name, p2);
	p2key->cls = get_obj_class_idx(p1->obj_classes[p1key->cls].name, p2);
	p2key->rule_type = p1key->rule_type;
	
	return 0;
}

/* return 0 on success completion.  If expr2 == NULL on a 0 return, means could
 * not make the p2 expr because something in p1 expr (e.g., a boolean) was not
 * defined in p2.  Return -1 for error. */
static int make_p2_cond_expr(int idx1, policy_t *p1, cond_expr_t **expr2, policy_t *p2)
{
	int idx2;
	cond_expr_t *cur1, *cur2, *t;
	
	assert(p1 != NULL && p2 != NULL && expr2 != NULL);
	if(!is_valid_cond_expr_idx(idx1, p1)) {
		assert(0);
		return -1;
	}
	*expr2 = cur2 = NULL;
	
	for(cur1 = p1->cond_exprs[idx1].expr; cur1 != NULL; cur1  = cur1->next) {
		if (cur1->bool >= p1->num_cond_bools || cur1->bool < 0) {
			continue;
		}
		idx2 = get_cond_bool_idx(p1->cond_bools[cur1->bool].name, p2);
		if(idx2 < 0) {
			cond_free_expr(*expr2); 
			*expr2 = NULL;
			return 0; /* can't make it */
		}
		t = malloc(sizeof(cond_expr_t));
		if (t == NULL) {
			fprintf(stderr, "out of memory\n");
			cond_free_expr(*expr2);
			return -1;
		}
		t->expr_type = cur1->expr_type;
		t->bool = idx2;
		t->next = NULL;
		if(*expr2 == NULL) {
			*expr2 = cur2 = t;	
		}
		else {
			cur2->next = t;
			cur2 = t;
		}
	}
	
	return 0;	
}


static bool_t does_cond_match(avh_node_t *n1, policy_t *p1, avh_node_t *n2, policy_t *p2, bool_t *inverse)
{
	int rt;
	cond_expr_t *expr2;
	bool_t ans;
	
	assert(n1 != NULL && n2 != NULL && p1 != NULL && p2 != NULL && inverse != NULL);
	/* This function assumes that the keys already match by virtue of hash tab lookup.
	 * What this fn does is check the conditional data to see if that too matches.*/
	if((n1->flags & AVH_FLAG_COND) != (n2->flags & AVH_FLAG_COND) ) {
		return FALSE; /* one is cond, the other is not */
	}
	if((!(n1->flags & AVH_FLAG_COND) && !(n2->flags & AVH_FLAG_COND)))
		return TRUE; /* neither is conditional, therefore they match! */
	/* so both are conditional; now the harder checks
	 * We must determine whether their conditionals are the same, and if so if the rules
	 * are in the same true/false list */
	rt = make_p2_cond_expr(n1->cond_expr, p1, &expr2, p2);
	if(rt < 0) {
		assert(0);
		return FALSE;
	}
	if(expr2 == NULL) {
		return FALSE; /* couldn't construct p2 expr dur to bool differences*/
	}
	ans = cond_exprs_semantic_equal(expr2, p2->cond_exprs[n2->cond_expr].expr, p2, inverse);
	cond_free_expr(expr2);
	if(!ans)
		return FALSE;
	/* At this point the conditionals match; next see if the rules are on the same T/F list */
	if(*inverse) 
		return (n1->cond_list != n2->cond_list);
	else
		return (n1->cond_list == n2->cond_list);	
}

/* find things in p1 that are different than in p2; this fun is from the perspective of p1 */
static apol_diff_t *apol_get_pol_diffs(unsigned int opts, policy_t *p1, policy_t *p2, bool_t isbin) 
{
	int i, j, idx, idx2, rt;
	apol_diff_t *t = NULL;
	char *name;
	bool_t added;
	int *pmap = NULL;
	rbac_bool_t rb, rb2;
	
	if(p1 == NULL || p2 == NULL)
		return NULL;
	
	t = apol_new_diff();
	if(t == NULL) 		
		return NULL;
	
	/* TODO: There's potential for less code here, but creating ingenous functions that can be called
	 * multiple times for various policy elements....future work */
	

	/* types */
	if(opts & POLOPT_TYPES) {
		for(i = 0; i < p1->num_types; i++) {
			idx2 = find_type_in_p2(p1->types[i].name, p1->types[i].aliases, p2);
			if(idx2 < 0) {
				/* type i is missing from p2 */
				rt = add_i_to_inta(i, &t->num_types, &t->types);
				if(rt < 0)
					goto err_return;
			}
			else if(!isbin) {
				/* type i is in p2; make sure it's defined the same in p2 */
				/* NOTE: We do not check differences in attributes if either policy is binary */			
				added = FALSE;
				for(j = 0; j < p1->types[i].num_attribs; j++) {
					rt = get_attrib_name(p1->types[i].attribs[j], &name, p1);
					if(rt < 0)
						goto err_return;
					if(!is_attrib_in_type(name, idx2, p2)) {
						if(!added) {
							/* add the type to the diff, and then note the first missing attrib */
							added = TRUE;
							rt = add_i_to_inta(i, &t->num_types, &t->types);
							if(rt < 0) {
								free(name);
								goto err_return;
							}
						}
						/* note the missing attribute */
						rt = add_i_to_a(p1->types[i].attribs[j], &t->types->numa, &t->types->a);
						if(rt < 0) {
							free(name);
							goto err_return;
						}
					}
					free(name);
				}
			}
		}
	}
	/* attributes */
	/* Skip attributes for binary policies */
	if((opts & POLOPT_TYPES) && !isbin) {
		for(i = 0; i < p1->num_attribs; i++ ) {
			idx2 = get_attrib_idx(p1->attribs[i].name, p2);
			if(idx2 < 0) {
				/* attrib i is missing from p2 */
				rt = add_i_to_inta(i, &t->num_attribs, &t->attribs);
				if(rt < 0)
					goto err_return;
			}
			else {
				/* attrib i is in p2; make sure it has the same types assigned in p2 */
				added = FALSE;
				for(j = 0; j < p1->attribs[i].num; j++) {
					rt = get_type_name(p1->attribs[i].a[j], &name, p1);
					if(rt < 0)
						goto err_return;
					if(!is_type_in_attrib(name, idx2, p2)) {
						if(!added) {
							/* add the attrib to the diff, and then note the first missing type */
							added = TRUE;
							rt = add_i_to_inta(i, &t->num_attribs, &t->attribs);
							if(rt < 0) {
								free(name);
								goto err_return;
							}
						}
						/* note the missing type*/
						rt = add_i_to_a(p1->attribs[i].a[j], &t->attribs->numa, &t->attribs->a);
						if(rt < 0) {
							free(name);
							goto err_return;
						}
					}
					free(name);
				}
			}
		}
	}
	
	
	/* roles */
	if(opts & POLOPT_ROLES)	{
		for(i = 0; i < p1->num_roles; i++) {
			idx2 = get_role_idx(p1->roles[i].name, p2);
			if(idx2 < 0) {
				/* attrib i is missing from p2 */
				rt = add_i_to_inta(i, &t->num_roles, &t->roles);
				if(rt  < 0)
					goto err_return;
			}
			else {
				/* role i is in p2; make sure it has the same types assigned in p2 */
				added = FALSE;
				for(j = 0; j < p1->roles[i].num; j++) {
					rt = get_type_name(p1->roles[i].a[j], &name, p1);
					if(rt < 0)
						goto err_return;
					if(!is_type_in_role(name, idx2, p2)) {
						if(!added) {
							/* add the role to the diff, and then note the first missing type */
							added = TRUE;
							rt  = add_i_to_inta(i, &t->num_roles, &t->roles);
							if(rt  < 0) {
								free(name);
								goto err_return;
							}
						}
						/* note the missing type */
						rt = add_i_to_a(p1->roles[i].a[j], &t->roles->numa, &t->roles->a);
						if(rt < 0) {
							free(name);
							goto err_return;
						}
					}
					free(name);
				}
			}
		}
	}
	
	/* users */
	if(opts & POLOPT_USERS) {
		for(i = 0; i < p1->num_users; i++) {
			idx2 = get_user_idx(p1->users[i].name, p2);
			if(idx2 < 0) {
				/* user i is missing from p2 */
				rt  = add_i_to_inta(i, &t->num_users, &t->users);
				if(rt  < 0)
					goto err_return;
			}
			else {
				/* user i is in p2; make sure it has the same roles assigned in p2 */
				added = FALSE;
				for(j = 0; j < p1->users[i].num; j++) {
					rt = get_role_name(p1->users[i].a[j], &name, p1);
					if(rt < 0)
						goto err_return;
					if(!is_role_in_user(name, idx2, p2)) {
						if(!added) {
							/* add the user to the diff, and then note the first missing role*/
							added = TRUE;
							rt  = add_i_to_inta(i, &t->num_users, &t->users);
							if(rt  < 0) {
								free(name);
								goto err_return;
							}
						}
						/* note the missing role */
						rt = add_i_to_a(p1->users[i].a[j], &t->users->numa, &t->users->a);
						if(rt < 0) {
							free(name);
							goto err_return;
						}
					}
					free(name);
				}
			}
		}
	}
	
	/* booleans */
	if(opts & POLOPT_COND_BOOLS) {
		for(i = 0; i < p1->num_cond_bools; i++) {
			idx2 = get_cond_bool_idx(p1->cond_bools[i].name, p2);
			if(idx2 < 0) {
				/* boolean i is missing from p2 */
				rt = add_bool_diff(i, FALSE, t);
				if(rt < 0)
					goto err_return;
			}
			else {
				/* boolean exists in p2; make sure has same default state */
				if(p1->cond_bools[i].default_state != p2->cond_bools[idx2].default_state) {
					rt = add_bool_diff(i, TRUE, t);
					if(rt < 0)
						goto err_return;
				}
			}		
		}
	}
	
	/* classes */
	if(opts & POLOPT_CLASSES) {
		for(i = 0; i < p1->num_obj_classes; i++) {
			idx2 = get_obj_class_idx(p1->obj_classes[i].name, p2);
			if(idx2 < 0) {
				/* class i is missing from p2 */
				rt  = add_i_to_inta(i, &t->num_classes, &t->classes);
				if(rt  < 0)
					goto err_return;
			}
			else {
				/* class i is in p2; make sure it has the same permissions assigned in p2 */
				int num_perms, pidx2;
				num_perms = get_num_perms_for_obj_class(i, p1);
				added = FALSE;
				for(j = 0; j < num_perms; j++) {
					idx = get_obj_class_nth_perm_idx(i, j, p1);
					if(idx < 0)
						goto err_return;
					rt = get_perm_name(idx, &name, p1);
					if(rt < 0)
						goto err_return;
						
					pidx2 = get_perm_idx(name, p2);
					free(name);
					
					if(pidx2 < 0 || !is_valid_perm_for_obj_class(p2, idx2, pidx2)) {
						if(!added) {
							/* add the class to the diff, and then note the first missing perm */
							added = TRUE;
							rt  = add_i_to_inta(i, &t->num_classes, &t->classes);
							if(rt  < 0) 
								goto err_return;
						}
						/* note the missing permission */
						rt = add_i_to_a(idx, &t->classes->numa, &t->classes->a);
						if(rt < 0) 
							goto err_return;
					}
				}
			}
		}
	}
	
	/* permissions */
	if(opts & POLOPT_PERMS) {
		for(i = 0; i < p1->num_perms; i++) {
			idx2 = get_perm_idx(p1->perms[i], p2);
			if(idx2 < 0) {
				/* permission missing in p2 */
				rt = add_i_to_a(i, &t->num_perms, &t->perms);
				if(rt < 0)
					goto err_return;
			}
		}
	}
	
	/* common permissions */
	if(opts & POLOPT_PERMS) {
		for(i = 0; i < p1->num_common_perms; i++) {
			idx2 = get_common_perm_idx(p1->common_perms[i].name, p2);
			if(idx2 < 0) {
				/* common perm i is missing from p2 */
				rt  = add_i_to_inta(i, &t->num_common_perms, &t->common_perms);
				if(rt  < 0)
					goto err_return;
			}
			else {
				/* common perm i is in p2; make sure it has the same permissions assigned in p2 */
				int num_perms, pidx2;
				num_perms = num_common_perm_perms(i, p1);
				added = FALSE;
				for(j = 0; j < num_perms; j++) {
					idx = p1->common_perms[i].perms[j];
					rt = get_perm_name(idx, &name, p1);
					if(rt < 0)
						goto err_return;
						
					pidx2 = get_perm_idx(name, p2);
					free(name);
					
					if(pidx2 < 0 || !does_common_perm_use_perm(idx2, pidx2, p2) ) {
						if(!added) {
							/* add the common perm to the diff, and then note the first missing perm */
							added = TRUE;
							rt  = add_i_to_inta(i, &t->num_common_perms, &t->common_perms);
							if(rt  < 0) 
								goto err_return;
						}
						/* note the missing permission */
						rt = add_i_to_a(idx, &t->common_perms->numa, &t->common_perms->a);
						if(rt < 0) 
							goto err_return;
					}
				}
			}
		}		
	}

	/* rbac */
	if(opts & POLOPT_RBAC)	{
		for(i = 0; i < p1->num_roles; i++) {
			idx = get_role_idx(p1->roles[i].name, p2);
			if(idx < 0) 
				continue;
				/* Role isn't in p2 */

			if (init_rbac_bool(&rb, p1, TRUE) != 0) 
				goto err_return;
			
			if (init_rbac_bool(&rb2, p2, TRUE) != 0) 
				goto err_return;
	
			rt = match_rbac_roles(i, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb, p1);
			if (rt < 0) 
				goto err_return;

			rt = match_rbac_roles(idx, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb2, p2);
			if (rt < 0)
				goto err_return;

			added = FALSE;
			
			for (j = 0; j < p1->num_roles; j++) {
				if (rb.allow[j]) {
					
					idx2 = get_role_idx(p1->roles[j].name, p2);
					if (idx2 < 0)
						continue;
						/* role j is missing from p2 */

					if (rb2.allow[idx2]) {
						continue;
						/* it's in both, continue */
					}
					if(!added) {
						/* add the role to the diff, and then note the first missing role */
						added = TRUE;
						rt  = add_i_to_inta(i, &t->num_role_allow, &t->role_allow);
						if(rt  < 0) 
							goto err_return;
					}
					/* note the missing role */
					rt = add_i_to_a(j, &t->role_allow->numa, &t->role_allow->a);
					if(rt < 0) 
						goto err_return;
				}
			}
			free_rbac_bool(&rb);
			free_rbac_bool(&rb2);
		}
	}
	
	/* AV and Type Rules */
	if(opts & POLOPT_TE_RULES) {
		avh_node_t *p1cur, *p2node, *newnode;
		int *data = NULL, num_data = 0;
		avh_rule_t *r;
		bool_t missing, add, inverse;
		avh_key_t key;
		
		/* We're performing a semantic check of the differences of TE rules.  We use
		 * the hash table to perform this check.  What we do is build a hash table for p1
		 * for p2 (if necessary) and then take each and every rule in p1's table, and check that
		 * it is completely satisfied in p2's hash table.  If not we add it to a diff
		 * hash table for p1.  */
		if(!avh_hash_table_present(p1->avh)) {
			rt = avh_build_hashtab(p1);
			if(rt < 0) {
				fprintf(stderr, "\nError building p1's hash table: %d\n", rt);
				goto err_return;
			}
		}
		if(!avh_hash_table_present(p2->avh)) {
			rt = avh_build_hashtab(p2);
			if(rt < 0) {
				fprintf(stderr, "\nError building p2's hash table: %d\n", rt);
				goto err_return;
			}
		}
		/* The results are stored in the same type of avh hash table; since we are comparing
		 * two of these we can assume that all issue of duplication of keys, as well as
		 * issues of ensuring proper conditional assoications are taken care of.  Thus when we
		 * have a miss; we just add it to our results hash table. */
		rt = avh_new(&t->te);
			if(rt < 0) 
				goto err_return;
		
		/* For AV rules, we need to map the idx's of p1 to the idx's of p2 so we can quickly
		 * lookup the mappings for comparison purposes. We won't do the same for default types
		 * since there are many fewer of type rules and even fewer of the many types used.  
		 * Instead we will just look up the types when necessary. */
		pmap = (int *)malloc(sizeof(int) * p1->num_perms);
		if(pmap == NULL) {
			fprintf(stderr, "out of memory\n");
			goto err_return;
		}
		for(i = 0; i < p1->num_perms; i++) 
			pmap[i] = get_perm_idx(p1->perms[i], p2);

		
		/* loop thru all the p1 rules using the hash table */
		for (i = 0; i < AVH_SIZE; i++) {
			for(p1cur = p1->avh.tab[i]; p1cur != NULL; p1cur = p1cur->next) {
				missing = TRUE;
				add = FALSE;
				make_p2_key(&p1cur->key, &key, p1, p2);
				for(p2node = avh_find_first_node(&p2->avh, &key);  p2node != NULL; p2node = avh_find_next_node(p2node) )  {
					data = NULL;
					num_data = 0;
					/* see if there is a match; assume that only one rule in hash tab
					 * would ever match so once we match key and conditional attributes
					 * we need search no more.  If this assumption fails, check 
					 * the hash table contruction function */
					if(does_cond_match(p1cur, p1, p2node, p2, &inverse)) {
						missing = FALSE;
						if(is_av_rule_type(p1cur->key.rule_type)) {
							/* Have an av rule, use the pmap created above
							 * and note which permission are missing */
							for(j = 0; j < p1cur->num_data; j++) {
								assert(pmap[p1cur->data[j]] < 0 || is_valid_perm_idx(pmap[p1cur->data[j]], p2));
								idx2 = find_int_in_array(pmap[p1cur->data[j]], p2node->data, p2node->num_data);
								if(idx2 < 0) {
									/* the perm is missing from p2 node */
									rt = add_i_to_a(p1cur->data[j], &num_data, &data);
									if(rt < 0)
										goto err_return;
								}
							}
						}
						else {
							assert(is_type_rule_type(p1cur->key.rule_type));
							/* have a type rule, with same key and conditional...
							 * now just need to check whether the  default types
							 * are the same */
							assert(p1cur->num_data == 1);
							assert(p2node->num_data == 1);
							idx = p1cur->data[0];
							assert(is_valid_type_idx(idx, p1));
							/* get the idx in p2 of p1's deflt type */
							idx2 = find_type_in_p2(p1->types[idx].name, p1->types[idx].aliases, p2);
							/* now see if this p2 idx (idx2) is in the p2 node that matched */
							if(p2node->data[0] != idx2) {
								/* not a match! */
								rt = add_i_to_a(idx, &num_data, &data);
								if(rt < 0)
									goto err_return;
							}
							else {
								/* idx2 shouldn't = -1; that would mean the p2 node has
								 * an invalid idx in it! */
								 assert(idx2 >= 0);
							}
						}
						break;
					}
				}
				if(missing || num_data > 0) {
					/* there is some diff so we need a new node */
					newnode = avh_insert(&t->te, &p1cur->key);
					if(newnode == NULL) {
						if(data != NULL) {
							free(data);
							data = NULL;
						}
						assert(0);
						goto err_return;
					}
					newnode->flags = p1cur->flags;
					newnode->cond_expr = p1cur->cond_expr;
					newnode->cond_list = p1cur->cond_list;
					
					/* we handle the data (perms or deflt type) differently.
					 * If the rule was missing, then we just copy everything
					 * from the p1 cur node.  However, if it wasn't missing, then
					 * that means that the same key was found in p2, but the perms
					 * or deflt type were different.  In that case we just data the data
					 * created above. */
					if(missing) {
						for(j = 0; j < p1cur->num_data; j++) {
							rt = avh_add_datum(newnode, p1cur->data[j]);
							if(rt < 0) {
								assert(0);
								goto err_return;
							}
						}
						
					}
					else {
						assert(data != NULL);
						assert(num_data > 0);
						newnode->data = data;
						newnode->num_data = num_data;
					}
						
					/* Finally we need to copy the rule info; since we can't 
					 * tell which original rule cause the diff we give it all
					 * to the user! */
					for(r = p1cur->rules; r != NULL; r = r->next) {
						rt = avh_add_rule(newnode, r->rule, r->hint);
						if(rt < 0) {
							assert(0);
							goto err_return;
						}
					}
				}
			}
		}
		if(pmap != NULL) free(pmap);
	}
	
	
	return t;
err_return:
	apol_free_diff(t);
	if(pmap != NULL) free(pmap);
	return NULL;
}
		

/* opts are policy open options (see policy.h).  They indicate to apol_get_pol_diffs()
 * what parts of the policy to differntiate.  Policies p1 and p2 must be opened with
 * at least the same options.  If unsure you can always use POLOPT_ALL (and ensure
 * the policies are opened with POLOPT_ALL).  However this can add significant uneeded
 * time to open and compare parts of the policies you were not interested in, esp
 * with binary policies and when you are not interested in TE rules.
 */
apol_diff_result_t *apol_diff_policies(unsigned int opts, policy_t *p1, policy_t *p2) 
{
	apol_diff_result_t *t;
	
	if(p1 == NULL || p2 == NULL)
		return NULL;
	
	/* set up result structure */
	t = (apol_diff_result_t *)malloc(sizeof(apol_diff_result_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		goto err_return;
	}
	memset(t, 0, sizeof(apol_diff_result_t));
	t->p1 = p1;
	t->p2 = p2;
	t->bindiff = (is_binary_policy(p1) || is_binary_policy(p2));
	
	/* determine the differences */
	t->diff1 = apol_get_pol_diffs(opts, p1, p2, t->bindiff);
	if(t->diff1 == NULL) 
		goto err_return;
	t->diff2 = apol_get_pol_diffs(opts, p2, p1, t->bindiff);
	if(t->diff2 == NULL)
		goto err_return;
	
	return t;
	
err_return:
	apol_free_diff_result(FALSE, t);
	return NULL;
}

