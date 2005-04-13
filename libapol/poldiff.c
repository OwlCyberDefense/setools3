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
#include <string.h>

static int make_p2_cond_expr(int idx1, policy_t *p1, cond_expr_t **expr2, policy_t *p2);

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
		if(t->str_id != NULL)
			free(t->str_id);
		n = t->next;
		free(t);
		t = n;
	}
	return;
}

static void free_cond_diff(ap_cond_expr_diff_t *ced)
{
	ap_cond_expr_diff_t *t, *n;
	if(ced == NULL)
		return;
		
	for(t = ced; t != NULL; ) {
		n = t->next;
		free(t);
		t = n;
	}
	return;
}

static void free_rtrans_diff(ap_rtrans_diff_t *rtd)
{
	ap_rtrans_diff_t *t, *n;
	if(rtd == NULL)
		return;
		
	for(t = rtd; t != NULL; ) {
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
	free_inta_diff(ad->role_allow);
	free_bool_diff(ad->booleans);
	free_rtrans_diff(ad->role_trans);
	free_cond_diff(ad->cond_exprs);
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


static int_a_diff_t *add_i_to_inta(int i, int *num, int_a_diff_t **inta,char **str_id)
{
	int_a_diff_t *t;
	int_a_diff_t *p = NULL,*q = NULL;
	if(num == NULL || inta == NULL)
		return NULL;
		
	/* we do care(for showing the diff in the gui) about ordering, so now we
	   are going to do an in order insert based on str_id */

	t = (int_a_diff_t *)malloc(sizeof(int_a_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	memset(t, 0, sizeof(int_a_diff_t));
	t->idx = i;
	t->str_id = *str_id;
	t->missing = FALSE;
	t->next = NULL;
	/* is the list empty? just shove it on there*/
	if (*inta == NULL) {
		*inta = t;
	}
	else {
		for(p = *inta; p !=NULL && (strcmp(p->str_id,*str_id) < 0);p = p->next)
			q = p;
		/* if q is null then t should go first */
		if (q == NULL) {
			t->next = p;
			*inta = t;
		} else {
			q->next = t;
			t->next = p;
		}
	}
	(*num)++;

	return t;
}

static ap_cond_expr_diff_t *find_cond_expr_diff(int idx,apol_diff_t *diff)
{
	ap_cond_expr_diff_t *curr;
	for (curr = diff->cond_exprs;curr != NULL;curr = curr->next){
		if (idx == curr->idx)
			return curr;
	}
	return NULL;
}

static int add_rule_to_cond_expr_diff(ap_cond_expr_diff_t *cond_diff,avh_node_t *rule)
{
	if (cond_diff == NULL)
		return -1;

	if (rule->cond_list == TRUE) {
		if (cond_diff->true_list_diffs == NULL) {
			cond_diff->true_list_diffs = (avh_node_t **) malloc(sizeof(avh_node_t *));
			if (cond_diff->true_list_diffs == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
		}
		else
			cond_diff->true_list_diffs = (avh_node_t **) realloc(cond_diff->true_list_diffs,
									     (cond_diff->num_true_list_diffs + 1) * sizeof(avh_node_t *));
		cond_diff->true_list_diffs[cond_diff->num_true_list_diffs] = rule;
		cond_diff->num_true_list_diffs++;
	}
	else {
		if (cond_diff->false_list_diffs == NULL) {
			cond_diff->false_list_diffs = (avh_node_t **) malloc(sizeof(avh_node_t *));
			if (cond_diff->false_list_diffs == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
		}
		else
			cond_diff->false_list_diffs = (avh_node_t **) realloc(cond_diff->false_list_diffs,
									      (cond_diff->num_false_list_diffs + 1) *sizeof(avh_node_t *));
		cond_diff->false_list_diffs[cond_diff->num_false_list_diffs] = rule;
		cond_diff->num_false_list_diffs++;
	}
}

/* search policy 2 for a matching conditional */
int find_cond_in_policy(int p1_idx,policy_t *p1,policy_t *p2,bool_t noinverse)
{
	int rt;
	cond_expr_t *expr2=NULL;
	bool_t inverse;
	int i;
	
	if (p1 == NULL || p2 == NULL)
		return -1;

	rt = make_p2_cond_expr(p1_idx, p1, &expr2, p2);
	if(rt < 0) {
		assert(0);
		return -1;
	}
	if(expr2 == NULL) {
		return -1; /* couldn't construct p2 expr dur to bool differences*/
	}

	for (i = 0; i < p2->num_cond_exprs;i++) {
		if (cond_exprs_semantic_equal(expr2, p2->cond_exprs[i].expr, p2, &inverse) 
		    && !(noinverse && inverse == FALSE)) {
			cond_free_expr(expr2);
			return i;
		}
	}
	cond_free_expr(expr2);
	return -1;
}


/* here we just prepend a new node to the diff list of cond exprs and return a pointer to it */
ap_cond_expr_diff_t *new_cond_diff(int idx,apol_diff_t *diff,policy_t *p1,policy_t *p2)
{
	ap_cond_expr_diff_t *t;
	int rt;
	
	t = (ap_cond_expr_diff_t *)malloc(sizeof(ap_cond_expr_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	memset(t, 0, sizeof(ap_cond_expr_diff_t));
	t->idx = idx;
	t->missing = TRUE;
	t->true_list_diffs = NULL;
	t->false_list_diffs = NULL;
	t->num_true_list_diffs = 0;
	t->num_false_list_diffs = 0;

	

	t->next = diff->cond_exprs;
	diff->cond_exprs = t;
	diff->num_cond_exprs += 1;
		
	/* in order to fully realize if this new cond exp is in p2 we create a p2 cond expr
	   and go through its lists comparing them */
	rt = find_cond_in_policy(idx,p1,p2,FALSE);
	if (rt >= 0)
		t->missing = FALSE;
	return t;
}


static int add_rtrans_diff(int rs_idx,int t_idx,int rt_idx, bool_t missing, apol_diff_t *diff)
{
	ap_rtrans_diff_t *t;

	if(diff == NULL)
		return -1;
	
	t = (ap_rtrans_diff_t *)malloc(sizeof(ap_rtrans_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(t, 0, sizeof(ap_rtrans_diff_t));
	t->rs_idx = rs_idx;
	t->t_idx = t_idx;
	t->rt_idx = rt_idx;
	t->missing = missing;
	t->next = diff->role_trans;
	diff->role_trans = t;
	diff->num_role_trans++;
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

int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2)
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
		if (cur1->expr_type == COND_BOOL) {
                        if (cur1->bool >= p1->num_cond_bools || cur1->bool < 0) {
                                continue;
                        }
                        idx2 = get_cond_bool_idx(p1->cond_bools[cur1->bool].name, p2);
                        if(idx2 < 0) {
                                cond_free_expr(*expr2); 
                                *expr2 = NULL;
                                return 0; /* can't make it */
                        }
                }
                else {
                        idx2 = cur1->bool;
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

/* search diff2's conditional differences and try to find a match for cond_expr_diff,
   the conditional expr in policy 1 */
ap_cond_expr_diff_t *find_cdiff_in_policy(ap_cond_expr_diff_t *cond_expr_diff,apol_diff_t *diff2,policy_t *p1,policy_t *p2,bool_t *inverse)
{
	int rt;
	cond_expr_t *expr2=NULL;
	bool_t noinverse = *inverse;
	ap_cond_expr_diff_t *ced;
	
	if (cond_expr_diff == NULL || diff2 == NULL || p1 == NULL || p2 == NULL)
		return NULL;


	if (diff2->num_cond_exprs == 0)
		return NULL;
	rt = make_p2_cond_expr(cond_expr_diff->idx, p1, &expr2, p2);
	if(rt < 0) {
		assert(0);
		return NULL;
	}
	if(expr2 == NULL) {
		return NULL; /* couldn't construct p2 expr dur to bool differences*/
	}

	for (ced = diff2->cond_exprs;ced != NULL;ced = ced->next){
		if (cond_exprs_semantic_equal(expr2, p2->cond_exprs[ced->idx].expr, p2, inverse) 
		    && !(noinverse && *inverse == FALSE)) {
			cond_free_expr(expr2);
			return ced;
		}
	}
	cond_free_expr(expr2);
	return NULL;
}



bool_t does_cond_match(avh_node_t *n1, policy_t *p1, avh_node_t *n2, policy_t *p2, bool_t *inverse)
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
	int i, j, k,idx, idx2, rt=0;
	apol_diff_t *t = NULL;
	char *name;
	char *str_name;
	bool_t added,missing;
	int *pmap = NULL;
	rbac_bool_t rb, rb2;
	int rt1,rt2;
	ta_item_t *tgt_types;
	int_a_diff_t *iad_node = NULL;
	ap_cond_expr_diff_t *cond_expr;	
	avh_node_t *p1cur, *p2node, *newnode = NULL;

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
				if (get_type_name(i,&str_name,p1) >= 0) {
					iad_node = add_i_to_inta(i, &t->num_types, &t->types,&str_name);
					if(iad_node == NULL)
						goto err_return;
				}
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
							if (get_type_name(i,&str_name,p1) >= 0) {
								iad_node = add_i_to_inta(i, &t->num_types, &t->types,&str_name);
								if(iad_node == NULL) {
									free(name);
									goto err_return;
								}
							}
						}
						/* note the missing attribute */
						rt = add_i_to_a(p1->types[i].attribs[j], &iad_node->numa, &iad_node->a);
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
				if (get_attrib_name(i,&str_name,p1) >= 0) {
					iad_node = add_i_to_inta(i, &t->num_attribs, &t->attribs,&str_name);
					if(iad_node == NULL)
						goto err_return;
				}
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
							if (get_attrib_name(i,&str_name,p1) >= 0) {
								iad_node = add_i_to_inta(i, &t->num_attribs, &t->attribs,&str_name);
								if(rt < 0) {
									free(name);
									goto err_return;
								}
							}
						}
						/* note the missing type*/
						rt = add_i_to_a(p1->attribs[i].a[j], &iad_node->numa, &iad_node->a);
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
				/* role i is missing from p2 */
				if (get_role_name(i,&str_name,p1) >= 0) {
					iad_node = add_i_to_inta(i, &t->num_roles, &t->roles,&str_name);
					if(iad_node == NULL)
						goto err_return;
				}
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
							if (get_role_name(i,&str_name,p1) >= 0) {
								iad_node  = add_i_to_inta(i, &t->num_roles, &t->roles,&str_name);
								if(iad_node == NULL) {
									free(name);
									goto err_return;
								}
							}
						}
						/* note the missing type */
						rt = add_i_to_a(p1->roles[i].a[j], &iad_node->numa, &iad_node->a);
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
				if (get_user_name2(i,&str_name,p1) >= 0)
					iad_node  = add_i_to_inta(i, &t->num_users, &t->users,&str_name);
				if(iad_node == NULL)
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
							if (get_user_name2(i,&str_name,p1) >= 0) {
								iad_node  = add_i_to_inta(i, &t->num_users, &t->users,&str_name);
								if(iad_node == NULL) {
									free(name);
									goto err_return;
								}
							}
						}
						/* note the missing role */
						rt = add_i_to_a(p1->users[i].a[j], &iad_node->numa, &iad_node->a);
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
				if (get_obj_class_name(i,&str_name,p1) >= 0)
					iad_node  = add_i_to_inta(i, &t->num_classes, &t->classes,&str_name);
				if(iad_node == NULL)
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
							if (get_obj_class_name(i,&str_name,p1) >= 0) {
								iad_node  = add_i_to_inta(i, &t->num_classes, &t->classes,&str_name);
								if(iad_node == NULL) 
									goto err_return;
							}
						}
						/* note the missing permission */
						rt = add_i_to_a(idx, &iad_node->numa, &iad_node->a);
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
				if (get_common_perm_name(i,&str_name,p1) >= 0)
					iad_node  = add_i_to_inta(i, &t->num_common_perms, &t->common_perms,&str_name);
				if(iad_node == NULL)
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
							if (get_common_perm_name(i,&str_name,p1) >= 0) {
								iad_node = add_i_to_inta(i, &t->num_common_perms, &t->common_perms,&str_name);
								if(iad_node == NULL) 
									goto err_return;
							}
						}
						/* note the missing permission */
						rt = add_i_to_a(idx, &iad_node->numa, &iad_node->a);
						if(rt < 0) 
							goto err_return;
					}
				}
			}
		}		
	}

	/* rbac */
	if(opts & POLOPT_RBAC)	{
		int num_found;  /* if 0 then there will be no matching rules at all */
		for(i = 0; i < p1->num_roles; i++) {
			/* missing will tell is if role is missing in p2 */
			missing = FALSE;
			idx = get_role_idx(p1->roles[i].name, p2);
			if(idx < 0) 
				missing = TRUE;
				/* Role isn't in p2 */

			if (init_rbac_bool(&rb, p1, TRUE) != 0) 
				goto err_return;
			
			if (!missing && init_rbac_bool(&rb2, p2, TRUE) != 0) 
				goto err_return;
	
			rt = match_rbac_roles(i, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb, &num_found, p1);
			if (rt < 0) 
				goto err_return;

			if (!missing) {
				rt = match_rbac_roles(idx, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb2, &num_found, p2);
				if (rt < 0)
					goto err_return;
			}
			added = FALSE;

			for (j = 0; j < p1->num_roles; j++) {
				if (rb.allow[j]) {
					if (!missing) {
						idx2 = get_role_idx(p1->roles[j].name, p2);
						/* role j is missing from p2 */
						if (idx2 < 0) {
							if(!added) {
								/* add the role to the diff, and then note the first missing role */
								added = TRUE;
								if (get_role_name(i,&str_name,p1) >= 0)
									iad_node = add_i_to_inta(i, &t->num_role_allow, &t->role_allow,&str_name);
								if(iad_node == NULL) 
									goto err_return;
							}
						}
						else if (rb2.allow[idx2]) {
							continue;
							/* it's in both, continue */
						}
						if(!added) {
							/* add the role to the diff, and then note the first missing role */
							added = TRUE;
							if (get_role_name(i,&str_name,p1) >= 0)
								iad_node = add_i_to_inta(i, &t->num_role_allow, &t->role_allow,&str_name);
							if(iad_node == NULL) 
								goto err_return;
						}
						
					} else {
						/* if the role is missing from policy 2 */
						/* add the role to the diff, and then note the first missing role */
						if (!added) {
							added = TRUE;
							if (get_role_name(i,&str_name,p1) >= 0)
								iad_node = add_i_to_inta(i, &t->num_role_allow, &t->role_allow,&str_name);
							if(iad_node == NULL) 
								goto err_return;
						}
					}
					/* note the missing role */
					rt = add_i_to_a(j, &iad_node->numa, &iad_node->a);
					if(rt < 0) 
						goto err_return;
					/* if the source role is missing in p2 or there are no rules in p2 with that 
					   role in the source then we mark it as a missing rule */
					if (missing || num_found == 0) {
						iad_node->missing = TRUE;
					}
				}
			}
			free_rbac_bool(&rb);
			if (!missing)
				free_rbac_bool(&rb2);


			/* 
			   Current FIND ROLE TRANSITION DIFF ALGORITHM 
			   for all role indexs R1 in policy 1 P1
			       R2 = index of R1 in P2
			       if R2 is valid
			           for all trans rules TR1 with R1 in the source
				       for all types T1 in TR1
				           T2 = index of T1 in P2
				           RT1 = role target of TR1
					   RT2 = index of the role target of trans rule in P2 with key R2,T2
					   if RT2 is valid
					       if RT2 != index of RT1 in p2
					           add to diff (they have differing targets)   
					   else
					       add to diff (in this case the rule does not exist in P2)
			*/		       

			/* create a boolean array the size of the number of rules in the policy */
			if (init_rbac_bool(&rb, p1, FALSE) != 0) 
				goto err_return;

			/* first find all the rules in policy 1 so that we have not only the 
			   role, but also the types */
			rt = match_rbac_rules(i, IDX_ROLE, SRC_LIST, TRUE, FALSE, &rb, p1);
			if (rt < 0) 
				goto err_return;

			/* for all trans rules TR1 with R1 in src */ 
			/* we know that if missing = true then role is not in p2 and idx has no meaning */
			for (j = 0; j < p1->num_role_trans; j++) {
				/* does this this trans rule have R1 in it? */
				if (rb.trans[j]) {
					if (missing) {
						rt1 = p1->role_trans[j].trans_role.idx;
						/* for all types T1 in TR1 */
						tgt_types = p1->role_trans[j].tgt_types;
						while (tgt_types) {
							/* tgt_types can be an attribute, if it is we will need to 
							   expand it */
							/* if the target is just a type */
							if (tgt_types->type & IDX_TYPE) {
								add_rtrans_diff(i,tgt_types->idx,rt1,TRUE,t);					
							} else if (tgt_types->type & IDX_ATTRIB) {
								/* walk the types for this attribute */
								for(k = 0; k < p1->attribs[tgt_types->idx].num; k++) {
									add_rtrans_diff(i,p1->attribs[tgt_types->idx].a[k],rt1,TRUE,t);
								}
							}
							tgt_types = tgt_types->next;
						}
					} else {
						rt1 = p1->role_trans[j].trans_role.idx;
						/* for all types T1 in TR1 */
						tgt_types = p1->role_trans[j].tgt_types;
						while (tgt_types) {
							/* tgt_types can be an attribute, if it is we will need to 
							   expand it */
							/* if p2 has this type(if it doesn't than we don't
							   diff this, its a missing type */
							/* if the target is just a type */
							if (tgt_types->type & IDX_TYPE) {
								idx2 = get_type_idx(p1->types[tgt_types->idx].name, p2);
								if (idx2 >= 0) {
									/* first try to match the key(srole,type),
									   and get the role target in p2 */
									if (match_rbac_role_ta(idx,idx2,&rt2,p2)){
										/* if the role targets are not the same we have a diff! */
										if (rt2 != get_role_idx(p1->roles[rt1].name,p2)) {
											rt = add_rtrans_diff(i,tgt_types->idx,rt1,FALSE,t);		
											if (rt < 0)
												goto err_return;
										}
									}
									/* if the trans key is not in p2 */
									else
										add_rtrans_diff(i,tgt_types->idx,rt1,TRUE,t);					
								} else {
									add_rtrans_diff(i,tgt_types->idx,rt1,TRUE,t);					
								}
							} else if (tgt_types->type & IDX_ATTRIB) {
								/* walk the types for this attribute */
								for(k = 0; k < p1->attribs[tgt_types->idx].num; k++) {
									idx2 = get_type_idx(p1->types[p1->attribs[tgt_types->idx].a[k]].name, p2);
									if (0 <= idx2) {
										/* first try to match the key(srole,type),
										   and get the role target in p2 */
										if (match_rbac_role_ta(idx,idx2,&rt2,p2)){
											/* if the role targets are not the same we have a diff! */
											if (rt2 != get_role_idx(p1->roles[rt1].name,p2)) {
												rt = add_rtrans_diff(i,p1->attribs[tgt_types->idx].a[k],rt1,FALSE,t);		
												if (rt < 0)
													goto err_return;
											}
										}
										/* if the trans key is not in p2 */
										else
											add_rtrans_diff(i,p1->attribs[tgt_types->idx].a[k],rt1,TRUE,t);		
									} else {
										add_rtrans_diff(i,p1->attribs[tgt_types->idx].a[k],rt1,TRUE,t);
									}
								}
								
							}
							tgt_types = tgt_types->next;
						} 
					}
				}
			}
			free_rbac_bool(&rb);
		}
	}
	/* AV and Type Rules and Conditionals Part1 Conditionals with rules in them*/
	if(opts & POLOPT_TE_RULES) {

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
					
					/* Conditionals Part 1: conditionals with rules */
					if (newnode->flags & AVH_FLAG_COND) {
						cond_expr = find_cond_expr_diff(newnode->cond_expr,t);
						if (cond_expr == NULL) {
							cond_expr = new_cond_diff(newnode->cond_expr,t,p1,p2);
						}
						add_rule_to_cond_expr_diff(cond_expr,newnode);
					}


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
	/* Conditionals Part 2 - The empty conditional*/
	for (i = 0; i < p1->num_cond_exprs; i++){
		if (p1->cond_exprs[i].true_list == NULL &&
		    p1->cond_exprs[i].false_list == NULL){
			cond_expr = find_cond_expr_diff(i,t);
			if (cond_expr == NULL) {
				cond_expr = new_cond_diff(i,t,p1,p2);
			}
		}			
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

