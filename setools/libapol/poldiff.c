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

ap_diff_rename_t* ap_diff_rename_new()
{
	return (ap_diff_rename_t*)calloc(1, sizeof(ap_diff_rename_t));
}

void ap_diff_rename_free(ap_diff_rename_t *rename)
{
	if (rename == NULL)
		return;
	if (rename->p1) {
		free(rename->p1);
		rename->p1 = NULL;
	}
	if (rename->p2) {
		free(rename->p2);
		rename->p2 = NULL;
	}
	rename->num_items = 0;
	rename->sz = 0;
}

/* return codes:
 *  0 success
 * -1 p1 type already renamed
 * -2 p2 type already renamed
 * -3 p1 type occurs in p2 
 * -4 p2 type occurs in p1 
 * -5 memory error */
int ap_diff_rename_add(int p1_type, int p2_type, policy_t *p1, policy_t *p2, ap_diff_rename_t *rename)
{
	int i, rt;
	char *name;
	if (rename == NULL)
		return -5;
	for (i = 0; i < rename->num_items; i++) {
		if (rename->p1[i] == p1_type)
			return -1;
		if (rename->p2[i] == p2_type)
			return -2;
	}
	/* we make sure the the p1_type does not occur in p2 */
	rt = get_type_name(p1_type, &name, p1);
	assert(rt==0);
	if (get_type_idx(name, p2) >= 0) {
		free(name);
		return -3;
	}
	/* we make sure that the p2_type does not occur in p1 */
	rt = get_type_name(p2_type, &name, p2);
	assert(rt==0);
	if (get_type_idx(name, p1) >= 0) {
		free(name);
		return -4;
	}
	if (rename->num_items >= rename->sz) {
		rename->p1 = (int*)realloc(rename->p1, sizeof(int)*1);   //TODO: change to LIST_SZ
		if (rename->p1 == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			goto mem_err;
		}
		memset(&rename->p1[rename->num_items], 0, sizeof(int)*1);//TODO: change to LIST_SZ
	        rename->p2 = (int*)realloc(rename->p2, sizeof(int)*1);   //TODO: change to LIST_SZ
		if (rename->p2 == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			goto mem_err;
		}
		memset(&rename->p2[rename->num_items], 0, sizeof(int)*1);//TODO: change to LIST_SZ
		rename->sz += 1;                                         //TODO: change to LIST_SZ
	}
	rename->p1[rename->num_items] = p1_type;
	rename->p2[rename->num_items] = p2_type;
	rename->num_items++;
	return 0;
mem_err:
	return -5;
}

int ap_diff_rename_remove(int p1, int p2, ap_diff_rename_t *rename)
{
	int i, j;

	if (rename == NULL)
		return -1;
	for (i = 0; i < rename->num_items; i++) {
		if (rename->p1[i] == p1 && rename->p2[i] == p2) {
			if (rename->num_items > 1) {
				/* move the other items down in the list */
				for (j=i; j<rename->num_items-1; j++) {
					rename->p1[j] = rename->p1[j+1];
					rename->p2[j] = rename->p2[j+1];
				}
			}
			rename->num_items--;
			return 0;
		}
	}
	return -1;
}

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
}

static bool_t ap_diff_is_type_in_p2attrib(int p1_type, int p2_attrib, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int i, rt;
	char *name = NULL;
	bool_t ret;

	if (!p1 || !is_valid_type_idx(p1_type, p1) || !p2)
		return FALSE;

	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1_type) {
				rt = get_type_name(renamed_types->p2[i], &name, p2);
				assert(rt >= 0);
			}	
		}
	}
	if (name == NULL) {
		rt = get_type_name(p1_type, &name, p1);
		assert(rt >= 0);
	}
	ret = is_type_in_attrib(name, p2_attrib, p2);
	free(name);
	return ret;
}

static bool_t ap_diff_is_type_in_p2role(int p1_type, int p2_role, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int i, rt;
	char *name = NULL;
	bool_t ret;

	if (!p1 || !is_valid_type_idx(p1_type, p1) || !p2)
		return FALSE;

	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1_type) {
				rt = get_type_name(renamed_types->p2[i], &name, p2);
				assert(rt >= 0);
			}	
		}
	}
	if (name == NULL) {
		rt = get_type_name(p1_type, &name, p1);
		assert(rt >= 0);
	}
	ret = is_type_in_role(name, p2_role, p2);
	free(name);
	return ret;
}

void apol_free_single_iad(ap_single_iad_diff_t **siad,bool_t use_types) 
{
	if ((*siad)->add != NULL)
		free((*siad)->add);
	if ((*siad)->rem != NULL)
		free((*siad)->rem);

	if (use_types) {
		if ((*siad)->chg != NULL) {
			if ((*siad)->chg->add != NULL)
				free((*siad)->chg->add);
			if ((*siad)->chg->rem != NULL)
				free((*siad)->chg->rem);
			free((*siad)->chg);
		}
		if ((*siad)->chg_add != NULL) {
			if ((*siad)->chg_add->add != NULL)
				free((*siad)->chg_add->add);
			if ((*siad)->chg_add->rem != NULL)
				free((*siad)->chg_add->rem);
			free((*siad)->chg_add);
		}
		if ((*siad)->chg_rem != NULL) {
			if ((*siad)->chg_rem->add != NULL)
				free((*siad)->chg_rem->add);
			if ((*siad)->chg_rem->rem != NULL)
				free((*siad)->chg_rem->rem);
			free((*siad)->chg_rem);
		}
	} else {
		if ((*siad)->chg != NULL)
			free((*siad)->chg);
	}
	free(*siad);

}

void apol_free_single_view_diff(ap_single_view_diff_t *svd)
{
	if (svd->types != NULL) {
		apol_free_single_iad(&(svd->types),FALSE);
	}
	if (svd->roles != NULL) {
		apol_free_single_iad(&(svd->roles),FALSE);
	}
	if (svd->users != NULL) {
		apol_free_single_iad(&(svd->users),FALSE);
	}
	if (svd->attribs != NULL) {
		apol_free_single_iad(&(svd->attribs),TRUE);
	}
	if (svd->classes != NULL) {
		apol_free_single_iad(&(svd->classes),FALSE);
	}
	if (svd->perms != NULL) {
		free(svd->perms);
	}
	if (svd->common_perms != NULL) {
		apol_free_single_iad(&(svd->common_perms),FALSE);
	}
	if (svd->rallows != NULL) {
		apol_free_single_iad(&(svd->rallows),TRUE);
	}
	if (svd->bools != NULL) {
		if (svd->bools->add)
			free(svd->bools->add);
		if (svd->bools->rem)
			free(svd->bools->rem);
		if (svd->bools->chg)
			free(svd->bools->chg);
		free(svd->bools);
	}
	if (svd->rtrans != NULL) {
		if (svd->rtrans->add)
			free(svd->rtrans->add);
		if (svd->rtrans->rem)
			free(svd->rtrans->rem);
		if (svd->rtrans->chg_add)
			free(svd->rtrans->chg_add);
		if (svd->rtrans->chg_rem)
			free(svd->rtrans->chg_rem);
		if (svd->rtrans->add_type)
			free(svd->rtrans->add_type);
		if (svd->rtrans->rem_type)
			free(svd->rtrans->rem_type);
		free(svd->rtrans);
	}
	if (svd->te != NULL) {
		if (svd->te->add)
			free(svd->te->add);
		if (svd->te->rem)
			free(svd->te->rem);
		if (svd->te->add_type)
			free(svd->te->add_type);
		if (svd->te->rem_type)
			free(svd->te->rem_type);
		if (svd->te->chg)
			free(svd->te->chg);
		free(svd->te);
	}
	if (svd->conds != NULL) {
		if (svd->conds->add != NULL)
			free(svd->conds->add);
		if (svd->conds->rem != NULL)
			free(svd->conds->rem);
		if (svd->conds->chg_add != NULL)
			free(svd->conds->chg_add);
		if (svd->conds->chg_rem != NULL)
			free(svd->conds->chg_rem);
		free(svd->conds);
	}
		
	free(svd);
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
}


static int ap_diff_find_type_in_p2(int p1_type, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int i, idx;
	name_item_t *t;
	
	if (p1 == NULL || !is_valid_type_idx(p1_type, p1) || p2 == NULL)
		return -1;

	if (renamed_types && renamed_types->p1) {
		assert(renamed_types->p2);
		for (i = 0; i < renamed_types->num_items; i++)
			if (renamed_types->p1[i] == p1_type)
				return renamed_types->p2[i];
	}
	/* first check if type name is in p2 as type name */
	idx = get_type_idx(p1->types[p1_type].name, p2);
	if(idx >= 0)
		return idx;
	/* else as a p2 type alias name */
	idx = get_type_idx_by_alias_name(p1->types[p1_type].name, p2);
	if(idx >= 0)
		return idx;
	/* else check all of type's aliases if they're p2 types or aliases */
	for(t = p1->types[p1_type].aliases; t != NULL; t = t->next) {
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
		else {
			cond_diff->true_list_diffs = (avh_node_t **) realloc(cond_diff->true_list_diffs,
									     (cond_diff->num_true_list_diffs + 1) * sizeof(avh_node_t *));
			if (cond_diff->true_list_diffs == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}	
		}
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
		else {
			cond_diff->false_list_diffs = (avh_node_t **) realloc(cond_diff->false_list_diffs,
									      (cond_diff->num_false_list_diffs + 1) *sizeof(avh_node_t *));
			if (cond_diff->false_list_diffs == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}

		}
		cond_diff->false_list_diffs[cond_diff->num_false_list_diffs] = rule;
		cond_diff->num_false_list_diffs++;
	}
	return 0;
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

int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int p2src=-1, p2tgt=-1, i;

	if (p1key == NULL || p2key == NULL || p1 == NULL || p2 == NULL || 
	    !is_valid_type_idx(p1key->src, p1) || !is_valid_type_idx(p1key->tgt, p1) || !is_valid_obj_class(p1, p1key->cls))
		return -1;
	
	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1key->src)
				p2src = renamed_types->p2[i];
			if (renamed_types->p1[i] == p1key->tgt)
				p2tgt = renamed_types->p2[i];
		}
	}
	if (p2src < 0)
		p2key->src = get_type_idx(p1->types[p1key->src].name, p2);
	else 
		p2key->src = p2src;

	if (p2tgt < 0)
		p2key->tgt = get_type_idx(p1->types[p1key->tgt].name, p2);
	else 
		p2key->tgt = p2tgt;

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
   the conditional expr in policy 1 return NULL if not found */
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
static apol_diff_t *apol_get_pol_diffs(unsigned int opts, policy_t *p1, policy_t *p2, bool_t isbin, ap_diff_rename_t *renamed_types) 
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
			idx2 = ap_diff_find_type_in_p2(i, p1, p2, renamed_types);
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
					if (!ap_diff_is_type_in_p2attrib(p1->attribs[i].a[j], idx2, p1, p2, renamed_types)) {
						if(!added) {
							/* add the attrib to the diff, and then note the first missing type */
							added = TRUE;
							if (get_attrib_name(i,&str_name,p1) >= 0) {
								iad_node = add_i_to_inta(i, &t->num_attribs, &t->attribs,&str_name);
								if(rt < 0)
									goto err_return;
							}
						}
						/* note the missing type*/
						rt = add_i_to_a(p1->attribs[i].a[j], &iad_node->numa, &iad_node->a);
						if(rt < 0)
							goto err_return;
					}
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
					if (!ap_diff_is_type_in_p2role(p1->roles[i].a[j], idx2, p1, p2, renamed_types)) {
						if(!added) {
							/* add the role to the diff, and then note the first missing type */
							added = TRUE;
							if (get_role_name(i,&str_name,p1) >= 0) {
								iad_node  = add_i_to_inta(i, &t->num_roles, &t->roles,&str_name);
								if(iad_node == NULL)
									goto err_return;
							}
						}
						/* note the missing type */
						rt = add_i_to_a(p1->roles[i].a[j], &iad_node->numa, &iad_node->a);
						if(rt < 0)
							goto err_return;
					}
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
				make_p2_key(&p1cur->key, &key, p1, p2, renamed_types);
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
							idx2 = ap_diff_find_type_in_p2(idx, p1, p2, renamed_types);
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
						rt = add_rule_to_cond_expr_diff(cond_expr,newnode);
						if (rt < 0)
							goto err_return;
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

typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);		
typedef int(*get_iad_idx_fn_t)(const char *name,policy_t *policy);
/* if the item exists first check to see if the item exists in the policy using get_name, if the item exists than this
   is a change */
int ap_iad_new_addrem(int_a_diff_t *iad,int_a_diff_t ***addrem,ap_single_iad_chg_t **chg,policy_t *p,
		      get_iad_name_fn_t get_name,get_iad_idx_fn_t get_idx,int *addremcnt,int *chgcnt,bool_t add)
{
	int rt;
	char *name = NULL;   
	rt = (*get_name)(iad->idx, &name, p);
	if (rt < 0)
		return -1;
	rt = (*get_idx)(name,p);
	free(name);
	/* if the name does not exist in the other policy this is a
	   new item */
	if (rt < 0 && iad->missing) {
		*addrem = (int_a_diff_t **)realloc(*addrem,sizeof(int_a_diff_t *)*(*addremcnt+1));
		*addrem[*addremcnt] = iad;
		*addremcnt++;
	}
	/* they have the same name this is a change */
	else {
		*chg = (ap_single_iad_chg_t *)realloc(*chg,sizeof(ap_single_iad_chg_t)*(*chgcnt+1));
		if (add) 
			(*chg)[*chgcnt].add_iad = iad;
		else
			(*chg)[*chgcnt].rem_iad = iad;
		*chgcnt++;
	}
	return 0;
}

/* handle changes for roles/attribs where some missing things are because a type is gone */
int ap_iad_new_type_chg(ap_single_iad_diff_t *siad,int_a_diff_t *add,int_a_diff_t *rem,policy_t *p1,policy_t *p2)
{
	int curr;
	char *name;
	bool_t incremented_chg = FALSE,incremented_add = FALSE,incremented_rem = FALSE; 
	int rt;
	if (siad == NULL || add == NULL || rem == NULL)
		return -1;
	/* In order to handle a change with something that could have changed because of an added or removed type
	   we have to go through all the sub elements of the iads(i.e. the types) and check them against the 
	   opposite policy to see if they exist, if they do they get added to the chg array, if they don't
	   they get added to chg_add or chg_rem depending on the starting list */
	curr = 0;
	for (curr = 0;curr < add->numa;curr ++) {
		rt = get_type_name(add->a[curr],&name,p2);
		if (rt < 0)
			goto _error;
		rt = get_type_idx(name,p1);
		free(name);
		/* this is an add because of a new type */
		if (rt < 0) {
			if (incremented_add == FALSE) {
				siad->chg_add = (ap_single_iad_chg_t *)realloc(siad->chg_add,sizeof(ap_single_iad_chg_t)*(siad->num_chg_add+1));
				if (siad->chg_add == NULL)
					goto _error;
				siad->chg_add[siad->num_chg_add].p1_idx = rem->idx;
				siad->num_chg_add++;
				incremented_add = TRUE;
			}
			siad->chg_add[siad->num_chg_add-1].add = (int *)realloc(siad->chg_add[siad->num_chg_add-1].add,
									  sizeof(int)*(siad->chg_add[siad->num_chg_add-1].num_add+1));
			siad->chg_add[siad->num_chg_add-1].add[siad->chg_add[siad->num_chg_add-1].num_add] = add->a[curr];
			siad->chg_add[siad->num_chg_add-1].num_add++;			
		} else {
			/* this is an add because of a changed type */
			if (incremented_chg == FALSE) {
				siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t)*(siad->num_chg+1));
				if (siad->chg == NULL)
					goto _error;
				siad->chg[siad->num_chg].p1_idx = rem->idx;
				siad->num_chg++;
				incremented_chg = TRUE;
			}
			siad->chg[siad->num_chg-1].add = (int *)realloc(siad->chg[siad->num_chg-1].add,
									sizeof(int)*(siad->chg[siad->num_chg-1].num_add+1));
			siad->chg[siad->num_chg-1].add[siad->chg[siad->num_chg-1].num_add] = add->a[curr];
			siad->chg[siad->num_chg-1].num_add++;			
		}
	}
	for (curr = 0;curr < rem->numa;curr ++) {
		rt = get_type_name(rem->a[curr],&name,p1);
		if (rt < 0)
			goto _error;
		rt = get_type_idx(name,p2);
		free(name);
		/* this is an rem because of a rem type */
		if (rt < 0) {
			if (incremented_rem == FALSE) {
				siad->chg_rem = (ap_single_iad_chg_t *)realloc(siad->chg_rem,sizeof(ap_single_iad_chg_t)*(siad->num_chg_rem+1));
				if (siad->chg_rem == NULL)
					goto _error;
				siad->chg_rem[siad->num_chg_rem].p1_idx = rem->idx;
				siad->num_chg_rem++;
				incremented_rem = TRUE;
			}
			siad->chg_rem[siad->num_chg_rem-1].rem = (int *)realloc(siad->chg_rem[siad->num_chg_rem-1].add,
									  sizeof(int)*(siad->chg_rem[siad->num_chg_rem-1].num_rem+1));
			siad->chg_rem[siad->num_chg_rem-1].rem[siad->chg_rem[siad->num_chg_rem-1].num_rem] = rem->a[curr];
			siad->chg_rem[siad->num_chg_rem-1].num_rem++;			
			

		} else {
			/* this is an add because of a changed type */
			if (incremented_chg == FALSE) {
				siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t)*(siad->num_chg+1));
				if (siad->chg == NULL)
					goto _error;
				siad->chg[siad->num_chg].p1_idx = rem->idx;
				siad->num_chg++;
				incremented_chg = TRUE;
			}
			siad->chg[siad->num_chg-1].rem = (int *)realloc(siad->chg[siad->num_chg-1].rem,
									  sizeof(int)*(siad->chg[siad->num_chg-1].num_rem+1));
			siad->chg[siad->num_chg-1].rem[siad->chg[siad->num_chg-1].num_rem] = add->a[curr];
			siad->chg[siad->num_chg-1].num_rem++;			
		}
	}

_error:
	return -1;
}

/* handle changes for everything but roles/attribs which have more complex
   differences that can exist */
int ap_iad_new_chg(ap_single_iad_diff_t *siad,int_a_diff_t *add,int_a_diff_t *rem)
{
	if (siad == NULL || add == NULL || rem == NULL)
		return -1;
	siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t )*(siad->num_chg+1));
	if (siad->chg == NULL) {
		fprintf(stderr,"out of memory\n");
		return -1;
	}
	siad->chg[siad->num_chg].add_iad = add;
	siad->chg[siad->num_chg].rem_iad = rem;
	siad->num_chg++;
	return 0;
}

ap_single_iad_diff_t *ap_new_iad_diff(apol_diff_result_t *diff,unsigned int option,policy_t *p1,policy_t *p2)
{

	int_a_diff_t *add = NULL,*rem = NULL;
	ap_single_iad_diff_t *siad = NULL;
	char *name = NULL,*name2 = NULL;
	int rt;
	get_iad_name_fn_t get_name;
	get_iad_idx_fn_t get_idx;
	bool_t has_types_diff = FALSE;
	if (diff == NULL || diff->p1 == NULL || diff->p2 == NULL)
		return NULL;
       
	p1 = diff->p1;
	p2 = diff->p2;

	switch (option) {
	case IDX_OBJ_CLASS:
		get_name = &get_obj_class_name;
		get_idx = &get_obj_class_idx;
		add = diff->diff2->classes;
		rem = diff->diff1->classes;
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_idx = &get_type_idx;
		add = diff->diff2->types;
		rem = diff->diff1->types;
		break;
	case IDX_ROLE|IDX_PERM:
		get_name = &get_role_name;
		get_idx = &get_role_idx;
		add = diff->diff2->role_allow;
		rem = diff->diff1->role_allow;
		break;
	case IDX_ROLE:
		get_name = &get_role_name;
		get_idx = &get_role_idx;
		add = diff->diff2->roles;
		rem = diff->diff1->roles;
		has_types_diff = TRUE;
		break;
	case IDX_USER:
		get_name = &get_user_name2;
		get_idx = &get_user_idx;
		add = diff->diff2->users;
		rem = diff->diff1->users;
		break;
	case IDX_ATTRIB:
		get_name = &get_attrib_name;
		get_idx = &get_attrib_idx;
		add = diff->diff2->attribs;
		rem = diff->diff1->attribs;
		has_types_diff = TRUE;
		break;
	case IDX_COMMON_PERM:
		get_name = &get_common_perm_name;
		get_idx = &get_common_perm_idx;
		add = diff->diff2->common_perms;
		rem = diff->diff1->common_perms;		
		break;
	default:
		break;
	}

	/* set up result structure */
	siad = (ap_single_iad_diff_t *)malloc(sizeof(ap_single_iad_diff_t));
	if(siad == NULL) {
		fprintf(stderr, "out of memory\n");
		goto siad_error_return;
	}
	memset(siad, 0, sizeof(ap_single_iad_diff_t));

	siad->type = option;

	/* here we remember that these lists are ordered, and we want to find matching items
	   so as long as we have two lists, we compare the names, if they're equal we know this is
	   just a change, if they're not than we strip out the name that comes first, so we can compare correctly
	   the next time around.  Then we test to see if that name is in the other policy at all, if its not than 
	   its an add/rem, it is is than this is a change with nothing in the other diff.  , than this might be a 
	   change we're not sure yet, we have to check to see if the item exists in the other policy, if it does, 
	   then we just add it */ 
	while (add != NULL || rem != NULL) {
		if (add != NULL && rem != NULL) {
			rt = (*get_name)(add->idx, &name2, p2);
			if (rt < 0) {
				//fprintf(stderr, "Problem getting name for %s %d\n", descrp, add->idx);
				goto siad_error_return;
			}
			rt = (*get_name)(rem->idx, &name, p1);
			if (rt < 0) {
				//fprintf(stderr, "Problem getting name for %s %d\n", descrp, rem->idx);
				goto siad_error_return;
			}
			
			rt = strcmp(name,name2);
			if (rt == 0) {
				/* here we have a change with adds and removes*/
				if (has_types_diff) {
					rt = ap_iad_new_type_chg(siad,add,rem,p1,p2);
				} else {
					rt = ap_iad_new_chg(siad,add,rem);
					if (rt < 0)
						goto siad_error_return;
				}
				rem = rem->next;
				add = add->next;
				
			} else if (rt < 0) {
				/* rem goes first */
				rt = ap_iad_new_addrem(rem,&(siad->rem),&(siad->chg),p2,get_name,
						       get_idx,&(siad->num_rem),&(siad->num_chg),FALSE);
				rem = rem->next;
			} else if (rt > 0) {
				/* add goes first */
				rt = ap_iad_new_addrem(add,&(siad->add),&(siad->chg),p1,get_name,
						       get_idx,&(siad->num_add),&(siad->num_chg),TRUE);
				add = add->next;
			}
		} else if (add != NULL) {
			rt = (*get_name)(add->idx, &name2, p2);
			if (rt < 0) {
				//fprintf(stderr, "Problem getting name for %s %d\n", descrp, add->idx);
				goto siad_error_return;	
			}   
			rt = ap_iad_new_addrem(add,&(siad->add),&(siad->chg),p1,get_name,
					       get_idx,&(siad->num_add),&(siad->num_chg),TRUE);
			add = add->next;
		} else if (rem != NULL) {
			rt = (*get_name)(rem->idx, &name2, p1);
			if (rt < 0) {
				//fprintf(stderr, "Problem getting name for %s %d\n", descrp, rem->idx);
				goto siad_error_return;
			}
			rt = ap_iad_new_addrem(rem,&(siad->rem),&(siad->chg),p2,get_name,
					       get_idx,&(siad->num_rem),&(siad->num_chg),FALSE);
			rem = rem->next;
		}		
	}

	return siad;

siad_error_return:
	if (siad != NULL)
		free(siad);
	return NULL;
}

/* given p1 key, find node in p2 that matches */
avh_node_t *find_avh_full_match(avh_node_t *p1_node,policy_t *p1,policy_t *p2,avh_t *hash, ap_diff_rename_t *renamed_types)
{
	avh_node_t *cur = NULL;
	bool_t inverse;
	avh_key_t key;

	make_p2_key(&(p1_node->key),&key,p1,p2, renamed_types);
	cur = avh_find_first_node(hash, &key);
	while (cur != NULL && does_cond_match(cur,p2,cur,p2,&inverse) == FALSE)
		cur = avh_find_next_node(cur);
	return cur;
}

/* add a single te change, this can be a change with only added permissions,
   a change with only removed permissions, a chang with both */
int ap_new_single_te_chg(ap_single_te_diff_t *std,avh_node_t *d1,avh_node_t *d2,
			 avh_node_t *p1,avh_node_t *p2)
{
//        fprintf(stderr,"in te_chg\n");
	if (std == NULL || p1 == NULL || p2 == NULL || (d1 == NULL && d2 == NULL))
		return -1;
	std->chg = (ap_single_te_chg_t *)realloc(std->chg,sizeof(ap_single_te_chg_t)*(std->num_chg + 1));
	if (std->chg == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	std->chg[std->num_chg].add = p2;
	std->chg[std->num_chg].rem = p1;
	std->chg[std->num_chg].add_diff = d2;
	std->chg[std->num_chg].rem_diff = d1;
	std->num_chg++;

	return 0;
}

int ap_new_single_te_addrem(ap_single_te_diff_t *std,avh_node_t *diff,bool_t add,bool_t type)
{
	if (std == NULL || diff == NULL)
		return -1;

	if (add && type) {
		std->add_type = (avh_node_t **)realloc(std->add_type,sizeof(avh_node_t *)*(std->num_add_type + 1));
		if (std->add_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		std->add_type[std->num_add_type] = diff;
		std->num_add_type++;
	} else if (add) {
		std->add = (avh_node_t **)realloc(std->add,sizeof(avh_node_t *)*(std->num_add + 1));
		if (std->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}	
		std->add[std->num_add] = diff;
		std->num_add++;
	} else if (type) {
		std->rem_type = (avh_node_t **)realloc(std->rem_type,sizeof(avh_node_t *)*(std->num_rem_type + 1));
		if (std->rem_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}	
		std->rem_type[std->num_rem_type] = diff;
		std->num_rem_type++;
	} else {
		std->rem = (avh_node_t **)realloc(std->rem,sizeof(avh_node_t *)*(std->num_rem + 1));
		if (std->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}	
		std->rem[std->num_rem] = diff;
		std->num_rem++;
	}
	return 0;		
}

ap_single_te_diff_t *ap_new_single_te_diff(apol_diff_result_t *diff, ap_diff_rename_t *renamed_types)

{
	avh_node_t *diffcur1 = NULL;
	avh_node_t *diffcur2 = NULL;
	avh_node_t *d_cur = NULL;
	avh_node_t *p1_node,*p2_node;
	int src_idx,tgt_idx,rt,i;
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;

	p1 = diff->p1;
	p2 = diff->p2;

	ap_single_te_diff_t *std = NULL;

	if ( p1 == NULL || p2 == NULL)
		return NULL;
	diff1 = diff->diff1;
	diff2 = diff->diff2;

	/* set up result structure */
	std = (ap_single_te_diff_t *)malloc(sizeof(ap_single_te_diff_t));
	if(std == NULL) {
		fprintf(stderr, "out of memory\n");
		goto ap_new_single_te_diff_error;
	}
	memset(std, 0, sizeof(ap_single_te_diff_t));

	/* first go the p1 diff and look for missing(i.e the rule is not in p2 at all
	   , changes only because of removed perms and for changes because of added/removed perms
	   and fill everything up */
 	for (i = 0; i < AVH_SIZE; i++) { 
 		for (diffcur1 = diff1->te.tab[i];diffcur1 != NULL; diffcur1 = diffcur1->next) {
			/* find the node in p1 */
			p1_node = find_avh_full_match(diffcur1,p1,p1,&p1->avh, renamed_types);
			/* find if there is a node in p2 */
			p2_node = find_avh_full_match(diffcur1,p1,p2,&p2->avh, renamed_types);
			if (p2_node != NULL) {
				/* find if there is a node in d2 */
				d_cur = find_avh_full_match(diffcur1,p1,p2,&diff2->te, renamed_types);
				if (d_cur != NULL) {
					rt = ap_new_single_te_chg(std,diffcur1,d_cur,p1_node,p2_node);
					if (rt < 0)
						goto ap_new_single_te_diff_error;
				} else {
					rt = ap_new_single_te_chg(std,diffcur1,NULL,p1_node,p2_node);
					if (rt < 0)
						goto ap_new_single_te_diff_error;
				}
			} else {
				src_idx = ap_diff_find_type_in_p2(diffcur1->key.src, p1, p2, renamed_types);
				tgt_idx = ap_diff_find_type_in_p2(diffcur1->key.tgt, p1, p2, renamed_types); // !!!!!! changed from key.src to key.tgt !!!!!
				if (src_idx == -1 || tgt_idx == -1)
					ap_new_single_te_addrem(std,diffcur1,FALSE,TRUE);
				else
					ap_new_single_te_addrem(std,diffcur1,FALSE,FALSE);
				
			}
		}
		/* now since we have already handled changes for added and removed perms in the first while loop
	   in this while loop we only have to look for changes only because of adds, or for just a completely
	   new rule */
	}
	for (i = 0; i < AVH_SIZE; i++) {
		for (diffcur2 = diff2->te.tab[i];diffcur2 != NULL; diffcur2 = diffcur2->next) {
			/* find the node in p2 */
			p2_node = find_avh_full_match(diffcur2,p2,p2,&p2->avh, renamed_types);
			/* find if there is a node in p1 */
			p1_node = find_avh_full_match(diffcur2,p2,p1,&p1->avh, renamed_types);
			if (p1_node != NULL) {
				/* find if there is a node in d1 */
				d_cur = find_avh_full_match(diffcur2,p2,p1,&diff1->te, renamed_types);
				if (d_cur == NULL) {
					rt = ap_new_single_te_chg(std,NULL,diffcur2,p1_node,p2_node);
					if (rt < 0)
						goto ap_new_single_te_diff_error;
				}
			} else {
				src_idx = ap_diff_find_type_in_p2(diffcur2->key.src, p2, p1, renamed_types);
				tgt_idx = ap_diff_find_type_in_p2(diffcur2->key.tgt, p2, p1, renamed_types); // !!!!!! changed key.src to key.tgt !!!!!!
				if (src_idx == -1 || tgt_idx == -1)
					ap_new_single_te_addrem(std,diffcur2,TRUE,TRUE);			
				else
					ap_new_single_te_addrem(std,diffcur2,TRUE,FALSE);
				if (rt < 0)
					goto ap_new_single_te_diff_error;
			}

		}
	}
	return std;
ap_new_single_te_diff_error:
	if (std != NULL)
		free(std);
	return NULL;
}

int ap_new_single_cond_addrem(ap_single_cond_diff_t *scd,ap_cond_expr_diff_t *diff,bool_t add)
{
	if (scd == NULL || diff == NULL)
		return -1;

	if (add) {
		scd->add = (ap_cond_expr_diff_t **)realloc(scd->add,sizeof(ap_cond_expr_diff_t *)*(scd->num_add + 1));
		if (scd->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		scd->add[scd->num_add] = diff;
		scd->num_add++;
	} else {
		scd->rem = (ap_cond_expr_diff_t **)realloc(scd->rem,sizeof(ap_cond_expr_diff_t *)*(scd->num_rem + 1));
		if (scd->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}	
		scd->rem[scd->num_rem] = diff;
		scd->num_rem++;
	}
	return 0;		
}

ap_single_cond_diff_t *ap_new_single_cond_diff(apol_diff_result_t *diff)
{
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;	
	ap_cond_expr_diff_t *cd = NULL;
	ap_single_cond_diff_t *scd = NULL;
	int rt;

	p1 = diff->p1;
	p2 = diff->p2;
	diff1 = diff->diff1;
	diff2 = diff->diff2;

	if (diff == NULL || p1 == NULL || p2 == NULL || diff1 == NULL || diff2 == NULL)
		return NULL;

	/* set up result structure */
	scd = (ap_single_cond_diff_t *)malloc(sizeof(ap_single_cond_diff_t));
	if(scd == NULL) {
		fprintf(stderr, "out of memory\n");
		goto ap_new_single_cond_diff_error;
	}
	memset(scd, 0, sizeof(ap_single_cond_diff_t));


	cd = diff1->cond_exprs;
	while (cd != NULL) {
		/* if the rule is not in the other policy */
		if (cd->missing)
			rt = ap_new_single_cond_addrem(scd,cd,FALSE);
		else {

		}
		cd = cd->next;
	}
	cd = diff2->cond_exprs;
	while (cd != NULL) {
		/* if the rule is not in the other policy */
		if (cd->missing)
			rt = ap_new_single_cond_addrem(scd,cd,TRUE);
		else {

		}
		cd = cd->next;
	}

	return scd;
ap_new_single_cond_diff_error:
	if (scd != NULL)
		free(scd);
	return NULL;
}

/* insert a single add remove or change into the single view boolean diff */
int ap_new_single_bool_addremchg(ap_single_bool_diff_t *sbd,bool_diff_t *bd,int which)
{
	if (which == 0) {
		sbd->add = (bool_diff_t **)realloc(sbd->add,sizeof(bool_diff_t *)*(sbd->num_add + 1));
		if (sbd->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		sbd->add[sbd->num_add] = bd;
		sbd->num_add++;
	} else if (which == 1){
		sbd->rem = (bool_diff_t **)realloc(sbd->rem,sizeof(bool_diff_t *)*(sbd->num_rem + 1));
		if (sbd->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		sbd->rem[sbd->num_rem] = bd;
		sbd->num_rem++;
	} else if (which == 2){
		sbd->chg = (bool_diff_t **)realloc(sbd->chg,sizeof(bool_diff_t *)*(sbd->num_chg + 1));
		if (sbd->chg == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		sbd->chg[sbd->num_chg] = bd;
		sbd->num_chg++;
	} 
	return 0;
}

ap_single_bool_diff_t *ap_new_single_bool_diff(apol_diff_result_t *diff)
{
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;	
	bool_diff_t *bd = NULL;
	ap_single_bool_diff_t *sbd = NULL;
	int rt;

	p1 = diff->p1;
	p2 = diff->p2;
	diff1 = diff->diff1;
	diff2 = diff->diff2;

	if (diff == NULL || p1 == NULL || p2 == NULL || diff1 == NULL || diff2 == NULL)
		return NULL;

	/* set up result structure */
	sbd = (ap_single_bool_diff_t *)malloc(sizeof(ap_single_bool_diff_t));
	if(sbd == NULL) {
		fprintf(stderr, "out of memory\n");
		goto ap_new_single_bool_diff_error;
	}
	memset(sbd, 0, sizeof(ap_single_bool_diff_t));


	bd = diff1->booleans;
	while (bd != NULL) {
		/* is this a change? */
		if (bd->state_diff)
			rt = ap_new_single_bool_addremchg(sbd,bd,2);
		else
			rt = ap_new_single_bool_addremchg(sbd,bd,1);
		bd = bd->next;
	}
	bd = diff2->booleans;
	while (bd != NULL) {
		/* is this a change? */
		if (!bd->state_diff)
			rt = ap_new_single_bool_addremchg(sbd,bd,0);
		bd = bd->next;
	}
	return sbd;
		
ap_new_single_bool_diff_error:
	if (sbd != NULL)
		free(sbd);
	return NULL;
}

int ap_new_single_rtrans_chg(ap_single_rtrans_diff_t *srd,ap_rtrans_diff_t *add,ap_rtrans_diff_t *rem) 
{

	if (srd == NULL || add == NULL || rem == NULL)
		return -1;
	srd->chg_add = (ap_rtrans_diff_t **)realloc(srd->chg_add,sizeof(ap_single_rtrans_diff_t *)*(srd->num_chg + 1));
	if (srd->chg_add == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	srd->chg_rem = (ap_rtrans_diff_t **)realloc(srd->chg_rem,sizeof(ap_single_rtrans_diff_t *)*(srd->num_chg + 1));
	if (srd->chg_rem == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	srd->chg_add[srd->num_chg] = add;
	srd->chg_rem[srd->num_chg] = rem;
	srd->num_chg++;
	return 0;
}

int ap_new_single_rtrans_addrem(ap_single_rtrans_diff_t *srd,ap_rtrans_diff_t *diff,bool_t add,bool_t type) 
{
	if (srd == NULL || diff == NULL)
		return -1;
	if (add && type) {
		srd->add_type = (ap_rtrans_diff_t **)realloc(srd->add_type,sizeof(ap_single_rtrans_diff_t *)*(srd->num_add_type + 1));
		if (srd->add_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		srd->num_add_type++;
	} else if (add) {
		srd->add = (ap_rtrans_diff_t **)realloc(srd->add,sizeof(ap_single_rtrans_diff_t *)*(srd->num_add + 1));
		if (srd->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		srd->num_add++;
	} else if (type) {
		srd->rem_type = (ap_rtrans_diff_t **)realloc(srd->rem_type,sizeof(ap_single_rtrans_diff_t *)*(srd->num_rem_type + 1));
		if (srd->rem_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		srd->num_rem_type++;
	} else {
		srd->rem = (ap_rtrans_diff_t **)realloc(srd->rem,sizeof(ap_single_rtrans_diff_t *)*(srd->num_rem + 1));
		if (srd->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		srd->num_rem++;
	}
		
	return 0;

}

ap_single_rtrans_diff_t *ap_new_single_rtrans_diff(apol_diff_result_t *diff)
{
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;	
	ap_rtrans_diff_t *rd = NULL;
	ap_rtrans_diff_t *rd_cur = NULL;
	ap_single_rtrans_diff_t *srd = NULL;
	int rt,r2,t2;
	char *name = NULL;

	p1 = diff->p1;
	p2 = diff->p2;
	diff1 = diff->diff1;
	diff2 = diff->diff2;

	if (diff == NULL || p1 == NULL || p2 == NULL || diff1 == NULL || diff2 == NULL)
		return NULL;

	/* set up result structure */
	srd = (ap_single_rtrans_diff_t *)malloc(sizeof(ap_single_rtrans_diff_t));
	if(srd == NULL) {
		fprintf(stderr, "out of memory\n");
		goto ap_new_single_rtrans_diff_error;
	}
	memset(srd, 0, sizeof(ap_single_rtrans_diff_t));

	rd = diff1->role_trans;
	while (rd != NULL) {
		/* is this a change? */
		if (!rd->missing){
			rt = get_role_name(rd->rs_idx,&name,p1);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
			r2 = get_role_idx(name,p2);
			free(name);
			rt = get_type_name(rd->t_idx,&name,p1);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
			t2 = get_type_idx(name,p2);
			free(name);
			rd_cur = diff2->role_trans;
			while (rd_cur && (rd_cur->rs_idx != r2 || rd_cur->t_idx != t2))
				rd_cur = rd_cur->next;
			if(rd_cur ==NULL)
				goto ap_new_single_rtrans_diff_error;
			rt = ap_new_single_rtrans_chg(srd,rd,rd_cur);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
		} else {
			/* lets find out if this is because of a type not
			   being in p2 */
			rt = get_type_name(rd->t_idx,&name,p1);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
			t2 = get_type_idx(name,p2);
			free(name);
			if (t2 < 0) {
				ap_new_single_rtrans_addrem(srd,rd,FALSE,TRUE);
			} else {
				ap_new_single_rtrans_addrem(srd,rd,FALSE,FALSE);
			}
		}
		rd = rd->next;
	}
	rd = diff1->role_trans;
	while (rd != NULL) {
		if (rd->missing) {
			/* lets find out if this is because of a type not
			   in p1 */
			rt = get_type_name(rd->t_idx,&name,p2);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
			t2 = get_type_idx(name,p1);
			free(name);
			if (t2 < 0) {
				ap_new_single_rtrans_addrem(srd,rd,TRUE,TRUE);
			} else {
				ap_new_single_rtrans_addrem(srd,rd,TRUE,FALSE);
			}

		}
		rd = rd->next;
	}
	return srd;
		
ap_new_single_rtrans_diff_error:
	if (srd != NULL)
		free(srd);
	return NULL;


}


ap_single_perm_diff_t *ap_new_single_perm_diff(apol_diff_result_t *diff)
{
	ap_single_perm_diff_t *pd;
	if (diff == NULL)
		return NULL;
	pd = (ap_single_perm_diff_t*)malloc(sizeof(ap_single_perm_diff_t));
	pd->add = diff->diff2->perms;
	pd->num_add = diff->diff2->num_perms;
	pd->rem = diff->diff1->perms;
	pd->num_rem = diff->diff1->num_perms;
	return pd;
}

ap_single_view_diff_t *ap_new_single_view_diff(apol_diff_result_t *diff, ap_diff_rename_t *renamed_types)
{
	ap_single_view_diff_t *svd = NULL;

	if (diff == NULL)
		return NULL;

	/* set up result structure */
	svd = (ap_single_view_diff_t *)malloc(sizeof(ap_single_view_diff_t));
	if(svd == NULL) {
		fprintf(stderr, "out of memory\n");
		goto svd_error_return;
	}
	memset(svd, 0, sizeof(ap_single_view_diff_t));

	/*** types ***/
	svd->types = ap_new_iad_diff(diff,IDX_TYPE,NULL,NULL);              // !!!!!!! do we need to pass renamed types? !!!!!!!!!!
	/*** attribs ***/
	svd->attribs = ap_new_iad_diff(diff,IDX_ATTRIB,diff->p1,diff->p2);  // !!!!!!! do we need to pass renamed types? !!!!!!!!!!
	/*** roles ***/
	svd->roles = ap_new_iad_diff(diff,IDX_ROLE,diff->p1,diff->p2);
	/*** users ***/
	svd->users = ap_new_iad_diff(diff,IDX_USER,NULL,NULL);
	/*** classes ***/
	svd->classes = ap_new_iad_diff(diff,IDX_OBJ_CLASS,NULL,NULL);
	/*** permissions ***/
	svd->perms = ap_new_single_perm_diff(diff);
	/*** common permissions ***/
	svd->common_perms = ap_new_iad_diff(diff,IDX_COMMON_PERM,NULL,NULL);
	/*** booleans ***/
	svd->bools = ap_new_single_bool_diff(diff);
	/*** role allows ***/
	svd->rallows = ap_new_iad_diff(diff,IDX_ROLE|IDX_PERM,NULL,NULL);
	/*** role transitions ***/
	svd->rtrans = ap_new_single_rtrans_diff(diff);
	/*** te rules ***/
	svd->te = ap_new_single_te_diff(diff, renamed_types);                // !!!!!!! now passing in renamed types here
	/*** conditionals ***/
	svd->conds = ap_new_single_cond_diff(diff);

	return svd;
svd_error_return:


	return NULL;

}


/* opts are policy open options (see policy.h).  They indicate to apol_get_pol_diffs()
 * what parts of the policy to differntiate.  Policies p1 and p2 must be opened with
 * at least the same options.  If unsure you can always use POLOPT_ALL (and ensure
 * the policies are opened with POLOPT_ALL).  However this can add significant uneeded
 * time to open and compare parts of the policies you were not interested in, esp
 * with binary policies and when you are not interested in TE rules.
 */
apol_diff_result_t *apol_diff_policies(unsigned int opts, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types) 
{
	apol_diff_result_t *t;
	ap_diff_rename_t r_renamed_types;
	
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
	t->diff1 = apol_get_pol_diffs(opts, p1, p2, t->bindiff, renamed_types);
	if(t->diff1 == NULL) 
		goto err_return;

	if (renamed_types) {
		r_renamed_types.p1 = renamed_types->p2;
		r_renamed_types.p2 = renamed_types->p1;
		r_renamed_types.num_items = renamed_types->num_items;
		r_renamed_types.sz = renamed_types->sz;
		t->diff2 = apol_get_pol_diffs(opts, p2, p1, t->bindiff, &r_renamed_types);
	} else {
		t->diff2 = apol_get_pol_diffs(opts, p2, p1, t->bindiff, NULL);	
	}


	if(t->diff2 == NULL)
		goto err_return;

	return t;
	
err_return:
	apol_free_diff_result(FALSE, t);
	return NULL;
}
