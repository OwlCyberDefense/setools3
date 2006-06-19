/* Copyright (C) 2004-2006 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * poldiff.c
 *
 * Support for semantically diff'ing two policies 
 */
#if 0
 
#include "poldiff.h"
#include "policy.h"
#include "old-policy-query.h"
#include "policy-io.h"
#include "semantic/avhash.h"
#include "semantic/avsemantics.h"
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

static void ap_bool_diff_destroy(ap_bool_diff_t *bd)
{
	ap_bool_diff_t *cur, *next;

	if(bd == NULL)
		return;
		
	for(cur = bd; cur != NULL; ) {
		next = cur->next;
		free(cur);
		cur = next;
	}
}

static void ap_single_bool_diff_destroy(ap_single_bool_diff_t *sbd)
{
	if (sbd == NULL)
		return;

	/* we don't free each linked list because we don't own them we just point to them here
	 * namely: sbd->add, sbd->rem, sbd->chg */
	free(sbd->add);
	free(sbd->rem);
	free(sbd->chg);
	free(sbd);
}

static void ap_single_perm_diff_destroy(ap_single_perm_diff_t *spd)
{
	if (spd == NULL)
		return;
	free(spd);
}

static ap_single_perm_diff_t *ap_single_perm_diff_new(apol_diff_result_t *diff)
{
	ap_single_perm_diff_t *pd;

	if (diff == NULL)
		return NULL;

	pd = (ap_single_perm_diff_t*)malloc(sizeof(ap_single_perm_diff_t));
	memset(pd, 0, sizeof(ap_single_perm_diff_t));
	pd->add = diff->diff2->perms;
	pd->num_add = diff->diff2->num_perms;
	pd->rem = diff->diff1->perms;
	pd->num_rem = diff->diff1->num_perms;
	return pd;
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
		memset(t, 0, sizeof(cond_expr_t));
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
		rename->p1 = (int*)realloc(rename->p1, sizeof(int)*LIST_SZ);  
		if (rename->p1 == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			goto mem_err;
		}
		memset(&rename->p1[rename->num_items], 0, sizeof(int)*LIST_SZ);
	        rename->p2 = (int*)realloc(rename->p2, sizeof(int)*LIST_SZ);   
		if (rename->p2 == NULL) {
			fprintf(stderr, "Error: Out of memory\n");
			goto mem_err;
		}
		memset(&rename->p2[rename->num_items], 0, sizeof(int)*LIST_SZ);
		rename->sz += LIST_SZ;                                         
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

static apol_diff_t *apol_diff_new()
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

static void int_a_diff_free(int_a_diff_t *iad)
{
	int_a_diff_t *cur, *next;
	if(iad == NULL)
		return;
		
	for(cur = iad; cur != NULL; ) {
	       	if(cur->a != NULL)
			free(cur->a);
		if(cur->str_id != NULL)
			free(cur->str_id);
		next = cur->next;
		free(cur);
		cur = next;
	}
}

static void ap_cond_expr_diff_free(ap_cond_expr_diff_t *ced)
{
	ap_cond_expr_diff_t *cur, *next;
	if(ced == NULL)
		return;
	for(cur = ced; cur != NULL; ) {
		next = cur->next;
		free(cur->true_list_diffs);
		free(cur->false_list_diffs);
		free(cur);
		cur = next;
	}
}

static void ap_rtrans_diff_destroy(ap_rtrans_diff_t *rtd)
{
	ap_rtrans_diff_t *cur, *next;
	if(rtd == NULL)
		return;
		
	for(cur = rtd; cur != NULL; ) {
		next = cur->next;
		free(cur);
		cur = next;
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
	if(idx >= 0) {
		return idx;
	}
	/* else check all of type's aliases if they're p2 types or aliases */
	for(t = p1->types[p1_type].aliases; t != NULL; t = t->next) {
		idx = get_type_idx(t->name, p2);
		if(idx >= 0) {
			return idx;
		}
		idx = get_type_idx_by_alias_name(t->name, p2);
		if(idx >= 0) {
			return idx;
		}
	}
	return -1; /* not in p2 */		
}

static bool_t ap_diff_is_type_in_p2attrib(int p1_type, int p2_attrib, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int i, rt = -1;
	char *name = NULL;
	bool_t ret;

	if (!p1 || !is_valid_type_idx(p1_type, p1) || !p2)
		return FALSE;
	/* first check renamed types */
	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1_type) {
				rt = renamed_types->p2[i];
				assert(rt >= 0);
			       
			}	
		}
	}
	/* if we didn't find a value in renamed types */
	if (rt < 0) {
		/* when looking for types we have to make sure we check aliases, this fcn will */
		rt = ap_diff_find_type_in_p2(p1_type, p1,p2,renamed_types);
	}
	if (rt < 0)
		return FALSE;
	get_attrib_name(p2_attrib,&name,p2);
	/* use this fcn since is_type_in_attrib wants a type name and won't do a thorough alias search */
	ret = is_attrib_in_type(name,rt,p2);
	free(name);
	return ret;
}

static bool_t ap_diff_is_type_in_p2role(int p1_type, int p2_role, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int i, rt = -1;
	bool_t ret;

	if (!p1 || !is_valid_type_idx(p1_type, p1) || !p2)
		return FALSE;

	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1_type) {
				rt = renamed_types->p2[i];
				assert(rt >= 0);
			}	
		}
	}
	/* if we didn't find a value in renamed types */
	if (rt < 0) {
		/* when looking for types we have to make sure we check aliases, this fcn will */
		rt = ap_diff_find_type_in_p2(p1_type, p1,p2,renamed_types);
	}
	if (rt < 0)
		return FALSE;
	ret = does_role_use_type(p2_role,rt,p2);
	
	return ret;
}

static void ap_single_iad_diff_destroy(ap_single_iad_diff_t *siad) 
{
	if (siad == NULL)
		return;
	if (siad->chg != NULL) {
		if (siad->chg->add != NULL)
			free(siad->chg->add);
		if (siad->chg->rem != NULL)
			free(siad->chg->rem);
		free(siad->chg);
	}
	if (siad->chg_add != NULL) {
		if (siad->chg_add->add != NULL)
			free(siad->chg_add->add);
		if (siad->chg_add->rem != NULL)
			free(siad->chg_add->rem);
		free(siad->chg_add);
	}
	if (siad->chg_rem != NULL) {
		if (siad->chg_rem->add != NULL)
			free(siad->chg_rem->add);
		if (siad->chg_rem->rem != NULL)
			free(siad->chg_rem->rem);
		free(siad->chg_rem);
	}
	free(siad);
}

static void ap_single_te_diff_free(ap_single_te_diff_t *std)
{
	if (std == NULL)
		return;

	free(std->chg);
}

static void ap_single_cond_diff_node_free(ap_single_cond_diff_node_t *node)
{
	ap_single_te_diff_free(node->true_list);
	ap_single_te_diff_free(node->false_list);
}

static void apol_diff_destroy(apol_diff_t *ad)
{
	if(ad == NULL)
		return;
	
	int_a_diff_free(ad->types);
	int_a_diff_free(ad->attribs);
	int_a_diff_free(ad->roles);
	int_a_diff_free(ad->users);
	int_a_diff_free(ad->classes);
	int_a_diff_free(ad->common_perms);
	free(ad->perms);
	ap_bool_diff_destroy(ad->booleans);
	int_a_diff_free(ad->role_allow);
	ap_rtrans_diff_destroy(ad->role_trans);
	ap_cond_expr_diff_free(ad->cond_exprs);
	avh_free(&ad->te);
	free(ad);
}

static void apol_diff_result_destroy(bool_t close_pols, apol_diff_result_t *adr)
{
	if(adr == NULL)
		return;
		
	apol_diff_destroy(adr->diff1);
	apol_diff_destroy(adr->diff2);
	if(close_pols) {
		close_policy(adr->p1);
		close_policy(adr->p2);
	}
	free(adr);
}

static void ap_single_rtrans_diff_destroy(ap_single_rtrans_diff_t *srtd)
{
	if (srtd == NULL)
		return;

	free(srtd->add);
	free(srtd->rem);
	free(srtd->chg_add);
	free(srtd->chg_rem);
	free(srtd->add_type);
	free(srtd->rem_type);
	free(srtd);
}

static void ap_single_cond_diff_destroy(ap_single_cond_diff_t *scd)
{
	int i;

	if (scd == NULL) 
		return;

	for (i = 0;i < scd->num_add; i++)
		ap_single_cond_diff_node_free(&(scd->add[i]));
	for (i = 0;i < scd->num_rem; i++)
		ap_single_cond_diff_node_free(&(scd->rem[i]));
	for (i = 0;i < scd->num_chg; i++)
		ap_single_cond_diff_node_free(&(scd->chg[i]));
	free(scd->add);
	free(scd->rem);
	free(scd->chg);
	free(scd);
}

void ap_single_view_diff_destroy(ap_single_view_diff_t *svd)
{
	if (svd == NULL)
		return;

	if (svd->types)
		ap_single_iad_diff_destroy(svd->types);
	if (svd->roles)
		ap_single_iad_diff_destroy(svd->roles);
	if (svd->users)
		ap_single_iad_diff_destroy(svd->users);
	if (svd->attribs)
		ap_single_iad_diff_destroy(svd->attribs);
	if (svd->classes)
		ap_single_iad_diff_destroy(svd->classes);
	if (svd->perms)
		ap_single_perm_diff_destroy(svd->perms);
	if (svd->common_perms)
		ap_single_iad_diff_destroy(svd->common_perms);
	if (svd->rallows)
		ap_single_iad_diff_destroy(svd->rallows);
	if (svd->bools)
		ap_single_bool_diff_destroy(svd->bools);
	if (svd->rtrans)
		ap_single_rtrans_diff_destroy(svd->rtrans);
	if (svd->te) {
		ap_single_te_diff_free(svd->te); 
		free(svd->te);
	}
	if (svd->conds)
		ap_single_cond_diff_destroy(svd->conds);
	if (svd->diff)
		apol_diff_result_destroy(FALSE, svd->diff);
	free(svd);
}

static int_a_diff_t *add_i_to_inta(int i, int *num, int_a_diff_t **inta,char **str_id)
{
	int_a_diff_t *t;
	int_a_diff_t *p = NULL,*q = NULL;
	if(num == NULL || inta == NULL)
		return NULL;
		
	/* we do care(for showing the diff in the gui) about ordering, so now we
	 * are going to do an in order insert based on str_id */
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

/* find a conditional expression in the 2 view difference structure */
static ap_cond_expr_diff_t *find_cond_expr_diff(int idx,apol_diff_t *diff)
{
	ap_cond_expr_diff_t *curr;
	for (curr = diff->cond_exprs;curr != NULL;curr = curr->next){
		if (idx == curr->idx)
			return curr;
	}
	return NULL;
}

/* find a conditional expression in the 2 view difference structure */
static int find_single_cond_diff_node(int idx,ap_single_cond_diff_node_t *scdn,int num)
{
	int i;
	if (scdn == NULL)
		return -1;
	for (i = 0;i < num;i++){
		if (idx == scdn[i].idx)
			return i;
	}
	return -1;
}

/* insert a new node into the arrays, idx is the p1 or p2 idx, scdn is the array to insert
   cnt is the size of scdn before insert */
static int new_single_cond_diff_node(int idx,int idx2,ap_single_cond_diff_node_t **scdn,int *cnt)
{
	
	(*scdn) = (ap_single_cond_diff_node_t *)realloc((*scdn), sizeof(ap_single_cond_diff_node_t)*(*cnt + 1));
	
	if (scdn == NULL) {
		fprintf(stderr,"out of memory\n");
		return -1;
	}
	memset(&((*scdn)[*cnt]),0,sizeof(ap_single_cond_diff_node_t));
	(*scdn)[*cnt].idx = idx;	
	(*scdn)[*cnt].idx2 = idx2;
	(*scdn)[*cnt].true_list = (ap_single_te_diff_t *)malloc(sizeof(ap_single_te_diff_t));
	(*scdn)[*cnt].false_list = (ap_single_te_diff_t *)malloc(sizeof(ap_single_te_diff_t));
	if ((*scdn)[*cnt].true_list == NULL || (*scdn)[*cnt].false_list == NULL)
		return -1;
	memset((*scdn)[*cnt].true_list,0,sizeof(ap_single_te_diff_t));
	memset((*scdn)[*cnt].false_list,0,sizeof(ap_single_te_diff_t));
	(*cnt)++;
       

	return ((*cnt)-1);
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
static int find_cond_in_policy(int p1_idx,policy_t *p1,policy_t *p2,bool_t *inverse)
{
	int rt;
	cond_expr_t *expr2=NULL;
	bool_t noinverse = *inverse;
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
		if (cond_exprs_semantic_equal(expr2, p2->cond_exprs[i].expr, p2, inverse) 
		    && !(noinverse == TRUE && inverse == FALSE)) {
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
	bool_t inverse = FALSE;
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

	rt = find_cond_in_policy(idx,p1,p2,&inverse);
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

/* add a boolean diff to the apol_diff_t struct */
static int add_bool_diff(int idx, bool_t state_diff, apol_diff_t *diff)
{
	ap_bool_diff_t *t;
	
	if(diff == NULL)
		return -1;
	
	t = (ap_bool_diff_t *)malloc(sizeof(ap_bool_diff_t));
	if(t == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(t, 0, sizeof(ap_bool_diff_t));
	t->idx = idx;
	t->state_diff = state_diff;
	t->next = diff->booleans;
	diff->booleans = t;
	diff->num_booleans++;
	return 0;
}

/* create a p2 hash table key based upon p1 */
static int make_p2_key(avh_key_t *p1key, avh_key_t *p2key, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types)
{
	int p2src=-1, p2tgt=-1, i;

	if (p1key == NULL || p2key == NULL || p1 == NULL || p2 == NULL || 
	    !is_valid_type_idx(p1key->src, p1) || !is_valid_type_idx(p1key->tgt, p1) || !is_valid_obj_class(p1, p1key->cls))
		return -1;

	if (p1 == p2)
		renamed_types = NULL; /* this seems like a HACK, we ignore renamed types when the policies are the same */

	if (renamed_types) {
		for (i = 0; i < renamed_types->num_items; i++) {
			if (renamed_types->p1[i] == p1key->src)
				p2src = renamed_types->p2[i];
			if (renamed_types->p1[i] == p1key->tgt)
				p2tgt = renamed_types->p2[i];
		}
	}
	if (p2src < 0)
		p2key->src = ap_diff_find_type_in_p2(p1key->src,p1,p2,renamed_types);
	else 
		p2key->src = p2src;

	if (p2tgt < 0)
		p2key->tgt = ap_diff_find_type_in_p2(p1key->tgt,p1,p2,renamed_types);
	else 
		p2key->tgt = p2tgt;

	p2key->cls = get_obj_class_idx(p1->obj_classes[p1key->cls].name, p2);
	p2key->rule_type = p1key->rule_type;

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
	
	t = apol_diff_new();
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
				for(j = 0; j < p1->roles[i].num_types; j++) {
					if (!ap_diff_is_type_in_p2role(p1->roles[i].types[j], idx2, p1, p2, renamed_types)) {
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
						rt = add_i_to_a(p1->roles[i].types[j], &iad_node->numa, &iad_node->a);
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
				for(j = 0; j < p1->users[i].num_roles; j++) {
					rt = get_role_name(p1->users[i].roles[j], &name, p1);
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
						rt = add_i_to_a(p1->users[i].roles[j], &iad_node->numa, &iad_node->a);
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

			/* if this source is in p2, then create an array of size num_roles */
			if (!missing && init_rbac_bool(&rb2, p2, TRUE) != 0) 
				goto err_return;
	
			rt = match_rbac_roles(i, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb, &num_found, p1);
			if (rt < 0) 
				goto err_return;

			if (!missing) {
				/* find all roles that are tgts in allow rules with idx as src */
				rt = match_rbac_roles(idx, IDX_ROLE, SRC_LIST, FALSE, TRUE, &rb2, &num_found, p2);
				if (rt < 0)
					goto err_return;
			}
			added = FALSE;

			for (j = 0; j < p1->num_roles; j++) {
				/* if p1 has an allow rule with this role as the target */
				if (rb.allow[j]) {
					/* if the src role is not missing from p2 */
					if (!missing) {
						idx2 = get_role_idx(p1->roles[j].name, p2);
						/* target role j is missing from p2 */
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
						/* if this target is in the rule then continue */
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
								idx2 = ap_diff_find_type_in_p2(tgt_types->idx, p1, p2, renamed_types);
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
									idx2 = ap_diff_find_type_in_p2(p1->attribs[tgt_types->idx].a[k], p1, p2, renamed_types);
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
	apol_diff_destroy(t);
	if(pmap != NULL) free(pmap);
	return NULL;
}

typedef int(*get_iad_name_fn_t)(int idx, char **name, policy_t *policy);		
typedef int(*get_iad_idx_fn_t)(const char *name, policy_t *policy);

/* handle changes for roles/attribs where some missing things are because a type is gone */
static int ap_iad_new_type_chg(ap_single_iad_diff_t *siad, int_a_diff_t *add, int_a_diff_t *rem, policy_t *p1, policy_t *p2)
{
	int curr;
	int rt;
	bool_t changed, added_chg, removed_chg;
	
	if (siad == NULL)
		return -1;

	changed = added_chg = removed_chg = FALSE;
	/* In order to handle a change with something that could have changed because of an added or removed type
	 * we have to go through all the sub elements of the iads(i.e. the types) and check them against the 
	 * opposite policy to see if they exist, if they do they get added to the chg array, if they don't
	 * they get added to chg_add or chg_rem depending on the starting list */
	curr = 0;
	for (curr = 0; add && curr < add->numa; curr++) {
		rt = ap_diff_find_type_in_p2(add->a[curr], p2, p1, NULL);
		/* this is an add because of a new type */
		if (rt < 0) {
			if (added_chg == FALSE) {
				siad->chg_add = (ap_single_iad_chg_t *)realloc(siad->chg_add, sizeof(ap_single_iad_chg_t)*(siad->num_chg_add+1));
				if (siad->chg_add == NULL) {
					fprintf(stderr,"out of memory");
					goto error;
				}
				memset(&(siad->chg_add[siad->num_chg_add]), 0, sizeof(ap_single_iad_chg_t));
				siad->chg_add[siad->num_chg_add].p2_idx = add->idx;
				siad->chg_add[siad->num_chg_add].p1_idx = -1;
				siad->num_chg_add++;
				added_chg = TRUE;
			}
			siad->chg_add[siad->num_chg_add-1].add = (int *)realloc(siad->chg_add[siad->num_chg_add-1].add,
										sizeof(int)*(siad->chg_add[siad->num_chg_add-1].num_add+1));
			if (siad->chg_add[siad->num_chg_add-1].add == NULL) {
				fprintf(stderr,"out of memory");
				goto error;
			}
			memset(&(siad->chg_add[siad->num_chg_add-1].add[siad->chg_add[siad->num_chg_add-1].num_add]),0,sizeof(int));
			siad->chg_add[siad->num_chg_add-1].add[siad->chg_add[siad->num_chg_add-1].num_add] = add->a[curr];
			siad->chg_add[siad->num_chg_add-1].num_add++;			
		} else {
			if (changed == FALSE) {
				siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t)*(siad->num_chg+1));
				if (siad->chg == NULL)
					goto error;
				memset(&(siad->chg[siad->num_chg]),0,sizeof(ap_single_iad_chg_t));
				siad->chg[siad->num_chg].p2_idx = add->idx;
				siad->chg[siad->num_chg].p1_idx = -1;					
				siad->num_chg++;
				changed = TRUE;
			}
			/* this is an add because of a changed type */
			siad->chg[siad->num_chg-1].add = (int *)realloc(siad->chg[siad->num_chg-1].add,
									sizeof(int)*(siad->chg[siad->num_chg-1].num_add+1));
			if (siad->chg[siad->num_chg-1].add == NULL) {
				fprintf(stderr,"out of memory");
				goto error;
			}
			memset(&(siad->chg[siad->num_chg-1].add[siad->chg[siad->num_chg-1].num_add]),0,sizeof(int));
			siad->chg[siad->num_chg-1].add[siad->chg[siad->num_chg-1].num_add] = add->a[curr];
			siad->chg[siad->num_chg-1].num_add++;			
		}

	}
	for (curr = 0;rem && curr < rem->numa;curr++) {
		rt = ap_diff_find_type_in_p2(rem->a[curr], p1, p2, NULL);
		/* this is an rem because of a rem type */
		if (rt < 0) {
			if (removed_chg == FALSE) {
				siad->chg_rem = (ap_single_iad_chg_t *)realloc(siad->chg_rem,sizeof(ap_single_iad_chg_t)*(siad->num_chg_rem+1));
				if (siad->chg_rem == NULL) {
					fprintf(stderr,"out of memory\n");
					goto error;
				}
				memset(&(siad->chg_rem[siad->num_chg_rem]),0,sizeof(ap_single_iad_chg_t));
				siad->chg_rem[siad->num_chg_rem].p1_idx = rem->idx;
				siad->chg_rem[siad->num_chg_rem].p2_idx = -1;
				siad->num_chg_rem++;
				removed_chg = TRUE;
			}
			siad->chg_rem[siad->num_chg_rem-1].rem = (int *)realloc(siad->chg_rem[siad->num_chg_rem-1].rem,
									  sizeof(int)*(siad->chg_rem[siad->num_chg_rem-1].num_rem+1));
			if (siad->chg_rem[siad->num_chg_rem-1].rem == NULL) {
				fprintf(stderr,"out of memory");
				goto error;
			}
			memset(&(siad->chg_rem[siad->num_chg_rem-1].rem[siad->chg_rem[siad->num_chg_rem-1].num_rem]),0,sizeof(int));
			siad->chg_rem[siad->num_chg_rem-1].rem[siad->chg_rem[siad->num_chg_rem-1].num_rem] = rem->a[curr];
			siad->chg_rem[siad->num_chg_rem-1].num_rem++;			
			

		} else {
			if (changed == FALSE) {
				siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t)*(siad->num_chg+1));
				if (siad->chg == NULL)
					goto error;
				memset(&(siad->chg[siad->num_chg]),0,sizeof(ap_single_iad_chg_t));
				siad->chg[siad->num_chg].p1_idx = rem->idx;
				siad->chg[siad->num_chg].p2_idx = -1;
				siad->num_chg++;
				changed = TRUE;
			}
			siad->chg[siad->num_chg-1].rem = (int *)realloc(siad->chg[siad->num_chg-1].rem,
									  sizeof(int)*(siad->chg[siad->num_chg-1].num_rem+1));
			if (siad->chg[siad->num_chg-1].rem == NULL) {
				fprintf(stderr,"out of memory");
				goto error;
			}
			memset(&(siad->chg[siad->num_chg-1].rem[siad->chg[siad->num_chg-1].num_rem]),0,sizeof(int));
			siad->chg[siad->num_chg-1].rem[siad->chg[siad->num_chg-1].num_rem] = rem->a[curr];
			siad->chg[siad->num_chg-1].num_rem++;			
		}
	}
	return 0;
error:

	return -1;
}

/* if the item exists first check to see if the item exists in the policy using get_name, if the item exists than this
   is a change */
static int ap_iad_new_addrem(int_a_diff_t *iad,ap_single_iad_diff_t *siad,policy_t *p1,policy_t *p2,
		      get_iad_name_fn_t get_name,get_iad_idx_fn_t get_idx,bool_t add,bool_t typechange)
{
	int rt;
	char *name = NULL;   
	rt = (*get_name)(iad->idx, &name, p1);
	if (rt < 0)
		return -1;
	rt = (*get_idx)(name,p2);
	/* if the name does not exist in the other policy this is a
	   new item */
	if (rt < 0 || iad->missing) {
		if (add == TRUE) {
			siad->add = (int_a_diff_t **)realloc(siad->add,sizeof(int_a_diff_t *)*(siad->num_add+1));
			if (siad->add == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			siad->add[siad->num_add] = iad;
			siad->num_add++;
		} else {
			siad->rem = (int_a_diff_t **)realloc(siad->rem,sizeof(int_a_diff_t *)*(siad->num_rem+1));
			if (siad->rem == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			siad->rem[siad->num_rem] = iad;
			siad->num_rem++;
		}
	}
	/* they have the same name this is a change */
	else {
		if (typechange) {
			if (add == TRUE)
				ap_iad_new_type_chg(siad,iad,NULL,p2,p1);
			else
				ap_iad_new_type_chg(siad,NULL,iad,p1,p2);
		} else {
			siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t)*(siad->num_chg+1));
			if (siad->chg == NULL) {
				fprintf(stderr, "out of memory\n");
				return -1;
			}
			memset(&(siad->chg[siad->num_chg]),0,sizeof(ap_single_iad_chg_t));
			siad->chg[siad->num_chg].p2_idx = siad->chg[siad->num_chg].p1_idx = -1;
			if (add == TRUE)
				siad->chg[siad->num_chg].p2_idx = (*get_idx)(name,p1);
			else
				siad->chg[siad->num_chg].p1_idx = (*get_idx)(name,p1);
						
			if (add == TRUE) 
				siad->chg[siad->num_chg].add_iad = iad;
			else
				siad->chg[siad->num_chg].rem_iad = iad;
			siad->num_chg++;
		}
	}
	free(name);
	return 0;
}


/* handle changes for everything but roles/attribs which have more complex
   differences that can exist */
static int ap_iad_new_chg(ap_single_iad_diff_t *siad,int_a_diff_t *add,int_a_diff_t *rem)
{
	if (siad == NULL || add == NULL || rem == NULL)
		return -1;
	siad->chg = (ap_single_iad_chg_t *)realloc(siad->chg,sizeof(ap_single_iad_chg_t )*(siad->num_chg+1));
	if (siad->chg == NULL) {
		fprintf(stderr,"out of memory\n");
		return -1;
	}
	memset(&(siad->chg[siad->num_chg]),0,sizeof(ap_single_iad_chg_t ));
	siad->chg[siad->num_chg].p1_idx = rem->idx;
	siad->chg[siad->num_chg].p2_idx = add->idx;
	siad->chg[siad->num_chg].add_iad = add;
	siad->chg[siad->num_chg].rem_iad = rem;
	siad->num_chg++;
	return 0;
}

static ap_single_iad_diff_t *ap_single_iad_diff_new(apol_diff_result_t *diff,unsigned int id)
{
	int_a_diff_t *add = NULL,*rem = NULL;
	ap_single_iad_diff_t *siad = NULL;
	char *name = NULL,*name2 = NULL;
	int rt;
	get_iad_name_fn_t get_name=NULL;
	get_iad_idx_fn_t get_idx=NULL;
	bool_t has_types_diff = FALSE;
	char *descrp = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;

	if (diff == NULL)
		return NULL;
       
	p1 = diff->p1;
	p2 = diff->p2;

	switch (id) {
	case IDX_OBJ_CLASS:
		descrp = "Object Classes";
		get_name = &get_obj_class_name;
		get_idx = &get_obj_class_idx;
		add = diff->diff2->classes;
		rem = diff->diff1->classes;
		break;
	case IDX_TYPE:
		get_name = &get_type_name;
		get_idx = &get_type_idx;
		descrp = "Types";
		add = diff->diff2->types;
		rem = diff->diff1->types;
		break;
	case IDX_ROLE|IDX_PERM:
		descrp = "Role Allows";
		get_name = &get_role_name;
		get_idx = &get_role_idx;
		add = diff->diff2->role_allow;
		rem = diff->diff1->role_allow;
		break;
	case IDX_ROLE:
		descrp = "Roles";
		get_name = &get_role_name;
		get_idx = &get_role_idx;
		add = diff->diff2->roles;
		rem = diff->diff1->roles;
		has_types_diff = TRUE;
		break;
	case IDX_USER:
		descrp = "Users";
		get_name = &get_user_name2;
		get_idx = &get_user_idx;
		add = diff->diff2->users;
		rem = diff->diff1->users;
		break;
	case IDX_ATTRIB:
		descrp = "Attributes";
		get_name = &get_attrib_name;
		get_idx = &get_attrib_idx;
		add = diff->diff2->attribs;
		rem = diff->diff1->attribs;
		has_types_diff = TRUE;
		break;
	case IDX_COMMON_PERM:
		descrp = "Common Permissions";
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
		goto error;
	}
	memset(siad, 0, sizeof(ap_single_iad_diff_t));

	siad->id = id;

	/* here we remember that these lists are ordered, and we want to find matching items
	 * so as long as we have two lists, we compare the names, if they're equal we know this is
	 * just a change, if they're not than we strip out the name that comes first, so we can compare correctly
	 * the next time around.  Then we test to see if that name is in the other policy at all, if its not than 
	 * its an add/rem, it is is than this is a change with nothing in the other diff.  , than this might be a 
	 * change we're not sure yet, we have to check to see if the item exists in the other policy, if it does, 
	 * then we just add it */ 
	while (add != NULL || rem != NULL) {
		if (add != NULL && rem != NULL) {
			rt = (*get_name)(rem->idx, &name, p1);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, rem->idx);
				goto error;
			}
			rt = (*get_name)(add->idx, &name2, p2);
			if (rt < 0) {
				fprintf(stderr, "Problem getting name for %s %d\n", descrp, add->idx);
				goto error;
			}
			
			rt = strcmp(name,name2);
			if (rt == 0) {
				/* here we have a change with adds and removes*/
				if (has_types_diff == TRUE) {
					rt = ap_iad_new_type_chg(siad,add,rem,p1,p2);
					if (rt < 0)
						goto error;
				} else {
					rt = ap_iad_new_chg(siad,add,rem);
					if (rt < 0)
						goto error;
				}
				rem = rem->next;
				add = add->next;
				
			} else if (rt < 0) {
				/* rem goes first */
				rt = ap_iad_new_addrem(rem,siad,p1,p2,get_name,get_idx,FALSE,has_types_diff);
				rem = rem->next;
			} else if (rt > 0) {
				/* add goes first */
				rt = ap_iad_new_addrem(add,siad,p2,p1,get_name,get_idx,TRUE,has_types_diff);
				add = add->next;
			}
			free(name);
			free(name2);
		} else if (add != NULL) {
			rt = ap_iad_new_addrem(add,siad,p2,p1,get_name,get_idx,TRUE,has_types_diff);
			add = add->next;
		} else if (rem != NULL) {
			rt = ap_iad_new_addrem(rem,siad,p1,p2,get_name,get_idx,FALSE,has_types_diff);
			rem = rem->next;
		}		
	}

	return siad;

error:
	if (siad != NULL)
		free(siad);
	return NULL;
}

/* given p1 key, find node in p2 that matches */
static avh_node_t *find_avh_full_match(avh_node_t *p1_node,policy_t *p1,policy_t *p2,avh_t *hash, ap_diff_rename_t *renamed_types)
{
	avh_node_t *cur = NULL;
	bool_t inverse;
	avh_key_t key;

	make_p2_key(&(p1_node->key), &key, p1, p2, renamed_types);
	cur = avh_find_first_node(hash, &key);
	while (cur != NULL && does_cond_match(p1_node,p1,cur,p2,&inverse) == FALSE)
		cur = avh_find_next_node(cur);
	return cur;
}

/* add a single te change, this can be a change with only added permissions,
 * a change with only removed permissions, a chang with both */
static int ap_new_single_te_chg(ap_single_te_diff_t *std, avh_node_t *d1, avh_node_t *d2, avh_node_t *p1, avh_node_t *p2)
{
	if (std == NULL || p1 == NULL || p2 == NULL || (d1 == NULL && d2 == NULL)) {
		assert(FALSE);
		return -1;
	}

	std->chg = (ap_single_te_chg_t *)realloc(std->chg, sizeof(ap_single_te_chg_t)*(std->num_chg + 1));
	if (std->chg == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	memset(&(std->chg[std->num_chg]), 0, sizeof(ap_single_te_chg_t));
	std->chg[std->num_chg].add = p2;
	std->chg[std->num_chg].rem = p1;
	std->chg[std->num_chg].add_diff = d2;
	std->chg[std->num_chg].rem_diff = d1;
	std->num_chg++;
	return 0;
}

static int ap_new_single_cond_chg(ap_single_cond_diff_t *scd,avh_node_t *d1,avh_node_t *d2,
			   avh_node_t *p1_node,avh_node_t *p2_node,policy_t *p1,policy_t *p2)
{
	int idx,idx2,cdiff_idx,rt;
	bool_t noinverse = FALSE;

	if (scd == NULL || p1_node == NULL || p2_node == NULL || (d1 == NULL && d2 == NULL)) {
		assert(FALSE);
		return -1;
	}
    	
	if (d1 != NULL && (d1->flags & AVH_FLAG_COND)) {
		idx = d1->cond_expr;
		idx2 = find_cond_in_policy(idx,p1,p2,&noinverse);

	} else if (d2 != NULL && (d2->flags & AVH_FLAG_COND)) {
		idx = find_cond_in_policy(d2->cond_expr,p2,p1,&noinverse);
		idx2 = d2->cond_expr;
	} else 
		return 0;

	/* find the node index in the array */
        cdiff_idx = find_single_cond_diff_node(idx,scd->chg,scd->num_chg);
	if (cdiff_idx < 0) {
		cdiff_idx = new_single_cond_diff_node(idx,idx2,&(scd->chg),&(scd->num_chg));				
		if (cdiff_idx < 0)
			return -1;
	} 
	if (d1 && d2) {
		if (d1->cond_list == TRUE) {
			if (noinverse == FALSE)
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,d1,d2,p1_node,p2_node);
			else {
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,d1,NULL,p1_node,p2_node);
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,NULL,d2,p1_node,p2_node);
			}
		} else {
			if (noinverse == FALSE)
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,d1,d2,p1_node,p2_node);
			else {
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,d1,NULL,p1_node,p2_node);
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,NULL,d2,p1_node,p2_node);
			}
		}
	} else if (d1) {
		if (d1->cond_list == TRUE)
			rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,d1,NULL,p1_node,p2_node);
		else
			rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,d1,NULL,p1_node,p2_node);
	} else {
		if (d2->cond_list == TRUE) {
			if (noinverse == FALSE) 
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,NULL,d2,p1_node,p2_node);
			else
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,NULL,d2,p1_node,p2_node);
		} else {
			if (noinverse == FALSE)
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].false_list,NULL,d2,p1_node,p2_node);
			else
				rt = ap_new_single_te_chg(scd->chg[cdiff_idx].true_list,NULL,d2,p1_node,p2_node);
		}
	}
	return rt;
}

int ap_single_te_addrem_increment(avh_node_t ***node,int *num_node,avh_node_t *diff)
{
	(*node) = (avh_node_t **)realloc((*node),sizeof(avh_node_t *)*((*num_node) + 1));
	if ((*node) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(&((*node)[(*num_node)]),0,sizeof(avh_node_t *));
        (*node)[(*num_node)] = diff;
	(*num_node)++;
	return 0;
}

static int ap_new_single_te_addrem(ap_single_te_diff_t *std,avh_node_t *diff,bool_t add,bool_t type)
{
	int rt;

	if (std == NULL || diff == NULL)
		return -1;
	
	if (add && type) {
		rt = ap_single_te_addrem_increment(&(std->add_type),&(std->num_add_type),diff);
	} else if (add) {
		rt = ap_single_te_addrem_increment(&(std->add),&(std->num_add),diff);
	} else if (type) {
		rt = ap_single_te_addrem_increment(&(std->rem_type),&(std->num_rem_type),diff);
	} else {
		rt = ap_single_te_addrem_increment(&(std->rem),&(std->num_rem),diff);
	}
	return rt;		
}

static int add_rule_to_single_cond_node_addrem(ap_single_cond_diff_t *scd,avh_node_t *diff,policy_t *p1,policy_t *p2,bool_t add,bool_t type)
{
	int rt,idx2;
	ap_single_cond_diff_node_t **node;
	int *cnt;
	bool_t inverse=FALSE,chg=FALSE;

	/* if we're not a cond just return */
	if (!(diff->flags & AVH_FLAG_COND))
		return 0;

	/* if the conditional exists in the other policy its a change */
	idx2 = find_cond_in_policy(diff->cond_expr,p1,p2,&inverse);	
	if (idx2 >= 0) {		
		chg = TRUE;
		node = &(scd->chg);
		cnt = &(scd->num_chg);
		if (add == TRUE) {
			/* find the node index in the array, or if not found create a new one */
			rt = find_single_cond_diff_node(idx2,*node,*cnt);
			if (rt < 0) {
				rt = new_single_cond_diff_node(idx2,diff->cond_expr,node,cnt);				
				if (rt < 0)
					return -1;
			}
		} else {
			rt = find_single_cond_diff_node(diff->cond_expr,*node,*cnt);
			if (rt < 0) {
				rt = new_single_cond_diff_node(diff->cond_expr,idx2,node,cnt);				
				if (rt < 0)
					return -1;
			}
		}
	} else if (add == TRUE) {		
		node = &(scd->add);
		cnt = &(scd->num_add);
		/* find the node index in the array, or if not found create a new one */
		rt = find_single_cond_diff_node(diff->cond_expr,*node,*cnt);
		if (rt < 0) {
			rt = new_single_cond_diff_node(diff->cond_expr,-1,node,cnt);				
			if (rt < 0)
				return -1;
		}

	} else {
		node = &(scd->rem);
		cnt = &(scd->num_rem);
		/* find the node index in the array, or if not found create a new one */
		rt = find_single_cond_diff_node(diff->cond_expr,*node,*cnt);
		if (rt < 0) {
			rt = new_single_cond_diff_node(diff->cond_expr,-1,node,cnt);				
			if (rt < 0)
				return -1;
		}

	}

	if (diff->cond_list == TRUE) {
		if (chg && inverse == TRUE && add == TRUE)
			rt = ap_new_single_te_addrem((*node)[rt].false_list,diff,add,type);
		else
			rt = ap_new_single_te_addrem((*node)[rt].true_list,diff,add,type);
	} else {
		if (chg && inverse == TRUE && add == TRUE)		
			rt = ap_new_single_te_addrem((*node)[rt].true_list,diff,add,type);
		else
			rt = ap_new_single_te_addrem((*node)[rt].false_list,diff,add,type);
	}
	return rt;
}

static int ap_new_single_te_diff(ap_single_view_diff_t *svd, apol_diff_result_t *diff, ap_diff_rename_t *renamed_types)

{
	avh_node_t *diffcur1 = NULL;
	avh_node_t *diffcur2 = NULL;
	avh_node_t *d_cur = NULL;
	avh_node_t *p1_node, *p2_node;
	int src_idx,tgt_idx,rt,i;
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;

	if ( svd == NULL || diff == NULL || diff->p1 == NULL || diff->p2 == NULL) {
		assert(FALSE);
		return -1;
	}

	p1 = diff->p1;
	p2 = diff->p2;
	diff1 = diff->diff1;
	diff2 = diff->diff2;

	/* set up result structure */
	svd->te = (ap_single_te_diff_t *)malloc(sizeof(ap_single_te_diff_t));
	if(svd->te == NULL) {
		fprintf(stderr, "out of memory\n");
		goto error;
	}
	memset(svd->te, 0, sizeof(ap_single_te_diff_t));

	svd->conds = (ap_single_cond_diff_t *)malloc(sizeof(ap_single_cond_diff_t));
	if (svd->conds == NULL) {
		fprintf(stderr,"out of memory\n");
		goto error;
	}
	memset(svd->conds, 0, sizeof(ap_single_cond_diff_t));

 	for (i = 0; i < AVH_SIZE; i++) { 
 		for (diffcur1 = diff1->te.tab[i]; diffcur1 != NULL; diffcur1 = diffcur1->next) {
			/* find the node in p1 */
			p1_node = find_avh_full_match(diffcur1, p1, p1, &p1->avh, renamed_types);
			/* find if there is a node in p2 */
			p2_node = find_avh_full_match(diffcur1, p1, p2, &p2->avh, renamed_types);
			if (p2_node != NULL) {
				/* find if there is a node in d2 */
				d_cur = find_avh_full_match(diffcur1, p1, p2, &diff2->te, renamed_types);
				rt = ap_new_single_te_chg(svd->te, diffcur1, d_cur, p1_node, p2_node);
				if (rt < 0)
					goto error;
				rt = ap_new_single_cond_chg(svd->conds, diffcur1, d_cur, p1_node, p2_node, p1, p2);
				if (rt < 0)
					goto error;
			} else {
				src_idx = ap_diff_find_type_in_p2(diffcur1->key.src, p1, p2, renamed_types);
				tgt_idx = ap_diff_find_type_in_p2(diffcur1->key.tgt, p1, p2, renamed_types); 
				if (src_idx == -1 || tgt_idx == -1) {
					rt = add_rule_to_single_cond_node_addrem(svd->conds, diffcur1, p1, p2, FALSE, TRUE);
					rt = ap_new_single_te_addrem(svd->te, diffcur1, FALSE, TRUE);
				} else {
					rt = add_rule_to_single_cond_node_addrem(svd->conds, diffcur1, p1, p2, FALSE, FALSE);
					rt = ap_new_single_te_addrem(svd->te, diffcur1, FALSE, FALSE);
				}
				if (rt < 0)
					goto error;
			}
		}
	/* now since we have already handled changes for added and removed perms in the first while loop
	 * in this while loop we only have to look for changes only because of adds, or for just a completely
	 * new rule */
	}
	for (i = 0; i < AVH_SIZE; i++) {
		for (diffcur2 = diff2->te.tab[i];diffcur2 != NULL; diffcur2 = diffcur2->next) {
			/* find the node in p2 */
			p2_node = find_avh_full_match(diffcur2,p2,p2,&(p2->avh), renamed_types);
			/* find if there is a node in p1 */
			p1_node = find_avh_full_match(diffcur2,p2,p1,&(p1->avh), renamed_types);
			if (p1_node != NULL) {
				/* find if there is a node in d1 */
				d_cur = find_avh_full_match(diffcur2,p2,p1,&diff1->te, renamed_types);
				if (d_cur == NULL) {
					rt = ap_new_single_te_chg(svd->te,NULL,diffcur2,p1_node,p2_node);
					if (rt < 0)
						goto error;
					rt = ap_new_single_cond_chg(svd->conds,NULL,diffcur2,p1_node,p2_node,p1,p2);
					if (rt < 0)
						goto error;
				}
			} else {
				src_idx = ap_diff_find_type_in_p2(diffcur2->key.src, p2, p1, renamed_types);
				tgt_idx = ap_diff_find_type_in_p2(diffcur2->key.tgt, p2, p1, renamed_types);
				if (src_idx == -1 || tgt_idx == -1) {
					rt = add_rule_to_single_cond_node_addrem(svd->conds,diffcur2,p2,p1,TRUE,TRUE);
					rt = ap_new_single_te_addrem(svd->te,diffcur2,TRUE,TRUE);			
				} else {
					rt = add_rule_to_single_cond_node_addrem(svd->conds,diffcur2,p2,p1,TRUE,FALSE);
					rt = ap_new_single_te_addrem(svd->te,diffcur2,TRUE,FALSE);
				}
				if (rt < 0)
					goto error;
			}
		}
	}
	return 0;
error:
	if (svd->te != NULL) {
		free(svd->te);
		svd->te = NULL;
	}
	return -1;
}

static int ap_find_empty_single_cond_diff(ap_single_cond_diff_t *scd, apol_diff_result_t *adr)
{
	apol_diff_t *diff = NULL;
	int rt,rta,rtc,idx;
	bool_t inverse;
	policy_t *p1 = adr->p1;
	policy_t *p2 = adr->p2;
	ap_cond_expr_diff_t *curr = NULL;

	diff = adr->diff1;
	/* for all the things in the diff */
	for (curr = adr->diff1->cond_exprs;curr != NULL; curr = curr->next) {
		/* if this is an empty conditional */
		if (curr->num_true_list_diffs == 0 &&
		    curr->num_false_list_diffs == 0) {
			/* if the conditional is missing from the other policy we only have to check removes */
			if (curr->missing == TRUE) {
				rt = find_single_cond_diff_node(curr->idx,scd->rem,scd->num_rem);
				if (rt < 0) {
					rt = new_single_cond_diff_node(curr->idx,-1,&(scd->rem),&(scd->num_rem));
					if (rt < 0)
						return -1;
				}
			} else {
				idx = find_cond_in_policy(curr->idx,p1,p2,&inverse);	
				rt = find_single_cond_diff_node(curr->idx,scd->rem,scd->num_rem);
				rta = find_single_cond_diff_node(idx,scd->add,scd->num_add);
				rtc = find_single_cond_diff_node(curr->idx,scd->chg,scd->num_chg);
				if (rt < 0 && rta < 0 && rtc < 0) {
					rt = new_single_cond_diff_node(curr->idx,idx,&(scd->rem),&(scd->num_rem));
					if (rt < 0)
						return -1;
				}
			}

		}			
	}


	curr = adr->diff2->cond_exprs;
	/* for all the things in the diff */
	for (curr = adr->diff2->cond_exprs;curr != NULL; curr = curr->next) {
		/* if this is an empty conditional */
		if (curr->num_true_list_diffs == 0 &&
		    curr->num_false_list_diffs == 0) {
			/* if the conditional is missing from the other policy we only have to check removes */
			if (curr->missing == TRUE) {
				rt = find_single_cond_diff_node(curr->idx,scd->add,scd->num_add);
				if (rt < 0) {
					rt = new_single_cond_diff_node(-1,curr->idx,&(scd->add),&(scd->num_add));
					if (rt < 0)
						return -1;
				}
			} else {				
				idx = find_cond_in_policy(curr->idx,p2,p1,&inverse);	
				rt = find_single_cond_diff_node(idx,scd->rem,scd->num_rem);
				rta = find_single_cond_diff_node(curr->idx,scd->add,scd->num_add);
				rtc = find_single_cond_diff_node(curr->idx,scd->chg,scd->num_chg);
				if (rt < 0 && rta < 0 && rtc < 0) {
					rt = new_single_cond_diff_node(idx,curr->idx,&(scd->rem),&(scd->num_rem));
					if (rt < 0)
						return -1;
				}
			}
		}			
	}

	return 0;
}


/* insert a single add remove or change into the single view boolean diff */
static int ap_new_single_bool_addremchg(ap_single_bool_diff_t *sbd, ap_bool_diff_t *bd, int which)
{
	if (which == 0) {
		sbd->add = (ap_bool_diff_t **)realloc(sbd->add,sizeof(ap_bool_diff_t *)*(sbd->num_add + 1));
		if (sbd->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(sbd->add[sbd->num_add]),0,sizeof(ap_bool_diff_t *));
		sbd->add[sbd->num_add] = bd;
		sbd->num_add++;
	} else if (which == 1){
		sbd->rem = (ap_bool_diff_t **)realloc(sbd->rem,sizeof(ap_bool_diff_t *)*(sbd->num_rem + 1));
		if (sbd->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(sbd->rem[sbd->num_rem]),0,sizeof(ap_bool_diff_t *));
		sbd->rem[sbd->num_rem] = bd;
		sbd->num_rem++;
	} else if (which == 2){
		sbd->chg = (ap_bool_diff_t **)realloc(sbd->chg,sizeof(ap_bool_diff_t *)*(sbd->num_chg + 1));
		if (sbd->chg == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(sbd->chg[sbd->num_chg]),0,sizeof(ap_bool_diff_t *));
		sbd->chg[sbd->num_chg] = bd;
		sbd->num_chg++;
	} 
	return 0;
}

static ap_single_bool_diff_t *ap_single_bool_diff_new(apol_diff_result_t *diff)
{
	apol_diff_t *diff1 = NULL;
	apol_diff_t *diff2 = NULL;
	policy_t *p1 = NULL;
	policy_t *p2 = NULL;	
	ap_bool_diff_t *bd = NULL;
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

static int ap_new_single_rtrans_chg(ap_single_rtrans_diff_t *srd,ap_rtrans_diff_t *add,ap_rtrans_diff_t *rem) 
{

	if (srd == NULL || add == NULL || rem == NULL)
		return -1;
	srd->chg_add = (ap_rtrans_diff_t **)realloc(srd->chg_add,sizeof(ap_single_rtrans_diff_t *)*(srd->num_chg + 1));
	if (srd->chg_add == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(&(srd->chg_add[srd->num_chg]),0,sizeof(ap_rtrans_diff_t *));
	srd->chg_rem = (ap_rtrans_diff_t **)realloc(srd->chg_rem,sizeof(ap_single_rtrans_diff_t *)*(srd->num_chg + 1));
	if (srd->chg_rem == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(&(srd->chg_rem[srd->num_chg]),0,sizeof(ap_rtrans_diff_t *));
	srd->chg_add[srd->num_chg] = add;
	srd->chg_rem[srd->num_chg] = rem;
	srd->num_chg++;
	return 0;
}

static int ap_new_single_rtrans_addrem(ap_single_rtrans_diff_t *srd,ap_rtrans_diff_t *diff,bool_t add,bool_t type) 
{
	if (srd == NULL || diff == NULL)
		return -1;
	if (add && type) {
		srd->add_type = (ap_rtrans_diff_t **)realloc(srd->add_type,sizeof(ap_single_rtrans_diff_t *)*(srd->num_add_type + 1));
		if (srd->add_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(srd->add_type[srd->num_add_type]),0,sizeof(ap_single_rtrans_diff_t *));
		srd->add_type[srd->num_add_type] = diff;
		srd->num_add_type++;
	} else if (add) {
		srd->add = (ap_rtrans_diff_t **)realloc(srd->add,sizeof(ap_single_rtrans_diff_t *)*(srd->num_add + 1));
		if (srd->add == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(srd->add[srd->num_add]),0,sizeof(ap_single_rtrans_diff_t *));
		srd->add[srd->num_add] = diff;
		srd->num_add++;
	} else if (type) {
		srd->rem_type = (ap_rtrans_diff_t **)realloc(srd->rem_type,sizeof(ap_single_rtrans_diff_t *)*(srd->num_rem_type + 1));
		if (srd->rem_type == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(srd->rem_type[srd->num_rem_type]),0,sizeof(ap_single_rtrans_diff_t *));
		srd->rem_type[srd->num_rem_type] = diff;
		srd->num_rem_type++;
	} else {
		srd->rem = (ap_rtrans_diff_t **)realloc(srd->rem,sizeof(ap_single_rtrans_diff_t *)*(srd->num_rem + 1));
		if (srd->rem == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(srd->rem[srd->num_rem]),0,sizeof(ap_single_rtrans_diff_t *));
		srd->rem[srd->num_rem] = diff;
		srd->num_rem++;
	}
		
	return 0;

}

static ap_single_rtrans_diff_t *ap_new_single_rtrans_diff(apol_diff_result_t *diff)
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
			t2 = ap_diff_find_type_in_p2(rd->t_idx, p1, p2, NULL);
			rd_cur = diff2->role_trans;
			while (rd_cur && (rd_cur->rs_idx != r2 || rd_cur->t_idx != t2))
				rd_cur = rd_cur->next;
			if(rd_cur == NULL)
				goto ap_new_single_rtrans_diff_error;
			rt = ap_new_single_rtrans_chg(srd, rd_cur, rd);
			if (rt < 0)
				goto ap_new_single_rtrans_diff_error;
		} else {
			/* lets find out if this is because of a type not
			   being in p2 */
			t2 = ap_diff_find_type_in_p2(rd->t_idx, p1, p2, NULL);
			if (t2 < 0) {
				ap_new_single_rtrans_addrem(srd,rd,FALSE,TRUE);
			} else {
				ap_new_single_rtrans_addrem(srd,rd,FALSE,FALSE);
			}
		}
		rd = rd->next;
	}
	rd = diff2->role_trans;
	while (rd != NULL) {
		if (rd->missing) {
			/* lets find out if this is because of a type not
			   in p1 */
			t2 = ap_diff_find_type_in_p2(rd->t_idx, p1, p2, NULL);
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

/* this function simply copies two single_te_chg_t items */
static void ap_copy_single_te_chg(ap_single_te_chg_t *src,ap_single_te_chg_t *tgt)
{
	tgt->add = src->add;
	tgt->rem = src->rem;
	tgt->add_diff = src->add_diff;
	tgt->rem_diff = src->rem_diff;
}

/* the partition fcn (used in quicksort) that will work on te_chg items 
   this will sort using either source type, target type, or object class depending on
   opt passed in, and direction tells us whether to sort ascending or descending */
static int ap_partition_te_chg(ap_single_te_chg_t *arr,policy_t *policy, int p, int r, int opt,int direction)
{
	char *name = NULL;
	int i,j;
	ap_single_te_chg_t holder;
	
	if (arr == NULL || policy == NULL)
		return -1;
	i = p-1;
	
	if (opt == AP_SRC_TYPE) {
		name = policy->types[arr[r].rem->key.src].name;
		for (j = p; j <= r-1; j++) {
			if ((direction * strcmp(policy->types[arr[j].rem->key.src].name,name)) <= 0) {
				i++;
				ap_copy_single_te_chg(&arr[j],&holder);
				ap_copy_single_te_chg(&arr[i],&arr[j]);
				ap_copy_single_te_chg(&holder,&arr[i]);
			}
		}
	} else if (opt == AP_TGT_TYPE) {
		name = policy->types[arr[r].rem->key.tgt].name;
		for (j = p; j <= r-1; j++) {
			if ((direction * strcmp(policy->types[arr[j].rem->key.tgt].name,name)) <= 0) {
				i++;
				ap_copy_single_te_chg(&arr[j],&holder);
				ap_copy_single_te_chg(&arr[i],&arr[j]);
				ap_copy_single_te_chg(&holder,&arr[i]);
			}
		}
	} else {
		name = policy->obj_classes[arr[r].rem->key.tgt].name;
		for (j = p; j <= r-1; j++) {
			if ((direction * strcmp(policy->obj_classes[arr[j].rem->key.tgt].name,name)) <= 0) {
				i++;
				ap_copy_single_te_chg(&arr[j],&holder);
				ap_copy_single_te_chg(&arr[i],&arr[j]);
				ap_copy_single_te_chg(&holder,&arr[i]);
			}
		}
	}
	holder = arr[r];
	arr[r] = arr[i+1];
	arr[i+1] = holder;
	return i+1;
}

/* the partition fcn (used in quicksort) that will work on te adds and rems  
   this will sort using either source type, target type, or object class depending on
   opt passed in, and direction tells us whether to sort ascending or descending */
static int ap_partition_te_addrem(avh_node_t **arr,policy_t *policy,int p, int r,int opt,int direction)
{
	char *name = NULL;
	int i,j;
	avh_node_t *holder = NULL;

	
	if (arr == NULL || policy == NULL)
		return -1;
	i = p-1;
	if (opt == AP_SRC_TYPE) {
		name = policy->types[(arr)[r]->key.src].name;
		for (j = p; j <= r-1; j++) {
			if ((strcmp(policy->types[(arr)[j]->key.src].name,name)*direction) <= 0) {
				i++;
				holder = (arr)[j];
				(arr)[j] = (arr)[i];
				(arr)[i] = holder;			       
			}
		}
	} else if (opt == AP_TGT_TYPE) {
		name = policy->types[(arr)[r]->key.tgt].name;
		for (j = p; j <= r-1; j++) {
			if ((strcmp(policy->types[(arr)[j]->key.tgt].name,name)*direction) <= 0) {
				i++;
				holder = (arr)[j];
				(arr)[j] = (arr)[i];
				(arr)[i] = holder;
			}
		}
	} else {
		name = policy->obj_classes[(arr)[r]->key.cls].name;
		for (j = p; j <= r -1; j++) {
			if ((strcmp(policy->obj_classes[(arr)[j]->key.cls].name,name)*direction) <= 0) {
				i++;
				holder = (arr)[j];
				(arr)[j] = (arr)[i];
				(arr)[i] = holder;
			}
		}
	}
	holder = (arr)[r];
	(arr)[r] = (arr)[i+1];
	(arr)[i+1] = holder;
	return i+1;
}

/* the qsort function for the added and removed arrays of the single view of a TE diff, opt is used by partition
   to know which column to sort by direction tells whether to sort ascending or descending*/
static void ap_qsort_single_view_te_addrem(avh_node_t **arr, policy_t *policy,int p, int r,int opt,int direction)
{
	int q;

	if (p < r) {
		q = ap_partition_te_addrem(arr,policy,p,r,opt,direction);
		ap_qsort_single_view_te_addrem(arr,policy,p,q-1,opt,direction);
		ap_qsort_single_view_te_addrem(arr,policy,q+1,r,opt,direction);				
	}
}

/* the qsort function for the changed array of the single view of a TE diff, opt is used by partition
   to know which column to sort by direction tells whether to sort ascending or descending*/
static void ap_qsort_single_view_te_chg(ap_single_te_chg_t *arr, policy_t *policy,int p, int r,int opt,int direction)
{
	int q;
	
	if (p < r) {
		q = ap_partition_te_chg(arr,policy,p,r,opt,direction);
		ap_qsort_single_view_te_chg(arr,policy,p,q-1,opt,direction);
		ap_qsort_single_view_te_chg(arr,policy,q+1,r,opt,direction);				
	}
}

/* the function called by the outside world to sort the te rules in a ap_single_view_diff_t
 * sort_col says whether we are sorting the source type, target type, or object class
 * which_arr says whether to sort the added, removed, added type, removed type, or changed arrays,
 * direction says whether to sort ascending or descending */
void ap_single_view_diff_sort_te_rules(ap_single_view_diff_t *svd, int sort_col, int which_arr, int direction) 
{
	if (which_arr & AP_SVD_OPT_ADD) {
		ap_qsort_single_view_te_addrem((svd->te->add),svd->diff->p2,0,svd->te->num_add-1,sort_col,direction);
	}
	if (which_arr & AP_SVD_OPT_ADD_TYPE) {
		ap_qsort_single_view_te_addrem((svd->te->add_type),svd->diff->p2,0,(svd->te->num_add_type)-1,sort_col,direction);
	}
	if (which_arr & AP_SVD_OPT_REM) {
		ap_qsort_single_view_te_addrem((svd->te->rem),svd->diff->p1,0,svd->te->num_rem-1,sort_col,direction);
	}
	if (which_arr & AP_SVD_OPT_REM_TYPE) {
		ap_qsort_single_view_te_addrem((svd->te->rem_type),svd->diff->p1,0,svd->te->num_rem_type-1,sort_col,direction);
	}
	if (which_arr & AP_SVD_OPT_CHG) {
		ap_qsort_single_view_te_chg(svd->te->chg,svd->diff->p1,0,svd->te->num_chg-1,sort_col,direction);
	}
}

/* return the total number of differences in the single view diff */
int ap_single_view_diff_get_num_diffs(ap_single_view_diff_t *svd)
{
	int total = 0;

	if (!svd)
		return -1;

	/* types */
	if (svd->types)
		total += svd->types->num_add + svd->types->num_rem + svd->types->num_chg +
			svd->types->num_chg_add + svd->types->num_chg_rem;
	/* roles */
	if (svd->roles)
		total += svd->roles->num_add + svd->roles->num_rem + svd->roles->num_chg +
			svd->roles->num_chg_add + svd->roles->num_chg_rem;
	/* users */
	if (svd->users)
		total += svd->users->num_add + svd->users->num_rem + svd->users->num_chg +
			svd->users->num_chg_add + svd->users->num_chg_rem;
	/* attributes */
	if (svd->attribs)
		total += svd->attribs->num_add + svd->attribs->num_rem + svd->attribs->num_chg +
			svd->attribs->num_chg_add + svd->attribs->num_chg_rem;
	/* classes */
	if (svd->classes)
		total += svd->classes->num_add + svd->classes->num_rem + svd->classes->num_chg +
			svd->classes->num_chg_add + svd->classes->num_chg_rem;
	/* common perms */
	if (svd->common_perms)
		total += svd->common_perms->num_add + svd->common_perms->num_rem + svd->common_perms->num_chg +
			svd->common_perms->num_chg_add + svd->common_perms->num_chg_rem;
	/* role allows */
	if (svd->rallows)
		total += svd->rallows->num_add + svd->rallows->num_rem + svd->rallows->num_chg +
			svd->rallows->num_chg_add + svd->rallows->num_chg_rem;
	/* bools */
	if (svd->bools)
		total += svd->bools->num_add + svd->bools->num_rem + svd->bools->num_chg;
	/* role trans */
	if (svd->rtrans)
		total += svd->rtrans->num_add + svd->rtrans->num_rem + svd->rtrans->num_chg + 
			svd->rtrans->num_add_type + svd->rtrans->num_rem_type;
	/* perms */
	if (svd->perms)
		total += svd->perms->num_add + svd->perms->num_rem;
	/* te */
	if (svd->te)
		total += svd->te->num_add + svd->te->num_rem + svd->te->num_chg + svd->te->num_add_type +
			svd->te->num_rem_type;
	/* conds */
	if (svd->conds)
		total += svd->conds->num_add + svd->conds->num_rem + svd->conds->num_chg;

#ifdef DEBUG
	/* NOTE: this is not a perfect check, but we need to make sure this function gets updated 
	 * as we provide more difference capabilities in the future */
	if (sizeof(ap_single_view_diff_t) != sizeof(svd->types) + sizeof(svd->roles) + sizeof(svd->users) + sizeof(svd->attribs) + 
	    sizeof(svd->classes) + sizeof(svd->perms) + sizeof(svd->common_perms) + sizeof(svd->rallows) + sizeof(svd->bools) + 
	    sizeof(svd->rtrans) + sizeof(svd->te) + sizeof(svd->conds) + sizeof(svd->diff)) {
		assert(FALSE);
		return -1;
	}
#endif

	return total;
}

/* opts are policy open options (see policy.h).  They indicate to apol_get_pol_diffs()
 * what parts of the policy to differntiate.  Policies p1 and p2 must be opened with
 * at least the same options.  If unsure you can always use POLOPT_ALL (and ensure
 * the policies are opened with POLOPT_ALL).  However this can add significant uneeded
 * time to open and compare parts of the policies you were not interested in, esp
 * with binary policies and when you are not interested in TE rules.
 */
static apol_diff_result_t *apol_diff_policies(unsigned int opts, policy_t *p1, policy_t *p2, ap_diff_rename_t *renamed_types) 
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
	apol_diff_result_destroy(FALSE, t);
	return NULL;
}


ap_single_view_diff_t *ap_single_view_diff_new(unsigned int opts, policy_t *p1, policy_t *p2,ap_diff_rename_t *renamed_types)
{
	ap_single_view_diff_t *svd = NULL;
	int rt;
	apol_diff_result_t *diff;

	if(p1 == NULL || p2 == NULL)
		return NULL;

	/* set up result structure */
	svd = (ap_single_view_diff_t *)malloc(sizeof(ap_single_view_diff_t));
	if(svd == NULL) {
		fprintf(stderr, "out of memory\n");
		goto error;
	}
	memset(svd, 0, sizeof(ap_single_view_diff_t));

	svd->diff = apol_diff_policies(opts, p1, p2, renamed_types);
	if (svd->diff == NULL) {
		fprintf(stderr, "out of memory\n");
		goto error;
	}
	diff = svd->diff;
	if (opts & POLOPT_TYPES) {
		svd->types = ap_single_iad_diff_new(diff, IDX_TYPE);
		if (svd->types == NULL)
			goto error;
		svd->attribs = ap_single_iad_diff_new(diff, IDX_ATTRIB); 
		if (svd->attribs == NULL)
			goto error;
	}
	if (opts & POLOPT_ROLES) {
		svd->roles = ap_single_iad_diff_new(diff, IDX_ROLE);
		if (svd->roles == NULL)
			goto error;
	}
	if (opts & POLOPT_USERS) {
		svd->users = ap_single_iad_diff_new(diff, IDX_USER);
		if (svd->users == NULL)
			goto error;
	}
	if (opts & POLOPT_CLASSES) {
		svd->classes = ap_single_iad_diff_new(diff, IDX_OBJ_CLASS);
		if (svd->classes == NULL)
			goto error;
		svd->perms = ap_single_perm_diff_new(diff);
		if (svd->perms == NULL)
			goto error;
		svd->common_perms = ap_single_iad_diff_new(diff, IDX_COMMON_PERM);
		if (svd->common_perms == NULL)
			goto error;
	}
	if (opts & POLOPT_COND_BOOLS) {
		svd->bools = ap_single_bool_diff_new(diff);
		if (svd->bools == NULL)
			goto error;
	}
	if (opts & POLOPT_ROLE_RULES) {
		svd->rallows = ap_single_iad_diff_new(diff, IDX_ROLE|IDX_PERM);
		if (svd->rallows == NULL)
			goto error;
		svd->rtrans = ap_new_single_rtrans_diff(diff);
		if (svd->rtrans == NULL)
			goto error;
	}
	if (opts & POLOPT_AV_RULES) {
		rt = ap_new_single_te_diff(svd, diff, renamed_types); 
		if (rt < 0 || svd->te == NULL || svd->conds == NULL)
			goto error;
	}
	if (opts & POLOPT_COND_POLICY) {
		rt = ap_find_empty_single_cond_diff(svd->conds, diff);
		if (rt < 0)
			goto error;
	}
	return svd;
error:
	if (svd)
		ap_single_view_diff_destroy(svd);
	
	return NULL;
}


#endif
