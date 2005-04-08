/* Copyright (C) 2001-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
 *	
 * Modified by: don.patterson@tresys.com
 *		6-24-2003: Added functions for getting users|roles for a given type. 
 */

/* policy.c
 *
 * Our policy database (see policy.h) is completly different
 * than that used by checkpolicy/SS; we're trying to analyze from
 * policy.conf "up" to higher abstractions.
 *
 * Some of the functions to build a policy object is contained in
 * apolicy_parse.y
 */

#include "policy.h"
#include "policy-avl.h"
#include "avl-util.h"
#include "perm-map.h"
#include "util.h"
#include "cond.h"
#include <asm/types.h>

#include <stdlib.h>
#include <assert.h>

/* The following is a private global array of constant strings. */
const char *policy_version_strings[] = { "Unkown version", 
			 	 	 "prior to v. 11", 
			 	 	 "v.11 -- v.12", 
			 	 	 "v.15", "v.16", 
					 "v.17", "v.18",
					 "v.18 -- v.19",
					 "v.19", "v.19mls"};
			 	 
/* get a policy version string from the global array of constant strings. 
 * We use the defined policy version numbers as indices into this array.*/
const char* get_policy_version_name(int policy_version)
{
	if (!is_valid_policy_version(policy_version)) 
		return policy_version_strings[POL_VER_UNKNOWN];
	else 
		return policy_version_strings[policy_version];
}
		 	 
/**************/
/* these are INTERNAL functions only; allow direct access to type/attrib name string
 * stored within the policy db.  These functions shouldn't be exported as a caller
 * could corrupt the db.  It is used internally within the policy db file for
 * efficient access to strings when doing regex compares.
 *
 * THE CALLER SHOULD NOT FREE OR OTHERWISE MODIFY THE RETURNED STRING!!!!
 */
int _get_attrib_name_ptr(int idx, char **name, policy_t *policy)
{
	if(!is_valid_attrib_idx(idx, policy))
		return -1;
	*name = policy->attribs[idx].name;
	return 0;
}
int _get_type_name_ptr(int idx, char **name, policy_t *policy)
{
	if(!is_valid_type_idx(idx, policy))
		return -1;
	*name = policy->types[idx].name;
	return 0;
}
int _get_role_name_ptr(int idx, char **name, policy_t *policy)
{
	if(!is_valid_role_idx(idx, policy))
		return -1;
	*name = policy->roles[idx].name;
	return 0;
}
int _get_user_name_ptr(int idx, char **name, policy_t *policy)
{
	if(!is_valid_user_idx(idx, policy))
		return -1;
	*name = policy->users[idx].name;
	return 0;
}
/**************/


int init_policy(policy_t **p)
{
	char *key;
	int idx;
	
	policy_t *policy;
	assert(*p == NULL);
	policy = (policy_t *)malloc(sizeof(policy_t));
	if(policy == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->version = POL_VER_UNKNOWN;
	policy->opts = POLOPT_NONE;
	policy->policy_type = POL_TYPE_SOURCE;

	/* permissions */
	policy->perms = (char **)malloc(sizeof(char*) * LIST_SZ);
	if(policy->perms == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_PERMS] = LIST_SZ;
	policy->num_perms = 0;
	/* common perms */
	policy->common_perms = (common_perm_t *)malloc(sizeof(common_perm_t) * LIST_SZ);
	if(policy->common_perms == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	policy->list_sz[POL_LIST_COMMON_PERMS] = LIST_SZ;
	policy->num_common_perms = 0;
	
	/* object classes */
	policy->obj_classes = (obj_class_t *)malloc(sizeof(obj_class_t) * LIST_SZ);
	if(policy->obj_classes == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	policy->list_sz[POL_LIST_OBJ_CLASSES] = LIST_SZ;
	policy->num_obj_classes = 0;
	
	/* initial SIDs */
	policy->initial_sids = (initial_sid_t *)malloc(sizeof(initial_sid_t) * LIST_SZ);
	if(policy->initial_sids == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_INITIAL_SIDS] = LIST_SZ;
	policy->num_initial_sids = 0;
	
	/* types list */
	policy->types = (type_item_t *)malloc(sizeof(type_item_t) * LIST_SZ);
	if(policy->types == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_TYPE] = LIST_SZ;
	policy->num_types = 0;
	
	/* type aliases */
	policy->aliases = (alias_item_t *)malloc(sizeof(alias_item_t) * LIST_SZ);
	if(policy->aliases == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ALIAS] = LIST_SZ;
	policy->num_aliases = 0;
	
	/* type attributes list */
	policy->attribs = (name_a_t *)malloc(sizeof(name_a_t) * LIST_SZ);
	if(policy->attribs == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ATTRIB] = LIST_SZ;
	policy->num_attribs = 0;
	
	/* conditional booleans */
	policy->cond_bools = (cond_bool_t *)malloc(sizeof(cond_bool_t) * LIST_SZ);
	if(policy->cond_bools == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_COND_BOOLS] = LIST_SZ;	
	policy->num_cond_bools = 0;
	
	/* conditional expressions */
	policy->cond_exprs = (cond_expr_item_t *)malloc(sizeof(cond_expr_item_t) * LIST_SZ);
	if(policy->cond_exprs == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_COND_EXPRS] = LIST_SZ;	
	policy->num_cond_exprs = 0;	
	
	/* av_access rules */
	policy->av_access = (av_item_t *)malloc(sizeof(av_item_t) * LIST_SZ);
	if(policy->av_access == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_AV_ACC] = LIST_SZ;
	policy->num_av_access = 0;

	/* av_audit rules */
	policy->av_audit = (av_item_t *)malloc(sizeof(av_item_t) * LIST_SZ);
	if(policy->av_audit == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_AV_AU] = LIST_SZ;
	policy->num_av_audit = 0;

	/* type transition, etc. rules */
	policy->te_trans = (tt_item_t *)malloc(sizeof(tt_item_t) * LIST_SZ);
	if(policy->te_trans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_TE_TRANS] = LIST_SZ;
	policy->num_te_trans = 0;

	/* clone rules */
	policy->clones = NULL;

	/* role definitions */
	policy->roles = (name_a_t *)malloc(sizeof(name_a_t) * LIST_SZ);
	if(policy->roles == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLES] = LIST_SZ;
	policy->num_roles = 0;
	
	/* role allow rules */
	policy->role_allow = (role_allow_t *)malloc(sizeof(role_allow_t) * LIST_SZ);
	if(policy->role_allow == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLE_ALLOW] = LIST_SZ;
	policy->num_role_allow = 0;
	
	/* role transition rules */
	policy->role_trans = (rt_item_t *)malloc(sizeof(rt_item_t) * LIST_SZ);
	if(policy->role_trans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLE_TRANS] = LIST_SZ;
	policy->num_role_trans = 0;	
	
	/* users */
	policy->users = (name_a_t *)malloc(sizeof(name_a_t) * LIST_SZ);
	if(policy->users == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_USERS] = LIST_SZ;
	policy->num_users = 0;	
	
	
	/* rule stats */
	memset(policy->rule_cnt, 0, sizeof(int) * RULE_MAX);
	
	/* permission maps */
	policy->pmap = NULL;

        (void) memset (&(policy->avh), 0, sizeof (avh_t));
        
	if(init_avl_trees(policy) != 0) {
		return -1;
	}
	
	(void) memset (&(policy->avh), 0, sizeof (avh_t));

	/* make certain that the self type is present - some code assumes the presence
	 * of this 'special' type, so it must always be added */
	key = (char *)malloc(5);
	if(key == NULL) {
		fprintf(stderr, "Memory error\n");
		return -1;
	}
	strcpy(key, "self");
	idx = add_type(key, policy);
	if (idx < 0) {
		fprintf(stderr, "Error adding self type\n");
		return -1;
	}
	
	policy->avh.tab = NULL;
	policy->avh.num = 0;

	*p = policy;
	return 0;
}

/* set policy version, and display a warning message first time set 
 * -1 error
 */
int set_policy_version(int ver, policy_t *policy)
{
	if(policy == NULL || ver <= 0 || ver > POL_VER_MAX)
		return -1;
	
	if(policy->version >= ver)
		return 0; /* already set the same or higher version */
	policy->version = ver;
	return 0;
}

int pol_ver[] = {0,10,12,15,16,17,18,19,19,19};
int get_policy_version_num(policy_t *policy)
{
	if(policy == NULL || !is_valid_policy_version(policy->version))
		return -1;
	return pol_ver[policy->version]; 
}


static int free_name_list(name_item_t *list)
{
	name_item_t *ptr, *old;
	for(ptr = list; ptr != NULL; ){
		if(ptr->name != NULL)
			free(ptr->name);
		old = ptr;
		ptr = ptr->next;
		free(old);
	}
	return 0;
}

int free_ta_list(ta_item_t *list)
{
	ta_item_t *ptr, *ptr2;
	for(ptr = list; ptr != NULL; ptr = ptr2) {
		ptr2 = ptr->next;
		free(ptr);
	}
	return 0;
}


static int free_av_list(av_item_t *list, int num)
{
	int i;
	if(list == NULL)
		return 0;
	for(i = 0; i < num; i++) {
		free_ta_list(list[i].src_types);
		free_ta_list(list[i].tgt_types);
		free_ta_list(list[i].classes);
		free_ta_list(list[i].perms);
	}
	return 0;
}


/* frees attrib_item_t and those aliases to it */
static int free_name_a(name_a_t *ptr, int num)
{
	int i;
	if(ptr == NULL) 
		return 0;
			
	for(i = 0; i < num; i++) {
		if(ptr[i].name != NULL)
			free(ptr[i].name);
		if(ptr[i].a != NULL)
			free(ptr[i].a);
	}
	free(ptr);
	return 0;
}


int free_policy(policy_t **p)
{
	int i;
	policy_t *policy;
	if(p == NULL || *p == NULL)
		return 0;
		
	policy = *p;
		
	/* permissions */
	if(policy->perms != NULL) {
		for(i = 0; i < policy->num_perms; i++) {
			free(policy->perms[i]);
		}
		free(policy->perms);
	}
	
	/* common perms */
	if(policy->common_perms != NULL) {
		for(i = 0; i < policy->num_common_perms; i++) {
			free(policy->common_perms[i].name);
			if(policy->common_perms[i].perms != NULL)
				free(policy->common_perms[i].perms);
		}
		free(policy->common_perms);
	}

	/* object classes */
	if(policy->obj_classes != NULL) {
		for(i = 0; i < policy->num_obj_classes; i++) {
			free(policy->obj_classes[i].u_perms);
			free(policy->obj_classes[i].name);
		}
		free(policy->obj_classes);
	}

	/* initial SIDs list */
	if(policy->initial_sids != NULL) {
		for(i = 0; i < policy->num_initial_sids; i++) {
			if(policy->initial_sids[i].name != NULL) {
				free(policy->initial_sids[i].name);
				free(policy->initial_sids[i].scontext);
			}
		}
		free(policy->initial_sids);
	}


	/* types list */
	if(policy->types != NULL) {
		for(i = 0; i < policy->num_types; i++) {
			if(policy->types[i].name != NULL)
				free(policy->types[i].name);
			free_name_list(policy->types[i].aliases);
			if(policy->types[i].num_attribs)
				free(policy->types[i].attribs);
		}
		free(policy->types);
	}

	/* type aliases list */
	/* NOTE: while we still have the name list for attributes associated with 
	 * the types, the alias names in the alias list will be freed above in the
	 * types area and we do not need to free them again */
	if(policy->aliases != NULL) {
		free(policy->aliases);
	} 
	

	/* type attributes list */
	free_name_a(policy->attribs, policy->num_attribs);
	
	/* conditional bools list */
	if(policy->cond_bools != NULL) {
		for(i = 0; i < policy->num_cond_bools; i++) {
			cond_free_bool(&policy->cond_bools[i]);
		}
		free(policy->cond_bools);
	}
	
	/* conditional expression list */
	if(policy->cond_exprs != NULL) {
		for(i = 0; i < policy->num_cond_exprs; i++) {
			cond_free_expr_item(&policy->cond_exprs[i]);
		}
		free(policy->cond_exprs);
	}
	
	/* av_access rules */
	if(policy->av_access != NULL) {
		free_av_list(policy->av_access, policy->num_av_access);
		free(policy->av_access);
	}

	/* av_audit rules */
	if(policy->av_audit != NULL) {
		free_av_list(policy->av_audit, policy->num_av_audit);
		free(policy->av_audit);
	}

	/* type transition, etc. rules */
	if(policy->te_trans != NULL) {
		for(i = 0; i < policy->num_te_trans; i++) {
			free_ta_list(policy->te_trans[i].src_types);
			free_ta_list(policy->te_trans[i].tgt_types);
			free_ta_list(policy->te_trans[i].classes);
		}
		free(policy->te_trans);
	}

	/* clone rules */
	{
		cln_item_t *ptr, *ptr2;
		for(ptr = policy->clones; ptr != NULL; ptr = ptr2) {
			ptr2 = ptr->next;
			free(ptr);
		}
	}

	/* role lists */
	free_name_a(policy->roles, policy->num_roles);
	
	/* role allow rules */
	if(policy->role_allow != NULL) {
		for(i = 0; i < policy->num_role_allow; i++) {
			free_ta_list(policy->role_allow[i].src_roles);
			free_ta_list(policy->role_allow[i].tgt_roles);	
		}
		free(policy->role_allow);
	}	
	
	/* role trans rules */
	if(policy->role_trans != NULL) {
		for(i = 0; i < policy->num_role_trans; i++) {
			free_ta_list(policy->role_trans[i].src_roles);
			free_ta_list(policy->role_trans[i].tgt_types);
		}
		free(policy->role_trans);
	}	
	
	/* users */
	free_name_a(policy->users, policy->num_users);
	
	/* perm map */
	if(policy->pmap != NULL) {
		free_perm_mapping(policy->pmap);
	} 

	if(free_avl_trees(policy) != 0)
		return -1;

	free(policy);
	*p = NULL;
	return 0;
}

/***********************************************************
 * General support functions for name_a_t (used by at least
 * roles, users, and attributes
 ***********************************************************/
/*
 * Returns idxs (a) in name_a struct (caller must free) and # idxs
 */
static int na_get_idxs(int nidx, name_a_t *na, int a_sz, int *num, int **idxs)
{
	int i, rt;

	if (na== NULL || num == NULL || idxs == NULL)
		return -1;
	if (nidx >= a_sz)
		return -1;
	*num = 0;
	*idxs = NULL;

	for (i = 0; i < na[nidx].num; i++) {
		rt = add_i_to_a(na[nidx].a[i], num, idxs);	
		if (rt != 0)
			goto bad;
	}
	return 0;
bad:
	if (*idxs != NULL)
		free(*idxs);
	return -1;
}

/* allocates space for name, release memory with free() */
static int na_get_name(int nidx, name_a_t *na, int a_sz, char **name)
{
	if(name == NULL || na == NULL)
		return -1;
	if (nidx >= a_sz)
		return -1;
		
	if((*name = (char *)malloc(strlen(na[nidx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, na[nidx].name);
	return 0;
}

static bool_t na_is_idx_in_a(int idx, name_a_t *na)
{
	int i;
	if(na == NULL)
		return FALSE;
	
	for(i = 0; i < na->num; i++) {
		if(na->a[i] == idx)
			return TRUE;
	}
	return FALSE;
} 

/* checks for idx already in a, and if so doesn't add it again */
static int na_add_idx(int idx, name_a_t *na)
{
	if(na == NULL)
		return -1;
	if(na_is_idx_in_a(idx, na))
		return 0; /* already in list */
	return(add_i_to_a(idx, &na->num, &na->a));
}

/* END name_a_t support */
/***********************************************************/

/* Initial SIDs */
int add_initial_sid(char *name, policy_t *policy)
{
	int rt, idx;

	if(name == NULL || policy == NULL)
		return -1;
	rt= avl_insert(&policy->tree[AVL_INITIAL_SIDS], name, &idx);
	if(rt < 0)	/* error or already exists */
		return rt;
	return idx;
}

/* same as above but also stores the sid # */
int add_initial_sid2(char *name, __u32 sid, policy_t *policy) 
{
	int idx;
	
	idx = add_initial_sid(name, policy);
	if(idx < 0)
		return idx;
	
	assert(idx < num_initial_sids(policy));
	policy->initial_sids[idx].sid = sid;
	return idx;
}

int add_initial_sid_context(int idx, security_con_t *scontext, policy_t *policy)
{
	if(!is_valid_initial_sid_idx(idx, policy))
		return -1;
	policy->initial_sids[idx].scontext = scontext;
	return 0;
}


int get_initial_sid_idx(const char *name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;

	/* traverse the avl tree */
	return avl_get_idx(name, &policy->tree[AVL_INITIAL_SIDS]);
}

/* allocates space for name, release memory with free() */
int get_initial_sid_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_initial_sid_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->initial_sids[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->initial_sids[idx].name);
	return 0;
}

/* selected SID idxs returned in results (NULL means no matches)...caller must free
 * For user, type, and role, use NULL to not use that criteria.  A match means that
 * ALL criteria is satisfied. */
int search_initial_sids_context(int **isids, int *num_isids, const char *user, const char *role, const char *type, policy_t *policy)
{
	/* initialize ridx and tidx so to avoid compile warnings when compiled with optimized flag */
	int uidx = -1, ridx = -1, tidx = -1, i;
	
	if(policy == NULL || isids == NULL || num_isids == NULL) {
		return -1;
	}
	
	/* For role and type idx, we use < 0 as an indicator that we don't care about these criteria.
	 * So we can simply take the error return from the idx lookup functions.  For uidx, NULL
	 * is used to indicate we don't care. */
	 
	/* NOTE: since a match must meet ALL criteria, if we fail to look up any of the criteria
	 * in the policy (because they id does not exists), we will return immediately with a 
	 * empty list of isids */
	*num_isids = 0;
	*isids = NULL;
		
	if(role != NULL) {
		ridx = get_role_idx(role, policy);
		if(ridx < 0) {
			return 0;
		}
	} 
	
	if(type != NULL) {
		tidx = get_type_idx(type, policy);
		if(tidx < 0) {
			return 0;
		}
	} 
	
	if(user != NULL) {
		uidx = get_user_idx(user, policy);
		if(uidx < 0) {
			return 0;
		}
	} 

	for(i = 0; i < policy->num_initial_sids; i++) {
		if (type != NULL) {
			 /* Make sure this sid has a context and if so, compare the type field */
			 if (!(policy->initial_sids[i].scontext != NULL && tidx == policy->initial_sids[i].scontext->type)) {
			 	continue;
			 }
		}
		if (role != NULL) {
			 /* Make sure this sid has a context and if so, compare the role field */
			 if (!(policy->initial_sids[i].scontext != NULL && ridx == policy->initial_sids[i].scontext->role)) {
			 	continue;	
			 }
		}
		if (user != NULL) {
			 /* Make sure this sid has a context and if so, compare the user field */
			 if (!(policy->initial_sids[i].scontext != NULL && uidx == policy->initial_sids[i].scontext->user)) {
			 	continue;	
			 }
		}
		/* If we get here, we have either matched ALL criteria or all parameters given are empty. */
		if(add_i_to_a(i, num_isids, isids) < 0) {
			free(isids);
			return -1;
		}
	}
	return 0;
}


/*
 * Check that type is valid for this policy. If self_allowed is FALSE
 * then self type will return FALSE.
 */
bool_t is_valid_type(policy_t *policy, int type, bool_t self_allowed)
{
	assert(policy);

	if (!self_allowed && type == 0)
		return FALSE;
	if (type < 0 || type >= policy->num_types)
		return FALSE;
	return TRUE;
}

/*
 * Check that obj_class is valid for this policy.
 */
bool_t is_valid_obj_class(policy_t *policy, int obj_class)
{
	assert(policy);

	if (obj_class < 0 || obj_class >= policy->num_obj_classes)
		return FALSE;
	return TRUE;
}

/* check if TYPE ALIAS array has room for new entry, grow if necessary */
int check_alias_array(policy_t *policy)
{
	assert(policy != NULL);
	if (policy->num_aliases >= policy->list_sz[POL_LIST_ALIAS]) {
		/* grow the dynamic array */
		alias_item_t * ptr;
		ptr = (alias_item_t *)realloc(policy->aliases, (LIST_SZ+policy->list_sz[POL_LIST_ALIAS]) * sizeof(alias_item_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->aliases = ptr;
		policy->list_sz[POL_LIST_ALIAS] += LIST_SZ;
	}
	return 0;
}

/* check the alias array to see if name matches and if so return the associated
 * type idx */
int get_type_idx_by_alias_name(const char *alias, policy_t *policy)
{
	int i;
	if(alias == NULL || policy == NULL)
		return -1;
	for(i = 0; i < policy->num_aliases; i++) {
		if(strcmp(alias, policy->aliases[i].name) == 0) 
			return policy->aliases[i].type;
	} 
	return -1;
}

/* returns an array of type idencies that match the provided regex (preg).  
 * types is the returned array and num the # of elements in the array (types==NULL
 * if num <= 0).
 */
int get_type_idxs_by_regex(int **types, int *num, regex_t *preg, bool_t include_self, policy_t *policy)
{
	int i, j;
	char *name;
	bool_t *bools; /* use this to track which types match */
	if(types == NULL || num == NULL || preg == NULL || policy == NULL)
		return -1;
	
	/* initialize the bool array to false */
	bools = (bool_t *)malloc(sizeof(bool_t) * policy->num_types);
	if(bools == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	memset(bools, 0, sizeof(bool_t) * policy->num_types);
	
	*num = 0;
	if (include_self)
		i = 0;
	else
		i = 1;
	for(; i < policy->num_types; i++) {
		/* DO NOT FREE name*/
		_get_type_name_ptr(i, &name, policy);
		if(regexec(preg, name, 0, NULL, 0) == 0) {
			bools[i] = TRUE;
			(*num)++;
		}
	}
	if(*num == 0) {
		*types = NULL;
		return 0;
	} 
	/* at this point we found some matches */
	*types = (int *)malloc(sizeof(int) * *num);
	if(*types == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	for(i = 0, j = 0; i < policy->num_types; i++) {
		if(bools[i]) {
			(*types)[j++] = i;
		} 
		assert(j <= *num);	
	}
	assert(j == *num);
	return 0;
}

int get_type_idx(const char *name, policy_t *policy)
{
	int rt, rt2;

	if(name == NULL || policy == NULL)
		return -1;

	/* traverse the avl tree */
	rt = avl_get_idx(name, &policy->tree[AVL_TYPES]);
	if(rt <0) {
		/* check aliases for a match */
		rt2 = get_type_idx_by_alias_name(name, policy);
		if(rt2 >=0 )
			return rt2;
	}
	return rt;		
}


/* allocates space for name, release memory with free() */
int get_type_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_type_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->types[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->types[idx].name);
	return 0;
}

/*
 * get the attribs for a type.
 * Returns attribs idxs in attribs (caller must free) and # of attribs in num_attribs
 */
int get_type_attribs(int type, int *num_attribs, int **attribs, policy_t *policy)
{
	int i, rt;

	if (policy == NULL || attribs == NULL)
		return -1;
	if (type >= policy->num_types)
		return -1;
	if (num_attribs == NULL)
		return -1;
	else
		*num_attribs = 0;
	*attribs = NULL;

	for (i = 0; i < policy->types[type].num_attribs; i++) {
		rt = add_i_to_a(policy->types[type].attribs[i], num_attribs, attribs);	
		if (rt != 0)
			goto bad;
	}

	return 0;
bad:
	if (*attribs != NULL)
		free(*attribs);
	return -1;
}

/*
 * get the users for a type.
 * Returns user idxs in users and # of users found
 * NOTE: Caller must free users!!
 */
int get_type_users(int type, int *num_users, int **users, policy_t *policy)
{
	int i, j, rt;
	int *roles = NULL, num_roles = 0;
	
	if (policy == NULL || users == NULL || num_users == NULL)
		return -1;
	if (!is_valid_type_idx(type, policy))
		return -1;
	
	*num_users = 0;
	*users = NULL;
	
	/* Get types roles */
	rt = get_type_roles(type, &num_roles, &roles, policy);
	if (rt != 0) {
		fprintf(stderr, "Unexpected error getting roles for type.\n");
		return -1;
	}
	
	for (i = 0; i < policy->num_users; i++) {
		for (j = 0; j < num_roles; j++) {
			if (does_user_have_role(i, roles[j], policy) &&
			    find_int_in_array(i, *users, *num_users) < 0) {
				rt = add_i_to_a(i, num_users, users);	
				if (rt != 0) {
					if (roles) free(roles);
					return -1;
				}
			}
		}
	}
	if (roles) free(roles);
	
	return 0;
}

/*
 * get the roles for a type.
 * Returns role idxs in roles and # of roles found
 * NOTE: Caller must free roles!!
 */
int get_type_roles(int type, int *num_roles, int **roles, policy_t *policy)
{
	int i, rt;
	
	if (policy == NULL || roles == NULL || num_roles == NULL)
		return -1;
	if (!is_valid_type_idx(type, policy))
		return -1;
	
	*num_roles = 0;
	*roles = NULL;

	for (i = 0; i < policy->num_roles; i++) {
		if (find_int_in_array(type, policy->roles[i].a, policy->roles[i].num) >= 0) {
			rt = add_i_to_a(i, num_roles, roles);	
			if (rt != 0) {
				return -1;
			}
		}
	}

	return 0;
}

/*
 * get the types for a attrib.
 * Returns type idxs in types (caller must free) and # of types in num_types
 */
int get_attrib_types(int attrib, int *num_types, int **types, policy_t *policy)
{
	if (policy == NULL )
		return -1;
	
	return (na_get_idxs(attrib, policy->attribs, policy->num_attribs, num_types, types));
}

/* allocates space for name, release memory with free() */
int get_attrib_name(int idx, char **name, policy_t *policy)
{
	return na_get_name(idx, policy->attribs, policy->num_attribs, name);
}

int get_attrib_idx(const char *name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;

	/* traverse the avl tree */
	return avl_get_idx(name, &policy->tree[AVL_ATTRIBS]);	
}

int get_type_or_attrib_idx(const char *name, int *idx_type, policy_t *policy) {
	int idx;
	if(name == NULL || policy == NULL)
		return -1;
	idx = get_type_idx(name, policy);
	if(idx < 0) {
		idx = get_attrib_idx(name, policy);
		if(idx < 0)
			return -1;
		else
			*idx_type = IDX_ATTRIB;
	}
	else
		*idx_type = IDX_TYPE;

	return idx;
}

bool_t is_attrib_in_type(const char *attrib, int type_idx, policy_t *policy) {
	
	int i;
	char *name;
	if(attrib == NULL || !is_valid_type_idx(type_idx, policy)) 
		return FALSE;
		
	for(i = 0; i < policy->types[type_idx].num_attribs; i++) {
		/* NEVER free name!!!; _get_attrib_name_ptr() in an internal fn returning actual pointer */
		_get_attrib_name_ptr(policy->types[type_idx].attribs[i], &name, policy);
		if(strcmp(attrib, name) == 0)
			return TRUE;
	}
	return FALSE;
}

typedef int (*_get_name_ptr_t)(int idx, char **name, policy_t *policy);
static bool_t is_name_in_namea(const char *name, int idx_type, int idx, policy_t *policy) {
	int i, rt;
	name_a_t *list;
	_get_name_ptr_t _get_name;
	char *n;
	
	switch(idx_type) {
	case IDX_ATTRIB:
		if(!is_valid_attrib_idx(idx, policy))
			return FALSE;
		list = policy->attribs;
		_get_name = &_get_type_name_ptr;
		break;
	case IDX_ROLE:
		if(!is_valid_role_idx(idx, policy))
			return FALSE;
		list = policy->roles;
		_get_name = &_get_type_name_ptr;
		break;
	case IDX_USER:
		if(!is_valid_user_idx(idx, policy))
			return FALSE;
		list = policy->users;
		_get_name = &_get_role_name_ptr;
		break;
	default:
		return FALSE;
	}
		
	for(i = 0; i < list[idx].num; i++) {
		/* DO NOT free() n; it's an internal ptr */
		rt = _get_name(list[idx].a[i], &n, policy);
		if(rt < 0) {
			assert(FALSE); /* shouldn't get this error */
			return FALSE;
		}
		if(strcmp(n, name) == 0)
			return TRUE;
	}
	return FALSE;
}

bool_t is_type_in_attrib(const char *type, int attrib_idx, policy_t *policy) {
	return(is_name_in_namea(type, IDX_ATTRIB, attrib_idx, policy));
}

bool_t is_type_in_role(const char *type, int role_idx, policy_t *policy) {
	return(is_name_in_namea(type, IDX_ROLE, role_idx, policy));
}

bool_t is_role_in_user(const char *role, int user_idx, policy_t *policy) {
	return(is_name_in_namea(role, IDX_USER, user_idx, policy));
}

int get_role_idx(const char *name, policy_t *policy) 
{
	int i;
	if(name == NULL || policy == NULL)
		return -1;
	for(i = 0; i < policy->num_roles; i++) {
		if(strcmp(policy->roles[i].name, name) == 0)
			return i;
	}
	return -1;
}



/* allocates space for name, release memory with free() */
int get_role_name(int idx, char **name, policy_t *policy)
{
	return na_get_name(idx, policy->roles, policy->num_roles, name);
}

int get_role_types(int role, int *num_types, int **types, policy_t *policy)
{
	int i, rt;

	if (policy == NULL || types == NULL)
		return -1;
	if (role < 0 || role >= policy->num_roles) 
		return -1;
	if (num_types == NULL)
		return -1;
	else
		*num_types = 0;
	*types = NULL;

	for (i = 0; i < policy->roles[role].num; i++) {
		rt = add_i_to_a(policy->roles[role].a[i], num_types, types);	
		if (rt != 0)
			goto bad;
	}
	return 0;
bad:
	if (*types != NULL)
		free(*types);
	return -1;
}

int get_user_roles(int user, int *num_roles, int **roles, policy_t *policy)
{
	int i, rt;

	if (policy == NULL || roles == NULL || num_roles == NULL)
		return -1;
	if (!is_valid_user_idx(user, policy)) 
		return -1;
	*num_roles = 0;
	*roles = NULL;

	for (i = 0; i < policy->users[user].num; i++) {
		rt = add_i_to_a(policy->users[user].a[i], num_roles, roles);	
		if (rt != 0)
			goto bad;
	}
	return 0;
bad:
	if (*roles != NULL)
		free(*roles);
	return -1;
}
/* allocates space for name, release memory with free() */
int get_user_name2(int idx, char **name, policy_t *policy)
{
	return na_get_name(idx, policy->users, policy->num_users, name);
}


/* check if user exists, and if so return its index */
int get_user_idx(const char *name, policy_t *policy)
{
	int i;
	if(name == NULL || policy == NULL)
		return -1;
	for(i = 0; i < policy->num_users; i++) {
		if(strcmp(policy->users[i].name, name) == 0)
			return i;
	}
	return -1;
}

/* check if user exists */
bool_t does_user_exists(const char *name, policy_t *policy)
{
	int idx;
	
	idx = get_user_idx(name, policy);
	if(idx >= 0)
		return TRUE;
	else
		return FALSE;
}

bool_t does_user_have_role(int user, int role, policy_t *policy)
{
	if(policy == NULL || !is_valid_user_idx(user, policy))
		return FALSE;
	return na_is_idx_in_a(role, &policy->users[user]);
}


static int add_type_to_attrib(int type_idx, name_a_t *attrib)
{
	/* do not multiply add types to attributes */
	if (find_int_in_array(type_idx, attrib->a, attrib->num) == -1) {
		if (add_i_to_a(type_idx, &(attrib->num), &(attrib->a)))
			return -1;
	}
	return 0;
}



int add_type_to_role(int type_idx, int role_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_role_idx(role_idx, policy))
		return -1;

	return(na_add_idx(type_idx, &policy->roles[role_idx]));
}


/* changed for Jul 2002 policy to allow adding attributes separately, and
 * not only as part of the type declaration.  If !with_type, then
 * type_idx is ignored.
 */
int add_attrib(bool_t with_type, int type_idx, policy_t *policy, char *attrib)
{
	int i, rt;
	
	if(attrib == NULL || policy == NULL)
		return -1;

	rt = avl_insert(&policy->tree[AVL_ATTRIBS], attrib, &i);
	/* if rt == -2, means already exit since we might need to add types below; but
	 * we also don't update the tree head */
	if(rt < 0 && rt != -2)
		return rt; /* error */

	if(with_type) {
		if (add_type_to_attrib(type_idx, &(policy->attribs[i])) == -1) {
			return -1;
		}
	}
		
	return i;
}


int add_alias(int type_idx, char *alias, policy_t *policy)
{
	char *aname;
	int idx;
	if(!is_valid_type_idx(type_idx, policy) || alias == NULL || policy == NULL)
		return -1;

	/* TODO: we have a problem with the way we handle aliases once AVL trees were added.
	 *	since the AVL trees are sorted by type name, the alias search doesn't work
	 *	(since an aliases is checked only if the type name doesn't match, but since we have
	 * 	an efficient type name tree, not all types (and therefore aliases) are searched).
	 *	What we've done for now is maintain a separate alias array while still maintaining
	 *	the old alias name list attached to each type.  The alias array will allow us to search
	 *	for a type using its alias name if it wasn't found via the AVL search using prime
	 *	type names.  Eventually we need to remove the name list and use references to the
	 *	alias array.
	 *
	 *	This is currently fragile as we don't check for syntax problems arising from the using
	 * 	the same alias twice (checkpolicy would not allow this).
	 */
	 
	/* We don't use caller's memory...allows for better error handling */
	aname = (char *)malloc(strlen(alias) +1);
	if(aname == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(aname, alias);
	
	/* first the simple name list */
	if(add_name(aname, &(policy->types[type_idx].aliases)) != 0) {
		free(aname);
		return -1;			
	}
	
	/* and now the alias array
	 * add_name also uses the memory for the name
	 */
	if(check_alias_array(policy) != 0) 
		return -1;
	idx = policy->num_aliases;
	policy->aliases[idx].name = aname;
	policy->aliases[idx].type = type_idx;
	(policy->num_aliases)++;

	return 0;
}

/* add a new type into db; we use the memory
 * of the parameter so the caller should not expect to use it after calling
 * this funciton.
 */
int add_type(char *type, policy_t *policy)
{
	int rt, idx;

	if(type == NULL || policy == NULL)
		return -1;

	rt= avl_insert(&policy->tree[AVL_TYPES], type, &idx);
	if(rt < 0)	/* error or already exists */
		return rt;
	return idx;
}

int add_attrib_to_type(int type_idx, char *token, policy_t *policy)
{
	int idx;

	if(policy == NULL || token == NULL || !is_valid_type_idx(type_idx, policy)) 
		return -1;

	idx = add_attrib(TRUE, type_idx, policy, token);
	if(idx < 0)
		return -1;
	
	/* do not multiply add attributes to types */
	if (find_int_in_array(idx, policy->types[type_idx].attribs, policy->types[type_idx].num_attribs) == -1) {
		if (add_i_to_a(idx, &(policy->types[type_idx].num_attribs), &(policy->types[type_idx].attribs)))
			return -1;
	}

	return 0;
}


/* allocates space for name, release memory with free() */
int get_obj_class_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_obj_class_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->obj_classes[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->obj_classes[idx].name);
	return 0;
}


int get_obj_class_perm_idx(int cls_idx, int idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_obj_class_idx(cls_idx, policy) || idx < 0 ||
			idx >= policy->obj_classes[cls_idx].num_u_perms) 
		return -1;
	return(policy->obj_classes[cls_idx].u_perms[idx]);
}

int get_num_perms_for_obj_class(int cls_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_obj_class_idx(cls_idx, policy) ) 
		return -1;
	assert(policy->obj_classes[cls_idx].common_perms >= 0 ? is_valid_common_perm_idx(policy->obj_classes[cls_idx].common_perms, policy)
			 : TRUE );

	if (policy->obj_classes[cls_idx].common_perms == -1)
		return policy->obj_classes[cls_idx].num_u_perms;
	return(policy->obj_classes[cls_idx].num_u_perms + policy->common_perms[policy->obj_classes[cls_idx].common_perms].num_perms);
}

/* This function treats the object class permission as a single array.
 * So for example, if there is a common perm, then the 0th perm for
 * the common perm is returned when n=0, otherwise the 0th unique perm
 * is returned. */
int get_obj_class_nth_perm_idx(int cls_idx, int n, policy_t *policy)
{
	int n2;
	if(n >= get_num_perms_for_obj_class(cls_idx, policy) || n < 0) 
		return -1;
	
	n2 = n;
	/* first check if there is a common perm */
	if (policy->obj_classes[cls_idx].common_perms != -1) {
		/* if there is a common perm, see if n is in the unique perms */
		if(n2 >= policy->common_perms[policy->obj_classes[cls_idx].common_perms].num_perms) {
			n2 -= policy->common_perms[policy->obj_classes[cls_idx].common_perms].num_perms;
			assert(n2 >= 0 && n2 < policy->obj_classes[cls_idx].num_u_perms);
		}
		else {
			/* n is a common perm */
			return(policy->common_perms[policy->obj_classes[cls_idx].common_perms].perms[n2]);
		}
	}
	/* it's a unique perm, n2 will be adjusted if there is a common perm */
	return(policy->obj_classes[cls_idx].u_perms[n2]);
}

int get_obj_class_common_perm_idx(int cls_idx,  policy_t *policy)
{
	if(policy == NULL || !is_valid_obj_class_idx(cls_idx, policy) ) 
		return -1;
	return(policy->obj_classes[cls_idx].common_perms);
}

int get_obj_class_idx(const char *name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;

	/* traverse the avl tree */
	return avl_get_idx(name, &policy->tree[AVL_CLASSES]);
}

int get_common_perm_idx(const char *name, policy_t *policy)
{
	int i;
	if(name == NULL || policy == NULL)
		return -1;
	for(i = 0; i < policy->num_common_perms; i++) {
		assert(policy->common_perms[i].name != NULL);
		if(strcmp(policy->common_perms[i].name, name) == 0)
			return i;
	}
	return -1;	
}

bool_t does_common_perm_use_perm(int cp_idx, int perm_idx, policy_t *policy)
{
	int i;
	if(policy == NULL || !is_valid_perm_idx(perm_idx, policy) || !is_valid_common_perm_idx(cp_idx, policy)) {
		return FALSE;
	}
	for(i = 0; i < policy->common_perms[cp_idx].num_perms; i++) {
		if(policy->common_perms[cp_idx].perms[i] == perm_idx)
			return TRUE;
	}
	return FALSE;
}

bool_t does_class_use_perm(int cls_idx, int perm_idx, policy_t *policy)
{
	int i;
	if(policy == NULL || !is_valid_perm_idx(perm_idx, policy) || !is_valid_obj_class_idx(cls_idx, policy)) {
		return FALSE;
	}
	for(i = 0; i < policy->obj_classes[cls_idx].num_u_perms; i++) {
		if(policy->obj_classes[cls_idx].u_perms[i] == perm_idx)
			return TRUE;
	}
	return FALSE;
}

bool_t does_class_indirectly_use_perm(int cls_idx, int perm_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_perm_idx(perm_idx, policy) || !is_valid_obj_class_idx(cls_idx, policy)) {
		return FALSE;
	}
	if(policy->obj_classes[cls_idx].common_perms < 0) {
		return FALSE;
	}
	else {
		return (does_common_perm_use_perm(policy->obj_classes[cls_idx].common_perms, perm_idx, policy));
	}
}

/* combine does_class_use_perm and does_class_indirectly_use_perm to determine
 * if a perm is valid for the given object class */
bool_t is_valid_perm_for_obj_class(policy_t *policy, int class, int perm)
{
	if (does_class_use_perm(class, perm, policy))
		return TRUE;
	if (does_class_indirectly_use_perm(class, perm, policy))
		return TRUE;
	return FALSE;
}

/* allocates space for name, release memory with free() */
int get_perm_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_perm_idx(idx, policy) || name == NULL )
		return -1;
	if((*name = (char *)malloc(strlen(policy->perms[idx])+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->perms[idx]);
	return 0;
}

int get_perm_idx(const char *name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;
	/* traverse the avl tree */
	return avl_get_idx(name, &policy->tree[AVL_PERMS]);
}

/*
 * get the perms for an object class - expands common perms.
 * Returns perm idxs in perms (caller must free) and # of perms in num_perms.
 * NOTE: The returned perms should be in order that they were parsed, thereby 
 * allow association with permission bitmaps from the base policy.
 */
int get_obj_class_perms(int obj_class, int *num_perms, int **perms, policy_t *policy)
{
	int i, rt, cp_idx;

	if (policy == NULL || perms == NULL)
		return -1;
	if (obj_class >= policy->num_obj_classes)
		return -1;
	if (num_perms == NULL)
		return -1;
	else
		*num_perms = 0;
	*perms = NULL;
	
	cp_idx = policy->obj_classes[obj_class].common_perms;
	if (cp_idx >= 0) {
		for (i = 0; i < policy->common_perms[cp_idx].num_perms; i++) {
			rt = add_i_to_a(policy->common_perms[cp_idx].perms[i], num_perms, perms);
			if (rt != 0)
				goto bad;
		}
	}
	
	for (i = 0; i < policy->obj_classes[obj_class].num_u_perms; i++) {
		rt = add_i_to_a(policy->obj_classes[obj_class].u_perms[i], num_perms, perms);	
		if (rt != 0)
			goto bad;
	}
	return 0;
bad:
	if (*perms != NULL)
		free(*perms);
	return -1;
}


/* take a list of classes, and return a list of permissions (union or intersection)
 * that contain the permissions for those classes.  The perm array is alloc amd must
 * be freed by caller.
 *
 * On error (< 0), num_perms is used to indicate which entry in perms cause problem (if applicable).
 * If error not related to a perm entry (from 0), then num_perms will be -1 on error return.
 *
 * Error returns:
 * -1 unspecified error
 * -2 invalid class name provided (num_perm has entry #)
 */
int get_perm_list_by_classes(bool_t union_flag, int num_classes, const char **classes, int *num_perms, int **perms, policy_t *policy)
{
	int cls_idx, *p_union, num_union = 0, *p_intersect = NULL, num_intersect, *p_count, i, j, rt, num, cp_idx, sz;
	
	if(num_perms == NULL) 
		return -1;
	else 
		*num_perms = -1; /* error indicator */
	
	if(policy == NULL || classes == NULL || perms == NULL || policy == NULL || num_classes < 1)
		return -1;
	
	/* make these arrays as large as worse case (i.e., num_perms + 1)*/
	sz = policy->num_perms;
	p_union = (int *)malloc(sizeof(int) * (sz));
	p_count = (int *)malloc(sizeof(int) * (sz));
	if(p_union == NULL || p_count == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}		
	
	/* validate classes and build union and count arrays */
	for(i = 0; i < num_classes; i++) {
		cls_idx = get_obj_class_idx(classes[i], policy);
		if(cls_idx < 0) {
			*num_perms = i; /* indicate which entry caused problem */
			rt =  -2; /* an invalid object class name */
			goto free_return;
		}
		num = get_num_perms_for_obj_class(cls_idx, policy);
		assert(num > 0);

		/* first common perms */
		cp_idx = policy->obj_classes[cls_idx].common_perms;
		if( cp_idx >= 0) {
			for(j = 0; j < policy->common_perms[cp_idx].num_perms; j++) {
				rt = find_int_in_array(policy->common_perms[cp_idx].perms[j], p_union, num_union);
				if(rt < 0){
					rt = add_int_to_array(policy->common_perms[cp_idx].perms[j], p_union, num_union, sz);
					if(rt != 0) {
						*num_perms = i;
						rt = -2;
						goto free_return;
					}
					p_count[num_union] = 1;
					num_union++;
				}
				else { /* already in union array; just up the count */
					p_count[rt]++;
				}
			}
		} /* end common perms */
		/* unique/class-specific perms */
		for(j = 0; j < policy->obj_classes[cls_idx].num_u_perms; j++) {
			rt = find_int_in_array(policy->obj_classes[cls_idx].u_perms[j], p_union, num_union);
			if(rt < 0){
				rt = add_int_to_array(policy->obj_classes[cls_idx].u_perms[j], p_union, num_union, sz);
				if(rt != 0) {
					*num_perms = i;
					rt = -2;
					goto free_return;
				}
				p_count[num_union] = 1;
				num_union++;
			}
			else { /* already in union array; just up the count */
				p_count[rt]++;
			}			
		}
	}
	/* At this point we have the union; if that's what we want go on.  If we want intersection
	 * then build a new array, with only those indicies whose count == num_classes */
	if(union_flag) {
		*perms = p_union;
		*num_perms = num_union;
	}
	else { /* intersection */
		p_intersect = (int *)malloc(sizeof(int) * num_union);
		if(p_intersect == NULL) {
			fprintf(stderr, "out of memory\n");
			rt = -1;
			goto free_return;
		}
		for(i = 0, num_intersect = 0; i < num_union; i++) {
			if(p_count[i] == num_classes) {
				p_intersect[num_intersect] = p_union[i];
				num_intersect++;
			}
		}
		*perms = p_intersect;
		*num_perms = num_intersect;
		free(p_union); 
	}
	free(p_count);
	return 0;
free_return:
	free(p_union); free(p_count);
	return rt;
}


/* allocates space for name, release memory with free() */
int get_common_perm_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_common_perm_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->common_perms[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->common_perms[idx].name);
	return 0;
}

/* gets the name of a perm assoicated with a common perm.  Retuns 0 if name return,
 * -1 for an error, and 1 if there are no more names.  memory is alloc for name
 * with malloc().  cp_idx is an idx for a common perm.  p_idx is used by this function
 * to track which perm is being queried.  On the first call you MUST set this to 0.
 * On future calls, just pass back the value returned.
 */
int get_common_perm_perm_name(int cp_idx, int *p_idx, char **name, policy_t *policy)
{
	int idx;
	if(policy  == NULL || !is_valid_common_perm_idx(cp_idx, policy) || p_idx == NULL ||
			name == NULL || *p_idx < 0)
		return -1;
	if(*p_idx >= policy->common_perms[cp_idx].num_perms)
		return 1; /* no more perms assoicated with common perm */
		
	assert(policy->common_perms[cp_idx].perms != NULL);
	idx =  policy->common_perms[cp_idx].perms[*p_idx];
	assert(is_valid_perm_idx(idx, policy));
	if((*name = (char*)malloc(strlen(policy->perms[idx])+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->perms[idx]);
	return 0;
}

int add_perm(char *perm, policy_t *policy)
{
	int i, rt;
	char *tmp;

	if(policy == NULL || perm == NULL)
		return -1;

	/* we can't assume that the caller won't free his memory, so we copy here before inserting */	
	tmp = (char *)malloc(sizeof(char)*(strlen(perm)+1));
	if(tmp == NULL){
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(tmp, perm);
	
	rt = avl_insert(&policy->tree[AVL_PERMS], tmp, &i);
	/* if the perm already exists (-2), it is not an error for perms */
	if(rt == -2) {
		free(tmp);
		return i;
	} else if(rt < 0) {
		return -1;
	} else {
		return i;
	}
}

int add_perm_to_common(int cp_idx, int p_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_perm_idx(p_idx, policy) || !is_valid_common_perm_idx(cp_idx, policy) ) 
		return -1;
		
	return(add_i_to_a(p_idx, &(policy->common_perms[cp_idx].num_perms), &(policy->common_perms[cp_idx].perms )) );
}

int add_perm_to_class(int cls_idx, int p_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_perm_idx(p_idx, policy) || !is_valid_obj_class_idx(cls_idx, policy) ) 
		return -1;
	return(add_i_to_a(p_idx, &(policy->obj_classes[cls_idx].num_u_perms), &(policy->obj_classes[cls_idx].u_perms) ));
}

/* we generally expect a small list of common perms, so we won't bother 
 * to use avl trees 
 * return -1 for err, -2 if already exist, new idx otherwise
 */
int add_common_perm(char *name, policy_t *policy)
{
	int idx;
	if(name == NULL || policy == NULL)
		return -1;
	/* check if common perm already exists */
	idx = get_common_perm_idx(name, policy);
	if(idx >= 0)
		 return -2; /* already exists */
	
	/* grow list if necessary */
	if(policy->num_common_perms >= policy->list_sz[POL_LIST_COMMON_PERMS]) {
		/* grow the dynamic array */
		common_perm_t *ptr;		
		ptr = (common_perm_t *)realloc(policy->common_perms, (LIST_SZ+policy->list_sz[POL_LIST_COMMON_PERMS]) * sizeof(common_perm_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->common_perms = ptr;
		policy->list_sz[POL_LIST_COMMON_PERMS] += LIST_SZ;
	}
	idx = policy->num_common_perms;
	policy->common_perms[idx].name = name;
	policy->common_perms[idx].num_perms = 0;
	policy->common_perms[idx].perms = NULL;
	
	(policy->num_common_perms)++;
	return idx;
}


int add_class(char *classname, policy_t *policy)
{
	int idx, rt;

	if(classname == NULL || policy == NULL)
		return -1;

	rt = avl_insert(&policy->tree[AVL_CLASSES], classname, &idx);
	if(rt < 0)
		return -1;
	return idx;
}


/* insert a ta_item_t into a list; this is a completely unsorted list! */
int insert_ta_item(ta_item_t *newitem, ta_item_t **list)
{
	ta_item_t *ptr;

	if(newitem == NULL)
		return -1;
	newitem->next = NULL;

	if(*list == NULL) {
		*list = newitem;
		return 0;
	}

	for(ptr = *list; ptr->next != NULL; ptr = ptr->next) { ; }
	ptr->next = newitem;
	return 0;
}


int add_user(char *user, policy_t *policy)
{
	size_t sz;
	name_a_t *new_user= NULL;
		
	if(user == NULL || policy == NULL)
		return -1;
		
	/* make sure there is a room for another role in the array */
	if(policy->list_sz[POL_LIST_USERS] <= policy->num_users) {
		sz = policy->list_sz[POL_LIST_USERS] + LIST_SZ;
		policy->users = (name_a_t *)realloc(policy->users, sizeof(name_a_t) * sz);
		if(policy->users == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_USERS] = sz;
	}
	/* next user available */
	new_user = &(policy->users[policy->num_users]);
	new_user->name = user;	/* use the memory passed in */
	new_user->num= 0; 
	new_user->a = NULL;
	(policy->rule_cnt[RULE_USER])++;	
	policy->num_users++;
	return policy->num_users - 1;	
}


int add_role_to_user(int role_idx, int user_idx, policy_t *policy)
{
	if(policy == NULL || !is_valid_user_idx(user_idx, policy))
		return -1;

	return(na_add_idx(role_idx, &policy->users[user_idx]));
}


/* add a name_item_t to the provided list */
/* DEPRECATED */
int add_name(char *name, name_item_t **list)
{
	name_item_t *newptr, *ptr;

	if(name == NULL)
		return -1;
	newptr = (name_item_t *)malloc(sizeof(name_item_t));
	if(newptr == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	newptr->next = NULL;
	newptr->name = name;
	if(*list == NULL) {
		*list = newptr;
		return 0;
	}
	for(ptr = *list; ptr->next != NULL; ptr = ptr->next) {; }
	ptr->next = newptr;
	return 0;
}

/* Get the next available entry in AV rule list, ensuring list grows as necessary.
 * We return a pointer to the new rule so that caller can complete its content. 
 * On return, the new rule will be in the batabase, but initialized. */
av_item_t *add_new_av_rule(int rule_type, policy_t *policy)
{
	int *sz, *num;
	av_item_t **rlist, *newitem;
	
	if(rule_type == RULE_TE_ALLOW || rule_type == RULE_NEVERALLOW) {
		sz = &(policy->list_sz[POL_LIST_AV_ACC]);
		num = &(policy->num_av_access);
		rlist = &(policy->av_access);
	}
	else if(rule_type == RULE_DONTAUDIT || rule_type == RULE_AUDITDENY || rule_type == RULE_AUDITALLOW) {
		sz = &(policy->list_sz[POL_LIST_AV_AU]);
		num = &(policy->num_av_audit);
		rlist = &(policy->av_audit);
	}
	else
		return NULL;
	
	if (*num >= *sz) {
		/* grow the dynamic array */
		av_item_t * ptr;		
		ptr = (av_item_t *)realloc(*rlist, (LIST_SZ + *sz) * sizeof(av_item_t));
		if(ptr == NULL) {
			fprintf(stderr,"out of memory\n");
			return NULL;
		}
		*rlist = ptr;
		*sz += LIST_SZ;
	}	
	
	newitem = &((*rlist)[*num]);
	(*num)++;
	/* initialize */
	memset(newitem, 0, sizeof(av_item_t));
	newitem->type = rule_type;
	newitem->cond_expr = -1;
	newitem->lineno = 0;
	(policy->rule_cnt[rule_type])++;
	
	return newitem;
}

/* Get the next available entry in TT rule list, ensuring list grows as necessary.
 * We return a pointer to the new rule so that caller can complete its content. 
 * On return, the new rule will be in the batabase, but initialized. */
tt_item_t *add_new_tt_rule(int rule_type, policy_t *policy)
{
	int *sz, *num;
	tt_item_t **rlist, *newitem;
	
	if(rule_type == RULE_TE_TRANS || rule_type == RULE_TE_MEMBER || rule_type == RULE_TE_CHANGE) {
		sz = &(policy->list_sz[POL_LIST_TE_TRANS]);
		num = &(policy->num_te_trans);
		rlist = &(policy->te_trans);
	}
	else
		return NULL;
	
	if (*num >= *sz) {
		/* grow the dynamic array */
		tt_item_t * ptr;		
		ptr = (tt_item_t *)realloc(*rlist, (LIST_SZ + *sz) * sizeof(tt_item_t));
		if(ptr == NULL) {
			fprintf(stderr,"out of memory\n");
			return NULL;
		}
		*rlist = ptr;
		*sz += LIST_SZ;
	}	
	
	newitem = &((*rlist)[*num]);
	(*num)++;
	/* initialize */
	memset(newitem, 0, sizeof(tt_item_t));
	newitem->type = rule_type;
	newitem->cond_expr = -1;
	newitem->lineno = 0;
	(policy->rule_cnt[rule_type])++;
	
	return newitem;
}

/* add a clone rule to a policy */
int add_clone_rule(int src, int tgt, unsigned long lineno, policy_t *policy)
{
	cln_item_t *newptr, *ptr;

	newptr = (cln_item_t *)malloc(sizeof(cln_item_t));
	if(newptr == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	/* initialize */
	memset(newptr, 0, sizeof(cln_item_t));
	
	newptr->next = NULL;
	newptr->src = src;
	newptr->tgt = tgt;
	newptr->lineno = lineno;
	if(policy->clones == NULL) {
		policy->clones = newptr;
		return 0;
	}
	for(ptr = policy->clones; ptr->next != NULL; ptr = ptr->next) {; }
	ptr->next = newptr;
	return 0;
}


static int append_attrib_types_to_array(int attrib, int *array_len, int **array, policy_t *policy)
{
	int i;
	
	if (attrib >= policy->num_attribs)
		return -1;

	for (i = 0; i < policy->attribs[attrib].num; i++) {
		if (add_i_to_a(policy->attribs[attrib].a[i], array_len, array) == -1)
					return -1;
	}
	return 0;
}

static int collect_subtracted_types_attribs(int *num_subtracted_types, int **subtracted_types,
	int *num_subtracted_attribs, int **subtracted_attribs, ta_item_t *tlist, policy_t *policy)
{
	ta_item_t *t;
	
	*subtracted_types = *subtracted_attribs = NULL;
	*num_subtracted_types = *num_subtracted_attribs = 0;
	for (t = tlist; t != NULL; t = t->next) {
		if ((t->type & IDX_SUBTRACT) && (t->type & IDX_TYPE)) {
			if (add_i_to_a(t->idx, num_subtracted_types, subtracted_types) == -1)
				goto err;
		} else if ((t->type & IDX_SUBTRACT) && (t->type & IDX_ATTRIB)) {
			if (append_attrib_types_to_array(t->idx, num_subtracted_types,
				subtracted_types, policy) == -1)
				goto err;
			if (add_i_to_a(t->idx, num_subtracted_attribs, subtracted_attribs) == -1)
				goto err;
		}
	}
	
	return 0;
err:
	if (*subtracted_types)
		free(*subtracted_types);
	if (*subtracted_attribs)
		free(*subtracted_attribs);
	return -1;
}

/* Checks not only for a direct match, but also indirect checks if user entered a type.
 * By indirect, we mean if type == IDX_TYPE, we see if the list contains either the type,
 * or one of the type's attributes. However, if type == IDX_ATTRIB (meaning the user 
 * entered an attribute instead of a type), we DON'T look for the attribute's types for matches
 * Logically, if one is asking for a match on an attribute, they want to match just
 * the attribute and not one of the attribute's types. 
 */
static int type_list_match_by_idx(	int idx,		/* idx of type/or attribure being matched*/
					int type, 		/* tells whether idx is type or attrib */
					bool_t do_indirect,
					ta_item_t *list,	/* list of types/attribs from a rule, usually src or tgt */
					policy_t *policy
					) 
{
	ta_item_t *ptr;
	int i, ret = 0, num_subtracted_types, num_subtracted_attribs;
	int *subtracted_types, *subtracted_attribs;

	assert(type == IDX_TYPE || type == IDX_ATTRIB);
	
	if (collect_subtracted_types_attribs(&num_subtracted_types, &subtracted_types,
		&num_subtracted_attribs, &subtracted_attribs, list, policy) == -1) {
		return -1;
	}
	
	if (type == IDX_TYPE) {
		if (find_int_in_array(idx, subtracted_types, num_subtracted_types) != -1) {
			ret = FALSE;
			goto out;
		}
	} else {
		if (find_int_in_array(idx, subtracted_attribs, num_subtracted_attribs) != -1) {
			ret = FALSE;
			goto out;
		}
	}
	
	/* check for direct matches; the fast check if we aren't looking for indirect matches,
	 * or if we don't have a TYPE (Attributes don't have indirect matches).
	 */
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		if(type == ptr->type && idx == ptr->idx) {
			ret = TRUE;
			goto out;
		}
	}
	
	/* check for indirect matches if type == IDX_TYPE  && do_indirect*/
	if(type == IDX_TYPE && do_indirect) {
		for(ptr = list; ptr != NULL; ptr = ptr->next) {
			if((ptr->type == IDX_TYPE) || (ptr->type & IDX_SUBTRACT))
				continue;
			for(i = 0; i < policy->types[idx].num_attribs; i++) {
				if(ptr->idx == policy->types[idx].attribs[i]) {
					if (find_int_in_array(ptr->idx, subtracted_types, num_subtracted_types) != -1)
						continue;
					ret = TRUE;
					goto out;
				}
			}
		}
	}
	
	ret = FALSE;
out:
	if (subtracted_types)
		free(subtracted_types);
	if (subtracted_attribs)
		free(subtracted_attribs);
	return ret;
}



int does_tt_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, tt_item_t *rule,
	int *cnt, policy_t *policy)
{
	int ans;
		
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->src_types, policy);
			if (ans == -1)
				return -1;
			if(ans) {
				(*cnt)++;
				 return TRUE;
			}		
		}
	}

	if(whichlist & TGT_LIST) {
		if(rule->flags & (AVFLAG_TGT_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if (ans == -1)
				return -1;
			if(ans) {
				(*cnt)++;
				 return TRUE;
			}
		}		
	}
	if(whichlist & DEFAULT_LIST) {
		ans = type_list_match_by_idx(idx, type, do_indirect, &(rule->dflt_type), policy);
		if (ans == -1)
			return -1;
		if(ans) {
			(*cnt)++;
			 return TRUE;
		}		
	}
	
	/* no match */
	return FALSE;
}

int does_av_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, 
	av_item_t *rule, int *cnt, policy_t *policy)
{
	int ans;
	
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->src_types, policy);
			if (ans == -1)
				return -1;
			if(ans) {
				(*cnt)++;
				return TRUE;
			}
		}		
	}
	
	if(whichlist & TGT_LIST) {
		if(rule->flags & (AVFLAG_TGT_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if (ans == -1)
				return -1;
			if(ans) {
				(*cnt)++;
				return TRUE;
			}		
		}
	}	
	
	/* no match */
	return FALSE;
}



/* wrapper for does_av_rule_use_type() that accepts a rule idx rather than a rule pointer 
 * This wrapper also does not expose the cnter incrementing feature.  For rule_type,
 * 0 = access rules, 1 = audit rules  */
int does_av_rule_idx_use_type(int rule_idx, unsigned char rule_type, int type_idx, int ta_type, 
		unsigned char whichlist, bool_t do_indirect, policy_t *policy)
{
	int unused_cnt = 0;
	av_item_t *rule;
	if(policy == NULL || rule_type > 1 || !(whichlist & (SRC_LIST|TGT_LIST))) {
		return FALSE;
	}
	if(rule_type == 0) {
		if(rule_idx >= policy->num_av_access)
			return FALSE;
		rule = &(policy->av_access[rule_idx]);
	}
	else if(rule_type ==1) {
		if(rule_idx >= policy->num_av_audit)
			return FALSE;
		rule = &(policy->av_audit[rule_idx]);
	}
	else
		return FALSE;
	return does_av_rule_use_type(type_idx, ta_type, whichlist, do_indirect, rule, &unused_cnt, policy);
}


bool_t does_clone_rule_use_type(int idx, int type, unsigned char whichlist, cln_item_t *rule,
	int *cnt, policy_t *policy)
{
	/* As we understand, clone rules can only have types (not attribs) */
	if(type != IDX_TYPE)
	return FALSE;
	
	if(whichlist & SRC_LIST) {
		if(rule->src == idx) {
			return TRUE;
		}
	}
	if(whichlist & TGT_LIST) {
		if(rule->tgt == idx) {
			return TRUE;
		}
	}
	return FALSE;
}


int add_role(char *role, policy_t *policy)
{
	size_t sz;
	name_a_t *new_role = NULL;
	name_a_t *ptr = NULL;
	
	if(role == NULL || policy == NULL)
		return -1;
		
	/* make sure there is a room for another role in the array */
	if(policy->list_sz[POL_LIST_ROLES] <= policy->num_roles) {
		sz = policy->list_sz[POL_LIST_ROLES] + LIST_SZ;
		ptr = (name_a_t *)realloc(policy->roles, sizeof(name_a_t) * sz);
		if (ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&ptr[policy->num_roles], 0, sizeof(name_a_t) * LIST_SZ);
		policy->roles = ptr;
		policy->list_sz[POL_LIST_ROLES] = sz;
	}
	
	/* next role available */
	new_role = &(policy->roles[policy->num_roles]);
	new_role->name = role;	/* use the memory passed in */
	new_role->num= 0;
	new_role->a = NULL;
	policy->num_roles++;
	return policy->num_roles - 1;
}

/* determine whether a role contains a given type (by idx) */
bool_t does_role_use_type(int role, int type, policy_t *policy)
{
	if(policy == NULL || !is_valid_role_idx(role, policy))
		return FALSE;
	return na_is_idx_in_a(type, &policy->roles[role]);
}

/* Determine whether a role allow includes the roles provided 
 * Use -1 for source and/or target role to not match against it.
 * At least one of src/tgt must be a valid role idx
 */
bool_t does_role_allow_use_role(int idx, unsigned char whichlist, bool_t do_indirect, role_allow_t *rule, int *cnt)
{
	ta_item_t *item;
		
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {
					
			for(item = rule->src_roles; item != NULL; item = item->next) {
				assert(item->type == IDX_ROLE);
				if(idx == item->idx) {
					(*cnt)++;
					return TRUE;
				}
			}
		}	
	}
	if(whichlist & TGT_LIST) {
		if(rule->flags & (AVFLAG_TGT_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}	
		else {	
			for(item = rule->tgt_roles; item != NULL; item = item->next) {
				assert(item->type == IDX_ROLE);
				if(idx == item->idx) {
					(*cnt)++;
					return TRUE;
				}
			}
		}
	}
	return FALSE;
}


/* NOTE: role_transition rule only has roles in the source and default field. */
bool_t does_role_trans_use_role(int idx, unsigned char whichlist, bool_t do_indirect, rt_item_t *rule, int *cnt)
{
	ta_item_t *item;
		
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {			
			for(item = rule->src_roles; item != NULL; item = item->next) {
				assert(item->type == IDX_ROLE);
				if(idx == item->idx) {
					(*cnt)++;
					return TRUE;
				}
			}
		}	
	}
	if(whichlist & DEFAULT_LIST) {
		assert(rule->trans_role.type == IDX_ROLE);
		if(idx == rule->trans_role.idx) {
			(*cnt)++;
			return TRUE;
		}
	}
	return FALSE;
}

/* NOTE: role_transition rule only has types/attribs in the target field. */
int does_role_trans_use_ta(int idx, int type, bool_t do_indirect, rt_item_t *rule, int *cnt, policy_t *policy)
{
	ta_item_t *item;
	int ans;

	if(rule->flags & (AVFLAG_TGT_STAR)) {
		if(do_indirect) {
			(*cnt)++;
			return TRUE;
		}
	}
	else {			
		for(item = rule->tgt_types; item != NULL; item = item->next) {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if (ans == -1)
				return -1;
			if(ans) {
				(*cnt)++;
				return TRUE;
			}		
		}
	}	
	
	return FALSE;
}

/* rule_type == 1 means access rules, otherwise audit rules */
bool_t does_av_rule_use_classes(int rule_idx, int rule_type, int *cls_idxs, int num_cls_idxs, policy_t *policy)
{
	int i;
	av_item_t *rule;
	ta_item_t *ptr;
	
	if(policy == NULL || !is_valid_av_rule_idx(rule_idx, rule_type, policy))
		return FALSE;
	if(cls_idxs == NULL || num_cls_idxs < 1)
		return TRUE;
	
	if(rule_type == 1) {
		rule = &(policy->av_access[rule_idx]);
	}
	else {
		rule = &(policy->av_audit[rule_idx]);
	}

	for(ptr = rule->classes; ptr != NULL ; ptr = ptr->next) {
		assert(ptr->type == IDX_OBJ_CLASS);
		for(i = 0; i < num_cls_idxs; i++) {
			if(cls_idxs[i] == ptr->idx)
				return TRUE;
		}
	}

	return FALSE;
}

/* rule_type == 1 means access rules, otherwise audit rules 
 * FIX?: Doesn't address  ~  */
bool_t does_av_rule_use_perms(int rule_idx, int rule_type, int *perm_idxs, int num_perm_idxs, policy_t *policy)
{
	int i;
	av_item_t *rule;
	ta_item_t *ptr;
	
	if(policy == NULL || !is_valid_av_rule_idx(rule_idx, rule_type, policy))
		return FALSE;
	if(perm_idxs == NULL || num_perm_idxs < 1)
		return TRUE;
	
	if(rule_type == 1) {
		rule = &(policy->av_access[rule_idx]);
	}
	else {
		rule = &(policy->av_audit[rule_idx]);
	}
	if(rule->flags & AVFLAG_PERM_STAR) {
		return TRUE;
	}
	for(ptr = rule->perms; ptr != NULL ; ptr = ptr->next) {
		assert(ptr->type == IDX_PERM);
		for(i = 0; i < num_perm_idxs; i++) {
			if(perm_idxs[i] == ptr->idx)
				return TRUE;
		}
	}
	return FALSE;
}


bool_t does_tt_rule_use_classes(int rule_idx, int *cls_idxs, int num_cls_idxs, policy_t *policy)
{
	int i;
	tt_item_t *rule;
	ta_item_t *ptr;

	if(policy == NULL || !is_valid_tt_rule_idx(rule_idx, policy))
		return FALSE;
	
	if(cls_idxs == NULL || num_cls_idxs < 1)
		return TRUE;

	rule = &(policy->te_trans[rule_idx]);

	for(ptr = rule->classes; ptr != NULL ; ptr = ptr->next) {
		assert(ptr->type == IDX_OBJ_CLASS);
		for(i = 0; i < num_cls_idxs; i++) {
			if(cls_idxs[i] == ptr->idx) {
				return TRUE;
			}
		}
	}

	return FALSE;
}

/* return the line number assoicated with a rule, return -1 for error */
int get_rule_lineno(int rule_idx, int rule_type, policy_t *policy)
{
	if(policy == NULL || rule_idx < 0 )
		return -1;
		
	switch(rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		if(rule_idx >= policy->num_av_access)
			return -1;
		return policy->av_access[rule_idx].lineno;
		break;
		
	case RULE_AUDITALLOW:
	case RULE_AUDITDENY:
	case RULE_DONTAUDIT:
		if(rule_idx >= policy->num_av_audit)
			return -1;
		return policy->av_audit[rule_idx].lineno;
		break;	
		
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		if(rule_idx >= policy->num_te_trans)
			return -1;
		return policy->te_trans[rule_idx].lineno;
		break;
	case RULE_CLONE:
		if(rule_idx >= policy->rule_cnt[RULE_CLONE])
			return -1;
		return policy->clones[rule_idx].lineno;
		break;
	case RULE_ROLE_ALLOW:
		if(rule_idx >= policy->num_role_allow)
			return -1;
		return policy->role_allow[rule_idx].lineno;
		break;
	case RULE_ROLE_TRANS:
		if(rule_idx >= policy->num_role_trans)
			return -1;
		return policy->role_trans[rule_idx].lineno;
		break;
	default:
		return -1;
		break;
	}
}


/* extract indicies of all types for selected rule, expanding attributes 
 * types is returned as an allocated array of ints num_types in sz, caller must free types 
 *
 * NOTE: * in list will return all types; this indicated by return 2, types = NULL, 
 *	num_type = policy->num_types
 * TODO?: ~ is ignored in this
 */
int extract_types_from_te_rule(int rule_idx, int rule_type, unsigned char whichlist, int **types, 
		int *num_types, policy_t *policy)
{
	ta_item_t *tlist, *t;
	unsigned char flags;
	bool_t *b_types = NULL;
	int i, ret = 0, num_subtracted_types, num_subtracted_attribs;
	int *subtracted_types, *subtracted_attribs;
	
	if(policy == NULL || types == NULL || num_types == NULL || rule_idx < 0 || !(whichlist & SRC_LIST || whichlist &TGT_LIST))
		return -1;
		
	/* finish validation and get ptr to appropriate type list */
	switch (rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		if(rule_idx >= policy->num_av_access)
			return -1;
		if(whichlist & SRC_LIST) {
			tlist = policy->av_access[rule_idx].src_types;
		} else {
			tlist = policy->av_access[rule_idx].tgt_types;
		}
		flags = policy->av_access[rule_idx].flags;
		break;
		
	case RULE_AUDITALLOW:
	case RULE_AUDITDENY:
	case RULE_DONTAUDIT:
		if(rule_idx >= policy->num_av_audit)
			return -1;
		if(whichlist & SRC_LIST) {
			tlist = policy->av_audit[rule_idx].src_types;
		} else {
			tlist = policy->av_audit[rule_idx].tgt_types;
		}
		flags = policy->av_audit[rule_idx].flags;
		break;	
		
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		if(rule_idx >= policy->num_te_trans)
			return -1;
		if(whichlist & SRC_LIST) {
			tlist = policy->te_trans[rule_idx].src_types;
		} else {
			tlist = policy->te_trans[rule_idx].tgt_types;
		}
		flags = policy->te_trans[rule_idx].flags;
		break;
	default:
		return -1;
		break;
	}
	
	/* first look for subtracted types and attributes - collect these for use later */
	if (collect_subtracted_types_attribs(&num_subtracted_types, &subtracted_types,
			&num_subtracted_attribs, &subtracted_attribs, tlist, policy) == -1)
		return -1;
	
	*types = NULL;
	*num_types = 0;
	/* handle star */
	if (((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_STAR)) ||
				((whichlist & TGT_LIST) && (flags & AVFLAG_TGT_STAR))) {
		if (num_subtracted_types || num_subtracted_attribs) {
			for (i = 0; i < policy->num_types; i++) {
				if (find_int_in_array(i, subtracted_types, num_subtracted_types) == -1)
					if (add_i_to_a(i, num_types, types) == -1) {
						ret = -1;
						goto out;
					}
			}
			ret = 0;
			goto out;
		} else {
			*num_types = policy->num_types;
			ret = 2;	/* indicate that all types via '*' */
			goto out;
		}
	}

	/* since there's a probability that more than one type will show up for a given rule
	 * (e.g., due to multiple attributes for which a given type may have), we're going
	 * to go through some pain to ensure that the returned list doesn't have redudant entries;
	 * b_types is a boolean array of num_types size for which we can track whether a type is
	 * already added.
	 */
	b_types = (bool_t *)malloc(sizeof(bool_t) * policy->num_types);
	if(b_types == NULL) {
		fprintf(stderr, "out of memory");
		ret = -1;
		goto out;
	}
	memset(b_types, 0, policy->num_types * sizeof(bool_t));
	for(t = tlist; t != NULL; t = t->next) {
		if(t->type == IDX_TYPE) {
			if (b_types[t->idx])
				continue;
			if (find_int_in_array(t->idx, subtracted_types, num_subtracted_types) != -1) {
				continue;
			}
			/* new type...add to list */
			if(add_i_to_a(t->idx, num_types, types) != 0) {
				ret = -1;
				goto out;
			}
			b_types[t->idx] = TRUE;
		} else if (t->type == IDX_ATTRIB) {
			/* attribute; need to enumerate all the assoicated types */
			int i, tidx;
			
			if (find_int_in_array(t->idx, subtracted_attribs, num_subtracted_attribs) != -1)
				continue;
			for (i = 0; i < policy->attribs[t->idx].num; i++) {
				tidx = policy->attribs[t->idx].a[i];
				if(!b_types[tidx] && (find_int_in_array(tidx, subtracted_types, num_subtracted_types) == -1)) {
					if(add_i_to_a(tidx, num_types, types) != 0) {
						ret = -1;
						goto out;
					}
				}
				b_types[tidx] = TRUE;	
			}
		}
	}
	
out:
	if (b_types)
		free(b_types);
	if (subtracted_types)
		free(subtracted_types);
	if (subtracted_attribs)
		free(subtracted_attribs);
	return ret;
}

/*
 * Extract the indices for the object classes for the selected rule. An array of indices is returned that
 * must be freed by the caller.
 *
 * NOTE: * in list will return all object classes; this indicated by return 2, obj_classes = NULL, 
 *	num_obj_classes = policy->num_obj_classes
 * TODO?: ~ is ignored in this
 */
int extract_obj_classes_from_te_rule(int rule_idx, int rule_type, int **obj_classes, int *num_obj_classes, policy_t *policy)
{
	ta_item_t* obj_class_ptr = NULL;
	unsigned char flags = 0;
	
	if (rule_idx >= (policy->num_av_access + policy->num_av_audit + policy->num_te_trans) || rule_idx < 0 || policy == NULL)
		return -1;

	*obj_classes = NULL;
	*num_obj_classes = 0;

	switch (rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		if(rule_idx >= policy->num_av_access)
			return -1;
		obj_class_ptr = policy->av_access[rule_idx].classes;
		flags = policy->av_access[rule_idx].flags;
		break;
		
	case RULE_AUDITALLOW:
	case RULE_AUDITDENY:
	case RULE_DONTAUDIT:
		if(rule_idx >= policy->num_av_audit)
			return -1;
		obj_class_ptr = policy->av_audit[rule_idx].classes;
		flags = policy->av_audit[rule_idx].flags;
		break;	
		
	case RULE_TE_TRANS:
	case RULE_TE_MEMBER:
	case RULE_TE_CHANGE:
		if(rule_idx >= policy->num_te_trans)
			return -1;
		obj_class_ptr = policy->te_trans[rule_idx].classes;
		flags = policy->te_trans[rule_idx].flags;
		break;
	default:
		return -1;
		break;
	}

	for (; obj_class_ptr != NULL;
	     obj_class_ptr = obj_class_ptr->next) {
		if (add_i_to_a(obj_class_ptr->idx, num_obj_classes, obj_classes) != 0) {
			return -1;
		}
	}
	return 0;
}

/*
 * Extract the indices for the perms for the selected rule. An array of indices is returned that
 * must be freed by the caller.
 *
 * NOTE: * in list will return 2, perms = NULL, and an undefined num_perms (which shouldn't be
 *       used. The caller must expand the perms for each object class in this case.
 * TODO?: ~ is ignored in this
 */
int extract_perms_from_te_rule(int rule_idx, int rule_type, int **perms, int *num_perms, policy_t *policy)
{
	ta_item_t* perm_ptr = NULL;
	av_item_t* rule = NULL;

	if (rule_idx >= (policy->num_av_access + policy->num_av_audit + policy->num_te_trans) || rule_idx < 0 || policy == NULL)
		return -1;

	*perms = NULL;
	*num_perms = 0;

	switch (rule_type) {
	case RULE_TE_ALLOW:
	case RULE_NEVERALLOW:
		if(rule_idx >= policy->num_av_access)
			return -1;
		rule = &policy->av_access[rule_idx];
		break;
		
	case RULE_AUDITALLOW:
	case RULE_AUDITDENY:
	case RULE_DONTAUDIT:
		if(rule_idx >= policy->num_av_audit)
			return -1;
		rule = &policy->av_audit[rule_idx];
		break;	
	default:
		fprintf(stderr, "Permissions not used for this rule type.\n");
		return -1;
		break;
	}

	if (rule->flags & AVFLAG_PERM_STAR) {
		*num_perms = -1;
		return 2;
	}

	for (perm_ptr = rule->perms; perm_ptr != NULL; perm_ptr = perm_ptr->next) {
		if (add_i_to_a(perm_ptr->idx, num_perms, perms) != 0) {
			return -1;
		}
	}
	return 0;
}


/* Returns a string with the appropriate name for a provided ta_item.  Will
 * determine which type/list the ta_item is for and then allocated the memory
 * for the return name. Caller must free the name.
 */
int get_ta_item_name(ta_item_t *ta, char **name, policy_t *policy)
{
	int rt;
	
	if(ta == NULL || name == NULL || policy == NULL)
		return -1;
	
	switch(ta->type) {
	case IDX_TYPE:
		rt = get_type_name(ta->idx, name, policy);
		break;
	case IDX_ATTRIB:
		rt = get_attrib_name(ta->idx, name, policy);
		break;
	case IDX_ROLE:
		rt = get_role_name(ta->idx, name, policy);
		break;
	case IDX_PERM:
		rt = get_perm_name(ta->idx, name, policy);
		break;
	case IDX_COMMON_PERM:
		rt = get_common_perm_name(ta->idx, name, policy);
		break;
	case IDX_OBJ_CLASS:
		rt = get_obj_class_name(ta->idx, name, policy);
		break;
	default:
		return -1;
	}
	return rt;
}

/* Conditional policy support */

/*
 * Add a boolean to the policy. Will not add a boolean if another with the same
 * name already exists.
 *
 * returns the index of the new boolean on success.
 * returns -2 if the boolean already exists.
 * return -1 on error.
 */
int add_cond_bool(char *name, bool_t state, policy_t *policy)
{
	int idx, rt;
	
	rt= avl_insert(&policy->tree[AVL_COND_BOOLS], name, &idx);
	if(rt < 0)	/* error or already exists */
		return rt;
		
	policy->cond_bools[idx].name = name;
	policy->cond_bools[idx].state = policy->cond_bools[idx].default_state = state;

	return idx;
}

/*
 * Get the index of a boolean in the policy.
 *
 * returns the index of the boolean on success.
 * returns -1 on error (including the boolean not existing).
 */
int get_cond_bool_idx(const char *name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;
	
	return avl_get_idx(name, &policy->tree[AVL_COND_BOOLS]);		
}

/*
 * Get the current value of the conditional boolean in the policy.
 *
 * returns the value of the boolean on success.
 * returns -1 on error.
 */
int get_cond_bool_val(const char *name, bool_t *val, policy_t *policy)
{
	int idx;
	
	if(name == NULL || policy == NULL || val == NULL)
		return -1;
	
	idx = avl_get_idx(name, &policy->tree[AVL_COND_BOOLS]);
	if (idx < 0) 
		return -1;
	*val = policy->cond_bools[idx].state; 
	return 0;
}

int get_cond_bool_default_val(const char *name, bool_t *val, policy_t *policy)
{
	int idx;
	
	if(name == NULL || policy == NULL || val == NULL)
		return -1;
	
	idx = avl_get_idx(name, &policy->tree[AVL_COND_BOOLS]);
	if (idx < 0) 
		return -1;
	*val = policy->cond_bools[idx].default_state; 	
	return 0;
}

int get_cond_bool_val_idx(int idx, bool_t *val, policy_t *policy) {
	if(val == NULL || !is_valid_cond_bool_idx(idx, policy))
		return -1;
	
	*val = policy->cond_bools[idx].state; 
	return 0;
}

int get_cond_bool_default_val_idx(int idx, bool_t *val, policy_t *policy) {
	if(val == NULL || !is_valid_cond_bool_idx(idx, policy))
		return -1;
	
	*val = policy->cond_bools[idx].default_state; 
	return 0;
}

static void update_cond_rule_list(cond_rule_list_t *list, bool_t state, policy_t *policy)
{
	int i;
	
	if (!list)
		return;
	
	for (i = 0; i < list->num_av_access; i++)
		policy->av_access[list->av_access[i]].enabled = state;
	for (i = 0; i < list->num_av_audit; i++)
		policy->av_audit[list->av_audit[i]].enabled = state;
	for (i = 0; i < list->num_te_trans; i++)
		policy->te_trans[list->te_trans[i]].enabled = state;
}

static int update_cond_expr_item(int idx, policy_t *policy)
{
	int rt;
	
	assert(policy->cond_exprs[idx].expr);
		
	rt = cond_evaluate_expr(policy->cond_exprs[idx].expr, policy);
	if (rt == -1) {
		fprintf(stderr, "Invalid expression\n");
		return -1;
	}
	if (rt)
		policy->cond_exprs[idx].cur_state = TRUE;
	else
		policy->cond_exprs[idx].cur_state = FALSE;
		
	update_cond_rule_list(policy->cond_exprs[idx].true_list, policy->cond_exprs[idx].cur_state, policy);
	update_cond_rule_list(policy->cond_exprs[idx].false_list, !policy->cond_exprs[idx].cur_state, policy);

	return 0;
}

void add_cond_expr_item_helper(int cond_expr, bool_t cond_list, cond_rule_list_t *list, policy_t * policy)
{
	int i;
	
	if (!list)
		return;
	
	for (i = 0; i < list->num_av_access; i++) {
		policy->av_access[list->av_access[i]].cond_expr = cond_expr;	
		policy->av_access[list->av_access[i]].cond_list = cond_list;	
	}
	
	for (i = 0; i < list->num_av_audit; i++) {
		policy->av_audit[list->av_audit[i]].cond_expr = cond_expr;	
		policy->av_audit[list->av_audit[i]].cond_list = cond_list;	
	}
	
	for (i = 0; i < list->num_te_trans; i++) {
		policy->te_trans[list->te_trans[i]].cond_expr = cond_expr;	
		policy->te_trans[list->te_trans[i]].cond_list = cond_list;	
	}
	
}

/*
 * Add a conditional expression to the policy. The expression cannot be null but the conditional
 * rule lists can. Also sets the cond_expr item for the rules to the index of the conditional
 * expression.
 *
 * returns the index of the conditional expression on success.
 * returns -1 on error.
 */
int add_cond_expr_item(cond_expr_t *expr, cond_rule_list_t *true_list, cond_rule_list_t *false_list, policy_t *policy)
{
	int idx;
	cond_expr_item_t *ptr = NULL;
	
	if (!policy || !expr)
		return -1;
		
	if (policy->num_cond_exprs >= policy->list_sz[POL_LIST_COND_EXPRS]) {
		ptr = (cond_expr_item_t*)realloc(policy->cond_exprs,
					     (LIST_SZ + policy->list_sz[POL_LIST_COND_EXPRS])
					     * sizeof(cond_expr_item_t));
		if (ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&ptr[policy->num_cond_exprs], 0, LIST_SZ * sizeof(cond_expr_item_t));
		policy->cond_exprs = ptr;
		policy->list_sz[POL_LIST_INITIAL_SIDS] += LIST_SZ;
	}
	idx = policy->num_cond_exprs;
	policy->num_cond_exprs++;
	
	policy->cond_exprs[idx].expr = expr;
	policy->cond_exprs[idx].true_list = true_list;
	add_cond_expr_item_helper(idx, TRUE, true_list, policy);
	policy->cond_exprs[idx].false_list = false_list;
	add_cond_expr_item_helper(idx, FALSE, false_list, policy);
	
	return idx;
}

/* Update all of the conditional expression items to reflect the current boolean values
 *
 * RETURNS:
 * 	0 on success
 *	-1 on error
 */
int update_cond_expr_items(policy_t *policy)
{
	int i;
	
	for (i = 0; i < policy->num_cond_exprs; i++) {
		if (update_cond_expr_item(i, policy) != 0)
			return -1;
	}
	return 0;
}

/*
 * Set the value of the condition bool. This will not update all of the conditional
 * expressions to reflect the change in value.
 *
 * RETURNS:
 * 	0 on success.
 * 	-1 on error.
 */
int set_cond_bool_val(int bool, bool_t state, policy_t *policy)
{
	if (!policy || !is_valid_cond_bool_idx(bool, policy))
		return -1;
	
	policy->cond_bools[bool].state = state;
	
	return 0;
}

int set_cond_bool_vals_to_default(policy_t *policy)
{
	int i;
	
	for (i = 0; i < policy->num_cond_bools; i++) {
		policy->cond_bools[i].state = policy->cond_bools[i].default_state;
	}
	return 0;
}

/* allocates space for name, release memory with free() */
int get_cond_bool_name(int idx, char **name, policy_t *policy)
{
	if(policy == NULL || !is_valid_cond_bool_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->cond_bools[idx].name) + 1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->cond_bools[idx].name);
	return 0;
}

static int apol_find_class_in_obj_perm_set_list(obj_perm_set_t *obj_options, int num_obj_options, int obj_class)
{
	int i;

	if (obj_options == NULL)
		return -1;
		
	assert(obj_class >= 0);

	for (i = 0; i < num_obj_options; i++) {
		if (obj_options[i].obj_class == obj_class) {
			return i;
		}
	}
	return -1;
}

int apol_obj_perm_set_init(obj_perm_set_t *it)
{
	if (!it) 
		return -1;
	
	it->obj_class = -1;
	it->num_perms = 0;
	it->perms = NULL;
	return 0;
}


void apol_free_obj_perm_set_data(obj_perm_set_t *it)
{
	if (!it) 
		return;
	if (it->perms) 
		free(it->perms);
	apol_obj_perm_set_init(it);
}


/*
 * Add an object class to a query - returns the index of
 * the obj_perm_set_t on success or -1 on failure. Checks to
 * prevent the addition of duplicate or contradictory object classes.
 */
int apol_add_class_to_obj_perm_set_list(obj_perm_set_t **obj_options, int *num_obj_options, int obj_class)
{
	int obj_idx, cur;

	assert(obj_class >= 0);

	/* find an existing entry for the object class */
	obj_idx = apol_find_class_in_obj_perm_set_list(*obj_options, *num_obj_options, obj_class);
	if (obj_idx != -1) {
			/* make certain that the entire object class is ignored */
			if ((*obj_options)[obj_idx].perms) {
				free((*obj_options)[obj_idx].perms);	
				(*obj_options)[obj_idx].perms = NULL;
				(*obj_options)[obj_idx].num_perms = 0;
			}
			return obj_idx;
	}

	/* add a new entry */
	cur = *num_obj_options;
	(*num_obj_options)++;
	*obj_options = (obj_perm_set_t*)realloc(*obj_options,
						      sizeof(obj_perm_set_t)
						      * (*num_obj_options));
	if (!(*obj_options)) {
		fprintf(stderr, "Memory error!\n");
		return -1;
	}
	memset(&(*obj_options)[cur], 0, sizeof(obj_perm_set_t));
	(*obj_options)[cur].obj_class = obj_class;

	return cur;
}


/*
 * Add an object class and perm to a query - returns the index of
 * the obj_perm_set_t on success or -1 on failure. Checks to
 * prevent the addition of duplicate or contradictory object classes.
 */
int apol_add_perm_to_obj_perm_set_list(obj_perm_set_t **obj_options, int *num_obj_options, int obj_class, int perm)
{
	int cur;
	bool_t add = FALSE;
	
	assert(obj_class >= 0 && perm >= 0);
	/* find an existing entry for the object class */
	cur = apol_find_class_in_obj_perm_set_list(*obj_options, *num_obj_options, obj_class);

        /* add a new entry */
	if (cur == -1) {
		cur = *num_obj_options;
		(*num_obj_options)++;
		*obj_options = (obj_perm_set_t*)realloc(*obj_options,
							       sizeof(obj_perm_set_t)
							       * (*num_obj_options));
		if (!(*obj_options)) {
			fprintf(stderr, "Memory error!\n");
			return -1;
		}
		memset(&(*obj_options)[cur], 0, sizeof(obj_perm_set_t));
		(*obj_options)[cur].obj_class = obj_class;
		
	}

	if (!(*obj_options)[cur].perms) {
		add = TRUE;
	} else {
		if (find_int_in_array(perm, (*obj_options)[cur].perms,
				      (*obj_options)[cur].num_perms) == -1)
			add = TRUE;
	}

	if (add) {
		if (add_i_to_a(perm, &(*obj_options)[cur].num_perms,
			       &(*obj_options)[cur].perms) == -1)
			return -1;
	}
	return 0;
}

