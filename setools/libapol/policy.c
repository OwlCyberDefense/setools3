/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
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
#include "util.h"
#include "perm-map.h"
#include "cond.h"

#include <stdlib.h>
#include <assert.h>

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
/**************/


int init_policy( policy_t **p)
{
	policy_t *policy;
	assert(*p == NULL);
	policy = (policy_t *)malloc(sizeof(policy_t));
	if(policy == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->version = POL_VER_UNKNOWN;
	policy->fresh_pol = TRUE;
	policy->opts = POLOPT_NONE;

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
	
	/* types list */
	policy->types = (type_item_t *)malloc(sizeof(type_item_t) * LIST_SZ);
	if(policy->types == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_TYPE] = LIST_SZ;
	policy->num_types = 0;
	
	/* type aliases */
	policy->aliases = (alias_item_t *)malloc(sizeof(type_item_t) * LIST_SZ);
	if(policy->aliases == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ALIAS] = LIST_SZ;
	policy->num_aliases = 0;
	
	/* type attributes list */
	policy->attribs = (attrib_item_t *)malloc(sizeof(attrib_item_t) * LIST_SZ);
	if(policy->attribs == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ATTRIB] = LIST_SZ;
	policy->num_attribs = 0;
	
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
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

#endif
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
	policy->roles = (role_item_t *)malloc(sizeof(role_item_t) * LIST_SZ);
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
	policy->users.head = NULL;
	policy->users.tail = NULL;
	
	
	/* rule stats */
	memset(policy->rule_cnt, 0, sizeof(int) * RULE_MAX);
	
	/* permission maps */
	policy->pmap = NULL;

	if(init_avl_trees(policy) != 0) {
		return -1;
	}

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

static int free_ta_list(ta_item_t *list)
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

/* does not free the generic data pointer; that's up to the user of the pointer*/
int free_user(user_item_t *ptr)
{
	free(ptr->name);
	free_ta_list(ptr->roles);
	free(ptr->data);
	free(ptr);
	return 0;
}

/* frees attrib_item_t and those aliases to it */
static int free_attrib_list(attrib_item_t *ptr, int num)
{
	int i;
	if(ptr == NULL) 
		return 0;
			
	for(i = 0; i < num; i++) {
		if(ptr[i].name != NULL)
			free(ptr[i].name);
		if(ptr[i].types != NULL)
			free(ptr[i].types);
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
	free_attrib_list(policy->attribs, policy->num_attribs);
	
#ifdef CONFIG_SECURITY_SELINUX_CONDITIONAL_POLICY
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
#endif
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
	free_attrib_list(policy->roles, policy->num_roles);
	
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
	{
		user_item_t *ptr, *ptr2;
		for(ptr = policy->users.head; ptr != NULL; ptr = ptr2) {
			ptr2 = ptr->next;
			free(ptr->name);
			free_ta_list(ptr->roles);
			free(ptr);
		}
	}
	
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
int get_type_idxs_by_regex(int **types, int *num, regex_t *preg, policy_t *policy)
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
	for(i = 0; i < policy->num_types; i++) {
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
 * get the types for a attrib.
 * Returns type idxs in types (caller must free) and # of types in num_types
 */
int get_attrib_types(int attrib, int *num_types, int **types, policy_t *policy)
{
	int i, rt;

	if (policy == NULL || types == NULL)
		return -1;
	if (attrib >= policy->num_attribs)
		return -1;
	if (num_types == NULL)
		return -1;
	else
		*num_types = 0;
	*types = NULL;

	for (i = 0; i < policy->attribs[attrib].num_types; i++) {
		rt = add_i_to_a(policy->attribs[attrib].types[i], num_types, types);	
		if (rt != 0)
			goto bad;
	}
	return 0;
bad:
	if (*types != NULL)
		free(*types);
	return -1;
}

/* allocates space for name, release memory with free() */
int get_attrib_name(int idx, char **name, policy_t *policy)
{
	if(name == NULL || policy == NULL)
		return -1;
		
	if(!is_valid_attrib_idx(idx, policy))
		return -1;
	if((*name = (char *)malloc(strlen(policy->attribs[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->attribs[idx].name);
	return 0;
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
	if(policy == NULL || !is_valid_role_idx(idx, policy) || name == NULL)
		return -1;
	if((*name = (char *)malloc(strlen(policy->roles[idx].name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, policy->roles[idx].name);
	return 0;
}


/* user names; allocates memory  */
int get_user_name(user_item_t *user, char **name)
{
	if(user == NULL || name == NULL) {
		return -1;
	}
	if((*name = (char *)malloc(strlen(user->name)+1)) == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(*name, user->name);
	return 0;
}

/* check if user exists */
bool_t does_user_exists(const char *name, policy_t *policy)
{
	user_item_t *ptr;
	if(name == NULL || policy == NULL) {
		return FALSE;
	}
	for(ptr = policy->users.head; ptr != NULL; ptr = ptr->next) {
		if(strcmp(name, ptr->name) == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

/* check if user exists, and if so return a pointer to its structure */
int get_user_by_name(const char *name, user_item_t **user, policy_t *policy)
{
	user_item_t *ptr;
	if(user == NULL || name == NULL || policy == NULL) {
		return -1;
	}
	
	for(ptr = policy->users.head; ptr != NULL; ptr = ptr->next) {
		if(strcmp(name, ptr->name) == 0) {
			*user = ptr;
			return 0;
		}
	}
	return -1;	
}


/* this allow us to check whether a give role is in assigned to user */
bool_t is_role_in_list(int role, ta_item_t *list)
{
	ta_item_t *ptr;
	if(list == NULL)
		return FALSE;
		
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		if(role == ptr->idx) {
			return TRUE;
		}
	}
	return FALSE;
}
bool_t does_user_have_role(user_item_t *user, int role, policy_t *policy)
{
	if(user == NULL || policy == NULL)
		return FALSE;
		
	return(is_role_in_list(role, user->roles));
}


static int add_type_to_attrib(int type_idx, attrib_item_t *attrib)
{
	return(add_i_to_a(type_idx, &(attrib->num_types), &(attrib->types)));
}



int add_type_to_role(int type_idx, role_item_t *role)
{
	if(role == NULL)
		return -1;
	else
		return(add_type_to_attrib(type_idx, role));
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
	int idx;
	if(!is_valid_type_idx(type_idx, policy) || alias == NULL || policy == NULL)
		return -1;

	/* TODO: we have a problem with the way we handle aliases once AVL trees were added.
	 *	since the AVL trees are sorted by type name, the alias search doesn't work
	 *	(since an aliases is checked only if the type name doesn't match, but since we have
	 * 	an efficient type name tree, not all types (and therefore aliases) are searched.
	 *	What we've done for now is maintain a separate alias array while still maintaining
	 *	the old alias name list attached to each type.  The alias array will allow us to search
	 *	for a type using its alias name if it wasn't found via the AVL search using prime
	 *	type names.  Eventually we need to remove the name list and use references to the
	 *	alias array.
	 *
	 *	This is currently fragile as we don't check for syntax problems arising from the using
	 * 	the same alias twice (checkpolicy would not allow this).
	 */
	/* first the simple name list */
	if(add_name(alias, &(policy->types[type_idx].aliases)) != 0) {
		return -1;			
	}
	/* and now the alias array; add_name also uses the memory for the name, so we need to be
	 * careful on free */
	if(check_alias_array(policy) != 0) 
		return -1;
	
	idx = policy->num_aliases;
	policy->aliases[idx].name = alias;
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

	return(add_i_to_a(idx, &(policy->types[type_idx].num_attribs), &(policy->types[type_idx].attribs)) );
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
 * Returns perm idxs in perms (caller must free) and # of perms in num_perms
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

/* add a user to user list */
int append_user(user_item_t *newuser, user_list_t *list)
{
	if(newuser == NULL || list == NULL)
		return -1;
	newuser->next = NULL;
	
	if(list->head == NULL) {
		list->head = newuser;
		list->tail = newuser;		
	}
	else {
		list->tail->next = newuser;
		list->tail = newuser;
	}

	return 0;
}


/* add a name_item_t to the provided list */
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


/* add a clone rule to a policy */
int add_clone_rule(int src, int tgt, unsigned long lineno, policy_t *policy)
{
	cln_item_t *newptr, *ptr;

	newptr = (cln_item_t *)malloc(sizeof(cln_item_t));
	if(newptr == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

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



/* PRESENTLY UNUSED AND NOT DEBUGGED*/
#if 0
static bool_t type_list_match_by_name(char * type, ta_item_t *list, policy_t *policy) 
{
	ta_item_t *ptr;
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		switch(ptr->type) {
		case IDX_TYPE:
			assert(ptr->idx < policy->num_types);
			if(strcmp(type, policy->types[ptr->idx].name) == 0) 
				return 1;
			break;
		case IDX_ATTRIB:
			assert(ptr->idx < policy->num_attribs);
			if(strcmp(type, policy->attribs[ptr->idx].name) == 0) 
				return 1;		
			break;
		default:
			fprintf(stderr, "invalid type for ta_item (%d)\n", ptr->type);
			break;
		}
	}
		
	return 0;
}
#endif


/* Checks not only for a direct match, but also indirect checks if user entered a type.
 * By indirect, we mean if type == IDX_TYPE, we see if the list contains either the type,
 * or one of the type's attributes. However, if type == IDX_ATTRIB (meaning the user 
 * entered an attribute instead of a type), we DON'T look for the attribute's types for matches
 * Logically, if one is asking for a match on an attribute, they want to match just
 * the attribute and not one of the attribute's types. 
 */
static bool_t type_list_match_by_idx(	int idx,		/* idx of type/or attribure being matched*/
					int type, 		/* tells whether idx is type or attrib */
					bool_t do_indirect,
					ta_item_t *list,	/* list of types/attribs from a rule, usually src or tgt */
					policy_t *policy
					) 
{
	ta_item_t *ptr;
	int i;

	/* check for direct matches; the fast check if we aren't looking for indirect matches,
	 * or if we don't have a TYPE (Attributes don't have indirect matches).
	 */
	for(ptr = list; ptr != NULL; ptr = ptr->next) {
		if(type == ptr->type && idx == ptr->idx) {
			return 1;
		}
	}
	
	/* check for indirect matches if type == IDX_TYPE  && do_indirect*/
	if(type == IDX_TYPE && do_indirect) {
		for(ptr = list; ptr != NULL; ptr = ptr->next) {
			if(ptr->type == IDX_TYPE)
				continue;
			for(i = 0; i < policy->types[idx].num_attribs; i++) {
				if(ptr->idx == policy->types[idx].attribs[i])
					return 1;
			}
		}
	}
	return 0;
}



bool_t does_tt_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, tt_item_t *rule, int *cnt, policy_t *policy)
{
	int ans = 0;
	
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return 1;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->src_types, policy);
			if(ans) {
				(*cnt)++;
				 return 1;
			}		
		}
	}

	if(whichlist & TGT_LIST) {
		if(rule->flags & (AVFLAG_TGT_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return 1;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if(ans) {
				(*cnt)++;
				 return 1;
			}
		}		
	}
	if(whichlist & DEFAULT_LIST) {
		ans = type_list_match_by_idx(idx, type, do_indirect, &(rule->dflt_type), policy);
		if(ans) {
			(*cnt)++;
			 return 1;
		}		
	}
	
	/* no match */
	return 0;
}

bool_t does_av_rule_use_type(int idx, int type, unsigned char whichlist, bool_t do_indirect, 
	av_item_t *rule, int *cnt, policy_t *policy)
{
	int ans = 0;
	
	if(whichlist & SRC_LIST) {
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return 1;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->src_types, policy);
			if(ans) {
				(*cnt)++;
				 return 1;
			}
		}		
	}
	
	if(whichlist & TGT_LIST) {
		if(rule->flags & (AVFLAG_TGT_STAR)) {
			if(do_indirect) {
				(*cnt)++;
				return 1;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if(ans) {
				(*cnt)++;
				 return 1;
			}		
		}
	}	
	
	/* no match */
	return 0;
}


/* wrapper for does_av_rule_use_type() that accepts a rule idx rather than a rule pointer 
 * This wrapper also does not expose the cnter incrementing feature.  For rule_type,
 * 0 = access rules, 1 = audit rules  */
bool_t does_av_rule_idx_use_type(int rule_idx, unsigned char rule_type, int type_idx, int ta_type, 
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



/* determine whether a role contains a given type (by idx) */
bool_t does_role_use_type(int role, int type, policy_t *policy)
{
	int i;
	if(policy == NULL || role < 0 || role >= policy->num_roles || 
		type < 0 || type > policy->num_types) {
		return FALSE;
	}
	for(i = 0; i < policy->roles[role].num_types; i++) {
		if(policy->roles[role].types[i] == type)
			return TRUE;
	}
	return FALSE;
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
bool_t does_role_trans_use_ta(int idx, int type, bool_t do_indirect, rt_item_t *rule, int *cnt, policy_t *policy)
{
	ta_item_t *item;
	bool_t ans;

	if(rule->flags & (AVFLAG_TGT_STAR)) {
		if(do_indirect) {
			(*cnt)++;
			return TRUE;
		}
	}
	else {			
		for(item = rule->tgt_types; item != NULL; item = item->next) {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->tgt_types, policy);
			if(ans) {
				(*cnt)++;
				 return TRUE;
			}		
		}
	}	
	
	return FALSE;
}

/* rule_type == 1 means access rules, otherwise audit rules */
/* FIX: ?maybe?  Doesn't address ~  */
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
	if(rule->flags & AVFLAG_CLS_STAR) {
		return TRUE;
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

/* FIX: ?maybe?  Doesn't address * nor ~  */
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
			if(cls_idxs[i] == ptr->idx)
				return TRUE;
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
	bool_t *b_types;
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
	/* build the list */
	*types = NULL;
	if(((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_STAR)) ||
			((whichlist & TGT_LIST) && (flags & AVFLAG_TGT_STAR))) {
		*num_types = policy->num_types;
		return  2;	/* indicate that all types via '*' */
	}
	*num_types = 0;

	/* since there's a probability that more than one type will show up for a given rule
	 * (e.g., due to multiple attributes for which a given type may have), we're going
	 * to go through some pain to ensure that the returned list doesn't have redudant entries;
	 * b_types is a boolean array of num_types size for which we can track whether a type is
	 * already added.
	 */
	b_types = (bool_t *)malloc(sizeof(bool_t) * policy->num_types);
	if(b_types == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	memset(b_types, 0, policy->num_types * sizeof(bool_t));
	for(t = tlist; t != NULL; t = t->next) {
		if(t->type == IDX_TYPE) {
			if (b_types[t->idx])
				continue;
			/* handle self in the target list */
			if (whichlist & TGT_LIST && t->idx == 0) {
				int i, r, n, *l;
				r = extract_types_from_te_rule(rule_idx, rule_type, SRC_LIST, &l, &n, policy);
				if (r == -1) {
					free(b_types);
					return -1;
				}
				if (r == 2) {
					free(b_types);
					if (*types != NULL)
						free(*types);
					*num_types = policy->num_types;
					return 2;
				}
				for (i = 0; i < n; i++) {
					if (b_types[l[i]])
						continue;
					if(add_i_to_a(l[i], num_types, types) != 0) {
						free(b_types);
						return -1;
					}
					b_types[l[i]] = TRUE;
				}
				free(l);
				b_types[t->idx] = TRUE;
			} else {
				/* new type...add to list */
				if(add_i_to_a(t->idx, num_types, types) != 0) {
					free(b_types);
					return -1;
				}
				b_types[t->idx] = TRUE;
			}
		}
		else {
			/* attribute; need to enumerate all the assoicated types */
			int i, tidx;
			assert(t->type == IDX_ATTRIB);
			for(i = 0; i < policy->attribs[t->idx].num_types; i++) {
				tidx = policy->attribs[t->idx].types[i];
				if(!b_types[t->idx]) {
					if(add_i_to_a(tidx, num_types, types) != 0) {
						free(b_types);
						return -1;
					}
				}
				b_types[tidx] = TRUE;	
			}
		}
	}
	free(b_types);
	return 0;
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
	
	if (rule_idx >= policy->num_av_access || rule_idx < 0 || policy == NULL)
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

	if (flags & AVFLAG_CLS_STAR) {
		*num_obj_classes = policy->num_obj_classes;
		return 2;
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

	if (rule_idx >= policy->num_av_access || rule_idx < 0 || policy == NULL)
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

