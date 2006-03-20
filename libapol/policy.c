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
#include <errno.h>

/* The following is a private global array of constant strings. */
const char *policy_version_strings[] = {
	"Unkown version",
	"prior to v.11",
	"v.11 - 12",
	"v.15",
	"v.16",
	"v.17",
	"v.18",
	"v.18 - 20",
	"v.19",
	"v.19 - 20",
	"v.20",
};
			 	 
/* get a policy version string from the global array of constant strings. 
 * We use the defined policy version numbers as indices into this array.*/
const char* get_policy_version_name(int policy_version)
{
	if (!is_valid_policy_version(policy_version)) 
		return policy_version_strings[POL_VER_UNKNOWN];
	else 
		return policy_version_strings[policy_version];
}
		 	 
char *get_policy_version_type_mls_str(policy_t *policy)
{
	char buff[BUF_SZ];
	char *str = NULL;

	str = &(buff[0]);
	str += snprintf(str, BUF_SZ - 1, "%s (", get_policy_version_name(policy->version));
	if (policy->policy_type == POL_TYPE_SOURCE) {
		str += snprintf(str, BUF_SZ - 1 - (str - buff) * sizeof(char), "source, ");
	} else if (policy->policy_type == POL_TYPE_BINARY) {
		str += snprintf(str, BUF_SZ - 1 - (str - buff) * sizeof(char), "binary, ");
	} else {
		str += snprintf(str, BUF_SZ - 1 - (str - buff) * sizeof(char), "unknown, ");
	}
	str += snprintf(str, BUF_SZ - 1 - (str - buff) * sizeof(char), "%s)", policy->mls?"MLS":"non-MLS");

	str = strdup(buff);

	return str;
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
	policy->mls = FALSE;

	/* permissions */
	policy->perms = (char **)calloc(LIST_SZ, sizeof(char*));
	if(policy->perms == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_PERMS] = LIST_SZ;
	policy->num_perms = 0;
	/* common perms */
	policy->common_perms = (common_perm_t *)calloc(LIST_SZ, sizeof(common_perm_t));
	if(policy->common_perms == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	policy->list_sz[POL_LIST_COMMON_PERMS] = LIST_SZ;
	policy->num_common_perms = 0;
	
	/* object classes */
	policy->obj_classes = (obj_class_t *)calloc(LIST_SZ, sizeof(obj_class_t));
	if(policy->obj_classes == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}	
	policy->list_sz[POL_LIST_OBJ_CLASSES] = LIST_SZ;
	policy->num_obj_classes = 0;
	
	/* initial SIDs */
	policy->initial_sids = (initial_sid_t *)calloc(LIST_SZ, sizeof(initial_sid_t));
	if(policy->initial_sids == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_INITIAL_SIDS] = LIST_SZ;
	policy->num_initial_sids = 0;
	
	/* types list */
	policy->types = (type_item_t *)calloc(LIST_SZ, sizeof(type_item_t));
	if(policy->types == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_TYPE] = LIST_SZ;
	policy->num_types = 0;
	
	/* type aliases */
	policy->aliases = (alias_item_t *)calloc(LIST_SZ, sizeof(alias_item_t));
	if(policy->aliases == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ALIAS] = LIST_SZ;
	policy->num_aliases = 0;
	
	/* type attributes list */
	policy->attribs = (name_a_t *)calloc(LIST_SZ, sizeof(name_a_t));
	if(policy->attribs == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ATTRIB] = LIST_SZ;
	policy->num_attribs = 0;
	
	/* conditional booleans */
	policy->cond_bools = (cond_bool_t *)calloc(LIST_SZ, sizeof(cond_bool_t));
	if(policy->cond_bools == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_COND_BOOLS] = LIST_SZ;	
	policy->num_cond_bools = 0;
	
	/* conditional expressions */
	policy->cond_exprs = (cond_expr_item_t *)calloc(LIST_SZ, sizeof(cond_expr_item_t));
	if(policy->cond_exprs == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_COND_EXPRS] = LIST_SZ;	
	policy->num_cond_exprs = 0;	
	
	/* av_access rules */
	policy->av_access = (av_item_t *)calloc(LIST_SZ, sizeof(av_item_t));
	if(policy->av_access == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_AV_ACC] = LIST_SZ;
	policy->num_av_access = 0;

	/* av_audit rules */
	policy->av_audit = (av_item_t *)calloc(LIST_SZ, sizeof(av_item_t));
	if(policy->av_audit == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_AV_AU] = LIST_SZ;
	policy->num_av_audit = 0;

	/* type transition, etc. rules */
	policy->te_trans = (tt_item_t *)calloc(LIST_SZ, sizeof(tt_item_t));
	if(policy->te_trans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_TE_TRANS] = LIST_SZ;
	policy->num_te_trans = 0;

	/* clone rules */
	policy->clones = NULL;

	/* role definitions */
	policy->roles = (ap_role_t *)calloc(LIST_SZ, sizeof(ap_role_t));
	if(policy->roles == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLES] = LIST_SZ;
	policy->num_roles = 0;
	
	/* role allow rules */
	policy->role_allow = (role_allow_t *)calloc(LIST_SZ, sizeof(role_allow_t));
	if(policy->role_allow == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLE_ALLOW] = LIST_SZ;
	policy->num_role_allow = 0;
	
	/* role transition rules */
	policy->role_trans = (rt_item_t *)calloc(LIST_SZ, sizeof(rt_item_t));
	if(policy->role_trans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_ROLE_TRANS] = LIST_SZ;
	policy->num_role_trans = 0;	
	
	/* users */
	policy->users = (ap_user_t *)calloc(LIST_SZ, sizeof(ap_user_t));
	if(policy->users == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_USERS] = LIST_SZ;
	policy->num_users = 0;	
	
	/* fs_use */
	policy->fs_use = (ap_fs_use_t *)calloc(LIST_SZ, sizeof(ap_fs_use_t));
	if(policy->fs_use == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_FS_USE] = LIST_SZ;
	policy->num_fs_use = 0;

	/* portcon */
	policy->portcon = (ap_portcon_t *)calloc(LIST_SZ, sizeof(ap_portcon_t));
	if(policy->portcon == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_PORTCON] = LIST_SZ;
	policy->num_portcon = 0;

	/* netifcon */
	policy->netifcon = (ap_netifcon_t *)calloc(LIST_SZ, sizeof(ap_netifcon_t));
	if(policy->netifcon == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_NETIFCON] = LIST_SZ;
	policy->num_netifcon = 0;

	/* nodecon */
	policy->nodecon = (ap_nodecon_t *)calloc(LIST_SZ, sizeof(ap_nodecon_t));
	if (policy->nodecon == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_NODECON] = LIST_SZ;
	policy->num_nodecon = 0;

	/* genfscon */
	policy->genfscon = (ap_genfscon_t *)calloc(LIST_SZ, sizeof(ap_genfscon_t));
	if (policy->genfscon == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_GENFSCON] = LIST_SZ;
	policy->num_genfscon = 0;

	/* constraints */
	policy->constraints = (ap_constraint_t *)calloc(LIST_SZ, sizeof(ap_constraint_t));
	if (policy->constraints == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_CONSTRAINT] = LIST_SZ;
	policy->num_constraints = 0;

	/* validatetrans */
	policy->validatetrans = (ap_validatetrans_t *)calloc(LIST_SZ, sizeof(ap_validatetrans_t));
	if (policy->validatetrans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_VALIDATETRANS] = LIST_SZ;
	policy->num_validatetrans = 0;

	/* MLS components */
	policy->sensitivities = (ap_mls_sens_t*)calloc(LIST_SZ, sizeof(ap_mls_sens_t));
	if (policy->sensitivities == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_SENSITIVITIES] = LIST_SZ;
	policy->num_sensitivities = 0;

	policy->categories = (ap_mls_cat_t*)calloc(LIST_SZ, sizeof(ap_mls_cat_t));
	if (policy->categories == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_CATEGORIES] = LIST_SZ;
	policy->num_categories = 0;

	policy->levels = (ap_mls_level_t*)calloc(LIST_SZ, sizeof(ap_mls_level_t));
	if (policy->levels == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_LEVELS] = LIST_SZ;
	policy->num_levels = 0;

	policy->rangetrans = (ap_rangetrans_t*)calloc(LIST_SZ, sizeof(ap_rangetrans_t));
	if (policy->rangetrans == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	policy->list_sz[POL_LIST_RANGETRANS] = LIST_SZ;
	policy->num_rangetrans = 0;

	policy->mls_dominance = NULL;

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

int free_name_list(name_item_t *list)
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
			free_ta_list(policy->obj_classes[i].constraints);
			free_ta_list(policy->obj_classes[i].validatetrans);
		}
		free(policy->obj_classes);
	}

	/* initial SIDs list */
	if(policy->initial_sids != NULL) {
		for(i = 0; i < policy->num_initial_sids; i++) {
			if(policy->initial_sids[i].name != NULL) {
				free(policy->initial_sids[i].name);
				security_con_destroy(policy->initial_sids[i].scontext);
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
	if (policy->roles != NULL) {
		for (i = 0; i < policy->num_roles; i++) {
			free(policy->roles[i].types);
			free(policy->roles[i].dom_roles);
		}
		free(policy->roles);
	}
	
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
	if (policy->users != NULL) {
		for (i = 0; i < policy->num_users; i++) {
			ap_user_free(&(policy->users[i]));
		}
		free(policy->users);
	}

	/* perm map */
	if(policy->pmap != NULL) {
		free_perm_mapping(policy->pmap);
	}

	/* fs_use */
	if (policy->fs_use != NULL) {
		for (i = 0; i < policy->num_fs_use; i++) {
			free(policy->fs_use[i].fstype);
			security_con_destroy(policy->fs_use[i].scontext);
		}
		free(policy->fs_use);
	}

	/* portcon */
	if (policy->portcon) {
		for (i = 0; i < policy->num_portcon; i++) {
			security_con_destroy(policy->portcon[i].scontext);
		}
		free(policy->portcon);
	}

	/* netifcon */
	if (policy->netifcon) {
		for (i = 0; i < policy->num_netifcon; i++) {
			free(policy->netifcon[i].iface);
			security_con_destroy(policy->netifcon[i].device_context);
			security_con_destroy(policy->netifcon[i].packet_context);
		}
		free(policy->netifcon);
	}

	/* nodecon */
	if (policy->nodecon) {
		for (i = 0; i < policy->num_nodecon; i++) {
			security_con_destroy(policy->nodecon[i].scontext);
		}
		free(policy->nodecon);
	}

	/* genfscon */
	if (policy->genfscon) {
		for (i = 0; i < policy->num_genfscon; i++) {
			ap_genfscon_node_destroy(policy->genfscon[i].paths);
		}
		free(policy->genfscon);
	}

	/* constraints */
	if (policy->constraints) {
		for (i = 0; i < policy->num_constraints; i++) {
			free_ta_list(policy->constraints[i].classes);
			free_ta_list(policy->constraints[i].perms);
			ap_constraint_expr_destroy(policy->constraints[i].expr);
		}
		free(policy->constraints);
	}

	/* validatetrans */
	if (policy->validatetrans) {
		for (i = 0; i < policy->num_validatetrans; i++) {
			free_ta_list(policy->validatetrans[i].classes);
			ap_constraint_expr_destroy(policy->validatetrans[i].expr);
		}
		free(policy->validatetrans);
	}

	/* MLS components */
	if (policy->sensitivities) {
		for (i = 0; i < policy->num_sensitivities; i++) {
			free_name_list(policy->sensitivities[i].aliases);
			free(policy->sensitivities[i].name);
		}
		free(policy->sensitivities);
	}
	if (policy->categories) {
		for (i = 0; i < policy->num_categories; i++) {
			free_name_list(policy->categories[i].aliases);
			free(policy->categories[i].name);
		}
		free(policy->categories);
	}
	if (policy->levels) {
		for (i = 0; i < policy->num_levels; i++) {
			free(policy->levels[i].categories);
		}
		free(policy->levels);
	}
	if (policy->rangetrans) {
		for (i = 0; i < policy->num_rangetrans; i++) {
			free_ta_list(policy->rangetrans[i].src_types);
			free_ta_list(policy->rangetrans[i].tgt_types);
			ap_mls_range_free(policy->rangetrans[i].range);
		}
		free(policy->rangetrans);
	}
	free(policy->mls_dominance);

	if(free_avl_trees(policy) != 0)
		return -1;

	if(policy->avh.tab)
		avh_free(&(policy->avh));

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
	if(rt < 0) {
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
		if (find_int_in_array(type, policy->roles[i].types, policy->roles[i].num_types) >= 0) {
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

int get_type_or_attrib_idx(const char *name, int *idx_type, policy_t *policy) 
{
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

bool_t is_attrib_in_type(const char *attrib, int type_idx, policy_t *policy) 
{
	
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
static bool_t is_name_in_namea(const char *name, int idx_type, int idx, policy_t *policy) 
{
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

bool_t is_type_in_attrib(const char *type, int attrib_idx, policy_t *policy) 
{
	return(is_name_in_namea(type, IDX_ATTRIB, attrib_idx, policy));
}

bool_t is_type_in_role(const char *type, int role_idx, policy_t *policy) 
{
	int type_idx;

	if (!type || !policy || !is_valid_role_idx(role_idx, policy)) {
		errno = EINVAL;
		return FALSE;
	}

	type_idx = get_type_idx(type, policy);
	if (!is_valid_type_idx(type_idx, policy)) {
		errno = EINVAL;
		return FALSE;
	}

	return ((find_int_in_array(type_idx, policy->roles[role_idx].types, policy->roles[role_idx].num_types) != -1) ? TRUE : FALSE);
}

bool_t is_role_in_user(const char *role, int user_idx, policy_t *policy) 
{
	int role_idx;

	if (!role || !policy || !is_valid_user_idx(user_idx, policy)) {
		errno = EINVAL;
		return FALSE;
	}

	role_idx = get_role_idx(role, policy);
	if (!is_valid_role_idx(role_idx, policy)) {
		errno = EINVAL;
		return FALSE;
	}

	return ((find_int_in_array(role_idx, policy->users[user_idx].roles, policy->users[user_idx].num_roles) != -1) ? TRUE : FALSE);
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
	if (!policy || !name || !is_valid_role_idx(idx, policy)) {
		errno = EINVAL;
		return -1;
	}

	*name = strdup(policy->roles[idx].name);
	if (!(*name))
		return -1; /* errno set by strdup */

	return 0;
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

	for (i = 0; i < policy->roles[role].num_types; i++) {
		rt = add_i_to_a(policy->roles[role].types[i], num_types, types);	
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

	for (i = 0; i < policy->users[user].num_roles; i++) {
		rt = add_i_to_a(policy->users[user].roles[i], num_roles, roles);	
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
	if (!policy || !name || idx < 0 || idx >= policy->num_users) {
		errno = EINVAL;
		return -1;
	}

	*name = strdup(policy->users[idx].name);
	if (!(*name))
		return -1; /* errno set by strdup */

	return 0;
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

	if (find_int_in_array(role, policy->users[user].roles, policy->users[user].num_roles) == -1)
		return FALSE;
	else
		return TRUE;
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
	if(policy == NULL || !is_valid_role_idx(role_idx, policy)) {
		errno = EINVAL;
		return -1;
	}

	return(add_i_to_a(type_idx, &(policy->roles[role_idx].num_types), &(policy->roles[role_idx].types)));
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

int add_alias(int type_idx, const char *alias, policy_t *policy)
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
	ap_user_t *new_user= NULL;
		
	if(user == NULL || policy == NULL)
		return -1;
		
	/* make sure there is a room for another role in the array */
	if(policy->list_sz[POL_LIST_USERS] <= policy->num_users) {
		sz = policy->list_sz[POL_LIST_USERS] + LIST_SZ;
		policy->users = (ap_user_t *)realloc(policy->users, sizeof(ap_user_t) * sz);
		if(policy->users == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_USERS] = sz;
	}
	/* next user available */
	new_user = &(policy->users[policy->num_users]);
	new_user->name = user;	/* use the memory passed in */
	new_user->num_roles = 0; 
	new_user->roles = NULL;
	new_user->dflt_level = NULL;
	new_user->range = NULL;
	(policy->rule_cnt[RULE_USER])++;	
	policy->num_users++;
	return policy->num_users - 1;	
}

int add_role_to_user(int role_idx, int user_idx, policy_t *policy)
{
	int i, retv;

	if(policy == NULL || !is_valid_user_idx(user_idx, policy) || !is_valid_role_idx(role_idx, policy))
		return -1;

	/* add all roles dominated by role_idx to user (roles always dominate themselves) */
	for (i = 0; i < policy->roles[role_idx].num_dom_roles; i++) {
		retv = add_i_to_a(policy->roles[role_idx].dom_roles[i], &(policy->users[user_idx].num_roles), &(policy->users[user_idx].roles));
		if (retv)
			return -1;
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
			if (ans && !(rule->flags & (AVFLAG_SRC_TILDA))) {
				(*cnt)++;
				 return TRUE;
			} else if (!ans && (rule->flags & (AVFLAG_SRC_TILDA)) && do_indirect) {
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
			if (ans && !(rule->flags & (AVFLAG_TGT_TILDA))) {
				(*cnt)++;
				 return TRUE;
			} else if (!ans && (rule->flags & (AVFLAG_TGT_TILDA)) && do_indirect) {
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
		if (idx == 0 && type == IDX_TYPE) /* self not valid */
			return FALSE;
		if(rule->flags & (AVFLAG_SRC_STAR)) {
			if(do_indirect ) {
				(*cnt)++;
				return TRUE;
			}
		}
		else {
			ans = type_list_match_by_idx(idx, type, do_indirect, rule->src_types, policy);
			if (ans == -1)
				return -1;
			if(ans && !(rule->flags & (AVFLAG_SRC_TILDA))) {
				(*cnt)++;
				 return TRUE;
			} else if (!ans && (rule->flags & (AVFLAG_SRC_TILDA)) && do_indirect) {
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
			if (ans == -1)
				return -1;
			if (ans && !(rule->flags & (AVFLAG_TGT_TILDA))) {
				(*cnt)++;
				 return TRUE;
			} else if (!ans && (rule->flags & (AVFLAG_TGT_TILDA)) && do_indirect) {
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
	ap_role_t *new_role = NULL;
	ap_role_t *ptr = NULL;
	int retv;
	
	if(role == NULL || policy == NULL)
		return -1;
		
	/* make sure there is a room for another role in the array */
	if(policy->list_sz[POL_LIST_ROLES] <= policy->num_roles) {
		sz = policy->list_sz[POL_LIST_ROLES] + LIST_SZ;
		ptr = (ap_role_t *)realloc(policy->roles, sizeof(ap_role_t) * sz);
		if (ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&ptr[policy->num_roles], 0, sizeof(ap_role_t) * LIST_SZ);
		policy->roles = ptr;
		policy->list_sz[POL_LIST_ROLES] = sz;
	}
	
	/* next role available */
	new_role = &(policy->roles[policy->num_roles]);
	new_role->name = role;	/* use the memory passed in */
	new_role->num_types= 0;
	new_role->types = NULL;
	new_role->num_dom_roles = 0;
	new_role->dom_roles = NULL;
	/* make role dominate itself */
	retv = add_i_to_a(policy->num_roles, &(new_role->num_dom_roles), &(new_role->dom_roles));
	if (retv) {
		return -1;
	}
	policy->num_roles++;
	return policy->num_roles - 1;
}

/* determine whether a role contains a given type (by idx) */
bool_t does_role_use_type(int role, int type, policy_t *policy)
{
	if(policy == NULL || !is_valid_role_idx(role, policy))
		return FALSE;
	if (find_int_in_array(type, policy->roles[role].types, policy->roles[role].num_types) == -1)
		return FALSE;
	else
		return TRUE;
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
					if (do_indirect)
						return !(rule->flags & (AVFLAG_SRC_TILDA));
					else
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
					if (do_indirect) {
						if (!(rule->flags & (AVFLAG_TGT_TILDA))) {
							(*cnt)++;
							return TRUE;
						} else {
							return FALSE;
						}
					} else {
						(*cnt)++;
						return TRUE;
					}
				}
			}
			if (do_indirect && (rule->flags & (AVFLAG_TGT_TILDA))) {
				return TRUE; /* have ~ but didn't find type in list */
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
					if (do_indirect) {
						if (!(rule->flags & (AVFLAG_SRC_TILDA))) {
							(*cnt)++;
							return TRUE;
						} else {
							return FALSE;
						}
					} else {
						(*cnt)++;
						return TRUE;
					}
				}
			}
			if (do_indirect && (rule->flags & (AVFLAG_SRC_TILDA))) {
				return TRUE; /* have ~ but didn't find type in list */
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
			if(ans && !(rule->flags & (AVFLAG_TGT_TILDA))) {
				(*cnt)++;
				 return TRUE;
			} else if (!ans && (rule->flags & (AVFLAG_TGT_TILDA)) && do_indirect) {
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
 * ~ and * handled in extract */
bool_t does_av_rule_use_perms(int rule_idx, int rule_type, int *perm_idxs, int num_perm_idxs, policy_t *policy)
{
	int i, j;
	av_item_t *rule;
	int *rule_perms = NULL, num_rule_perms = 0;
	
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
	if (extract_perms_from_te_rule(rule_idx, rule->type, &rule_perms, &num_rule_perms, policy))
		return FALSE;
	for (i = 0; i < num_rule_perms; i++) {
		for(j = 0; j < num_perm_idxs; j++) {
			if(perm_idxs[j] == rule_perms[i])
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
 * CHANGED
 * NOTE: * in list now returns list of all types to match other expansion behavior
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
	b_types = (bool_t *)calloc(policy->num_types,  sizeof(bool_t));
	if(b_types == NULL) {
		fprintf(stderr, "out of memory");
		ret = -1;
		goto out;
	}

	/* handle star */
	if (((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_STAR)) ||
				((whichlist & TGT_LIST) && (flags & AVFLAG_TGT_STAR))) {
		memset(b_types, TRUE, (policy->num_types) * sizeof(bool_t));
		if ((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_STAR))
			b_types[0] = FALSE; /* self not valid*/
	}

	for(t = tlist; t != NULL; t = t->next) {
		if(t->type == IDX_TYPE) {
			if (find_int_in_array(t->idx, subtracted_types, num_subtracted_types) != -1) {
				continue;
			}
			b_types[t->idx] = TRUE;
		} else if (t->type == IDX_ATTRIB) {
			/* attribute; need to enumerate all the assoicated types */
			int i, tidx;
			
			if (find_int_in_array(t->idx, subtracted_attribs, num_subtracted_attribs) != -1)
				continue;
			for (i = 0; i < policy->attribs[t->idx].num; i++) {
				tidx = policy->attribs[t->idx].a[i];
				b_types[tidx] = TRUE;	
			}
		}
	}
	for (i = 0; i < num_subtracted_types; i++) 
		b_types[subtracted_types[i]] = FALSE;
	if (((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_TILDA)) ||
				((whichlist & TGT_LIST) && (flags & AVFLAG_TGT_TILDA))) {
		for (i = 0; i < (policy->num_types); i++) 
			b_types[i] = !b_types[i];
	}
	if ((whichlist & SRC_LIST) && (flags & AVFLAG_SRC_TILDA))
		b_types[0] = FALSE; /* self not valid*/
	for (i = 0; i < (policy->num_types); i++) {
		if (b_types[i]) {
			if (add_i_to_a(i, num_types, types)){
				fprintf(stderr, "out of memory");
				ret = -1;
				goto out;
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
 * CHANGED
 * NOTE: * in list now returns list of all perms valid for all object classes in the rule
 */
int extract_perms_from_te_rule(int rule_idx, int rule_type, int **perms, int *num_perms, policy_t *policy)
{
	ta_item_t* perm_ptr = NULL;
	av_item_t* rule = NULL;
	bool_t *b_perms = NULL, *v_perms = NULL;
	int *objects = NULL, *obj_perms = NULL;
	int num_objects = 0, num_obj_perms = 0, i, j;


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

	b_perms = (bool_t *)calloc(policy->num_perms, sizeof(bool_t));
	if (!b_perms) {
		return -1;
	}
	v_perms = (bool_t *)calloc(policy->num_perms, sizeof(bool_t));
	if (!v_perms) {
		return -1;
	}

	if (extract_obj_classes_from_te_rule(rule_idx, rule->type, &objects, &num_objects, policy)) {
		return -1;
	}

	
	/* v_perms is array of all valid perms for all listed object classes */
	for (i = 0; i < num_objects; i++) {
		if(get_obj_class_perms(objects[i], &num_obj_perms, &obj_perms, policy))
			return -1;
		for (j = 0; j < num_obj_perms; j++) {
			v_perms[obj_perms[j]] = TRUE;
			/* if star add all valid perms */
			if (rule->flags & AVFLAG_PERM_STAR)
				b_perms[obj_perms[j]] = TRUE;
		}
		free(obj_perms);
		obj_perms = NULL;
		num_obj_perms = 0;
	}

	/* this loop is skipped if star */
	for (perm_ptr = rule->perms; perm_ptr != NULL; perm_ptr = perm_ptr->next) {
		b_perms[perm_ptr->idx] = TRUE;
	}

	/* handle compliment*/
	if (rule->flags & AVFLAG_PERM_TILDA) {
		for (i = 0; i < policy->num_perms; i++)
			if (v_perms[i])
				b_perms[i] = !b_perms[i];
	}

	/* add perms to array to export */
	for (i = 0; i < policy->num_perms; i++) {
		if (b_perms[i]) {
			if (add_i_to_a(i, num_perms, perms) != 0) {
				return -1;
			}
		}
	}
	
	free(b_perms);
	free(v_perms);

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
	
	switch(ta->type & ~(IDX_SUBTRACT)) {
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
	case IDX_USER:
		rt = get_user_name2(ta->idx, name, policy);
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
		policy->list_sz[POL_LIST_COND_EXPRS] += LIST_SZ;
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

int add_fs_use(int behavior, char *fstype, security_con_t *scontext, policy_t *policy)
{
	size_t sz;
	ap_fs_use_t *new_fs_use= NULL;
		
	if((scontext == NULL && behavior != AP_FS_USE_PSID) || policy == NULL || fstype == NULL)
		return -1;
		
	/* make sure there is a room for another fs_use statement in the array */
	if(policy->list_sz[POL_LIST_FS_USE] <= policy->num_fs_use) {
		sz = policy->list_sz[POL_LIST_FS_USE] + LIST_SZ;
		policy->fs_use = (ap_fs_use_t *)realloc(policy->fs_use, sizeof(ap_fs_use_t) * sz);
		if(policy->fs_use == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_FS_USE] = sz;
	}
	/* next available index */
	new_fs_use = &(policy->fs_use[policy->num_fs_use]);
	new_fs_use->fstype = fstype;	/* use the memory passed in */
	new_fs_use->behavior= behavior; 
	new_fs_use->scontext = scontext;	/* use the memory passed in */
	policy->num_fs_use++;

	return 0;
}

int add_portcon(int protocol, int lowport, int highport, security_con_t *scontext, policy_t *policy)
{
	size_t sz;
	ap_portcon_t *new_portcon = NULL;

	if(scontext == NULL || policy == NULL)
		return -1;

	/* make sure there is a room for another portcon statement in the array */
	if(policy->list_sz[POL_LIST_PORTCON] <= policy->num_portcon) {
		sz = policy->list_sz[POL_LIST_PORTCON] + LIST_SZ;
		policy->portcon = (ap_portcon_t *)realloc(policy->portcon, sizeof(ap_portcon_t) * sz);
		if(policy->portcon == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_PORTCON] = sz;
	}
	/* next available index */
	new_portcon = &(policy->portcon[policy->num_portcon]);
	new_portcon->protocol = protocol;
	new_portcon->lowport = lowport;
	new_portcon->highport = highport;
	new_portcon->scontext = scontext; /* use the memory passed in */
	policy->num_portcon++;

	return 0;
}

int add_netifcon(char *iface, security_con_t *devcon, security_con_t *pktcon, policy_t *policy)
{
	size_t sz;
	ap_netifcon_t *new_netifcon = NULL;

	if (!iface || !devcon || !pktcon || !policy)
		return -1;

	/* make sure there is a room for another netifcon statement in the array */
	if(policy->list_sz[POL_LIST_NETIFCON] <= policy->num_netifcon) {
		sz = policy->list_sz[POL_LIST_NETIFCON] + LIST_SZ;
		policy->netifcon = (ap_netifcon_t *)realloc(policy->netifcon, sizeof(ap_netifcon_t) * sz);
		if(policy->netifcon == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_NETIFCON] = sz;
	}
	/* next available index */
	new_netifcon = &(policy->netifcon[policy->num_netifcon]);
	new_netifcon->iface = iface;
	new_netifcon->device_context = devcon;
	new_netifcon->packet_context = pktcon;
	policy->num_netifcon++;

	return 0;
}

int add_nodecon(int flag, uint32_t *addr, uint32_t *mask, security_con_t *scontext, policy_t *policy)
{
	size_t sz;
	ap_nodecon_t *new_nodecon = NULL;
	int i;

	if (!addr || !mask || !scontext || !policy)
		return -1;

	/* make sure there is a room for another nodecon statement in the array */
	if(policy->list_sz[POL_LIST_NODECON] <= policy->num_nodecon) {
		sz = policy->list_sz[POL_LIST_NODECON] + LIST_SZ;
		policy->nodecon = (ap_nodecon_t *)realloc(policy->nodecon, sizeof(ap_nodecon_t) * sz);
		if(policy->nodecon == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_NODECON] = sz;
	}

	new_nodecon = &(policy->nodecon[policy->num_nodecon]);

	new_nodecon->flag = flag;
	for (i = 0; i < 4; i++) {
		new_nodecon->addr[i] = addr[i];
	}
	for (i = 0; i < 4; i++) {
		new_nodecon->mask[i] = mask[i];
	}
	new_nodecon->scontext = scontext;
	policy->num_nodecon++;

	return 0;
}

int add_genfscon(char *fstype, policy_t *policy)
{
	size_t sz;
	ap_genfscon_t *new_genfscon = NULL;

	if (!fstype || !policy)
		return -1;

	/* make sure there is a room for another genfscon statement in the array */
	if(policy->list_sz[POL_LIST_GENFSCON] <= policy->num_genfscon) {
		sz = policy->list_sz[POL_LIST_GENFSCON] + LIST_SZ;
		policy->genfscon = (ap_genfscon_t *)realloc(policy->genfscon, sizeof(ap_genfscon_t) * sz);
		if(policy->genfscon == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_GENFSCON] = sz;
	}
	/* next available index */
	new_genfscon = &(policy->genfscon[policy->num_genfscon]);
	new_genfscon->fstype = fstype;
	new_genfscon->paths = NULL;
	policy->num_genfscon++;

	return 0;
}

int add_path_to_genfscon(ap_genfscon_t *genfscon, char *path, int filetype, security_con_t *context)
{
	ap_genfscon_node_t *new_path_node = NULL;

	if (!genfscon || !path || !context)
		return -1;

	new_path_node = (ap_genfscon_node_t *)calloc(1, sizeof(ap_genfscon_node_t));
	if (!new_path_node) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}

	new_path_node->path = path;
	new_path_node->filetype = filetype;
	new_path_node->scontext = context;
	new_path_node->next = genfscon->paths;
	genfscon->paths = new_path_node;

	return 0;
}

int ap_genfscon_get_idx(char *fstype, policy_t *policy)
{
	int i;

	if (!fstype || !policy)
		return -1;

	for (i = 0; i < policy->num_genfscon; i++) {
		if (!strcmp(policy->genfscon[i].fstype, fstype))
			return i;
	}

	return -1;
}

void ap_genfscon_node_destroy(ap_genfscon_node_t *node)
{
	ap_genfscon_node_t *tmp = NULL, *next = NULL;

	for (tmp = node; tmp; tmp = next) {
		next = tmp->next;
		free(tmp);
	}
}

int add_constraint(bool_t is_mls, ta_item_t *classes, ta_item_t *perms, ap_constraint_expr_t *expr, unsigned long lineno, policy_t *policy)
{
	size_t sz;
	ap_constraint_t *new_constraint = NULL;
	ta_item_t *item = NULL, *obj_class = NULL;

	if (!classes || !perms || !policy)
		return -1;

	/* make sure there is room for another constraint */
	if (policy->list_sz[POL_LIST_CONSTRAINT] <= policy->num_constraints) {
		sz = policy->list_sz[POL_LIST_CONSTRAINT] + LIST_SZ;
		policy->constraints = (ap_constraint_t *)realloc(policy->constraints, sizeof(ap_constraint_t) * sz);
		if (!policy->constraints) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_CONSTRAINT] = sz;
	}

	new_constraint = &(policy->constraints[policy->num_constraints]);

	new_constraint->is_mls = is_mls;
	new_constraint->classes = classes;
	new_constraint->perms = perms;
	new_constraint->expr = expr;
	new_constraint->lineno = lineno;
	policy->num_constraints++;

	/* insert into object class */
	for (obj_class = classes; obj_class; obj_class = obj_class->next) {
		item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
		if (!item) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		item->type = IDX_CONSTRAINT;
		item->idx = policy->num_constraints - 1;
		insert_ta_item(item, &(policy->obj_classes[obj_class->idx].constraints));
		item = NULL;
	}

	return 0;
}

int add_validatetrans(bool_t is_mls, ta_item_t *classes, ap_constraint_expr_t *expr, unsigned long lineno, policy_t *policy)
{
	size_t sz;
	ap_constraint_t *new_vtrx = NULL;
	ta_item_t *item = NULL, *obj_class = NULL;

	if (!classes || !policy)
		return -1;

	/* make sure there is room for another validatetrans */
	if (policy->list_sz[POL_LIST_VALIDATETRANS] <= policy->num_validatetrans) {
		sz = policy->list_sz[POL_LIST_VALIDATETRANS] + LIST_SZ;
		policy->validatetrans = (ap_constraint_t *)realloc(policy->constraints, sizeof(ap_constraint_t) * sz);
		if (!policy->validatetrans) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_VALIDATETRANS] = sz;
	}

	new_vtrx = &(policy->validatetrans[policy->num_validatetrans]);

	new_vtrx->is_mls = is_mls;
	new_vtrx->classes = classes;
	new_vtrx->perms = NULL;
	new_vtrx->expr = expr;
	new_vtrx->lineno = lineno;
	policy->num_validatetrans++;

	/* insert into object class */
	for (obj_class = classes; obj_class; obj_class = obj_class->next) {
		item = (ta_item_t*)calloc(1, sizeof(ta_item_t));
		if (!item) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		item->type = IDX_VALIDATETRANS;
		item->idx = policy->num_validatetrans - 1;
		insert_ta_item(item, &(policy->obj_classes[obj_class->idx].validatetrans));
		item = NULL;
	}

	return 0;
}

int add_sensitivity_alias(int sens, char *alias, policy_t *policy)
{
        char *name;
	if (sens < 0 || sens >= policy->num_sensitivities || alias == NULL || policy == NULL)
		return -1;
        /* strdup() the name */
        if ((name = malloc(strlen(alias) + 1)) == NULL) {
                return -1;
        }
        strcpy(name, alias);
	return add_name(name, &(policy->sensitivities[sens].aliases));
}

/* Sensitivities do not require an order, so they are stored in the order they were
 * added to the policy. */
int add_sensitivity(char *name, name_item_t *aliases, policy_t *policy)
{
	size_t sz;
	ap_mls_sens_t *new_sens;

	if (!name || !policy) /* aliases == NULL is valid */
		return -1;

	/* make sure there is enough room */
	if (policy->list_sz[POL_LIST_SENSITIVITIES] <= policy->num_sensitivities) {
		sz = policy->list_sz[POL_LIST_SENSITIVITIES] + LIST_SZ;
		policy->sensitivities = (ap_mls_sens_t*)realloc(policy->sensitivities, sizeof(ap_mls_sens_t) * sz);
		if(policy->sensitivities == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_SENSITIVITIES] = sz;
	}

	new_sens = &(policy->sensitivities[policy->num_sensitivities]);
	new_sens->name = name;
	new_sens->aliases = aliases;
	policy->num_sensitivities++;

	return 0;
}

int add_category_alias(int category, char *alias, policy_t *policy)
{
        char *name;
	if (category < 0 || category >= policy->num_categories || alias == NULL || policy == NULL)
		return -1;
        /* strdup() the name */
        if ((name = malloc(strlen(alias) + 1)) == NULL) {
                return -1;
        }
        strcpy(name, alias);
	return add_name(name, &(policy->categories[category].aliases));
}

/* Categories have to be stored in order - so the indx is the order or value of the category. 
 * If a category already exists at the index we return -1 */
int add_category(char *name, int idx, name_item_t *aliases, policy_t *policy)
{
	size_t sz, old_sz;
	ap_mls_cat_t *new_cat = NULL;

	if (!name || !policy || idx < 0) /* aliases == NULL is valid */
		return -1;

	/* make sure there is enough room */
	while (idx > policy->list_sz[POL_LIST_CATEGORIES] - 1) {
		old_sz = policy->list_sz[POL_LIST_CATEGORIES];
		sz = policy->list_sz[POL_LIST_CATEGORIES] + LIST_SZ;
		policy->categories = (ap_mls_cat_t*)realloc(policy->categories, sizeof(ap_mls_cat_t) * sz);
		if(policy->categories == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		memset(&(policy->categories[old_sz]), 0, (sz-old_sz) * sizeof(ap_mls_cat_t));
		policy->list_sz[POL_LIST_CATEGORIES] = sz;
	}
	/* check if we have a collision */
	if (policy->categories[idx].name != NULL) {
		fprintf(stderr, "category name collision\n");
		return -1;
	}

	new_cat = &(policy->categories[idx]);
	new_cat->name = name;
	new_cat->aliases = aliases;
	policy->num_categories++;

	return 0;
}

/* defined for sorting category list */
static int int_compar(const void *a, const void *b) {return *(int*)a - *(int*)b;}

int add_mls_level(int sens, int *cats, int num_cats, policy_t *policy)
{
	size_t sz;
	ap_mls_level_t *new_level = NULL;

	if (!policy || (num_cats > 0 && !cats) || num_cats < 0)
		return -1;

	/* make sure there is enough room */
	if (policy->list_sz[POL_LIST_LEVELS] <= policy->num_levels) {
		sz = policy->list_sz[POL_LIST_LEVELS] + LIST_SZ;
		policy->levels = (ap_mls_level_t*)realloc(policy->levels, sizeof(ap_mls_level_t) * sz);
		if (policy->levels == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_LEVELS] = sz;
	}

	qsort(cats, num_cats, sizeof(int), &int_compar);

	new_level = &(policy->levels[policy->num_levels]);
	new_level->sensitivity = sens;
	new_level->categories = cats;
	new_level->num_categories = num_cats;
	policy->num_levels++;

	return 0;
}

int get_sensitivity_idx(const char *name, policy_t *policy)
{
	int i;
	name_item_t *alias = NULL;
	
	if (!name || !policy)
		return -1;

	for (i = 0; i < policy->num_sensitivities; i++) {
		if (!strcmp(name, policy->sensitivities[i].name))
			return i;
		for (alias = policy->sensitivities[i].aliases; alias; alias = alias->next) {
			if (!strcmp(name, alias->name))
				return i;
		}
	}

	return -1;
}

int get_category_idx(const char *name, policy_t *policy)
{
	int i;
	name_item_t *alias = NULL;
	
	if (!name || !policy)
		return -1;

	for (i = 0; i < policy->num_categories; i++) {
		if (!strcmp(name, policy->categories[i].name))
			return i;
		for (alias = policy->categories[i].aliases; alias; alias = alias->next) {
			if (!strcmp(name, alias->name))
				return i;
		}
	}

	return -1;
}


void ap_mls_level_free(ap_mls_level_t *lvl)
{
	if (!lvl)
		return;
	free(lvl->categories);
}

void ap_mls_range_free(ap_mls_range_t *rng)
{
	if (!rng)
		return;

	if (rng->high == rng->low)
		rng->high = NULL; /* to avoid a double free */

	ap_mls_level_free(rng->low);
	ap_mls_level_free(rng->high);
}

void ap_constraint_expr_destroy(ap_constraint_expr_t *expr)
{
	ap_constraint_expr_t *tmp = NULL, *next = NULL;

	if (!expr)
		return;

	for (tmp = expr; tmp; tmp = next) {
		next = tmp->next;
		free_ta_list(tmp->names);
		free(tmp);
	}
}

ap_rangetrans_t *add_new_rangetrans(policy_t *policy)
{
	/* as with av rules return pointer to next available space
	 * so caller can complete the contents */
	size_t sz;
	ap_rangetrans_t *new_rngtr = NULL;

	/* make sure there is enough room */
	if (policy->list_sz[POL_LIST_RANGETRANS] <= policy->num_rangetrans) {
		sz = policy->list_sz[POL_LIST_RANGETRANS] + LIST_SZ;
		policy->rangetrans = (ap_rangetrans_t*)realloc(policy->rangetrans, sizeof(ap_rangetrans_t) * sz);
		if (policy->rangetrans == NULL) {
			fprintf(stderr, "out of memory\n");
			return NULL;
		}
	}

	new_rngtr = &(policy->rangetrans[policy->num_rangetrans]);
	memset(new_rngtr, 0, sizeof(ap_rangetrans_t));
	policy->num_rangetrans++;
	return new_rngtr;
}

/* MLS additions */
bool_t ap_mls_does_level_use_category(ap_mls_level_t *level, int cat)
{
	int retv;

	if (!level)
		return FALSE;

	retv = find_int_in_array(cat, level->categories,  level->num_categories);
	if (retv < 0 || retv > level->num_categories)
		return FALSE;

	return TRUE;
}

bool_t ap_mls_does_range_include_level(ap_mls_range_t *range, ap_mls_level_t *level, policy_t *policy)
{
	int high_cmp = -1, low_cmp = -1;

	if (!policy || !ap_mls_validate_range(range, policy) || !ap_mls_validate_level(level, policy))
		return FALSE;

	if (range->low != range->high) {
		low_cmp = ap_mls_level_compare(range->low, level, policy);
	}

	high_cmp = ap_mls_level_compare(range->high, level, policy);

	if (high_cmp == AP_MLS_EQ || high_cmp == AP_MLS_DOM) {
		if ((low_cmp == AP_MLS_EQ || low_cmp == AP_MLS_DOMBY) && range->low != range->high)
			return TRUE;
		else if (range->low == range->high && level->sensitivity == range->low->sensitivity)
			return TRUE;
	}

	return FALSE;
}

bool_t ap_mls_does_range_contain_subrange(ap_mls_range_t *range, ap_mls_range_t *subrange, policy_t *policy)
{
	if (!policy || !ap_mls_validate_range(subrange, policy)) /* range validity will be checked via ap_mls_does_range_include_level */
		return FALSE;

	if (ap_mls_does_range_include_level(range, subrange->low, policy) && ap_mls_does_range_include_level(range, subrange->high, policy))
		return TRUE;

	return FALSE;
}

int ap_mls_get_sens_dom_val(int sensitivity, policy_t *policy)
{
	if (!policy || sensitivity < 0 || sensitivity > policy->num_sensitivities)
		return -1;

	return find_int_in_array(sensitivity, policy->mls_dominance, policy->num_sensitivities);
}

bool_t ap_mls_validate_level(ap_mls_level_t *level, policy_t *policy)
{
	ap_mls_level_t *plvl = NULL;
	int i;

	if (!level || !policy)
		return FALSE;

	if (level->sensitivity < 0 || level->sensitivity > policy->num_sensitivities)
		return FALSE;

	plvl = ap_mls_sensitivity_get_level(level->sensitivity, policy);
	if (!plvl)
		return FALSE;

	for (i = 0; i < level->num_categories; i++) {
		if (!ap_mls_does_level_use_category(plvl, level->categories[i]))
			return FALSE;
	}

	return TRUE;
}

bool_t ap_mls_validate_range(ap_mls_range_t *range, policy_t *policy)
{
	int retv;

	if (!range || !policy)
		return FALSE;

	if (!ap_mls_validate_level(range->low, policy))
		return FALSE;

	if (range->high != range->low && !ap_mls_validate_level(range->high, policy))
		return FALSE;

	retv = ap_mls_level_compare(range->low, range->high, policy);
	if (retv != AP_MLS_EQ && retv != AP_MLS_DOMBY)
		return FALSE;

	return TRUE;
}

int ap_mls_level_compare(ap_mls_level_t *l1, ap_mls_level_t *l2, policy_t *policy)
{
	int sens_cmp, i;
	bool_t ucat = FALSE;
	int m_list = 0;
	int *cat_list_master = NULL, cat_list_master_sz = 0;
	int *cat_list_subset = NULL, cat_list_subset_sz = 0; 

	if (!policy || !ap_mls_validate_level(l1, policy) || !ap_mls_validate_level(l2, policy))
		return -1;

	sens_cmp = ap_mls_get_sens_dom_val(l1->sensitivity, policy) - ap_mls_get_sens_dom_val(l2->sensitivity, policy);

	if (l1->num_categories < l2->num_categories) {
		m_list = 2;
		cat_list_master = l2->categories;
		cat_list_master_sz = l2->num_categories;
		cat_list_subset = l1->categories;
		cat_list_subset_sz = l1->num_categories;
	} else {
		m_list = 1;
		cat_list_master = l1->categories;
		cat_list_master_sz = l1->num_categories;
		cat_list_subset = l2->categories;
		cat_list_subset_sz = l2->num_categories;
	}

	for (i = 0; i < cat_list_subset_sz; i++) {
		if (find_int_in_array(cat_list_subset[i], cat_list_master, cat_list_master_sz) == -1) {
			ucat = TRUE;
			break;
		}
	}

	if (!sens_cmp && !ucat && l1->num_categories == l2->num_categories)
		return AP_MLS_EQ;

	if (sens_cmp >= 0 && m_list == 1 && !ucat)
		return AP_MLS_DOM;

	if (sens_cmp <= 0 && (m_list == 2 || l1->num_categories == l2->num_categories) && !ucat)
		return AP_MLS_DOMBY;

	return AP_MLS_INCOMP;
}

ap_mls_level_t * ap_mls_sensitivity_get_level(int sens, policy_t *policy)
{
	ap_mls_level_t *lvl = NULL;
	int i;

	if (!policy || sens < 0 || sens > policy->num_sensitivities)
		return NULL;
	
	for (i = 0; i < policy->num_levels; i++) {
		if (policy->levels[i].sensitivity == sens) {
			lvl = &(policy->levels[i]);
			break;
		}
	}

	return lvl;
}

int ap_mls_sens_get_level_cats(int sens, int **cats, int *num_cats, policy_t *policy)
{
	ap_mls_level_t *lvl = NULL;

	if (!policy || sens < 0 || sens > policy->num_sensitivities || !cats || !num_cats)
		return -1;

	lvl = ap_mls_sensitivity_get_level(sens, policy);
	if (!lvl)
		return -1;

	*num_cats = lvl->num_categories;
	if (*num_cats) {
		*cats = (int*)malloc( lvl->num_categories * sizeof(int));
		if (!(*cats))
			return -1;
		memcpy(*cats, lvl->categories, *num_cats * sizeof(int));
	} else {
		*cats = NULL;
	}

	return 0;
}

int ap_mls_category_get_sens(int cat, int **sens, int *num_sens, policy_t *policy)
{
	int retv, i;

	if (!policy || !sens || !num_sens || cat < 0 || cat > policy->num_categories)
		return -1;

	*sens = NULL;
	*num_sens = 0;

	for (i = 0; i < policy->num_levels; i++) {
		retv = find_int_in_array(cat, policy->levels[i].categories, policy->levels[i].num_categories);
		if (retv != -1) {
			retv = add_i_to_a(policy->levels[i].sensitivity, num_sens, sens);
			if (retv) {
				free(*sens);
				*sens = NULL;
				*num_sens = 0;
				return -1;
			}
		}
	}

	return 0;
}

/* dummy array matching function returns true if a1 and a2 have at least one common element*/
static bool_t match_int_arrays(int *a1, int a1_sz, int *a2, int a2_sz)
{
	int i;

	if (!a1 || !a2)
		return FALSE;

	for (i = 0; i < a1_sz; i++) {
		if (find_int_in_array(a1[i], a2, a2_sz) != -1)
			return TRUE;
	}

	return FALSE;
};

int ap_mls_range_transition_search(int *src_types, int num_src_types, int *tgt_types, int num_tgt_types, ap_mls_range_t *range, unsigned char search_type, int **rules, policy_t *policy)
{
	int num_rules = 0,  error = 0;
	int retv, i;
	int *types = NULL, num_types = 0;
	bool_t match = FALSE, add = FALSE;

	if (!policy) {
		errno = EINVAL;
		return -7;
	}

	if (search_type % 8 > 4 || search_type & 0xC0) {
		errno = EINVAL;
		return -6;
	}

	if (search_type & AP_MLS_RTS_RNG_EXACT && !ap_mls_validate_range(range, policy)) {
		errno = EINVAL;
		return -5;
	}

	if (search_type & AP_MLS_RTS_TGT_TYPE) {
		retv = 0;
		if (!tgt_types) {
			retv = -3;
		} else if (!num_tgt_types) {
			retv = -4;
		}
		if (retv) {
			errno = EINVAL;
			return retv;
		}
	}

	if (search_type & (AP_MLS_RTS_SRC_TYPE|AP_MLS_RTS_ANY_TYPE)) {
		retv = 0;
		if (!src_types) {
			retv = -1;
		} else if (!num_src_types) {
			retv = -2;
		}
		if (retv) {
			errno = EINVAL;
			return retv;
		}
	}

	/* options are valid begin search */
	for (i = 0; i < policy->num_rangetrans; i++) {
		match = FALSE;
		add = FALSE;
		if (search_type & (AP_MLS_RTS_SRC_TYPE|AP_MLS_RTS_ANY_TYPE)) {
			retv = extract_types_from_ta_list(policy->rangetrans[i].src_types, policy->rangetrans[i].flags & AVFLAG_SRC_TILDA, 0, &types, &num_types, policy);
			if (retv){
				error = errno;
				goto exit_error;
			}
			match = match_int_arrays(src_types, num_src_types, types, num_types);
			free(types);
			types = NULL;
			num_types = 0;
			if (match && search_type & (AP_MLS_RTS_MATCH_ANY)) {
				add = TRUE;
			} else if (!match && !(search_type & (AP_MLS_RTS_MATCH_ANY))) {
				continue;
			}
		}
		if (search_type & (AP_MLS_RTS_TGT_TYPE)) {
			retv = extract_types_from_ta_list(policy->rangetrans[i].tgt_types, policy->rangetrans[i].flags & AVFLAG_SRC_TILDA, 1, &types, &num_types, policy);
			if (retv){
				error = errno;
				goto exit_error;
			}
			match = match_int_arrays(tgt_types, num_tgt_types, types, num_types);
			free(types);
			types = NULL;
			num_types = 0;
			if (match && search_type & (AP_MLS_RTS_MATCH_ANY)) {
				add = TRUE;
			} else if (!match && !(search_type & (AP_MLS_RTS_MATCH_ANY))) {
				continue;
			}
		}
		if (search_type & (AP_MLS_RTS_ANY_TYPE)) {
			retv = extract_types_from_ta_list(policy->rangetrans[i].tgt_types, policy->rangetrans[i].flags & AVFLAG_SRC_TILDA, 1, &types, &num_types, policy);
			if (retv){
				error = errno;
				goto exit_error;
			}
			match = match_int_arrays(src_types, num_src_types, types, num_types);
			free(types);
			types = NULL;
			num_types = 0;
			if (match && search_type & (AP_MLS_RTS_MATCH_ANY)) {
				add = TRUE;
			} else if (!match && !(search_type & (AP_MLS_RTS_MATCH_ANY))) {
				continue;
			}
		}
		if ((search_type & ~(AP_MLS_RTS_SRC_TYPE|AP_MLS_RTS_TGT_TYPE|AP_MLS_RTS_ANY_TYPE|AP_MLS_RTS_MATCH_ANY)) ==  AP_MLS_RTS_RNG_EXACT) {
			match = FALSE;
			if (ap_mls_level_compare(policy->rangetrans[i].range->low, range->low, policy) == AP_MLS_EQ && ap_mls_level_compare(policy->rangetrans[i].range->high, range->high, policy) == AP_MLS_EQ)
				match = TRUE;
		} else if ((search_type & ~(AP_MLS_RTS_SRC_TYPE|AP_MLS_RTS_TGT_TYPE|AP_MLS_RTS_ANY_TYPE|AP_MLS_RTS_MATCH_ANY)) ==  AP_MLS_RTS_RNG_SUB) {
			match = ap_mls_does_range_contain_subrange(policy->rangetrans[i].range, range, policy);
		} else if ((search_type & ~(AP_MLS_RTS_SRC_TYPE|AP_MLS_RTS_TGT_TYPE|AP_MLS_RTS_ANY_TYPE|AP_MLS_RTS_MATCH_ANY)) ==  AP_MLS_RTS_RNG_SUPER) {
			match = ap_mls_does_range_contain_subrange(range, policy->rangetrans[i].range, policy);
		}
		/* if there was no search criteria */
		if (!(search_type & 0x1F)) {
			match = TRUE;
		}
		if (match) {
			add = TRUE;
		}

		if (add) {
			retv = add_i_to_a(i, &num_rules, rules);
			if (retv) {
				error = errno;
				goto exit_error;
			}
		}
	}

	return num_rules;

exit_error:
	free(*rules);
	*rules = NULL;
	free(types);
	errno = error;
	return -1;
}

int extract_types_from_ta_list(ta_item_t *list, bool_t compliment, bool_t allow_self, int **types, int *num_types, policy_t *policy)
{
	ta_item_t *item = NULL;
	bool_t *inc_types = NULL, *sub_types = NULL, *tmp = NULL;
	int retv, i, error = 0;
	int *attrib_types = NULL, num_attrib_types = 0;

	if (!list || !policy || !types || !num_types) {
		errno = EINVAL;
		return -1;
	}

	inc_types = (bool_t*)calloc(policy->num_types, sizeof(bool_t));
	if (!inc_types) {
		errno = ENOMEM;
		return -1;
	}
	sub_types = (bool_t*)calloc(policy->num_types, sizeof(bool_t));
	if (!sub_types) {
		free(inc_types);
		errno = ENOMEM;
		return -1;
	}

	for (item = list; item; item = item->next) {
		free(attrib_types);
		attrib_types = NULL;
		num_attrib_types = 0;
		if (item->type & IDX_TYPE) {
			if (item->type & IDX_SUBTRACT) {
				sub_types[item->idx] = TRUE;
			} else {
				inc_types[item->idx] = TRUE;
			}
			continue;
		} else if (item->type & IDX_ATTRIB) {
			retv = get_attrib_types(item->idx, &num_attrib_types, &attrib_types, policy);
			if (retv) {
				error = errno;
				goto exit_error;
			}
			if (item->type & IDX_SUBTRACT) {
				tmp = sub_types;
			} else {
				tmp = inc_types;
			}
			for (i = 0; i < num_attrib_types; i++) {
				tmp[attrib_types[i]] = TRUE;
			}
		} else {
			continue; /* neither an attribute nor type? do nothing */
		}
	}

	for (i = 0; i < policy->num_types; i++) {
		if (sub_types[i])
			inc_types[i] = FALSE;
	}

	if (compliment) {
		for (i = 0; i < policy->num_types; i++) {
			inc_types[i] = !inc_types[i];
		}
	}

	*types = NULL;
	*num_types = 0;

	for (i = allow_self?0:1; i < policy->num_types; i++) {
		if(inc_types[i]) {
			retv = add_i_to_a(i, num_types, types);
			if (retv) {
				error = errno;
				goto exit_error;
			}
		}
	}

	free(inc_types);
	free(sub_types);

	return 0;

exit_error:
	free(inc_types);
	free(sub_types);
	/* do not free tmp it points to either inc_ or sub_ */
	free(*types);
	*types = NULL;
	*num_types = 0;
	errno = error;
	return -1;
}

void ap_user_free(ap_user_t *user)
{
	if (!user)
		return;

	free(user->name);
	user->name = NULL;
	free(user->roles);
	user->roles = NULL;
	user->num_roles = 0;
	ap_mls_level_free(user->dflt_level);
	user->dflt_level = NULL;
	ap_mls_range_free(user->range);
	user->range = NULL;
}

void security_con_destroy(security_con_t *context)
{
	if (context == NULL)
		return;
	if (context->range != NULL)
		ap_mls_range_free(context->range);
	free(context);
}

bool_t validate_security_context(const security_con_t *context, policy_t *policy)
{
	if (!context || !policy)
		return FALSE;

	if (!is_valid_user_idx(context->user, policy) || 
	!is_valid_role_idx(context->role, policy) ||
	!is_valid_type_idx(context->type, policy))
		return FALSE;

	if (is_mls_policy(policy) && !ap_mls_validate_range(context->range, policy))
		return FALSE;
	if (context->role != get_role_idx("object_r", policy)) {
		if (!does_user_have_role(context->user, context->role, policy))
			return FALSE;
		if (!does_role_use_type(context->role, context->type, policy))
			return FALSE;
	}
	if (is_mls_policy(policy) && !ap_mls_does_range_contain_subrange(policy->users[context->user].range, context->range, policy))
		return FALSE;

	return TRUE;
}

bool_t match_security_context(security_con_t *context1, security_con_t *context2, unsigned char range_match, policy_t *policy)
{
	if (!context1 || !context2 || !policy)
		return FALSE;

	if (context1->user >= 0 && context2->user >= 0 && context1->user != context2->user)
		return FALSE;
	if (context1->role >= 0 && context2->role >= 0 && context1->role != context2->role)
		return FALSE;
	if (context1->type >= 0 && context2->type >= 0 && context1->type != context2->type)
		return FALSE;

	/* mask out unused bits */
	range_match &= AP_MLS_RTS_RNG_SUB|AP_MLS_RTS_RNG_SUPER|AP_MLS_RTS_RNG_EXACT;

	switch(range_match) {
	case AP_MLS_RTS_RNG_SUB:
	{
		if (!ap_mls_does_range_contain_subrange(context1->range, context2->range, policy))
			return FALSE;
                break;
	}
	case AP_MLS_RTS_RNG_SUPER:
	{
		if (!ap_mls_does_range_contain_subrange(context2->range, context1->range, policy))
			return FALSE;
                break;
	}
	case AP_MLS_RTS_RNG_EXACT: /* EXACT = SUB | SUPER */
	{
		if (ap_mls_level_compare(context1->range->low, context2->range->low, policy) != AP_MLS_EQ || ap_mls_level_compare(context1->range->high, context2->range->high, policy) != AP_MLS_EQ)
			return FALSE;
                break;
	}
	case 0: /* nothing selected - no matching check */
	{
		break;
	}
	default: /* should not be possible to get here */
	{
		assert(0);
		break;
	}
	}

	return TRUE;
}

int ap_genfscon_get_num_paths(policy_t *policy)
{
	int i, num_genfs = 0;
	ap_genfscon_node_t *tmp_node = NULL;

	if (!policy) {
		errno = EINVAL;
		return -1;
	}

	for (i = 0; i < policy->num_genfscon; i++)
		for (tmp_node = policy->genfscon[i].paths; tmp_node; tmp_node = tmp_node->next)
			num_genfs++;

	return num_genfs;
}

/******************** new stuff here ********************/

/**
 * @file policy.c
 *
 * Public interface for SELinux policies.  (FIX ME!)
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <sepol/policydb_query.h>

int apol_policy_is_mls(apol_policy_t *p)
{
	if (p == NULL) {
		return -1;
	}
	return sepol_policydb_is_mls_enabled(p->sh, p->p);
}

__attribute__ ((format (printf, 3, 4)))
void apol_handle_route_to_callback(void *varg, apol_policy_t *p,
				   const char *fmt, ...)
{
	va_list ap;
	if (p != NULL && p->msg_callback != NULL) {
		va_start(ap, fmt);
		p->msg_callback(varg, p, fmt, ap);
		va_end(ap);
	}
}
