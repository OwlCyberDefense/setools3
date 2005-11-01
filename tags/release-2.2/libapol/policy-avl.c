/* Copyright (C) 2002-2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mayerf@tresys.com
 */

/* policy-avl.c
 *
 * AVL binary tree functions that are aware of the policy database structure.
 */

#include "policy.h"
#include "util.h"
#include <stdlib.h>
#include <assert.h>
#include "avl-util.h"



static int grow_initial_sid_array(void *user_data, int sz)
{
	initial_sid_t * ptr;
	policy_t *policy = (policy_t*)user_data;
	assert(policy != NULL);

	if (sz > policy->list_sz[POL_LIST_INITIAL_SIDS]) {
	
		ptr = (initial_sid_t *)realloc(policy->initial_sids,
					     (LIST_SZ + policy->list_sz[POL_LIST_INITIAL_SIDS])
					     * sizeof(initial_sid_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->initial_sids = ptr;
		policy->list_sz[POL_LIST_INITIAL_SIDS] += LIST_SZ;
	}
	return 0;
}

static int grow_type_array(void *user_data, int sz)
{
	type_item_t * ptr;
	policy_t *policy = (policy_t*)user_data;
	assert(policy != NULL);

	if (sz > policy->list_sz[POL_LIST_TYPE]) {
		ptr = (type_item_t *)realloc(policy->types,
					     (LIST_SZ + policy->list_sz[POL_LIST_TYPE])
					     * sizeof(type_item_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->types = ptr;
		policy->list_sz[POL_LIST_TYPE] += LIST_SZ;
	}
	return 0;
}

static int grow_attrib_array(void *user_data, int sz)
{
	policy_t *policy = (policy_t*)user_data;
	assert(policy != NULL);
	if (sz > policy->list_sz[POL_LIST_ATTRIB]) {
		/* grow the dynamic array */
		name_a_t * ptr;

		ptr = (name_a_t *)realloc(policy->attribs,
					       (LIST_SZ+policy->list_sz[POL_LIST_ATTRIB])
					       * sizeof(name_a_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->attribs = ptr;
		policy->list_sz[POL_LIST_ATTRIB] += LIST_SZ;
	}
	return 0;
}

static int grow_class_array(void *user_data, int sz)
{
	policy_t *policy = (policy_t*)user_data;
	if (sz > policy->list_sz[POL_LIST_OBJ_CLASSES]) {
		/* grow the dynamic array */
		obj_class_t * ptr;

		ptr = (obj_class_t *)realloc(policy->obj_classes,
					     (LIST_SZ+policy->list_sz[POL_LIST_OBJ_CLASSES])
					     * sizeof(obj_class_t));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->obj_classes = ptr;
		policy->list_sz[POL_LIST_OBJ_CLASSES] += LIST_SZ;
	}
	return 0;
}

static int grow_perm_array(void *user_data, int sz)
{
	policy_t *policy = (policy_t*)user_data;
	if (sz > policy->list_sz[POL_LIST_PERMS]) {
		/* grow the dynamic array */
		char **ptr;

		ptr = (char **)realloc(policy->perms,
				       (LIST_SZ+policy->list_sz[POL_LIST_PERMS])
				       * sizeof(char*));
		if(ptr == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->perms = ptr;
		policy->list_sz[POL_LIST_PERMS] += LIST_SZ;
	}
	return 0;
}

static int grow_cond_bool_array(void *user_data, int sz)
{
	policy_t *policy = (policy_t*)user_data;
	
	if(policy->list_sz[POL_LIST_COND_BOOLS] <= policy->num_cond_bools) {
		sz = policy->list_sz[POL_LIST_COND_BOOLS] + LIST_SZ;
		policy->cond_bools = (cond_bool_t*)realloc(policy->cond_bools, sizeof(cond_bool_t) * sz);
		if(policy->cond_bools == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
		policy->list_sz[POL_LIST_COND_BOOLS] = sz;
	}
	return 0;
}

/* Compare support function for TYPES to use with avl-utils */
static int type_compare(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_type_idx(idx, policy)));
	return strcmp((char*)key, policy->types[idx].name);
}
/* ATTRIB comp function*/
static int attrib_compare(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_attrib_idx(idx, policy)));
	return strcmp((char*)key, policy->attribs[idx].name);
}
/* CLASSES comp function */
static int class_compare(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_obj_class_idx(idx, policy)));
	return strcmp((char*)key, policy->obj_classes[idx].name);
}

/* PERMS comp function */
static int perm_compare(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_perm_idx(idx, policy)));
	return strcmp((char*)key, policy->perms[idx]);
}

/* cond bool comp functions */
static int cond_bool_compare(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_cond_bool_idx(idx, policy)));
	return strcmp((char*)key, policy->cond_bools[idx].name);
}

static int initial_sid_compare( void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	assert(!(key == NULL || policy == NULL || !is_valid_initial_sid_idx(idx, policy)));
	return strcmp((char*)key, policy->initial_sids[idx].name);
}

static int avl_add_attrib(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *attrib = (char*)key;

	policy->attribs[idx].name = (char *) malloc(strlen(attrib)+1);
	if(policy->attribs[idx].name == NULL){
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	strcpy(policy->attribs[idx].name, attrib);
	policy->attribs[idx].num = 0;
	policy->attribs[idx].a = NULL;
	(policy->num_attribs)++;
	return 0;
}

static int avl_add_type(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *type = (char*)key;

	assert(policy != NULL && type != NULL);
	policy->types[idx].name = type;
	policy->types[idx].num_attribs = 0;
	policy->types[idx].aliases = NULL;	
	policy->types[idx].attribs = NULL;
	(policy->num_types)++;
	return 0;
}

static int avl_add_initial_sid(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *isid_name = (char*)key;

	assert(policy != NULL && isid_name != NULL);
	policy->initial_sids[idx].name = isid_name;
	policy->initial_sids[idx].sid = 0;
	policy->initial_sids[idx].scontext = NULL;
	(policy->num_initial_sids)++;
	return 0;
}


static int avl_add_class(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *class = (char*)key;
	
	policy->obj_classes[idx].name = class;
	policy->obj_classes[idx].common_perms = -1;
	policy->obj_classes[idx].num_u_perms = 0;
	policy->obj_classes[idx].u_perms = NULL;
	policy->obj_classes[idx].constraints = NULL;
	policy->obj_classes[idx].validatetrans = NULL;
	(policy->num_obj_classes)++;
	return 0;
}

static int avl_add_perm(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *perm = (char*)key;
	
	policy->perms[idx] = perm;
	(policy->num_perms)++;
	return 0;
}

static int avl_add_cond_bool(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *b = (char*)key;
	
	policy->cond_bools[idx].name = b;
        policy->cond_bools[idx].state = FALSE;
	(policy->num_cond_bools)++;
	return 0;
}

int init_avl_trees(policy_t *policy)
{
	if(policy == NULL)
		return -1;
	
	if (avl_init(&policy->tree[AVL_TYPES], policy, type_compare, grow_type_array, avl_add_type))
		return -1;
	if (avl_init(&policy->tree[AVL_ATTRIBS], policy, attrib_compare, grow_attrib_array, avl_add_attrib))
		return -1;
	if (avl_init(&policy->tree[AVL_CLASSES], policy, class_compare, grow_class_array, avl_add_class))
		return -1;
	if (avl_init(&policy->tree[AVL_PERMS], policy, perm_compare, grow_perm_array, avl_add_perm))
		return -1;
	if (avl_init(&policy->tree[AVL_INITIAL_SIDS], policy, initial_sid_compare, grow_initial_sid_array, avl_add_initial_sid))
		return -1;
	if (avl_init(&policy->tree[AVL_COND_BOOLS], policy, cond_bool_compare, grow_cond_bool_array, avl_add_cond_bool))
		return -1;

	return 0;
}

int free_avl_trees(policy_t *policy)
{
	int i;
	if(policy == NULL)
		return -1;
	for(i = 0; i < AVL_NUM_TREES; i++) {
		avl_free(&policy->tree[i]);
		}
	return 0;
}
