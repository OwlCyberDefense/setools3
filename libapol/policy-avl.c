/* Copyright (C) 2002 Tresys Technology, LLC
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
		attrib_item_t * ptr;

		ptr = (attrib_item_t *)realloc(policy->attribs,
					       (LIST_SZ+policy->list_sz[POL_LIST_ATTRIB])
					       * sizeof(attrib_item_t));
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
	policy->attribs[idx].num_types = 0;
	policy->attribs[idx].types = NULL;
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


static int avl_add_class(void *user_data, const void *key, int idx)
{
	policy_t *policy = (policy_t*)user_data;
	char *class = (char*)key;
	
	policy->obj_classes[idx].name = class;
	policy->obj_classes[idx].common_perms = -1;
	policy->obj_classes[idx].num_u_perms = 0;
	policy->obj_classes[idx].u_perms = NULL;
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





