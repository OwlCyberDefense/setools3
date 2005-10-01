/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * avhash.c
 *
 * Support for semantically examining the TE rules for a policy
 * via a hash table.
 */

#include "avhash.h"
#include "../policy.h"
#include <assert.h>
#include <stdio.h>

#define AVH_HASH(key) ((key->cls + (key->tgt << 2) + (key->src << 9)) & AVH_MASK)


/* adds a datum item (perm or dflt type); will check that perm not already present */
int avh_add_datum(avh_node_t *node, int pidx)
{
	int idx;
	if(node == NULL || !is_te_rule_type(node->key.rule_type)) 
		return -1;
	if(node->key.rule_type > RULE_MAX_AV) {
		/* type rules can only have a single default type; since we deal with source
		 * policy, we have to handle the case of possibly two rules with different types.
		 * So we will do what the compiler does and just take the last one in. */
		if(node->num_data > 0) {
			assert(node->num_data == 1);
			assert(node->data != NULL);
			node->data[0] = pidx;
			return 0;
		}
		return add_i_to_a(pidx, &node->num_data, &node->data);
	}
	
	/* av rule */
	idx = find_int_in_array(pidx, node->data, node->num_data);
	if(idx >= 0)
		return 0; /* perm already present */
	return add_i_to_a(pidx, &node->num_data, &node->data);
}

int avh_add_rule(avh_node_t *node, int ridx, unsigned char hint)
{
	avh_rule_t *newrule;
	
	if(node == NULL)
		return -1;
	newrule = (avh_rule_t *)malloc(sizeof(avh_rule_t));
	if(newrule == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	newrule->rule = ridx;
	newrule->hint = hint;
	newrule->next = NULL;	
	
	if(node->rules == NULL) {
		node->rules = node->last_rule = newrule;
	} else {
		node->last_rule->next = newrule;
		node->last_rule = newrule;
	}
	
	return 0;
}

avh_node_t *avh_find_first_node(avh_t *avh, avh_key_t *key)
{
	int hash;
	avh_node_t *cur;


	if (avh == NULL || key == NULL) {
		assert(0);
		return NULL;
	}

	hash = AVH_HASH(key);
	for (cur = avh->tab[hash]; cur != NULL; cur = cur->next) {
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls == cur->key.cls &&
		    key->rule_type == cur->key.rule_type)
			return cur;

		if (key->src < cur->key.src)
			break;
		if (key->src == cur->key.src && 
		    key->tgt < cur->key.tgt)
			break;
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls < cur->key.cls)
			break;
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls == cur->key.cls &&
		    key->rule_type < cur->key.rule_type)
			break;
	}
	return NULL;
}

/* find next node with same key as "node"; node should be from a previous
 * avh_find_first_node() or avh_find_next_node() call */
avh_node_t *avh_find_next_node(avh_node_t *node)
{
	avh_node_t *cur;

	for(cur = node->next; cur != NULL; cur = cur->next) {
		if (node->key.src == cur->key.src && 
		    node->key.tgt == cur->key.tgt &&
		    node->key.cls == cur->key.cls &&
		    node->key.rule_type == cur->key.rule_type)
			return cur;

		if (node->key.src < cur->key.src)
			break;
		if (node->key.src == cur->key.src && 
		    node->key.tgt < cur->key.tgt)
			break;
		if (node->key.src == cur->key.src && 
		    node->key.tgt == cur->key.tgt &&
		    node->key.cls < cur->key.cls)
			break;
		if (node->key.src == cur->key.src && 
		    node->key.tgt == cur->key.tgt &&
		    node->key.cls == cur->key.cls &&
		    node->key.rule_type < cur->key.rule_type)
			break;
	}
	return NULL;
}

static avh_idx_t *avh_index_create(void)
{
	avh_idx_t *n;
	
	n = (avh_idx_t*)malloc(sizeof(avh_idx_t));
	if (n == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	memset(n, 0, sizeof(avh_idx_t));
	
	return n;
}

static avh_idx_t *avh_idx_find(avh_idx_t *idx, int data)
{
	avh_idx_t *cur, *active;
	
	active = NULL;
	for (cur = idx; cur != NULL; cur = cur->next) {
		if (cur->data == data) {
			active = cur;
			break;
		}
		if (cur->data > data) {
			break;
		}
	}
	
	return active;
}

avh_idx_t *avh_src_type_idx_find(avh_t* avh, int type)
{
	return avh_idx_find(avh->src_type_idx, type);
}

avh_idx_t *avh_tgt_type_idx_find(avh_t *avh, int type)
{
	return avh_idx_find(avh->tgt_type_idx, type);
}

/* inserts node into index - does not check for uniqueness */
static int avh_idx_insert(avh_idx_t **idx, avh_node_t *node, int data)
{
	avh_idx_t *cur, *active, *prev;
	
	prev = NULL;
	active = NULL;
	for (cur = *idx; cur != NULL; cur = cur->next) {
		if (cur->data == data) {
			active = cur;
			break;
		}
		if (cur->data > data) {
			break;
		}
		prev = cur;
	}
	
	/* does not exist in index yet - create new index entry */
	if (active == NULL) {
		active = avh_index_create();
		if (active == NULL) {
			return -1;
		}
		active->data = data;
		if (prev) {
			/* insert into list */
			active->next = prev->next;
			prev->next = active;
		} else {
			if (*idx) {
				/* insert at beginning when list exists */
				active->next = *idx;
			}
			/* actual beginning insert - works with 0 or more current entries */
			*idx = active;
		}
	}
	
	active->nodes = (avh_node_t**)realloc(active->nodes, sizeof(avh_node_t*) * (active->num_nodes + 1));
	if (active->nodes == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	
	active->nodes[active->num_nodes] = node;
	active->num_nodes++;
	
	return 0;
}

/* allows multple insertions of the same key; if you want to ensure uniqueness search first.
 * Returns a pointer to the newly insert node or NULL on error */
avh_node_t *avh_insert(avh_t *avh, avh_key_t *key)
{
	int hash;
	avh_node_t *new_node, *cur, *prev;
	
	if(avh == NULL || key == NULL)
		return NULL;
	assert(is_te_rule_type(key->rule_type));
	
	hash = AVH_HASH(key);
	for (cur = avh->tab[hash], prev = NULL; cur != NULL; prev = cur, cur = cur->next) {
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls == cur->key.cls &&
		    key->rule_type == cur->key.rule_type)
			break;	
		if (key->src < cur->key.src)
			break;
		if (key->src == cur->key.src && 
		    key->tgt < cur->key.tgt)
			break;
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls < cur->key.cls)
			break;
		if (key->src == cur->key.src && 
		    key->tgt == cur->key.tgt &&
		    key->cls == cur->key.cls &&
		    key->rule_type < cur->key.rule_type)
			break;
	}
	new_node = (avh_node_t *)malloc(sizeof(avh_node_t));
	if(new_node == NULL) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}
	memset(new_node, 0, sizeof(avh_node_t));
	new_node->key.src = key->src;
	new_node->key.tgt = key->tgt;
	new_node->key.cls = key->cls;
	new_node->key.rule_type = key->rule_type;
	
	/* do the indexing */
	if (avh_idx_insert(&avh->src_type_idx, new_node, key->src) != 0) {
		return NULL;
	}
	
	if (avh_idx_insert(&avh->tgt_type_idx, new_node, key->tgt) != 0) {
		return NULL;
	}
	
	if(prev != NULL) {
		new_node->next = prev->next;
		prev->next = new_node;
	}
	else {
		new_node->next = avh->tab[hash];
		avh->tab[hash] = new_node;
	}
	avh->num++;
	
	return new_node;
}

int avh_new(avh_t *avh)
{
	int i;
	
	avh->tab = (avh_node_t**)malloc(sizeof(avh_node_t *) * AVH_SIZE);
	if (avh->tab == NULL) {
		fprintf(stderr, "out of memory\n");
		return -1;
	}
	for (i = 0; i < AVH_SIZE; i++)
		avh->tab[i] = NULL;
	avh->num = 0;
	avh->src_type_idx = NULL;
	avh->tgt_type_idx = NULL;
	
	return 0;
}

static void avh_free_rules(avh_rule_t *r)
{
	avh_rule_t *cur, *tmp;
	for(cur = r; cur != NULL; ) {
		tmp = cur;
		cur = tmp->next;
		free(tmp);
	}
	
}

void avh_idx_free(avh_idx_t *idx)
{
	if (idx == NULL)
		return;
		
	avh_idx_t *cur, *next;
	
	for (cur = idx; cur != NULL; ) {
		free(cur->nodes);
		next = cur->next;
		free(cur);
		cur = next;
	}
}

void avh_free(avh_t *avh)
{
	int i;
	avh_node_t *cur, *next;
	
	if(avh == NULL)
		return;
	if(avh->tab == NULL) {
		avh->num = 0;
		return;
	}
	
	for(i = 0; i < AVH_SIZE; i++) {
		for(cur = avh->tab[i]; cur != NULL;) {
			avh_free_rules(cur->rules);
			if(cur->data != NULL) free(cur->data);
			next = cur->next;
			free(cur);
			cur = next;
		}
	}
	free(avh->tab);
	avh->tab = NULL;
	avh->num = 0;
	
	avh_idx_free(avh->src_type_idx);
	avh_idx_free(avh->tgt_type_idx);
}

int avh_eval(avh_t *avh, int *max, int *num_entries, int *num_buckets, int *num_used)
{
	int i, len, total;
	avh_node_t *cur;

	if(avh == NULL || max == NULL || num_entries == NULL || num_buckets == NULL || num_used == NULL)
		return -1;
	
	*num_buckets = AVH_BUCKETS;
	*max = *num_entries = *num_used = total = 0;
	if(avh->tab == NULL) {
		assert(avh->num == 0);
		return 0;
	}
	
	for (i = 0; i < AVH_SIZE; i++) {
		cur = avh->tab[i];
		if (cur != NULL) {
			(*num_used)++;
			len = 0;
			while (cur != NULL) {
				len++;
				cur = cur->next;
			}
			(*num_entries) += len;
			if (len > *max)
				*max = len;
		}
	}

	return 0;
}




