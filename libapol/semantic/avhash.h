/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: mayerf@tresys.com
 *
 * avhash.h
 *
 * Support for semantically examining the TE rules for a policy
 * via a hash table.
 */
 
#ifndef _APOLICY_AVHASH_H_
#define _APOLICY_AVHASH_H_

#include "../util.h"

#define AVH_BITS 15
#define AVH_BUCKETS (1 << AVH_BITS)
#define AVH_MASK (AVH_BUCKETS-1)

#define AVH_SIZE AVH_BUCKETS


/* NOTE: There is no rule type here; the reason is that the key has
 * a rule type which tell you which apol rule list these indicies are
 * for */
typedef struct avh_rule {
	int	rule;		/* rule idx */
	unsigned char hint;	/* hint; indicates whether this rule adds read, write or both */
	struct avh_rule *next;
} avh_rule_t;


typedef struct avh_key {
	int 	src;
	int	tgt;
	int	cls;
	short rule_type; /* see RULE_* ids in policy.h */
} avh_key_t;

typedef struct avh_node {
	avh_key_t 	key;
#define AVH_FLAG_COND	0x01	/* set if conditional rule; otherwise it is non-cond rule */
	unsigned char	flags;
	int 		*data; 	/* array; perms for av rules; SINGLE dlt type for type rules */
	int		num_data;/* sz of data array */
	avh_rule_t 	*rules;	/* rules that contribute to this key; not used in bin policies */
	avh_rule_t	*last_rule;
	int		cond_expr; /* idx of assoicated cond expression if any */
	bool_t		cond_list; /* which list in assoc. cond expr, if any */
	struct avh_node *next;
} avh_node_t;

typedef struct avh {
	avh_node_t 	**tab;
	int		num;	
} avh_t;


/* avh is NOT a pointer, but an actual struct in this macro */
#define avh_hash_table_present(avh) (avh.tab != NULL)

int avh_new(avh_t *avh);
void avh_free(avh_t *avh);
int avh_add_datum(avh_node_t *node, int pidx);
avh_node_t *avh_find_first_node(avh_t *avh, avh_key_t *key);
int avh_add_rule(avh_node_t *node, int ridx, unsigned char hint);
avh_node_t *avh_find_next_node(avh_node_t *node);
avh_node_t *avh_insert(avh_t *avh, avh_key_t *key);
int avh_eval(avh_t *avh, int *max, int *num_entries, int *num_buckets, int *num_used);

#endif /* _APOLICY_AVHASH_H_ */


