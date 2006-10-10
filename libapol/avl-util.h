/* Copyright (C) 2001-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Authors: mayerf@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
 */

/* avl-util.h
 *
 * Generic avl trees. This data structure is an efficient way
 * to map keys to array indexes. The user of this interface
 * provides 3 callback functions and stores all of the data: the
 * avl trees simply provide a fast way to find a specific item
 * in an array.
 */


#ifndef _APOLICY_AVL_UTIL_H_
#define _APOLICY_AVL_UTIL_H_

typedef int(*avl_compare_t)(void *user_data, const void *a, int idx);
typedef int(*avl_grow_t)(void *user_data, int sz);
typedef int(*avl_add_t)(void *user_data, const void *key, int idx);

/* AVL tree structures */
typedef struct avl_pointers {
	int	left;
	int	right;
	int	height;
} avl_ptrs_t;

typedef struct avl_tree{
	int head;		/* array idx into assoicated list */
	int ptrs_len;		/* len of the ptrs array */
	avl_ptrs_t *ptrs;	/* dynamic array to mirror the assoicated list */
	void *user_data;	/* data passed to the callbacks */
	avl_compare_t compare;  /* callback to compare two keys */
	avl_grow_t grow;	/* callback to request more space */
	avl_add_t add;		/* callback to store a new value */
} avl_tree_t;

int avl_get_idx(const void *key, avl_tree_t *tree);
int avl_init(avl_tree_t *tree, void *user_data, avl_compare_t compare, avl_grow_t grow, avl_add_t add);
void avl_free(avl_tree_t *tree);
int avl_insert(avl_tree_t *tree, void *key, int *newidx);

#endif /* _APOLICY_AVL_UTIL_H_ */







