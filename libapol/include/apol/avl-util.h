/**
 * @file avl-util.h
 *
 * Generic avl trees. This data structure is an efficient way to map
 * keys to array indexes. The user of this interface provides 3
 * callback functions and stores all of the data: the avl trees simply
 * provide a fast way to find a specific item in an array.
 *
 * @deprecated This class will be removed very soon.  See bst.h for
 * the preferred way of constructing trees.
 *
 * @author mayerf@tresys.com
 * @author Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2001-2006 Tresys Technology, LLC
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

#ifndef APOL_AVL_UTIL_H
#define APOL_AVL_UTIL_H

typedef int(*apol_avl_compare_t)(void *user_data, const void *a, int idx);
typedef int(*apol_avl_grow_t)(void *user_data, int sz);
typedef int(*apol_avl_add_t)(void *user_data, const void *key, int idx);

typedef struct apol_avl_pointers {
	int	left;
	int	right;
	int	height;
} apol_avl_ptrs_t;

typedef struct apol_avl_tree {
	int head;		/* array idx into associated list */
	int ptrs_len;		/* len of the ptrs array */
	apol_avl_ptrs_t *ptrs;	/* dynamic array to mirror the associated list */
	void *user_data;	/* data passed to the callbacks */
	apol_avl_compare_t compare;  /* callback to compare two keys */
	apol_avl_grow_t grow;	/* callback to request more space */
	apol_avl_add_t add;		/* callback to store a new value */
} apol_avl_tree_t;

/**
 * Search for a specific key within the given AVL tree.
 *
 * @param tree AVL tree to search.
 * @param key Item to find within the tree.
 *
 * @return non-negative index of the key, or < 0 if not found or on
 * error.
 */
extern int apol_avl_get_idx(apol_avl_tree_t *tree, const void *key);

/**
 * Given a pointer to an already allocated tree, initialize its
 * components within.
 *
 * @param tree Pointer to a tree to initialize.
 * @param user_data Arbitrary value, used for callback routines.
 * @param compare Pointer to a comparison function.
 * @param grow Pointer to a function called to reallocate new space
 * for the tree.
 * @param add Pointer to a function to be called when a key is being
 * inserted into the tree.
 *
 * @return 0 on success, < 0 on error.
 */
extern int apol_avl_init(apol_avl_tree_t *tree,
			 void *user_data,
			 apol_avl_compare_t compare,
			 apol_avl_grow_t grow,
			 apol_avl_add_t add);

/**
 * Deallocate all space for the tree, <b>but not the pointer
 * itself</b>.  The caller must still free() the tree pointer as
 * necessary.
 *
 * @param tree Tree to free.
 */
extern void apol_avl_free(apol_avl_tree_t *tree);

/**
 * Try to insert a key into the avl tree.  If the key already exists
 * -2 is returned and newidx is set to the index of the existing key.
 * If the key is inserted 0 or a positive number is returned and
 * newidx is set to the index. -1 is returned on error.
 *
 * @param tree Existing AVL tree.
 * @param key Item to insert into the tree.  <b>This function makes a
 * shallow copy of the key.</b>
 * @param newidx Reference to where to write the index of the key,
 * either where it used to reside or where it does now.
 *
 * @return -2 if the key already existed, -1 on error, or non-negative
 * if the key was now to the tree.
 */
extern int apol_avl_insert(apol_avl_tree_t *tree,
			   void *key,
			   int *newidx);

#endif /* APOL_AVL_UTIL_H */
