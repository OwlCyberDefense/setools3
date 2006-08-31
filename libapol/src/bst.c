/**
 *  @file bst.c
 *  Contains the implementation of a generic binary search tree (not
 *  even an AVL).
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2006 Tresys Technology, LLC
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

#include <apol/bst.h>
#include <apol/vector.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct bst_node {
	void *elem;
	struct bst_node *left, *right;
} bst_node_t;

/**
 *  Generic vector structure. Stores elements as void*.
 */
struct apol_bst {
	/** Comparison function for nodes. */
	apol_bst_comp_func *cmp;
	/** The number of elements currently stored in the bst. */
	size_t size;
	/** Pointer to top of the tree. */
	bst_node_t *head;
};

apol_bst_t *apol_bst_create(apol_bst_comp_func *cmp)
{
	apol_bst_t *b = NULL;
	if ((b = calloc(1, sizeof(*b))) == NULL) {
		return NULL;
	}
	b->cmp = cmp;
	return b;
}

/**
 * Free the data stored within a bst node, recurse through the node's
 * children, and then the node itself.
 *
 * @param node Node to free.  If NULL then do stop recursing.
 * @param fr Callback to free a node's data.  If NULL then do not free
 * the data.
 */
static void bst_node_free(bst_node_t *node, apol_bst_free_func *fr)
{
	if (node != NULL) {
		if (fr != NULL) {
			fr(node->elem);
		}
		bst_node_free(node->left, fr);
		bst_node_free(node->right, fr);
		free(node);
	}
}

void apol_bst_destroy(apol_bst_t **b, apol_bst_free_func *fr)
{
	if (!b || !(*b))
		return;
	bst_node_free((*b)->head, fr);
	free(*b);
	*b = NULL;
}

/**
 * Given a BST node, traverse the node infix, appending the node's
 * element to vector v.
 *
 * @param node BST node to recurse.
 * @param v Vector to which append.
 *
 * @return 0 on success, < 0 on error.
 */
static int bst_node_to_vector(bst_node_t *node, apol_vector_t *v) {
	int retval;
	if (node == NULL) {
		return 0;
	}
	if ((retval = bst_node_to_vector(node->left, v)) < 0) {
		return retval;
	}
	if ((retval = apol_vector_append(v, node->elem)) < 0) {
		return retval;
	}
	return bst_node_to_vector(node->right, v);
}

apol_vector_t *apol_bst_get_vector(const struct apol_bst *b)
{
	apol_vector_t *v = NULL;
	if (!b) {
		errno = EINVAL;
		return NULL;
	}
	if ((v = apol_vector_create_with_capacity(b->size)) == NULL) {
		return NULL;
	}
	if (bst_node_to_vector(b->head, v) < 0) {
		int error = errno;
		apol_vector_destroy(&v, NULL);
		errno = error;
		return NULL;
	}
	return v;
}


size_t apol_bst_get_size(const apol_bst_t *b)
{
	if (!b) {
		errno = EINVAL;
		return 0;
	} else {
		return b->size;
	}
}

int apol_bst_get_element(const apol_bst_t *b, void *elem,
			 void *data, void **result)
{
	bst_node_t *node;
	int compval;
	if (!b || !elem) {
		errno = EINVAL;
		return -1;
	}
	node = b->head;
	while (node != NULL) {
		if (b->cmp != NULL) {
			compval = b->cmp(node->elem, elem, data);
		}
		else {
			char *p1 = (char *) node->elem;
			char *p2 = (char *) elem;
			if (p1 < p2) {
				compval = -1;
			}
			else if (p1 > p2) {
				compval = 1;
			}
			else {
				compval = 0;
			}
		}
		if (compval == 0) {
			*result = node->elem;
			return 0;
		}
		else if (compval < 0) {
			node = node->left;
		}
		else {
			node = node->right;
		}
	}
	return -1;
}

extern int apol_bst_insert(apol_bst_t *b, void *elem, void *data)
{
	bst_node_t *node, *new_node;
	int compval;
	if (!b || !elem) {
		errno = EINVAL;
		return -1;
	}
	if (b->head == NULL) {
		if ((new_node = calloc(1, sizeof(*node))) == NULL) {
			return -1;
		}
		new_node->elem = elem;
		b->head = new_node;
		b->size++;
		return 0;
	}
	while (node != NULL) {
		if (b->cmp != NULL) {
			compval = b->cmp(node->elem, elem, data);
		}
		else {
			char *p1 = (char *) node->elem;
			char *p2 = (char *) elem;
			if (p1 < p2) {
				compval = -1;
			}
			else if (p1 > p2) {
				compval = 1;
			}
			else {
				compval = 0;
			}
		}
		if (compval == 0) {
			return 1;
		}
		else if (compval < 0) {
			if (node->left == NULL) {
				if ((new_node = calloc(1, sizeof(*node))) == NULL) {
					return -1;
				}
				new_node->elem = elem;
				node->left = new_node;
				b->size++;
				return 0;
			}
			node = node->left;
		}
		else {
			if (node->right == NULL) {
				if ((new_node = calloc(1, sizeof(*node))) == NULL) {
					return -1;
				}
				new_node->elem = elem;
				node->right = new_node;
				b->size++;
				return 0;
			}
			node = node->right;
		}
	}
	/* should never get here */
	errno = EBADRQC;
	assert(0);
	return -1;
}
