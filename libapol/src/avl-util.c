/**
 * @file
 *
 * Generic support functions for AVL trees.
 *
 * @deprecated Use the BST functions in bst.h instead.
 *
 * @author mayerf@tresys.com
 * @author Karl MacMillan <kmacmillan@tresys.com>
 *
 * Copyright (C) 2001-2007 Tresys Technology, LLC
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

#include <config.h>

#include <apol/avl-util.h>
#include <apol/util.h>

#include <assert.h>
#include <stdlib.h>

#define	LEFT	0
#define RIGHT	1

#define  avl_height(idx, list) ((idx < 0) ? -1 : list[idx].height)

#define avl_max_child(idx, list) ((avl_height(list[idx].left, list) - avl_height(list[idx].right, list)) ? \
		avl_height(list[idx].left, list) : avl_height(list[idx].right, list) )

/* single rotated right */
static int avl_srl(int head, apol_avl_ptrs_t * ptrs)
{
	int newhead;

	assert(head >= 0 && ptrs != NULL);
	newhead = ptrs[head].left;
	ptrs[head].left = ptrs[newhead].right;
	ptrs[newhead].right = head;
	ptrs[head].height = avl_max_child(head, ptrs) + 1;
	ptrs[newhead].height = avl_max_child(newhead, ptrs) + 1;
	return newhead;
}

/* single rotate right */
static int avl_srr(int head, apol_avl_ptrs_t * ptrs)
{
	int newhead;

	assert(head >= 0 && ptrs != NULL);
	newhead = ptrs[head].right;
	ptrs[head].right = ptrs[newhead].left;
	ptrs[newhead].left = head;
	ptrs[head].height = avl_max_child(head, ptrs) + 1;
	ptrs[newhead].height = avl_max_child(newhead, ptrs) + 1;
	return newhead;
}

/* double rotate left */
static int avl_drl(int head, apol_avl_ptrs_t * ptrs)
{
	assert(head >= 0 && ptrs != NULL);
	ptrs[head].left = avl_srr(ptrs[head].left, ptrs);
	return avl_srl(head, ptrs);
}

/* double rotate right */
static int avl_drr(int head, apol_avl_ptrs_t * ptrs)
{
	assert(head >= 0 && ptrs != NULL);
	ptrs[head].right = avl_srl(ptrs[head].right, ptrs);
	return avl_srr(head, ptrs);
}

static int avl_get_subtree(int idx, int dir, apol_avl_tree_t * tree)
{
	assert(idx >= 0 && (dir == LEFT || dir == RIGHT) && tree != NULL);
	if (dir == LEFT)
		return tree->ptrs[idx].left;
	else
		return tree->ptrs[idx].right;
}

/* Searches an avl tree looking for a match to key. */
static int do_avl_get_idx(const void *key, int head, apol_avl_tree_t * tree)
{
	int cmpval, subtree;

	if (head < 0)
		return -1;	       /* no match */

	cmpval = tree->compare(tree->user_data, key, head);
	if (cmpval == 0)
		return head;	       /* found! */
	else if (cmpval < 0) {
		subtree = avl_get_subtree(head, LEFT, tree);
		return do_avl_get_idx(key, subtree, tree);
	} else {		       /* (cmpval > 0) */
		subtree = avl_get_subtree(head, RIGHT, tree);
		return do_avl_get_idx(key, subtree, tree);
	}
}

int apol_avl_get_idx(apol_avl_tree_t * tree, const void *key)
{
	assert(key != NULL && tree != NULL);
	return do_avl_get_idx(key, tree->head, tree);
}

static bool_t avl_check_balance(int idx, int dir, apol_avl_tree_t * tree)
{
	int l, r;

	assert(idx >= 0 && (dir == LEFT || dir == RIGHT) && tree != NULL);
	l = avl_height(tree->ptrs[idx].left, tree->ptrs);
	r = avl_height(tree->ptrs[idx].right, tree->ptrs);
	if (dir == LEFT) {
		return (l - r == 2);
	} else {
		return (r - l == 2);
	}
}

int apol_avl_init(apol_avl_tree_t * tree, void *user_data, apol_avl_compare_t compare, apol_avl_grow_t grow, apol_avl_add_t add)
{
	tree->head = -1;
	tree->ptrs = NULL;
	tree->ptrs_len = 0;
	tree->user_data = user_data;
	tree->compare = compare;
	tree->grow = grow;
	tree->add = add;
	return 0;
}

void apol_avl_free(apol_avl_tree_t * tree)
{
	if (tree->ptrs != NULL)
		free(tree->ptrs);
}

static int avl_grow(apol_avl_tree_t * tree)
{
	tree->ptrs_len++;
	tree->ptrs = (apol_avl_ptrs_t *) realloc(tree->ptrs, tree->ptrs_len * sizeof(apol_avl_ptrs_t));

	if (tree->ptrs == NULL) {
		fprintf(stderr, "Out of memory!\n");
		return -1;
	}

	tree->ptrs[tree->ptrs_len - 1].left = -1;
	tree->ptrs[tree->ptrs_len - 1].right = -1;
	tree->ptrs[tree->ptrs_len - 1].height = 0;

	if (tree->grow(tree->user_data, tree->ptrs_len))
		return -1;
	return 0;
}

static int do_avl_insert(apol_avl_tree_t * tree, int head, void *key, int *idx)
{
	int newidx, cmpval, tmpidx, newhead;

	if (head < 0) {
		if (avl_grow(tree))
			return -1;
		newidx = tree->ptrs_len - 1;
		if (tree->add(tree->user_data, key, newidx))
			return -1;
		tree->ptrs[newidx].left = -1;
		tree->ptrs[newidx].right = -1;
		tree->ptrs[newidx].height = 0;
		tree->head = newidx;
		*idx = newidx;
		return newidx;
	}

	cmpval = tree->compare(tree->user_data, key, head);
	/* already exists */
	if (cmpval == 0) {
		*idx = head;
		return -2;
	}
	if (cmpval > 0) {
		tmpidx = do_avl_insert(tree, tree->ptrs[head].right, key, idx);
		if (tmpidx < 0)
			return tmpidx;
		else
			tree->ptrs[head].right = tmpidx;
		if (avl_check_balance(tmpidx, RIGHT, tree)) {
			if (tree->compare(tree->user_data, key, tmpidx) > 0)
				newhead = avl_srr(head, tree->ptrs);
			else
				newhead = avl_drr(head, tree->ptrs);
		} else {
			newhead = head;
		}
	} else {
		tmpidx = do_avl_insert(tree, tree->ptrs[head].left, key, idx);
		if (tmpidx < 0)
			return tmpidx;
		else
			tree->ptrs[head].left = tmpidx;
		if (avl_check_balance(tmpidx, LEFT, tree)) {
			if (tree->compare(tree->user_data, key, tmpidx) < 0)
				newhead = avl_srl(head, tree->ptrs);
			else
				newhead = avl_drl(head, tree->ptrs);
		} else {
			newhead = head;
		}
	}

	tree->ptrs[newhead].height = avl_max_child(newhead, tree->ptrs) + 1;
	return newhead;
}

int apol_avl_insert(apol_avl_tree_t * tree, void *key, int *newidx)
{
	int rt;

	assert(tree != NULL && key != NULL && newidx != NULL);
	rt = do_avl_insert(tree, tree->head, key, newidx);
	if (rt < 0) {
		return rt;
	}
	tree->head = rt;
	return tree->head;
}
