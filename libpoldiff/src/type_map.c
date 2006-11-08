/**
 *  @file type_map.c
 *  Implementation of type equivalence mapping for semantic
 *  difference calculations.
 *  The mapping of types is handled by creating a list of pseudo type
 *  values to represent the set of all semantically unique types in
 *  both the original and modified policies.  This mapping takes into
 *  account both inferred and user specified mappings of types and may
 *  contain holes where a type does not exist in one of the policies.
 *
 *  @author Kevin Carr kcarr@tresys.com
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

#include "poldiff_internal.h"

#include <apol/policy-query.h>
#include <apol/util.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/**
 * A poldiff's type map consists of maps between policies' types to a
 * unified pseudo-type value.
 */
struct type_map
{
	/** array of size num_orig_types mapping types by (value - 1)
	    to pseudo value */
	uint32_t *orig_to_pseudo;
	/** array of size num_mod_types mapping types by (value - 1)
	    to pseudo value */
	uint32_t *mod_to_pseudo;
	/** vector of vector of qpol_type_t that reverse map pseudo
	    value to orig_pol value(s) */
	apol_vector_t *pseudo_to_orig;
	/** vector of vector of qpol_type_t that reverse map pseudo
	    value to mod_pol value(s) */
	apol_vector_t *pseudo_to_mod;
	size_t num_orig_types;
	size_t num_mod_types;
	/** vector of poldiff_type_remap_entry_t */
	apol_vector_t *remap;
};

/**
 * Each map entry consists of 2 vectors, each vector being a list of
 * qpol_type_t.
 */
struct poldiff_type_remap_entry
{
	apol_vector_t *orig_types;
	apol_vector_t *mod_types;
	int enabled;
};

/**
 * Free the space associated with a singly type remap entry.
 *
 * @param elem Pointer to a type remap entry to free.  If NULL then do
 * nothing.
 */
static void poldiff_type_remap_entry_free(void *elem)
{
	poldiff_type_remap_entry_t *entry = (poldiff_type_remap_entry_t *) elem;
	if (entry != NULL) {
		apol_vector_destroy(&entry->orig_types, NULL);
		apol_vector_destroy(&entry->mod_types, NULL);
		free(entry);
	}
}

/**
 * Allocate a new poldiff type remap entry, append it to the current
 * type remap vector, and return the entry.
 *
 * @param diff Policy diff structure containing remap vector.
 *
 * @return a new entry, or NULL on error.
 */
static poldiff_type_remap_entry_t *poldiff_type_remap_entry_create(poldiff_t * diff)
{
	poldiff_type_remap_entry_t *e = NULL;
	if ((e = calloc(1, sizeof(*e))) == NULL ||
	    (e->orig_types = apol_vector_create_with_capacity(1)) == NULL ||
	    (e->mod_types = apol_vector_create_with_capacity(1)) == NULL || apol_vector_append(diff->type_map->remap, e) < 0) {
		poldiff_type_remap_entry_free(e);
		return NULL;
	}
	diff->remapped = 1;
	return e;
}

int poldiff_type_remap_create(poldiff_t * diff, apol_vector_t * orig_names, apol_vector_t * mod_names)
{
	poldiff_type_remap_entry_t *entry = NULL;
	size_t i;
	char *name;
	qpol_type_t *type;
	unsigned char isalias, isattr;
	int retval = -1, error = 0;
	if (diff == NULL || orig_names == NULL || mod_names == NULL) {
		error = EINVAL;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (apol_vector_get_size(orig_names) == 0 ||
	    apol_vector_get_size(mod_names) == 0 || (apol_vector_get_size(orig_names) > 1 && apol_vector_get_size(mod_names) > 1)) {
		error = EINVAL;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if ((entry = calloc(1, sizeof(*entry))) == NULL ||
	    (entry->orig_types = apol_vector_create_with_capacity(1)) == NULL ||
	    (entry->mod_types = apol_vector_create_with_capacity(1)) == NULL) {
		error = ENOMEM;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(orig_names); i++) {
		name = (char *)apol_vector_get_element(orig_names, i);
		if (qpol_policy_get_type_by_name(diff->orig_qpol, name, &type) < 0 ||
		    qpol_type_get_isalias(diff->orig_qpol, type, &isalias) < 0 ||
		    qpol_type_get_isattr(diff->orig_qpol, type, &isattr) < 0) {
			error = errno;
			goto cleanup;
		}
		if (isalias || isattr) {
			error = EINVAL;
			ERR(diff, "%s is not a primary type.", name);
			goto cleanup;
		}
		if (apol_vector_append(entry->orig_types, type) < 0) {
			error = ENOMEM;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (i = 0; i < apol_vector_get_size(mod_names); i++) {
		name = (char *)apol_vector_get_element(mod_names, i);
		if (qpol_policy_get_type_by_name(diff->mod_qpol, name, &type) < 0 ||
		    qpol_type_get_isalias(diff->mod_qpol, type, &isalias) < 0 ||
		    qpol_type_get_isattr(diff->mod_qpol, type, &isattr) < 0) {
			error = errno;
			goto cleanup;
		}
		if (isalias || isattr) {
			error = EINVAL;
			ERR(diff, "%s is not a primary type.", name);
			goto cleanup;
		}
		if (apol_vector_append(entry->mod_types, type) < 0) {
			error = ENOMEM;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_append(diff->type_map->remap, entry) < 0) {
		error = ENOMEM;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	retval = 0;
	diff->remapped = 1;
      cleanup:
	if (retval < 0) {
		poldiff_type_remap_entry_free(entry);
	}
	errno = error;
	return retval;
}

apol_vector_t *poldiff_type_remap_get_entries(poldiff_t * diff)
{
	if (diff == NULL || diff->type_map == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->type_map->remap;
}

void poldiff_type_remap_entry_remove(poldiff_t * diff, poldiff_type_remap_entry_t * entry)
{
	size_t idx;
	if (diff == NULL || entry == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	if (apol_vector_get_index(diff->type_map->remap, entry, NULL, NULL, &idx) < 0) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	apol_vector_remove(diff->type_map->remap, idx);
	diff->remapped = 1;
}

apol_vector_t *poldiff_type_remap_entry_get_original_types(poldiff_t * diff, poldiff_type_remap_entry_t * entry)
{
	apol_vector_t *v = NULL;
	int error;
	size_t i;
	if (diff == NULL || entry == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if ((v = apol_vector_create_with_capacity(apol_vector_get_size(entry->orig_types))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(entry->orig_types); i++) {
		qpol_type_t *t = (qpol_type_t *) apol_vector_get_element(entry->orig_types, i);
		char *name;
		if (qpol_type_get_name(diff->orig_qpol, t, &name) < 0) {
			error = errno;
			apol_vector_destroy(&v, NULL);
			errno = error;
			return NULL;
		}
		if (apol_vector_append(v, name) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			apol_vector_destroy(&v, NULL);
			errno = error;
			return NULL;
		}
	}
	return v;
}

apol_vector_t *poldiff_type_remap_entry_get_modified_types(poldiff_t * diff, poldiff_type_remap_entry_t * entry)
{
	apol_vector_t *v = NULL;
	int error;
	size_t i;
	if (diff == NULL || entry == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	if ((v = apol_vector_create_with_capacity(apol_vector_get_size(entry->mod_types))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	for (i = 0; i < apol_vector_get_size(entry->mod_types); i++) {
		qpol_type_t *t = (qpol_type_t *) apol_vector_get_element(entry->mod_types, i);
		char *name;
		if (qpol_type_get_name(diff->mod_qpol, t, &name) < 0) {
			error = errno;
			apol_vector_destroy(&v, NULL);
			errno = error;
			return NULL;
		}
		if (apol_vector_append(v, name) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			apol_vector_destroy(&v, NULL);
			errno = error;
			return NULL;
		}
	}
	return v;
}

int poldiff_type_remap_entry_get_is_enabled(poldiff_type_remap_entry_t * entry)
{
	if (entry == NULL) {
		errno = EINVAL;
		return -1;
	}
	return entry->enabled;
}

void poldiff_type_remap_entry_set_enabled(poldiff_type_remap_entry_t * entry, int enabled)
{
	if (entry == NULL) {
		errno = EINVAL;
		return;
	}
	if (enabled) {
		entry->enabled = 1;
	} else {
		entry->enabled = 0;
	}
}

type_map_t *type_map_create(void)
{
	type_map_t *map = calloc(1, sizeof(*map));
	if (map == NULL) {
		return NULL;
	}
	if ((map->remap = apol_vector_create()) == NULL) {
		type_map_destroy(&map);
		return NULL;
	}
	return map;
}

/**
 * Free a vector of qpol_type_t pointers.
 */
static void type_map_vector_free(void *elem)
{
	apol_vector_t *v = (apol_vector_t *) elem;
	if (v != NULL) {
		apol_vector_destroy(&v, NULL);
	}
}

void type_map_destroy(type_map_t ** map)
{
	if (map != NULL && *map != NULL) {
		free((*map)->orig_to_pseudo);
		free((*map)->mod_to_pseudo);
		apol_vector_destroy(&(*map)->pseudo_to_orig, type_map_vector_free);
		apol_vector_destroy(&(*map)->pseudo_to_mod, type_map_vector_free);
		apol_vector_destroy(&(*map)->remap, poldiff_type_remap_entry_free);
		free(*map);
		*map = NULL;
	}
}

/**
 * If --enable-debug is given, then dump to stdout the type map from
 * policy's types -> pseudo-types.
 */
static void type_map_dump(poldiff_t * diff)
{
#ifdef SETOOLS_DEBUG
	size_t i, j;
	apol_vector_t *v;
	qpol_type_t *t;
	char *name;
	printf("# type map debug dump (qpol_type_t -> pseudo-type):\norig:\n");
	for (i = 0; i < diff->type_map->num_orig_types; i++) {
		printf("%3d:%5d", i, diff->type_map->orig_to_pseudo[i]);
		if ((i + 1) % 5 == 0) {
			printf("\n");
		} else {
			printf("\t");
		}
	}
	for (i = 0; i < apol_vector_get_size(diff->type_map->pseudo_to_orig); i++) {
		v = apol_vector_get_element(diff->type_map->pseudo_to_orig, i);
		printf("\n%3d->", i);
		for (j = 0; j < apol_vector_get_size(v); j++) {
			t = apol_vector_get_element(v, j);
			qpol_type_get_name(diff->orig_qpol, t, &name);
			printf(" %s", name);
		}
	}
	printf("\nmod:\n");
	for (i = 0; i < diff->type_map->num_mod_types; i++) {
		printf("%3d:%5d", i, diff->type_map->mod_to_pseudo[i]);
		if ((i + 1) % 5 == 0) {
			printf("\n");
		} else {
			printf("\t");
		}
	}
	for (i = 0; i < apol_vector_get_size(diff->type_map->pseudo_to_mod); i++) {
		v = apol_vector_get_element(diff->type_map->pseudo_to_mod, i);
		printf("\n%3d->", i);
		for (j = 0; j < apol_vector_get_size(v); j++) {
			t = apol_vector_get_element(v, j);
			qpol_type_get_name(diff->mod_qpol, t, &name);
			printf(" %s", name);
		}
	}
	printf("\n");
#endif
}

int type_map_build(poldiff_t * diff)
{
	type_map_t *map;
	apol_vector_t *ov = NULL, *mv = NULL;
	int retval = -1, error = 0;
	size_t i, j;
	qpol_type_t *t;
	uint32_t val, max_val, next_val;
	apol_vector_t *reverse_v = NULL;

	if (diff == NULL || diff->type_map == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	map = diff->type_map;
	free(map->orig_to_pseudo);
	map->orig_to_pseudo = NULL;
	map->num_orig_types = 0;
	free(map->mod_to_pseudo);
	map->mod_to_pseudo = NULL;
	map->num_mod_types = 0;
	apol_vector_destroy(&map->pseudo_to_orig, NULL);
	apol_vector_destroy(&map->pseudo_to_mod, NULL);

	if (apol_type_get_by_query(diff->orig_pol, NULL, &ov) < 0 || apol_type_get_by_query(diff->mod_pol, NULL, &mv) < 0) {
		error = errno;
		goto cleanup;
	}

	/* there is no guarantee that the number of types is equal to
	 * the highest type value (because a policy could have
	 * attributes), so calculate them here */
	max_val = 0;
	for (i = 0; i < apol_vector_get_size(ov); i++) {
		t = (qpol_type_t *) apol_vector_get_element(ov, i);
		if (qpol_type_get_value(diff->orig_qpol, t, &val) < 0) {
			error = errno;
			goto cleanup;
		}
		if (val > max_val) {
			max_val = val;
		}
	}
	if ((map->orig_to_pseudo = calloc(max_val, sizeof(*(map->orig_to_pseudo)))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	map->num_orig_types = max_val;
	max_val = 0;
	for (i = 0; i < apol_vector_get_size(mv); i++) {
		t = (qpol_type_t *) apol_vector_get_element(mv, i);
		if (qpol_type_get_value(diff->mod_qpol, t, &val) < 0) {
			error = errno;
			goto cleanup;
		}
		if (val > max_val) {
			max_val = val;
		}
	}
	if ((map->mod_to_pseudo = calloc(max_val, sizeof(*(map->mod_to_pseudo)))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	map->num_mod_types = max_val;

	if ((map->pseudo_to_orig = apol_vector_create()) == NULL || (map->pseudo_to_mod = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}

	next_val = 1;
	for (i = 0; i < apol_vector_get_size(map->remap); i++) {
		poldiff_type_remap_entry_t *e;
		char *name;
		e = (poldiff_type_remap_entry_t *) apol_vector_get_element(map->remap, i);
		if (!e->enabled) {
			continue;
		}

		if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		for (j = 0; j < apol_vector_get_size(e->orig_types); j++) {
			t = (qpol_type_t *) apol_vector_get_element(e->orig_types, j);
			if (qpol_type_get_value(diff->orig_qpol, t, &val) < 0 || qpol_type_get_name(diff->orig_qpol, t, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if (map->orig_to_pseudo[val - 1] != 0) {
				error = EINVAL;
				ERR(diff, "Type %s is already remapped.", name);
				goto cleanup;
			}
			map->orig_to_pseudo[val - 1] = next_val;
			if (apol_vector_append(reverse_v, t) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		if (apol_vector_append(map->pseudo_to_orig, reverse_v) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		reverse_v = NULL;

		if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		for (j = 0; j < apol_vector_get_size(e->mod_types); j++) {
			t = (qpol_type_t *) apol_vector_get_element(e->mod_types, j);
			if (qpol_type_get_value(diff->mod_qpol, t, &val) < 0 || qpol_type_get_name(diff->mod_qpol, t, &name) < 0) {
				error = errno;
				goto cleanup;
			}
			if (map->mod_to_pseudo[val - 1] != 0) {
				error = EINVAL;
				ERR(diff, "Type %s is already remapped.", name);
				goto cleanup;
			}
			map->mod_to_pseudo[val - 1] = next_val;
			if (apol_vector_append(reverse_v, t) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
		}
		if (apol_vector_append(map->pseudo_to_mod, reverse_v) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		reverse_v = NULL;

		next_val++;
	}

	/* all remaining types (both from orig and mod) get their own
	 * values */
	for (i = 0; i < apol_vector_get_size(ov); i++) {
		t = apol_vector_get_element(ov, i);
		if (qpol_type_get_value(diff->orig_qpol, t, &val) < 0) {
			error = errno;
			goto cleanup;
		}
		if (map->orig_to_pseudo[val - 1] == 0) {
			map->orig_to_pseudo[val - 1] = next_val;
			if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL ||
			    apol_vector_append(reverse_v, t) < 0 || apol_vector_append(map->pseudo_to_orig, reverse_v) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL ||
			    apol_vector_append(map->pseudo_to_mod, reverse_v) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			reverse_v = NULL;
			next_val++;
		}
	}
	for (i = 0; i < apol_vector_get_size(mv); i++) {
		t = apol_vector_get_element(mv, i);
		if (qpol_type_get_value(diff->mod_qpol, t, &val) < 0) {
			error = errno;
			goto cleanup;
		}
		if (map->mod_to_pseudo[val - 1] == 0) {
			map->mod_to_pseudo[val - 1] = next_val;
			if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL ||
			    apol_vector_append(reverse_v, t) < 0 || apol_vector_append(map->pseudo_to_mod, reverse_v) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			if ((reverse_v = apol_vector_create_with_capacity(1)) == NULL ||
			    apol_vector_append(map->pseudo_to_orig, reverse_v) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			reverse_v = NULL;
			next_val++;
		}
	}

	type_map_dump(diff);

	retval = 0;
      cleanup:
	apol_vector_destroy(&ov, NULL);
	apol_vector_destroy(&mv, NULL);
	apol_vector_destroy(&reverse_v, NULL);
	error = errno;
	return retval;
}

void poldiff_type_remap_flush(poldiff_t * diff)
{
	if (diff == NULL || diff->type_map == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	apol_vector_destroy(&(diff->type_map->remap), poldiff_type_remap_entry_free);
	/* no error checking below */
	diff->type_map->remap = apol_vector_create();
	diff->remapped = 1;
}

/**
 * Convenience struct for comparing elements within arrays of primary types.
 */
struct type_map_comp
{
	poldiff_t *diff;
	/** from which policy the first element came, either
	 * POLDIFF_POLICY_ORIG or POLDIFF_POLICY_MOD */
	int dir;
};

/**
 * Given two qpol_type_t pointers, both of which are primary types,
 * compare their names for equivalence.
 *
 * @param a Pointer to a qpol_type_t from a policy.
 * @param b Pointer to a qpol_type_t from a policy.
 * @param data Pointer to a type_map_comp struct.
 *
 * @return 0 if the names match, non-zero if not.
 */
static int type_map_primary_comp(const void *a, const void *b, void *data)
{
	qpol_type_t *ta = (qpol_type_t *) a;
	qpol_type_t *tb = (qpol_type_t *) b;
	struct type_map_comp *c = (struct type_map_comp *)data;
	poldiff_t *diff = c->diff;
	int dir = c->dir;
	char *na, *nb;
	if (dir == POLDIFF_POLICY_ORIG) {
		if (qpol_type_get_name(diff->orig_qpol, ta, &na) < 0 || qpol_type_get_name(diff->mod_qpol, tb, &nb) < 0) {
			return -1;
		}
	} else {
		if (qpol_type_get_name(diff->mod_qpol, ta, &na) < 0 || qpol_type_get_name(diff->orig_qpol, tb, &nb) < 0) {
			return -1;
		}
	}
	return strcmp(na, nb);
}

/**
 * Given two qpol_type_t pointers, both of which are primary types,
 * see if the first type matches any of the other type's aliases.
 *
 * @param a Pointer to a qpol_type_t from a policy.
 * @param b Pointer to a qpol_type_t from a policy.
 * @param data Pointer to a type_map_comp struct.
 *
 * @return 0 if b is a member of a's aliases, non-zero if not.
 */
static int type_map_prim_alias_comp(const void *a, const void *b, void *data)
{
	qpol_type_t *ta = (qpol_type_t *) a;
	qpol_type_t *tb = (qpol_type_t *) b;
	struct type_map_comp *c = (struct type_map_comp *)data;
	poldiff_t *diff = c->diff;
	int dir = c->dir;
	char *prim, *alias;
	qpol_iterator_t *iter = NULL;
	if (dir == POLDIFF_POLICY_ORIG) {
		if (qpol_type_get_alias_iter(diff->orig_qpol, ta, &iter) < 0 || qpol_type_get_name(diff->mod_qpol, tb, &prim) < 0) {
			qpol_iterator_destroy(&iter);
			return -1;
		}
	} else {
		if (qpol_type_get_alias_iter(diff->mod_qpol, ta, &iter) < 0 || qpol_type_get_name(diff->orig_qpol, tb, &prim) < 0) {
			qpol_iterator_destroy(&iter);
			return -1;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&alias) < 0) {
			qpol_iterator_destroy(&iter);
			return -1;
		}
		if (strcmp(prim, alias) == 0) {
			qpol_iterator_destroy(&iter);
			return 0;
		}
	}
	qpol_iterator_destroy(&iter);
	return -1;
}

/**
 * Given two qpol_type_t pointers, both of which are primary types,
 * see if the first type's aliases matches the second type's aliases.
 *
 * @param a Pointer to a qpol_type_t from a policy.
 * @param b Pointer to a qpol_type_t from a policy.
 * @param data Pointer to a type_map_comp struct.
 *
 * @return 0 if b is a member of a's aliases, non-zero if not.
 */
static int type_map_prim_aliases_comp(const void *a, const void *b, void *data)
{
	qpol_type_t *ta = (qpol_type_t *) a;
	qpol_type_t *tb = (qpol_type_t *) b;
	struct type_map_comp *c = (struct type_map_comp *)data;
	poldiff_t *diff = c->diff;
	int dir = c->dir;
	qpol_policy_t *p1, *p2;
	qpol_iterator_t *iter1 = NULL, *iter2 = NULL;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	size_t i;
	int retval = -1, error = 0;
	if (dir == POLDIFF_POLICY_ORIG) {
		p1 = diff->orig_qpol;
		p2 = diff->mod_qpol;
	} else {
		p1 = diff->mod_qpol;
		p2 = diff->orig_qpol;
	}
	if (qpol_type_get_alias_iter(p1, ta, &iter1) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((v1 = apol_vector_create_from_iter(iter1)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (qpol_type_get_alias_iter(p2, tb, &iter2) < 0) {
		error = errno;
		goto cleanup;
	}
	if ((v2 = apol_vector_create_from_iter(iter2)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
		retval = 1;
		goto cleanup;
	} else {
		apol_vector_sort_uniquify(v1, apol_str_strcmp, NULL, NULL);
		apol_vector_sort_uniquify(v2, apol_str_strcmp, NULL, NULL);
		retval = apol_vector_compare(v1, v2, apol_str_strcmp, NULL, &i);
	}
      cleanup:
	qpol_iterator_destroy(&iter1);
	qpol_iterator_destroy(&iter2);
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	errno = error;
	return retval;
}

/**
 * If --enable-debug is given, then dump to stdout the type-map from
 * pseudo-types to the policy's type(s).
 */
static void type_remap_vector_dump(poldiff_t * diff)
{
#ifdef SETOOLS_DEBUG
	apol_vector_t *v, *w;
	size_t i, j;
	poldiff_type_remap_entry_t *e;
	char *name;
	printf("# type remap vector debug dump (pseudo-type -> qpol_type_t(s):\n");
	v = poldiff_type_remap_get_entries(diff);
	for (i = 0; i < apol_vector_get_size(v); i++) {
		e = apol_vector_get_element(v, i);
		printf("%d\t%s\t", i, poldiff_type_remap_entry_get_is_enabled(e) ? "en" : "dis");
		w = poldiff_type_remap_entry_get_original_types(diff, e);
		for (j = 0; j < apol_vector_get_size(w); j++) {
			name = apol_vector_get_element(w, j);
			printf("%s ", name);
		}
		apol_vector_destroy(&w, NULL);
		printf("-> ");
		w = poldiff_type_remap_entry_get_modified_types(diff, e);
		for (j = 0; j < apol_vector_get_size(w); j++) {
			name = apol_vector_get_element(w, j);
			printf("%s ", name);
		}
		apol_vector_destroy(&w, NULL);
		printf("\n");
	}
#endif
}

int type_map_infer(poldiff_t * diff)
{
	apol_vector_t *ov = NULL, *mv = NULL;
	char *orig_done = NULL, *mod_done = NULL;
	size_t num_orig, num_mod, i, j;
	qpol_type_t *t, *u;
	struct type_map_comp c = { diff, 0 };
	poldiff_type_remap_entry_t *entry = NULL;
	int retval = -1, error = 0;

	if (diff == NULL || diff->type_map == NULL || diff->type_map->remap == NULL) {
		error = EINVAL;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	INFO(diff, "%s", "Inferring type remap.");
	if (apol_type_get_by_query(diff->orig_pol, NULL, &ov) < 0 || apol_type_get_by_query(diff->mod_pol, NULL, &mv) < 0) {
		error = errno;
		goto cleanup;
	}
	num_orig = apol_vector_get_size(ov);
	num_mod = apol_vector_get_size(mv);
	if ((orig_done = calloc(1, num_orig)) == NULL || (mod_done = calloc(1, num_mod)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}

	/* first map primary <--> primary */
	c.dir = POLDIFF_POLICY_MOD;
	for (i = 0; i < num_orig; i++) {
		t = (qpol_type_t *) apol_vector_get_element(ov, i);
		if (apol_vector_get_index(mv, t, type_map_primary_comp, &c, &j) < 0) {
			continue;
		}
		assert(!mod_done[j]);
		u = (qpol_type_t *) apol_vector_get_element(mv, j);
		if ((entry = poldiff_type_remap_entry_create(diff)) == NULL ||
		    apol_vector_append(entry->orig_types, t) < 0 || apol_vector_append(entry->mod_types, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		entry->enabled = 1;
		orig_done[i] = 1;
		mod_done[j] = 1;
	}

	/* now map primary -> primary's alias */
	c.dir = POLDIFF_POLICY_MOD;
	for (i = 0; i < num_orig; i++) {
		if (orig_done[i]) {
			continue;
		}
		t = (qpol_type_t *) apol_vector_get_element(ov, i);
		u = NULL;
		for (j = 0; j < num_mod; j++) {
			if (mod_done[j]) {
				continue;
			}
			u = (qpol_type_t *) apol_vector_get_element(mv, j);
			if (type_map_prim_alias_comp(u, t, &c) == 0) {
				break;
			}
		}
		if (j >= num_mod) {
			continue;
		}
		if ((entry = poldiff_type_remap_entry_create(diff)) == NULL ||
		    apol_vector_append(entry->orig_types, t) < 0 || apol_vector_append(entry->mod_types, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		entry->enabled = 1;
		orig_done[i] = 1;
		mod_done[j] = 1;
	}

	/* then map primary's alias <- primary */
	c.dir = POLDIFF_POLICY_ORIG;
	for (j = 0; j < num_mod; j++) {
		if (mod_done[j]) {
			continue;
		}
		u = (qpol_type_t *) apol_vector_get_element(mv, j);
		t = NULL;
		for (i = 0; i < num_orig; i++) {
			if (orig_done[i]) {
				continue;
			}
			t = (qpol_type_t *) apol_vector_get_element(ov, i);
			if (type_map_prim_alias_comp(t, u, &c) == 0) {
				break;
			}
		}
		if (i >= num_orig) {
			continue;
		}
		if ((entry = poldiff_type_remap_entry_create(diff)) == NULL ||
		    apol_vector_append(entry->orig_types, t) < 0 || apol_vector_append(entry->mod_types, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		entry->enabled = 1;
		orig_done[i] = 1;
		mod_done[j] = 1;
	}

	/* map alias <-> alias */
	c.dir = POLDIFF_POLICY_MOD;
	for (i = 0; i < num_orig; i++) {
		if (orig_done[i]) {
			continue;
		}
		t = (qpol_type_t *) apol_vector_get_element(ov, i);
		u = NULL;
		for (j = 0; j < num_mod; j++) {
			if (mod_done[j]) {
				continue;
			}
			u = (qpol_type_t *) apol_vector_get_element(mv, j);
			if (type_map_prim_aliases_comp(u, t, &c) == 0) {
				break;
			}
		}
		if (j >= num_mod) {
			continue;
		}
		if ((entry = poldiff_type_remap_entry_create(diff)) == NULL ||
		    apol_vector_append(entry->orig_types, t) < 0 || apol_vector_append(entry->mod_types, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		entry->enabled = 1;
		orig_done[i] = 1;
		mod_done[j] = 1;
	}

	type_remap_vector_dump(diff);

	retval = 0;
	diff->remapped = 1;
      cleanup:
	apol_vector_destroy(&ov, NULL);
	apol_vector_destroy(&mv, NULL);
	free(orig_done);
	free(mod_done);
	errno = error;
	return retval;
}

uint32_t type_map_lookup(poldiff_t * diff, qpol_type_t * type, int which_pol)
{
	uint32_t val;
	if (diff == NULL || type == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (which_pol == POLDIFF_POLICY_ORIG) {
		if (qpol_type_get_value(diff->orig_qpol, type, &val) < 0) {
			return 0;
		}
		assert(val <= diff->type_map->num_orig_types);
		assert(diff->type_map->orig_to_pseudo[val - 1] != 0);
		return diff->type_map->orig_to_pseudo[val - 1];
	} else {
		if (qpol_type_get_value(diff->mod_qpol, type, &val) < 0) {
			return 0;
		}
		assert(val <= diff->type_map->num_mod_types);
		assert(diff->type_map->mod_to_pseudo[val - 1] != 0);
		return diff->type_map->mod_to_pseudo[val - 1];
	}
}

apol_vector_t *type_map_lookup_reverse(poldiff_t * diff, uint32_t val, int which_pol)
{
	if (diff == NULL || val == 0) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return 0;
	}
	if (which_pol == POLDIFF_POLICY_ORIG) {
		return apol_vector_get_element(diff->type_map->pseudo_to_orig, val - 1);
	} else {
		return apol_vector_get_element(diff->type_map->pseudo_to_mod, val - 1);
	}
}
