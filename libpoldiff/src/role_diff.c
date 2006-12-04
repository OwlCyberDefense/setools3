/**
 *  @file role_diff.c
 *  Implementation for computing a semantic differences in roles.
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

#include <config.h>

#include "poldiff_internal.h"

#include <apol/util.h>
#include <qpol/policy_query.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_role_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_role
{
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_types;
	apol_vector_t *removed_types;
};

void poldiff_role_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->role_diffs->num_added;
	stats[1] = diff->role_diffs->num_removed;
	stats[2] = diff->role_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_role_to_string(poldiff_t * diff, const void *role)
{
	poldiff_role_t *r = (poldiff_role_t *) role;
	size_t num_added, num_removed, len = 0, i;
	char *s = NULL, *type;
	if (diff == NULL || role == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(r->added_types);
	num_removed = apol_vector_get_size(r->removed_types);
	switch (r->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", r->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", r->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf(&s, &len, "* %s (", r->name) < 0) {
				s = NULL;
				break;
			}
			if (num_added > 0) {
				if (apol_str_appendf(&s, &len, "%d Added Types", num_added) < 0) {
					break;
				}
			}
			if (num_removed > 0) {
				if (apol_str_appendf(&s, &len, "%s%d Removed Types", (num_added > 0 ? ", " : ""), num_removed) < 0) {
					break;
				}
			}
			if (apol_str_append(&s, &len, ")\n") < 0) {
				break;
			}
			for (i = 0; i < apol_vector_get_size(r->added_types); i++) {
				type = (char *)apol_vector_get_element(r->added_types, i);
				if (apol_str_appendf(&s, &len, "\t+ %s\n", type) < 0) {
					goto err;
				}
			}
			for (i = 0; i < apol_vector_get_size(r->removed_types); i++) {
				type = (char *)apol_vector_get_element(r->removed_types, i);
				if (apol_str_appendf(&s, &len, "\t- %s\n", type) < 0) {
					goto err;
				}
			}
			return s;
		}
	default:{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
      err:
	/* if this is reached then an error occurred */
	free(s);
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_role_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->role_diffs->diffs;
}

const char *poldiff_role_get_name(const poldiff_role_t * role)
{
	if (role == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role->name;
}

poldiff_form_e poldiff_role_get_form(const void *role)
{
	if (role == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_role_t *)role)->form;
}

apol_vector_t *poldiff_role_get_added_types(const poldiff_role_t * role)
{
	if (role == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role->added_types;
}

apol_vector_t *poldiff_role_get_removed_types(const poldiff_role_t * role)
{
	if (role == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role->removed_types;
}

/*************** protected functions for roles ***************/

poldiff_role_summary_t *role_create(void)
{
	poldiff_role_summary_t *rs = calloc(1, sizeof(*rs));
	if (rs == NULL) {
		return NULL;
	}
	if ((rs->diffs = apol_vector_create()) == NULL) {
		role_destroy(&rs);
		return NULL;
	}
	return rs;
}

static void role_free(void *elem)
{
	if (elem != NULL) {
		poldiff_role_t *r = (poldiff_role_t *) elem;
		free(r->name);
		apol_vector_destroy(&r->added_types, free);
		apol_vector_destroy(&r->removed_types, free);
		free(r);
	}
}

void role_destroy(poldiff_role_summary_t ** rs)
{
	if (rs != NULL && *rs != NULL) {
		apol_vector_destroy(&(*rs)->diffs, role_free);
		free(*rs);
		*rs = NULL;
	}
}

int role_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	role_destroy(&diff->role_diffs);
	diff->role_diffs = role_create();
	if (diff->role_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two roles from the same policy.
 */
static int role_name_comp(const void *x, const void *y, void *arg)
{
	qpol_role_t *r1 = (qpol_role_t *) x;
	qpol_role_t *r2 = (qpol_role_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;
	if (qpol_role_get_name(q, r1, &name1) < 0 || qpol_role_get_name(q, r2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *role_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_role_iter(q, &iter) < 0) {
		return NULL;
	}
	v = apol_vector_create_from_iter(iter);
	if (v == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		qpol_iterator_destroy(&iter);
		errno = error;
		return NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort(v, role_name_comp, policy);
	return v;
}

int role_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_role_t *r1 = (qpol_role_t *) x;
	qpol_role_t *r2 = (qpol_role_t *) y;
	char *name1, *name2;
	if (qpol_role_get_name(diff->orig_qpol, r1, &name1) < 0 || qpol_role_get_name(diff->mod_qpol, r2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new role difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the role that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling role_free() upon the returned
 * value.
 */
static poldiff_role_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_role_t *pr;
	int error;
	if ((pr = calloc(1, sizeof(*pr))) == NULL ||
	    (pr->name = strdup(name)) == NULL ||
	    (pr->added_types = apol_vector_create_with_capacity(1)) == NULL ||
	    (pr->removed_types = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		role_free(pr);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pr->form = form;
	return pr;
}

int role_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_role_t *r = (qpol_role_t *) item;
	char *name = NULL;
	poldiff_role_t *pr;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_role_get_name(diff->mod_qpol, r, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_role_get_name(diff->orig_qpol, r, &name) < 0)) {
		return -1;
	}
	pr = make_diff(diff, form, name);
	if (pr == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->role_diffs->diffs, pr) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		role_free(pr);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->role_diffs->num_added++;
	} else {
		diff->role_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given a role, return an unsorted vector of its allowed types (in
 * the form of uint32_t corresponding to pseudo-type values).
 *
 * @param diff Policy diff error handler.
 * @param role Role whose roles to get.
 * @param which Which policy, one of POLDIFF_POLICY_ORIG or
 * POLDIFF_POLICY_MOD.
 *
 * @return Vector of .  The caller is
 * responsible for calling apol_vector_destroy(), passing NULL as the
 * second parameter.  On error, return NULL.
 */
static apol_vector_t *role_get_types(poldiff_t * diff, qpol_role_t * role, int which)
{
	qpol_iterator_t *iter = NULL;
	qpol_type_t *type;
	uint32_t new_val;
	apol_vector_t *v = NULL;
	int retval = -1, error = 0;

	if ((v = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (which == POLDIFF_POLICY_ORIG) {
		if (qpol_role_get_type_iter(diff->orig_qpol, role, &iter) < 0) {
			goto cleanup;
		}
	} else {
		if (qpol_role_get_type_iter(diff->mod_qpol, role, &iter) < 0) {
			goto cleanup;
		}
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&type) < 0 || (new_val = type_map_lookup(diff, type, which)) == 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(v, (void *)new_val) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&iter);
	if (retval < 0) {
		apol_vector_destroy(&v, NULL);
		errno = error;
		return NULL;
	}
	return v;
}

int role_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_role_t *r1 = (qpol_role_t *) x;
	qpol_role_t *r2 = (qpol_role_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	apol_vector_t *added_types = NULL, *removed_types = NULL, *reverse_v;
	char *name, *new_name;
	uint32_t t1, t2;
	poldiff_role_t *r = NULL;
	qpol_type_t *t;
	size_t i, j;
	int retval = -1, error = 0;

	if (qpol_role_get_name(diff->orig_qpol, r1, &name) < 0 ||
	    (v1 = role_get_types(diff, r1, POLDIFF_POLICY_ORIG)) == NULL ||
	    (v2 = role_get_types(diff, r2, POLDIFF_POLICY_MOD)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort_uniquify(v1, NULL, NULL, NULL);
	apol_vector_sort_uniquify(v2, NULL, NULL, NULL);
	if ((added_types = apol_vector_create()) == NULL || (removed_types = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = j = 0; i < apol_vector_get_size(v1);) {
		if (j >= apol_vector_get_size(v2))
			break;
		t1 = (uint32_t) apol_vector_get_element(v1, i);
		t2 = (uint32_t) apol_vector_get_element(v2, j);
		if (t2 > t1) {
			if (apol_vector_append(removed_types, (void *)t1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (t1 > t2) {
			if (apol_vector_append(added_types, (void *)t2) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		} else {
			i++;
			j++;
		}
	}
	for (; i < apol_vector_get_size(v1); i++) {
		t1 = (uint32_t) apol_vector_get_element(v1, i);
		if (apol_vector_append(removed_types, (void *)t1) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		t2 = (uint32_t) apol_vector_get_element(v2, j);
		if (apol_vector_append(added_types, (void *)t2) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_get_size(added_types) > 0 || apol_vector_get_size(removed_types) > 0) {
		if ((r = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
			error = errno;
			goto cleanup;
		}
		for (i = 0; i < apol_vector_get_size(removed_types); i++) {
			t1 = (uint32_t) apol_vector_get_element(removed_types, i);
			if ((reverse_v = type_map_lookup_reverse(diff, t1, POLDIFF_POLICY_ORIG)) == NULL) {
				error = errno;
				goto cleanup;
			}
			for (j = 0; j < apol_vector_get_size(reverse_v); j++) {
				t = (qpol_type_t *) apol_vector_get_element(reverse_v, j);
				if (qpol_type_get_name(diff->orig_qpol, t, &name) < 0) {
					error = errno;
					goto cleanup;
				}
				if ((new_name = strdup(name)) == NULL || apol_vector_append(r->removed_types, new_name) < 0) {
					error = errno;
					free(new_name);
					ERR(diff, "%s", strerror(error));
					goto cleanup;
				}
			}
		}
		for (i = 0; i < apol_vector_get_size(added_types); i++) {
			t2 = (uint32_t) apol_vector_get_element(added_types, i);
			if ((reverse_v = type_map_lookup_reverse(diff, t2, POLDIFF_POLICY_MOD)) == NULL) {
				error = errno;
				goto cleanup;
			}
			for (j = 0; j < apol_vector_get_size(reverse_v); j++) {
				t = (qpol_type_t *) apol_vector_get_element(reverse_v, j);
				if (qpol_type_get_name(diff->mod_qpol, t, &name) < 0) {
					error = errno;
					goto cleanup;
				}
				if ((new_name = strdup(name)) == NULL || apol_vector_append(r->added_types, new_name) < 0) {
					error = errno;
					free(new_name);
					ERR(diff, "%s", strerror(error));
					goto cleanup;
				}
			}
		}
		apol_vector_sort(r->removed_types, apol_str_strcmp, NULL);
		apol_vector_sort(r->added_types, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->role_diffs->diffs, r) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->role_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	apol_vector_destroy(&added_types, NULL);
	apol_vector_destroy(&removed_types, NULL);
	if (retval != 0) {
		role_free(r);
	}
	errno = error;
	return retval;
}
