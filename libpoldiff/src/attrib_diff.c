/**
 *  @file attrib_diff.c
 *  Implementation for computing a semantic differences in attribs.
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

struct poldiff_attrib_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_attrib {
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_types;
	apol_vector_t *removed_types;
};

void poldiff_attrib_get_stats(poldiff_t *diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->attrib_diffs->num_added;
	stats[1] = diff->attrib_diffs->num_removed;
	stats[2] = diff->attrib_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_attrib_to_string(poldiff_t *diff, const void *attrib)
{
	poldiff_attrib_t *at = (poldiff_attrib_t *) attrib;
	size_t num_added, num_removed, len, i;
	char *s = NULL, *t = NULL, *type;
	if (diff == NULL || attrib == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(at->added_types);
	num_removed = apol_vector_get_size(at->removed_types);
	switch (at->form) {
	case POLDIFF_FORM_ADDED: {
		if (asprintf(&s, "+ %s", at->name) < 0) {
			s = NULL;
			break;
		}
		return s;
	}
	case POLDIFF_FORM_REMOVED: {
		if (asprintf(&s, "- %s", at->name) < 0) {
			s = NULL;
			break;
		}
		return s;
	}
	case POLDIFF_FORM_MODIFIED: {
		if (asprintf(&s, "* %s (", at->name) < 0) {
			s = NULL;
			break;
		}
		len = strlen(s);
		if (num_added > 0) {
			if (asprintf(&t, "%d Added Types", num_added) < 0) {
				t = NULL;
				break;
			}
			if (apol_str_append(&s, &len, t) < 0) {
				break;
			}
			free(t);
			t = NULL;
		}
		if (num_removed > 0) {
			if (asprintf(&t, "%s%d Removed Types",
				     (num_added > 0 ? ", " : ""),
				     num_removed) < 0) {
				t = NULL;
				break;
			}
			if (apol_str_append(&s, &len, t) < 0) {
				break;
			}
			free(t);
			t = NULL;
		}
		if (apol_str_append(&s, &len, ")\n") < 0) {
			break;
		}
		for (i = 0; i < apol_vector_get_size(at->added_types); i++) {
			type = (char *) apol_vector_get_element(at->added_types, i);
			if (asprintf(&t, "\t+ %s\n", type) < 0) {
				t = NULL;
				goto err;
			}
			if (apol_str_append(&s, &len, t) < 0) {
				goto err;
			}
			free(t);
			t = NULL;
		}
		for (i = 0; i < apol_vector_get_size(at->removed_types); i++) {
			type = (char *) apol_vector_get_element(at->removed_types, i);
			if (asprintf(&t, "\t- %s\n", type) < 0) {
				t = NULL;
				goto err;
			}
			if (apol_str_append(&s, &len, t) < 0) {
				goto err;
			}
			free(t);
			t = NULL;
		}
		return s;
	}
	default: {
		ERR(diff, "%s", strerror(ENOTSUP));
		errno = ENOTSUP;
		return NULL;
	}
	}
 err:
	/* if this is reached then an error occurred */
	free(s);
	free(t);
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_attrib_vector(poldiff_t *diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->attrib_diffs->diffs;
}

const char *poldiff_attrib_get_name(const poldiff_attrib_t *attrib)
{
	if (attrib == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return attrib->name;
}

poldiff_form_e poldiff_attrib_get_form(const void *attrib)
{
	if (attrib == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_attrib_t *) attrib)->form;
}

apol_vector_t *poldiff_attrib_get_added_types(const poldiff_attrib_t *attrib)
{
	if (attrib == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return attrib->added_types;
}

apol_vector_t *poldiff_attrib_get_removed_types(const poldiff_attrib_t *attrib)
{
	if (attrib == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return attrib->removed_types;
}

/*************** protected functions for attribs ***************/

poldiff_attrib_summary_t *attrib_summary_create(void)
{
	poldiff_attrib_summary_t *rs = calloc(1, sizeof(*rs));
	if (rs == NULL) {
		return NULL;
	}
	if ((rs->diffs = apol_vector_create()) == NULL) {
		attrib_summary_destroy(&rs);
		return NULL;
	}
	return rs;
}

static void attrib_free(void *elem)
{
	if (elem != NULL) {
		poldiff_attrib_t *t = (poldiff_attrib_t *) elem;
		free(t->name);
		apol_vector_destroy(&t->added_types, free);
		apol_vector_destroy(&t->removed_types, free);
		free(t);
	}
}

void attrib_summary_destroy(poldiff_attrib_summary_t **rs)
{
	if (rs != NULL && *rs != NULL) {
		apol_vector_destroy(&(*rs)->diffs, attrib_free);
		free(*rs);
		*rs = NULL;
	}
}

int attrib_reset(poldiff_t *diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	attrib_summary_destroy(&diff->attrib_diffs);
	diff->attrib_diffs = attrib_summary_create();
	if (diff->attrib_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two attribs from the same policy.
 */
static int attrib_name_comp(const void *x, const void *y, void *arg) {
	qpol_type_t *r1 = (qpol_type_t *) x;
	qpol_type_t *r2 = (qpol_type_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	char *name1, *name2;
	if (qpol_type_get_name(p->p, r1, &name1) < 0 ||
	    qpol_type_get_name(p->p, r2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *attrib_get_items(poldiff_t *diff, apol_policy_t *policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	int error = 0;
	if (qpol_policy_get_type_iter(policy->p, &iter) < 0) {
		return NULL;
	}
	v = apol_vector_create();
	if (v == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		qpol_iterator_destroy(&iter);
		errno = error;
		return NULL;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		unsigned char isattr;
		qpol_type_t *type;
		qpol_iterator_get_item(iter, (void**)&type);
		qpol_type_get_isattr(policy->p, type, &isattr);
		if (isattr) {
			apol_vector_append(v, type);
		}
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort(v, attrib_name_comp, policy);
	return v;
}

int attrib_comp(const void *x, const void *y, poldiff_t *diff)
{
	qpol_type_t *r1 = (qpol_type_t *) x;
	qpol_type_t *r2 = (qpol_type_t *) y;
	char *name1, *name2;
	if (qpol_type_get_name(diff->orig_pol->p, r1, &name1) < 0 ||
	    qpol_type_get_name(diff->mod_pol->p, r2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new attrib difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the attrib that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling attrib_free() upon the returned
 * value.
 */
static poldiff_attrib_t *make_diff(poldiff_t *diff, poldiff_form_e form, char *name)
{
	poldiff_attrib_t *pr;
	int error;
	if ((pr = calloc(1, sizeof(*pr))) == NULL ||
	    (pr->name = strdup(name)) == NULL ||
	    (pr->added_types = apol_vector_create_with_capacity(1)) == NULL ||
	    (pr->removed_types = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		attrib_free(pr);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pr->form = form;
	return pr;
}

int attrib_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item)
{
	qpol_type_t *r = (qpol_type_t *) item;
	char *name = NULL;
	poldiff_attrib_t *pr;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_type_get_name(diff->mod_pol->p, r, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_type_get_name(diff->orig_pol->p, r, &name) < 0)) {
		return -1;
	}
	pr = make_diff(diff, form, name);
	if (pr == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->attrib_diffs->diffs, pr) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		attrib_free(pr);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->attrib_diffs->num_added++;
	}
	else {
		diff->attrib_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given a attrib, return an unsorted vector of its allowed types (in
 * the form of uint32_t corresponding to pseudo-type values).
 *
 * @param diff Policy diff error handler.
 * @param attrib Attrib whose types to get.
 * @param which Which policy, one of POLDIFF_POLICY_ORIG or
 * POLDIFF_POLICY_MOD.
 *
 * @return Vector of pseudo-type values.  The caller is
 * responsible for calling apol_vector_destroy(), passing NULL as the
 * second parameter.  On error, return NULL.
 */
static apol_vector_t *attrib_get_types(poldiff_t *diff, qpol_type_t *attrib, int which)
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
		if (qpol_type_get_type_iter(diff->orig_pol->p, attrib, &iter) < 0) {
			goto cleanup;
		}
	}
	else {
		if (qpol_type_get_type_iter(diff->mod_pol->p, attrib, &iter) < 0) {
			goto cleanup;
		}
	}
	for ( ; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **) &type) < 0 ||
		    (new_val = type_map_lookup(diff, type, which)) == 0) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(v, (void *) new_val) < 0) {
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

int attrib_deep_diff(poldiff_t *diff, const void *x, const void *y)
{
	qpol_type_t *r1 = (qpol_type_t *) x;
	qpol_type_t *r2 = (qpol_type_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	apol_vector_t *added_types = NULL, *removed_types = NULL, *reverse_v;
	char *name, *new_name;
	uint32_t t1, t2;
	poldiff_attrib_t *r = NULL;
	qpol_type_t *t;
	size_t i, j;
	int retval = -1, error = 0;
	if (qpol_type_get_name(diff->orig_pol->p, r1, &name) < 0 ||
	    (v1 = attrib_get_types(diff, r1, POLDIFF_POLICY_ORIG)) == NULL ||
	    (v2 = attrib_get_types(diff, r2, POLDIFF_POLICY_MOD)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort_uniquify(v1, NULL, NULL, NULL);
	apol_vector_sort_uniquify(v2, NULL, NULL, NULL);
	if ((added_types = apol_vector_create()) == NULL ||
	    (removed_types = apol_vector_create()) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	for (i = j = 0; i < apol_vector_get_size(v1); ) {
		if (j >= apol_vector_get_size(v2))
			break;
		t1 = (uint32_t) apol_vector_get_element(v1, i);
		t2 = (uint32_t) apol_vector_get_element(v2, j);
		if (t2 > t1) {
			if (apol_vector_append(removed_types, (void *) t1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		}
		else if (t1 > t2) {
			if (apol_vector_append(added_types, (void *) t2) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		}
		else {
			i++;
			j++;
		}
	}
	for ( ; i < apol_vector_get_size(v1); i++) {
		t1 = (uint32_t) apol_vector_get_element(v1, i);
		if (apol_vector_append(removed_types, (void *) t1) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for ( ; j < apol_vector_get_size(v2); j++) {
		t2 = (uint32_t) apol_vector_get_element(v2, j);
		if (apol_vector_append(added_types, (void *) t2) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_get_size(added_types) > 0 ||
	    apol_vector_get_size(removed_types) > 0) {
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
				if (qpol_type_get_name(diff->orig_pol->p, t, &name) < 0) {
					error = errno;
					goto cleanup;
				}
				if ((new_name = strdup(name)) == NULL ||
				    apol_vector_append(r->removed_types, new_name) < 0) {
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
				if (qpol_type_get_name(diff->mod_pol->p, t, &name) < 0) {
					error = errno;
					goto cleanup;
				}
				if ((new_name = strdup(name)) == NULL ||
				    apol_vector_append(r->added_types, new_name) < 0) {
					error = errno;
					free(new_name);
					ERR(diff, "%s", strerror(error));
					goto cleanup;
				}
			}
		}
		apol_vector_sort(r->removed_types, apol_str_strcmp, NULL);
		apol_vector_sort(r->added_types, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->attrib_diffs->diffs, r) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->attrib_diffs->num_modified++;
	}
	retval = 0;
 cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	apol_vector_destroy(&added_types, NULL);
	apol_vector_destroy(&removed_types, NULL);
	if (retval != 0) {
		attrib_free(r);
	}
	errno = error;
	return retval;
}
