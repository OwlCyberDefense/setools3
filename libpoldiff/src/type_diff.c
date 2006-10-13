/**
 *  @file type_diff.c
 *  Implementation for computing a semantic differences in types.
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
#include <assert.h>

/******************** types ********************/

struct poldiff_type_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	int are_diffs_sorted;
	apol_vector_t *diffs;
};

struct poldiff_type {
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_attribs;
	apol_vector_t *removed_attribs;
};

void poldiff_type_get_stats(poldiff_t *diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->type_diffs->num_added;
	stats[1] = diff->type_diffs->num_removed;
	stats[2] = diff->type_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_type_to_string(poldiff_t *diff, const void *type)
{
	poldiff_type_t *t = (poldiff_type_t *) type;
	size_t num_added, num_removed, len, i;
	char *s = NULL, *n = NULL, *attrib;

	if (diff == NULL || type == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(t->added_attribs);
	num_removed = apol_vector_get_size(t->removed_attribs);
	switch (t->form) {
	case POLDIFF_FORM_ADDED: {
		if (asprintf(&s, "+ %s", t->name) < 0) {
			s = NULL;
			break;
		}
		return s;
	}
	case POLDIFF_FORM_REMOVED: {
		if (asprintf(&s, "- %s", t->name) < 0) {
			s = NULL;
			break;
		}
		return s;
	}
	case POLDIFF_FORM_MODIFIED: {
		if (asprintf(&s, "* %s (", t->name) < 0) {
			s = NULL;
			break;
		}
		len = strlen(s);
		if (num_added > 0) {
			if (asprintf(&n, "%d Added Attributes", num_added) < 0) {
				n = NULL;
				break;
			}
			if (apol_str_append(&s, &len, n) < 0) {
				break;
			}
			free(n);
			n = NULL;
		}
		if (num_removed > 0) {
			if (asprintf(&n, "%s%d Removed Attributes",
				     (num_added > 0 ? ", " : ""),
				     num_removed) < 0) {
				n = NULL;
				break;
			}
			if (apol_str_append(&s, &len, n) < 0) {
				break;
			}
			free(n);
			n = NULL;
		}
		if (apol_str_append(&s, &len, ")\n") < 0) {
			break;
		}
		for (i = 0; i < apol_vector_get_size(t->added_attribs); i++) {
			attrib = (char *) apol_vector_get_element(t->added_attribs, i);
			if (asprintf(&n, "\t+ %s\n", attrib) < 0) {
				n = NULL;
				goto err;
			}
			if (apol_str_append(&s, &len, n) < 0) {
				goto err;
			}
			free(n);
			n = NULL;
		}
		for (i = 0; i < apol_vector_get_size(t->removed_attribs); i++) {
			attrib = (char *) apol_vector_get_element(t->removed_attribs, i);
			if (asprintf(&n, "\t- %s\n", attrib) < 0) {
				n = NULL;
				goto err;
			}
			if (apol_str_append(&s, &len, n) < 0) {
				goto err;
			}
			free(n);
			n = NULL;
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
	free(n);
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
	return NULL;
}

static int poldiff_type_comp(const void *a, const void *b, void *data __attribute__((unused)))
{
	const poldiff_type_t *t1 = a;
	const poldiff_type_t *t2 = b;
	return strcmp(t1->name, t2->name);
}

apol_vector_t *poldiff_get_type_vector(poldiff_t *diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	/* the elements of the results vector are not sorted by name,
	   but by pseudo-type value.  thus sort them by name as
	   necessary */
        if (!diff->type_diffs->are_diffs_sorted) {
		apol_vector_sort(diff->type_diffs->diffs, poldiff_type_comp, NULL);
		diff->type_diffs->are_diffs_sorted = 1;
        }
	return diff->type_diffs->diffs;
}

const char *poldiff_type_get_name(const poldiff_type_t *type)
{
	if (type == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return type->name;
}

poldiff_form_e poldiff_type_get_form(const void *type)
{
	if (type == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_type_t *) type)->form;
}

apol_vector_t *poldiff_type_get_added_attribs(const poldiff_type_t *type)
{
	if (type == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return type->added_attribs;
}

apol_vector_t *poldiff_type_get_removed_attribs(const poldiff_type_t *type)
{
	if (type == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return type->removed_attribs;
}

/*************** protected functions for types ***************/

/**
 * Destroy a specified type
 * @param type The type to destroy (a poldiff_type_t object)
 */
static void type_destroy(void *type)
{
	poldiff_type_t *t;
	if (type == NULL)
		return;
	t = (poldiff_type_t*)type;
	free(t->name);
	apol_vector_destroy(&(t->added_attribs), &free);
	apol_vector_destroy(&(t->removed_attribs), &free);
	free(t);
}

void type_summary_destroy(poldiff_type_summary_t **type)
{
	if (type != NULL && *type != NULL) {
		apol_vector_destroy(&(*type)->diffs, &type_destroy);
		free(*type);
		*type = NULL;
	}
}

poldiff_type_summary_t *type_summary_create(void)
{
	poldiff_type_summary_t *type = calloc(1, sizeof(*type));
	if (type == NULL) {
		return NULL;
	}
	if ((type->diffs = apol_vector_create()) == NULL) {
		type_summary_destroy(&type);
		return NULL;
	}
	return type;
}

apol_vector_t *type_get_items(poldiff_t *diff, apol_policy_t *policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	int error = 0;
	qpol_type_t *t;
	unsigned char isattr, isalias;
	uint32_t val;

	if (diff == NULL || policy == NULL) {
		error = errno = EINVAL;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
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
		qpol_iterator_get_item(iter, (void**)&t);
		qpol_type_get_isalias(policy->p, t, &isalias);
		qpol_type_get_isattr(policy->p, t, &isattr);
		if (isattr || isalias)
			continue;
		val = type_map_lookup(diff, t, policy == diff->orig_pol ?
				      POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
		apol_vector_append(v, (void*)val);
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort_uniquify(v, NULL, NULL, NULL);
	return v;
}


int type_reset(poldiff_t *diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	type_summary_destroy(&diff->type_diffs);
	diff->type_diffs = type_summary_create();
	if (diff->type_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Compare two type map values
 * @param x The first type to compare, a (uint32_t) value
 * @param y The second type to compare, a (uint32_t) value
 * @param diff The policy difference structure
 *
 * @return < 0, 0, or > 0, if x is respectively less than
 * equal to, or greater than y.
 */
int type_comp(const void *x, const void *y, poldiff_t *diff)
{
	uint32_t p1val = (uint32_t)x;
	uint32_t p2val = (uint32_t)y;

	/* p1val == p2val means the types are semantically equivalent */
	return p1val - p2val;
}

/**
 * Allocate and return a new type difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the type that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling type_destroy() upon the
 * returned value.
 */
static poldiff_type_t *make_diff(poldiff_t *diff, poldiff_form_e form, char *name)
{
	poldiff_type_t *pt;
	int error;

	if ((pt = calloc(1, sizeof(poldiff_type_t))) == NULL ||
	    (pt->name = strdup(name)) == NULL ||
	    (pt->added_attribs = apol_vector_create_with_capacity(1)) == NULL ||
	    (pt->removed_attribs = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		type_destroy(pt);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pt->form = form;
	return pt;
}

static char* type_get_name(poldiff_t *diff, poldiff_form_e form, uint32_t tval)
{
	apol_vector_t *v1, *v2;
	size_t sv1, sv2;
	size_t i, len;
	qpol_type_t *qtype;
	char *name = NULL, *ret = NULL;

	/* names mapped from the first policy */
	v1 = type_map_lookup_reverse(diff, tval, POLDIFF_POLICY_ORIG);
	sv1 = apol_vector_get_size(v1);
	/* names mapped from the second policy */
	v2 = type_map_lookup_reverse(diff, tval, POLDIFF_POLICY_MOD);
	sv2 = apol_vector_get_size(v2);

	if (sv1 == 1 && sv2 == 0) {
		/* return the name in v1 */
		qtype = apol_vector_get_element(v1, 0);
		qpol_type_get_name(diff->orig_pol->p, qtype, &name);
		ret = strdup(name);
	} else if (sv1 == 0 && sv2 == 1) {
		/* return the name in v2 */
		qtype = apol_vector_get_element(v2, 0);
		qpol_type_get_name(diff->mod_pol->p, qtype, &name);
		ret = strdup(name);
	} else {
		/* if the single name in v1 and v2 is the same return that name */
		if (sv1 == sv2 && sv2 == 1) {
			char *name2;
			qpol_type_t *qtype2;
			qtype = apol_vector_get_element(v1, 0);
			qtype2 = apol_vector_get_element(v2, 0);
			qpol_type_get_name(diff->orig_pol->p, qtype, &name);
			qpol_type_get_name(diff->mod_pol->p, qtype2, &name2);
			if (strcmp(name, name2) == 0) {
				ret = strdup(name);
				goto exit;
			}
		}
		/* build and return the composite name */
		for (i = 0; i < sv1; i++) {
			qtype = apol_vector_get_element(v1, i);
			if (i > 0) {
				len = strlen(", ");
				apol_str_append(&ret, &len, ", ");
			}
			qpol_type_get_name(diff->orig_pol->p, qtype, &name);
			apol_str_append(&ret, &len, name);
		}
		apol_str_append(&ret, &len, " -> ");
		for (i = 0; i < sv2; i++) {
			qtype = apol_vector_get_element(v2, i);
			if (i > 0) {
				apol_str_append(&ret, &len, ", ");
			}
			qpol_type_get_name(diff->mod_pol->p, qtype, &name);
			apol_str_append(&ret, &len, name);
		}
	}
exit:
	return ret;
}

int type_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item)
{
	uint32_t tval = (uint32_t) item;
	char *name = NULL;
	poldiff_type_t *pt;
	int error;

	name = type_get_name(diff, form, tval);
	pt = make_diff(diff, form, name);
	if (pt == NULL) {
		return -1;
	}
	free(name);
	if (apol_vector_append(diff->type_diffs->diffs, pt) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		type_destroy(pt);
		errno = error;
		return -1;
	}
	diff->type_diffs->are_diffs_sorted = 0;
	if (form == POLDIFF_FORM_ADDED) {
		diff->type_diffs->num_added++;
	}
	else {
		diff->type_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given an type, return a vector of its attributes (in the form of
 * strings).
 *
 * @param diff Policy diff error handler.
 * @param p Policy from which the type came.
 * @param type Type whose attributes to get.
 *
 * @return Vector of attribute strings for the type.  The caller is
 * responsible for calling apol_vector_destroy(), passing free as the
 * second parameter.  On error, return NULL.
 */
static apol_vector_t *type_get_attrib_names(poldiff_t *diff, apol_policy_t *p, uint32_t type)
{
	qpol_iterator_t *attrib_iter = NULL;
	char *attrib, *new_attrib;
	apol_vector_t *v = NULL;
	apol_vector_t *ret = NULL;
	qpol_type_t *qt = NULL;
	int retval = -1, i;

	/* allocate vector to return */
	if ((ret = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		return NULL;
	}

	/* get the qpol_type_t objects for the specified type value
	   and policy */
	v = type_map_lookup_reverse(diff, type, (diff->orig_pol == p ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD));
	if (apol_vector_get_size(v) == 0) {
		assert(FALSE);
		return NULL;
	}
	/* append the attributes for each qpol_type_t to the vector we return */
	for (i = 0; i < apol_vector_get_size(v); i++) {
		qt = apol_vector_get_element(v, i);
		if (qt == NULL) {
			assert(FALSE);
			return NULL;
		}
		qpol_type_get_attr_iter(p->p, qt, &attrib_iter);
		for ( ; !qpol_iterator_end(attrib_iter); qpol_iterator_next(attrib_iter)) {

			if (qpol_iterator_get_item(attrib_iter, (void **) &qt) < 0) {
				goto cleanup;
			}
			qpol_type_get_name(p->p, qt, &attrib);
			if ((new_attrib = strdup(attrib)) == NULL ||
			    apol_vector_append(ret, new_attrib) < 0) {
				ERR(diff, "%s", strerror(errno));
				goto cleanup;
			}
		}
	}
	apol_vector_sort_uniquify(v, &apol_str_strcmp, NULL, NULL);
	retval = 0;
 cleanup:
	qpol_iterator_destroy(&attrib_iter);
	if (retval < 0) {
		apol_vector_destroy(&v, free);
		return NULL;
	}
	return ret;
}

int type_deep_diff(poldiff_t *diff, const void *x, const void *y)
{
	uint32_t tval1 = (uint32_t)x;
	uint32_t tval2 = (uint32_t)y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *attrib1 = NULL, *attrib2 = NULL, *name = NULL;
	poldiff_type_t *t = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	assert(tval1 == tval2);
	/* can't do a deep diff of type if either policy is binary
	 * because the attribute names are bogus */
	if (apol_policy_is_binary(diff->orig_pol) ||
	    apol_policy_is_binary(diff->mod_pol)) {
		return 0;
	}
	v1 = type_get_attrib_names(diff, diff->orig_pol, tval1);
	v2 = type_get_attrib_names(diff, diff->mod_pol, tval2);
	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1); ) {
		if (j >= apol_vector_get_size(v2))
			break;
		attrib1 = (char *) apol_vector_get_element(v1, i);
		attrib2 = (char *) apol_vector_get_element(v2, j);
		compval = strcmp(attrib1, attrib2);
		if (compval != 0 && t == NULL) {
			name = type_get_name(diff, POLDIFF_FORM_MODIFIED, tval1);
			if ((t = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
			free(name);
			name = NULL;
		}
		if (compval < 0) {
			if ((attrib1 = strdup(attrib1)) == NULL ||
			    apol_vector_append(t->removed_attribs, attrib1) < 0) {
				error = errno;
				free(attrib1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		}
		else if (compval > 0) {
			if ((attrib2 = strdup(attrib2)) == NULL ||
			    apol_vector_append(t->added_attribs, attrib2) < 0) {
				error = errno;
				free(attrib2);
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
	for (; i < apol_vector_get_size(v1); i++) {
		attrib1 = (char *) apol_vector_get_element(v1, i);
		if (t == NULL) {
			name = type_get_name(diff, POLDIFF_FORM_MODIFIED, tval1);
			if ((t = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
			free(name);
			name = NULL;
		}
		if ((attrib1 = strdup(attrib1)) == NULL ||
		    apol_vector_append(t->removed_attribs, attrib1) < 0) {
			error = errno;
			free(attrib1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		attrib2 = (char *) apol_vector_get_element(v2, j);
		if (t == NULL) {
			name = type_get_name(diff, POLDIFF_FORM_MODIFIED, tval1);
			if ((t = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
			free(name);
			name = NULL;
		}
		if ((attrib2 = strdup(attrib2)) == NULL ||
		    apol_vector_append(t->added_attribs, attrib2) < 0) {
			error = errno;
			free(attrib2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (t != NULL) {
		if (apol_vector_append(diff->type_diffs->diffs, t) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->type_diffs->are_diffs_sorted = 0;
		diff->type_diffs->num_modified++;
	}
	retval = 0;
 cleanup:
	apol_vector_destroy(&v1, free);
	apol_vector_destroy(&v2, free);
	free(name);
	if (retval != 0) {
		type_destroy(t);
	}
	errno = error;
	return retval;
	return 0;
}
