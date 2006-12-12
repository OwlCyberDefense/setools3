/**
 *  @file bool_diff.c
 *  Implementation for computing a semantic differences in bools.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
 *
 *  Copyright (C) 2006-2007 Tresys Technology, LLC
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
#include <apol/vector.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_bool_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_bool
{
	char *name;
	poldiff_form_e form;
	bool_t state;
};

void poldiff_bool_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->bool_diffs->num_added;
	stats[1] = diff->bool_diffs->num_removed;
	stats[2] = diff->bool_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_bool_to_string(poldiff_t * diff, const void *boolean)
{
	poldiff_bool_t *b = (poldiff_bool_t *) boolean;
	size_t len = 0;
	char *s = NULL;
	if (diff == NULL || boolean == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (b->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", b->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", b->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf
			    (&s, &len, "* %s (changed from %s)", b->name, (b->state ? "FALSE to TRUE" : "TRUE to FALSE")) < 0) {
				break;
			}
			return s;
		}
	default:{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_bool_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->bool_diffs->diffs;
}

const char *poldiff_bool_get_name(const poldiff_bool_t * boolean)
{
	if (boolean == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return boolean->name;
}

poldiff_form_e poldiff_bool_get_form(const void *boolean)
{
	if (boolean == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_bool_t *)boolean)->form;
}

/******************** protected functions ********************/

poldiff_bool_summary_t *bool_create(void)
{
	poldiff_bool_summary_t *bs = calloc(1, sizeof(*bs));
	if (bs == NULL) {
		return NULL;
	}
	if ((bs->diffs = apol_vector_create()) == NULL) {
		bool_destroy(&bs);
		return NULL;
	}
	return bs;
}

static void bool_free(void *elem)
{
	if (elem != NULL) {
		poldiff_bool_t *b = (poldiff_bool_t *) elem;
		free(b->name);
		free(b);
	}
}

void bool_destroy(poldiff_bool_summary_t ** bs)
{
	if (bs != NULL && *bs != NULL) {
		apol_vector_destroy(&(*bs)->diffs, bool_free);
		free(*bs);
		*bs = NULL;
	}
}

int bool_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	bool_destroy(&diff->bool_diffs);
	diff->bool_diffs = bool_create();
	if (diff->bool_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two bools from the same policy.
 */
static int bool_name_comp(const void *x, const void *y, void *arg)
{
	qpol_bool_t *c1 = (qpol_bool_t *) x;
	qpol_bool_t *c2 = (qpol_bool_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;
	if (qpol_bool_get_name(q, c1, &name1) < 0 || qpol_bool_get_name(q, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *bool_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_bool_iter(q, &iter) < 0) {
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
	apol_vector_sort(v, bool_name_comp, policy);
	return v;
}

int bool_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_bool_t *c1 = (qpol_bool_t *) x;
	qpol_bool_t *c2 = (qpol_bool_t *) y;
	char *name1, *name2;
	if (qpol_bool_get_name(diff->orig_qpol, c1, &name1) < 0 || qpol_bool_get_name(diff->mod_qpol, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new bool difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the bool that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling bool_free() upon the
 * returned value.
 */
static poldiff_bool_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_bool_t *pb;
	int error;
	if ((pb = calloc(1, sizeof(*pb))) == NULL || (pb->name = strdup(name)) == NULL) {
		error = errno;
		bool_free(pb);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pb->form = form;
	return pb;
}

int bool_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_bool_t *c = (qpol_bool_t *) item;
	char *name = NULL;
	poldiff_bool_t *pb;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_bool_get_name(diff->mod_qpol, c, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_bool_get_name(diff->orig_qpol, c, &name) < 0)) {
		return -1;
	}
	pb = make_diff(diff, form, name);
	if (pb == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->bool_diffs->diffs, pb) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		bool_free(pb);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED)
		diff->bool_diffs->num_added++;
	else
		diff->bool_diffs->num_removed++;
	return 0;
}

int bool_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_bool_t *b1 = (qpol_bool_t *) x;
	qpol_bool_t *b2 = (qpol_bool_t *) y;
	char *name;
	int s1, s2;
	poldiff_bool_t *b = NULL;
	int retval = -1, error = 0;

	if (qpol_bool_get_name(diff->orig_qpol, b1, &name) < 0 ||
	    qpol_bool_get_state(diff->orig_qpol, b1, &s1) < 0 || qpol_bool_get_state(diff->mod_qpol, b2, &s2) < 0) {
		error = errno;
		goto cleanup;
	}
	if (s1 != s2) {
		if ((b = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (s2)
			b->state = TRUE;
		else
			b->state = FALSE;
	}
	if (b != NULL) {
		if (apol_vector_append(diff->bool_diffs->diffs, b) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->bool_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	errno = error;
	return retval;
}
