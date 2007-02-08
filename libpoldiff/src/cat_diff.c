/**
 *  @file
 *  Implementation for computing a semantic differences in categories.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2007 Tresys Technology, LLC
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
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_cat_summary
{
	size_t num_added;
	size_t num_removed;
	apol_vector_t *diffs;
};

struct poldiff_cat
{
	char *name;
	poldiff_form_e form;
};

void poldiff_cat_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->cat_diffs->num_added;
	stats[1] = diff->cat_diffs->num_removed;
	stats[2] = 0;
	stats[3] = 0;
	stats[4] = 0;
}

apol_vector_t *poldiff_get_cat_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->cat_diffs->diffs;
}

char *poldiff_cat_to_string(poldiff_t * diff, const void *cat)
{
	poldiff_cat_t *c = (poldiff_cat_t *) cat;
	size_t len = 0;
	char *s = NULL;
	if (diff == NULL || cat == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (c->form) {
	case POLDIFF_FORM_ADDED:
	{
			if (apol_str_appendf(&s, &len, "+ %s", c->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:
	{
			if (apol_str_appendf(&s, &len, "- %s", c->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:
	default:
	{
			ERR(diff, "%s", strerror(ENOTSUP));
			errno = ENOTSUP;
			return NULL;
		}
	}
	return NULL;
}

const char *poldiff_cat_get_name(const poldiff_cat_t * cat)
{
	if (cat == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return cat->name;
}

poldiff_form_e poldiff_cat_get_form(const void *cat)
{
	if (cat == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}

	return ((const poldiff_cat_t *)cat)->form;
}

poldiff_cat_summary_t *cat_create(void)
{
	poldiff_cat_summary_t *cs = calloc(1, sizeof(poldiff_cat_summary_t));
	if (cs == NULL)
		return NULL;
	if ((cs->diffs = apol_vector_create()) == NULL) {
		cat_destroy(&cs);
		return NULL;
	}
	return cs;
}

static void cat_free(void *elem)
{
	poldiff_cat_t *s = elem;
	if (!elem)
		return;
	free(s->name);
	free(s);
}

void cat_destroy(poldiff_cat_summary_t ** cs)
{
	if (cs == NULL || *cs == NULL)
		return;
	apol_vector_destroy(&(*cs)->diffs, cat_free);
	free(*cs);
	*cs = NULL;
}

int cat_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	cat_destroy(&diff->cat_diffs);
	diff->cat_diffs = cat_create();
	if (diff->cat_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two categories from the same policy.
 */
static int cat_name_comp(const void *x, const void *y, void *arg)
{
	qpol_cat_t *c1 = (qpol_cat_t *) x;
	qpol_cat_t *c2 = (qpol_cat_t *) y;
	apol_policy_t *p = arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;

	if (qpol_cat_get_name(q, c1, &name1) < 0 || qpol_cat_get_name(q, c2, &name2) < 0)
		return 0;
	return strcmp(name1, name2);
}

apol_vector_t *cat_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_cat_iter(q, &iter) < 0) {
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
	apol_vector_sort_uniquify(v, cat_name_comp, policy, NULL);
	return v;
}

int cat_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_cat_t *c1 = (qpol_cat_t *) x;
	qpol_cat_t *c2 = (qpol_cat_t *) y;
	char *name1, *name2;
	if (qpol_cat_get_name(diff->orig_qpol, c1, &name1) < 0 || qpol_cat_get_name(diff->mod_qpol, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new level difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the level that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling level_free() upon the returned
 * value.
 */
static poldiff_cat_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_cat_t *pl;
	int error;
	if ((pl = calloc(1, sizeof(*pl))) == NULL ||
	    (pl->name = strdup(name)) == NULL) {
		error = errno;
		cat_free(pl);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pl->form = form;
	return pl;
}

int cat_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_cat_t *c = (qpol_cat_t *) item;
	char *name = NULL;
	poldiff_cat_t *pl;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_cat_get_name(diff->mod_qpol, c, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_cat_get_name(diff->orig_qpol, c, &name) < 0)) {
		return -1;
	}
	pl = make_diff(diff, form, name);
	if (pl == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->cat_diffs->diffs, pl) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		cat_free(pl);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->cat_diffs->num_added++;
	} else {
		diff->cat_diffs->num_removed++;
	}
	return 0;
}

int cat_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	/* Categories cannot be modified only added or removed.
	 * This call back simply returns 0 to satisfy the generic diff algorithm. */
	return 0;
}
 
