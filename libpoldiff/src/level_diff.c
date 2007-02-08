/**
 *  @file
 *  Implementation for computing a semantic differences in levels.
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

struct poldiff_level_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_level
{
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_cats;
	apol_vector_t *removed_cats;
};

void poldiff_level_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->level_diffs->num_added;
	stats[1] = diff->level_diffs->num_removed;
	stats[2] = diff->level_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

apol_vector_t *poldiff_get_level_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->level_diffs->diffs;
}

char *poldiff_level_to_string(poldiff_t * diff, const void *level)
{
	poldiff_level_t *l = (poldiff_level_t *) level;
	size_t num_added, num_removed, len = 0, i;
	char *s = NULL, *cat;
	if (diff == NULL || level == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(l->added_cats);
	num_removed = apol_vector_get_size(l->removed_cats);
	switch (l->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", l->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", l->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf(&s, &len, "* %s (", l->name) < 0) {
				break;
			}
			if (num_added > 0) {
				if (apol_str_appendf(&s, &len, "%d Added Categories", num_added) < 0) {
					break;
				}
			}
			if (num_removed > 0) {
				if (apol_str_appendf(&s, &len, "%s%d Removed Categories", (num_added > 0 ? ", " : ""), num_removed)
				    < 0) {
					break;
				}
			}
			if (apol_str_append(&s, &len, ")\n") < 0) {
				break;
			}
			for (i = 0; i < apol_vector_get_size(l->added_cats); i++) {
				cat = (char *)apol_vector_get_element(l->added_cats, i);
				if (apol_str_appendf(&s, &len, "\t+ %s\n", cat) < 0) {
					goto err;
				}
			}
			for (i = 0; i < apol_vector_get_size(l->removed_cats); i++) {
				cat = (char *)apol_vector_get_element(l->removed_cats, i);
				if (apol_str_appendf(&s, &len, "\t- %s\n", cat) < 0) {
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

const char *poldiff_level_get_name(const poldiff_level_t * level)
{
	if (level == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return level->name;
}

poldiff_form_e poldiff_level_get_form(const void *level)
{
	if (level == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}

	return ((const poldiff_level_t *)level)->form;
}

apol_vector_t *poldiff_level_get_added_cats(const poldiff_level_t * level)
{
	if (level == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return level->added_cats;
}

apol_vector_t *poldiff_level_get_removed_cats(const poldiff_level_t * level)
{
	if (level == NULL) {
		errno = EINVAL;
		return NULL;
	}

	return level->removed_cats;
}

poldiff_level_summary_t *level_create(void)
{
	poldiff_level_summary_t *ls = calloc(1, sizeof(poldiff_level_summary_t));
	if (ls == NULL)
		return NULL;
	if ((ls->diffs = apol_vector_create()) == NULL) {
		level_destroy(&ls);
		return NULL;
	}
	return ls;
}

static void level_free(void *elem)
{
	poldiff_level_t *s = elem;
	if (!elem)
		return;
	free(s->name);
	apol_vector_destroy(&s->added_cats, NULL);
	apol_vector_destroy(&s->removed_cats, NULL);
	free(s);
}

void level_destroy(poldiff_level_summary_t ** ls)
{
	if (ls == NULL || *ls == NULL)
		return;
	apol_vector_destroy(&(*ls)->diffs, level_free);
	free(*ls);
	*ls = NULL;
}

int level_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	level_destroy(&diff->level_diffs);
	diff->level_diffs = level_create();
	if (diff->level_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two levels from the same policy.
 */
static int level_name_comp(const void *x, const void *y, void *arg)
{
	qpol_level_t *s1 = (qpol_level_t *) x;
	qpol_level_t *s2 = (qpol_level_t *) y;
	apol_policy_t *p = arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;

	if (qpol_level_get_name(q, s1, &name1) < 0 || qpol_level_get_name(q, s2, &name2) < 0)
		return 0;
	return strcmp(name1, name2);
}

apol_vector_t *level_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_level_iter(q, &iter) < 0) {
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
	apol_vector_sort_uniquify(v, level_name_comp, policy, NULL);
	return v;
}

int level_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_level_t *l1 = (qpol_level_t *) x;
	qpol_level_t *l2 = (qpol_level_t *) y;
	char *name1, *name2;
	if (qpol_level_get_name(diff->orig_qpol, l1, &name1) < 0 || qpol_level_get_name(diff->mod_qpol, l2, &name2) < 0) {
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
static poldiff_level_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_level_t *pl;
	int error;
	if ((pl = calloc(1, sizeof(*pl))) == NULL ||
	    (pl->name = strdup(name)) == NULL ||
	    (pl->added_cats = apol_vector_create_with_capacity(1)) == NULL ||
	    (pl->removed_cats = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		level_free(pl);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pl->form = form;
	return pl;
}

int level_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_level_t *l = (qpol_level_t *) item;
	char *name = NULL;
	poldiff_level_t *pl;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_level_get_name(diff->mod_qpol, l, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_level_get_name(diff->orig_qpol, l, &name) < 0)) {
		return -1;
	}
	pl = make_diff(diff, form, name);
	if (pl == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->level_diffs->diffs, pl) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		level_free(pl);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->level_diffs->num_added++;
	} else {
		diff->level_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given a level, return a vector of its allowed categories (in the form of
 * strings).
 *
 * @param diff Policy diff error handler.
 * @param p Policy from which the level came.
 * @param level Level whose categories to get.
 *
 * @return Vector of category strings for the level.  The caller is
 * responsible for calling apol_vector_destroy(), passing NULL as the
 * second parameter.  On error, return NULL.
 */
static apol_vector_t *level_get_cats(poldiff_t * diff, apol_policy_t * p, qpol_level_t * level)
{
	qpol_iterator_t *iter = NULL;
	qpol_cat_t *cat;
	char *cat_name;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1, error = 0;

	if ((v = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_level_get_cat_iter(q, level, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&cat) < 0 || qpol_cat_get_name(q, cat, &cat_name)) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(v, cat_name) < 0) {
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

int level_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_level_t *l1 = (qpol_level_t *) x;
	qpol_level_t *l2 = (qpol_level_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *cat1, *cat2, *name;
	poldiff_level_t *l = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	if (qpol_level_get_name(diff->orig_qpol, l1, &name) < 0 ||
	    (v1 = level_get_cats(diff, diff->orig_pol, l1)) == NULL || (v2 = level_get_cats(diff, diff->mod_pol, l2)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1);) {
		if (j >= apol_vector_get_size(v2))
			break;
		cat1 = (char *)apol_vector_get_element(v1, i);
		cat2 = (char *)apol_vector_get_element(v2, j);
		compval = strcmp(cat1, cat2);
		if (compval != 0 && l == NULL) {
			if ((l = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if (compval < 0) {
			if ((cat1 = strdup(cat1)) == NULL || apol_vector_append(l->removed_cats, cat1) < 0) {
				error = errno;
				free(cat1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (compval > 0) {
			if ((cat2 = strdup(cat2)) == NULL || apol_vector_append(l->added_cats, cat2) < 0) {
				error = errno;
				free(cat2);
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
		cat1 = (char *)apol_vector_get_element(v1, i);
		if (l == NULL) {
			if ((l = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((cat1 = strdup(cat1)) == NULL || apol_vector_append(l->removed_cats, cat1) < 0) {
			error = errno;
			free(cat1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		cat2 = (char *)apol_vector_get_element(v2, j);
		if (l == NULL) {
			if ((l = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((cat2 = strdup(cat2)) == NULL || apol_vector_append(l->added_cats, cat2) < 0) {
			error = errno;
			free(cat2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (l != NULL) {
		apol_vector_sort(l->removed_cats, apol_str_strcmp, NULL);
		apol_vector_sort(l->added_cats, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->level_diffs->diffs, l) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->level_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	if (retval != 0) {
		level_free(l);
	}
	errno = error;
	return retval;
}
