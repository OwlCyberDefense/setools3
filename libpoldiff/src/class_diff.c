/**
 *  @file
 *  Implementation for computing semantic differences in classes and
 *  commons.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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
#include <errno.h>
#include <stdio.h>
#include <string.h>

/******************** object classes ********************/

struct poldiff_class_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_class
{
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_perms;
	apol_vector_t *removed_perms;
};

void poldiff_class_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->class_diffs->num_added;
	stats[1] = diff->class_diffs->num_removed;
	stats[2] = diff->class_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_class_to_string(poldiff_t * diff, const void *cls)
{
	poldiff_class_t *c = (poldiff_class_t *) cls;
	size_t num_added, num_removed, len = 0, i;
	char *s = NULL, *perm;
	if (diff == NULL || cls == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(c->added_perms);
	num_removed = apol_vector_get_size(c->removed_perms);
	switch (c->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", c->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", c->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf(&s, &len, "* %s (", c->name) < 0) {
				s = NULL;
				break;
			}
			if (num_added > 0) {
				if (apol_str_appendf(&s, &len, "%zd Added Permission%s", num_added, (num_added == 1 ? "" : "s")) <
				    0) {
					break;
				}
			}
			if (num_removed > 0) {
				if (apol_str_appendf
				    (&s, &len, "%s%zd Removed Permission%s", (num_added > 0 ? ", " : ""), num_removed,
				     (num_removed == 1 ? "" : "s"))
				    < 0) {
					break;
				}
			}
			if (apol_str_append(&s, &len, ")\n") < 0) {
				break;
			}
			for (i = 0; i < apol_vector_get_size(c->added_perms); i++) {
				perm = (char *)apol_vector_get_element(c->added_perms, i);
				if (apol_str_appendf(&s, &len, "\t+ %s\n", perm) < 0) {
					goto err;
				}
			}
			for (i = 0; i < apol_vector_get_size(c->removed_perms); i++) {
				perm = (char *)apol_vector_get_element(c->removed_perms, i);
				if (apol_str_appendf(&s, &len, "\t- %s\n", perm) < 0) {
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

apol_vector_t *poldiff_get_class_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->class_diffs->diffs;
}

const char *poldiff_class_get_name(const poldiff_class_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->name;
}

poldiff_form_e poldiff_class_get_form(const void *cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_class_t *)cls)->form;
}

apol_vector_t *poldiff_class_get_added_perms(const poldiff_class_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->added_perms;
}

apol_vector_t *poldiff_class_get_removed_perms(const poldiff_class_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->removed_perms;
}

/*************** protected functions for object classes ***************/

static void class_free(void *elem)
{
	if (elem != NULL) {
		poldiff_class_t *c = (poldiff_class_t *) elem;
		free(c->name);
		apol_vector_destroy(&c->added_perms);
		apol_vector_destroy(&c->removed_perms);
		free(c);
	}
}

poldiff_class_summary_t *class_create(void)
{
	poldiff_class_summary_t *cs = calloc(1, sizeof(*cs));
	if (cs == NULL) {
		return NULL;
	}
	if ((cs->diffs = apol_vector_create(class_free)) == NULL) {
		class_destroy(&cs);
		return NULL;
	}
	return cs;
}

void class_destroy(poldiff_class_summary_t ** cs)
{
	if (cs != NULL && *cs != NULL) {
		apol_vector_destroy(&(*cs)->diffs);
		free(*cs);
		*cs = NULL;
	}
}

int class_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	class_destroy(&diff->class_diffs);
	diff->class_diffs = class_create();
	if (diff->class_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two classes from the same policy.
 */
static int class_name_comp(const void *x, const void *y, void *arg)
{
	qpol_class_t *c1 = (qpol_class_t *) x;
	qpol_class_t *c2 = (qpol_class_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;
	if (qpol_class_get_name(q, c1, &name1) < 0 || qpol_class_get_name(q, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *class_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_class_iter(q, &iter) < 0) {
		return NULL;
	}
	v = apol_vector_create_from_iter(iter, NULL);
	if (v == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		qpol_iterator_destroy(&iter);
		errno = error;
		return NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort(v, class_name_comp, policy);
	return v;
}

int class_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_class_t *c1 = (qpol_class_t *) x;
	qpol_class_t *c2 = (qpol_class_t *) y;
	char *name1, *name2;
	if (qpol_class_get_name(diff->orig_qpol, c1, &name1) < 0 || qpol_class_get_name(diff->mod_qpol, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new class difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the class that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling class_free() upon the
 * returned value.
 */
static poldiff_class_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_class_t *pc;
	int error;
	if ((pc = calloc(1, sizeof(*pc))) == NULL ||
	    (pc->name = strdup(name)) == NULL ||
	    (pc->added_perms = apol_vector_create_with_capacity(1, free)) == NULL ||
	    (pc->removed_perms = apol_vector_create_with_capacity(1, free)) == NULL) {
		error = errno;
		class_free(pc);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pc->form = form;
	return pc;
}

int class_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_class_t *c = (qpol_class_t *) item;
	char *name = NULL;
	poldiff_class_t *pc;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_class_get_name(diff->mod_qpol, c, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_class_get_name(diff->orig_qpol, c, &name) < 0)) {
		return -1;
	}
	pc = make_diff(diff, form, name);
	if (pc == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->class_diffs->diffs, pc) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		class_free(pc);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->class_diffs->num_added++;
	} else {
		diff->class_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given an object class, return a vector of its permissions (in the
 * form of strings).  These permissions include those inherited from
 * the class's common, if present.
 *
 * @param diff Policy diff error handler.
 * @param p Policy from which the class came.
 * @param class Class whose permissions to get.
 *
 * @return Vector of permissions strings for the class.  The caller is
 * responsible for calling apol_vector_destroy().  On error, return
 * NULL.
 */
static apol_vector_t *class_get_perms(poldiff_t * diff, apol_policy_t * p, qpol_class_t * class)
{
	qpol_common_t *common;
	qpol_iterator_t *perm_iter = NULL, *common_iter = NULL;
	char *perm;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1;

	if ((v = apol_vector_create(NULL)) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_class_get_common(q, class, &common) < 0 || qpol_class_get_perm_iter(q, class, &perm_iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void **)&perm) < 0) {
			goto cleanup;
		}
		if (apol_vector_append(v, perm) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
	}
	if (common != NULL) {
		if (qpol_common_get_perm_iter(q, common, &common_iter) < 0) {
			goto cleanup;
		}
		for (; !qpol_iterator_end(common_iter); qpol_iterator_next(common_iter)) {
			if (qpol_iterator_get_item(common_iter, (void **)&perm) < 0) {
				goto cleanup;
			}
			if (apol_vector_append(v, perm) < 0) {
				ERR(diff, "%s", strerror(errno));
				goto cleanup;
			}
		}
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	qpol_iterator_destroy(&common_iter);
	if (retval < 0) {
		apol_vector_destroy(&v);
		return NULL;
	}
	return v;
}

int class_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_class_t *c1 = (qpol_class_t *) x;
	qpol_class_t *c2 = (qpol_class_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *perm1 = NULL, *perm2 = NULL, *name;
	poldiff_class_t *c = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	if (qpol_class_get_name(diff->orig_qpol, c1, &name) < 0 ||
	    (v1 = class_get_perms(diff, diff->orig_pol, c1)) == NULL || (v2 = class_get_perms(diff, diff->mod_pol, c2)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1);) {
		if (j >= apol_vector_get_size(v2))
			break;
		perm1 = (char *)apol_vector_get_element(v1, i);
		perm2 = (char *)apol_vector_get_element(v2, j);
		compval = strcmp(perm1, perm2);
		if (compval != 0 && c == NULL) {
			if ((c = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if (compval < 0) {
			if ((perm1 = strdup(perm1)) == NULL || apol_vector_append(c->removed_perms, perm1) < 0) {
				error = errno;
				free(perm1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (compval > 0) {
			if ((perm2 = strdup(perm2)) == NULL || apol_vector_append(c->added_perms, perm2) < 0) {
				error = errno;
				free(perm2);
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
		perm1 = (char *)apol_vector_get_element(v1, i);
		if (c == NULL) {
			if ((c = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((perm1 = strdup(perm1)) == NULL || apol_vector_append(c->removed_perms, perm1) < 0) {
			error = errno;
			free(perm1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		perm2 = (char *)apol_vector_get_element(v2, j);
		if (c == NULL) {
			if ((c = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((perm2 = strdup(perm2)) == NULL || apol_vector_append(c->added_perms, perm2) < 0) {
			error = errno;
			free(perm2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (c != NULL) {
		apol_vector_sort(c->removed_perms, apol_str_strcmp, NULL);
		apol_vector_sort(c->added_perms, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->class_diffs->diffs, c) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->class_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v1);
	apol_vector_destroy(&v2);
	if (retval != 0) {
		class_free(c);
	}
	errno = error;
	return retval;
}

/******************** common classes ********************/

struct poldiff_common_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_common
{
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_perms;
	apol_vector_t *removed_perms;
};

void poldiff_common_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->common_diffs->num_added;
	stats[1] = diff->common_diffs->num_removed;
	stats[2] = diff->common_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_common_to_string(poldiff_t * diff, const void *cls)
{
	poldiff_common_t *c = (poldiff_common_t *) cls;
	size_t num_added, num_removed, len = 0, i;
	char *s = NULL, *perm;
	if (diff == NULL || cls == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(c->added_perms);
	num_removed = apol_vector_get_size(c->removed_perms);
	switch (c->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", c->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", c->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (apol_str_appendf(&s, &len, "* %s (", c->name) < 0) {
				s = NULL;
				break;
			}
			if (num_added > 0) {
				if (apol_str_appendf(&s, &len, "%zd Added Permission%s", num_added, (num_added == 1 ? "" : "s")) <
				    0) {
					break;
				}
			}
			if (num_removed > 0) {
				if (apol_str_appendf
				    (&s, &len, "%s%zd Removed Permission%s", (num_added > 0 ? ", " : ""), num_removed,
				     (num_removed == 1 ? "" : "s"))
				    < 0) {
					break;
				}
			}
			if (apol_str_append(&s, &len, ")\n") < 0) {
				break;
			}
			for (i = 0; i < apol_vector_get_size(c->added_perms); i++) {
				perm = (char *)apol_vector_get_element(c->added_perms, i);
				if (apol_str_appendf(&s, &len, "\t+ %s\n", perm) < 0) {
					goto err;
				}
			}
			for (i = 0; i < apol_vector_get_size(c->removed_perms); i++) {
				perm = (char *)apol_vector_get_element(c->removed_perms, i);
				if (apol_str_appendf(&s, &len, "\t- %s\n", perm) < 0) {
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

apol_vector_t *poldiff_get_common_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->common_diffs->diffs;
}

const char *poldiff_common_get_name(const poldiff_common_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->name;
}

poldiff_form_e poldiff_common_get_form(const void *cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_common_t *)cls)->form;
}

apol_vector_t *poldiff_common_get_added_perms(const poldiff_common_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->added_perms;
}

apol_vector_t *poldiff_common_get_removed_perms(const poldiff_common_t * cls)
{
	if (cls == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return cls->removed_perms;
}

/*************** protected functions for common classes ***************/

static void common_free(void *elem)
{
	if (elem != NULL) {
		poldiff_common_t *c = (poldiff_common_t *) elem;
		free(c->name);
		apol_vector_destroy(&c->added_perms);
		apol_vector_destroy(&c->removed_perms);
		free(c);
	}
}

poldiff_common_summary_t *common_create(void)
{
	poldiff_common_summary_t *cs = calloc(1, sizeof(*cs));
	if (cs == NULL) {
		return NULL;
	}
	if ((cs->diffs = apol_vector_create(common_free)) == NULL) {
		common_destroy(&cs);
		return NULL;
	}
	return cs;
}

void common_destroy(poldiff_common_summary_t ** cs)
{
	if (cs != NULL && *cs != NULL) {
		apol_vector_destroy(&(*cs)->diffs);
		free(*cs);
		*cs = NULL;
	}
}

int common_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	common_destroy(&diff->common_diffs);
	diff->common_diffs = common_create();
	if (diff->common_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two commons from the same policy.
 */
static int common_name_comp(const void *x, const void *y, void *arg)
{
	qpol_common_t *c1 = (qpol_common_t *) x;
	qpol_common_t *c2 = (qpol_common_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;
	if (qpol_common_get_name(q, c1, &name1) < 0 || qpol_common_get_name(q, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *common_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_common_iter(q, &iter) < 0) {
		return NULL;
	}
	v = apol_vector_create_from_iter(iter, NULL);
	if (v == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		qpol_iterator_destroy(&iter);
		errno = error;
		return NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort(v, common_name_comp, policy);
	return v;
}

int common_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_common_t *c1 = (qpol_common_t *) x;
	qpol_common_t *c2 = (qpol_common_t *) y;
	char *name1, *name2;
	if (qpol_common_get_name(diff->orig_qpol, c1, &name1) < 0 || qpol_common_get_name(diff->mod_qpol, c2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new common difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the common that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling common_free() upon the
 * returned value.
 */
static poldiff_common_t *make_common_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_common_t *pc;
	int error;
	if ((pc = calloc(1, sizeof(*pc))) == NULL ||
	    (pc->name = strdup(name)) == NULL ||
	    (pc->added_perms = apol_vector_create_with_capacity(1, free)) == NULL ||
	    (pc->removed_perms = apol_vector_create_with_capacity(1, free)) == NULL) {
		error = errno;
		common_free(pc);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pc->form = form;
	return pc;
}

int common_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_common_t *c = (qpol_common_t *) item;
	char *name = NULL;
	poldiff_common_t *pc;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_common_get_name(diff->mod_qpol, c, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_common_get_name(diff->orig_qpol, c, &name) < 0)) {
		return -1;
	}
	pc = make_common_diff(diff, form, name);
	if (pc == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->common_diffs->diffs, pc) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		common_free(pc);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->common_diffs->num_added++;
	} else {
		diff->common_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given a common class, return a vector of its permissions (in the
 * form of strings).
 *
 * @param diff Policy diff error handler.
 * @param p Policy from which the common came.
 * @param common Common whose permissions to get.
 *
 * @return Vector of permissions strings for the common.  The caller
 * is responsible for calling apol_vector_destroy().  On error, return
 * NULL.
 */
static apol_vector_t *common_get_perms(poldiff_t * diff, apol_policy_t * p, qpol_common_t * common)
{
	qpol_iterator_t *perm_iter = NULL;
	char *perm;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1;

	if ((v = apol_vector_create(NULL)) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_common_get_perm_iter(q, common, &perm_iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(perm_iter); qpol_iterator_next(perm_iter)) {
		if (qpol_iterator_get_item(perm_iter, (void **)&perm) < 0) {
			goto cleanup;
		}
		if (apol_vector_append(v, perm) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	qpol_iterator_destroy(&perm_iter);
	if (retval < 0) {
		apol_vector_destroy(&v);
		return NULL;
	}
	return v;
}

int common_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_common_t *c1 = (qpol_common_t *) x;
	qpol_common_t *c2 = (qpol_common_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *perm1 = NULL, *perm2 = NULL, *name;
	poldiff_common_t *c = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	if (qpol_common_get_name(diff->orig_qpol, c1, &name) < 0 ||
	    (v1 = common_get_perms(diff, diff->orig_pol, c1)) == NULL || (v2 = common_get_perms(diff, diff->mod_pol, c2)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1);) {
		if (j >= apol_vector_get_size(v2))
			break;
		perm1 = (char *)apol_vector_get_element(v1, i);
		perm2 = (char *)apol_vector_get_element(v2, j);
		compval = strcmp(perm1, perm2);
		if (compval != 0 && c == NULL) {
			if ((c = make_common_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if (compval < 0) {
			if ((perm1 = strdup(perm1)) == NULL || apol_vector_append(c->removed_perms, perm1) < 0) {
				error = errno;
				free(perm1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (compval > 0) {
			if ((perm2 = strdup(perm2)) == NULL || apol_vector_append(c->added_perms, perm2) < 0) {
				error = errno;
				free(perm2);
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
		perm1 = (char *)apol_vector_get_element(v1, i);
		if (c == NULL) {
			if ((c = make_common_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((perm1 = strdup(perm1)) == NULL || apol_vector_append(c->removed_perms, perm1) < 0) {
			error = errno;
			free(perm1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		perm2 = (char *)apol_vector_get_element(v2, j);
		if (c == NULL) {
			if ((c = make_common_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((perm2 = strdup(perm2)) == NULL || apol_vector_append(c->added_perms, perm2) < 0) {
			error = errno;
			free(perm2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (c != NULL) {
		apol_vector_sort(c->removed_perms, apol_str_strcmp, NULL);
		apol_vector_sort(c->added_perms, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->common_diffs->diffs, c) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->common_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v1);
	apol_vector_destroy(&v2);
	if (retval != 0) {
		common_free(c);
	}
	errno = error;
	return retval;
}
