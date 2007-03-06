/**
 *  @file
 *  Implementation for computing a semantic differences in users.
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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_user_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

typedef struct poldiff_range poldiff_range_t;

struct poldiff_range
{
	apol_mls_range_t *orig_range;
	apol_mls_range_t *mod_range;
	/** a vector of poldiff_level_t */
	apol_vector_t *levels;
};

struct poldiff_user
{
	char *name;
	poldiff_form_e form;
	/* the next three are vector of strings */
	apol_vector_t *unmodified_roles;
	apol_vector_t *added_roles;
	apol_vector_t *removed_roles;
	/** if not diffing a MLS policy, this will be NULL */
	poldiff_level_t *orig_default_level;
	/** if not diffing a MLS policy, this will be NULL; this is
	    also NULL if orig_default_level->form is
	    POLDIFF_FORM_MODIFIED */
	poldiff_level_t *mod_default_level;
	/** if not diffing MLS policies then the range is NULL */
	poldiff_range_t *range;
};

void poldiff_user_get_stats(poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->user_diffs->num_added;
	stats[1] = diff->user_diffs->num_removed;
	stats[2] = diff->user_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

/**
 * Generate the to_string for a poldiff_level_t within a user diff.
 */
static int user_level_to_modified_string(poldiff_t * diff, poldiff_level_t * level, char **s, size_t * len)
{
	char t, *cat, *sep = "";
	size_t i;
	switch (level->form) {
	case POLDIFF_FORM_ADDED:
		t = '+';
		break;
	case POLDIFF_FORM_REMOVED:
		t = '-';
		break;
	case POLDIFF_FORM_MODIFIED:
		t = '*';
		break;
	default:
		/* don't show unmodified levels */
		return 0;
	}
	if (apol_str_appendf(s, len, "     %c%s", t, level->name) < 0) {
		return -1;
	}
	if ((level->unmodified_cats != NULL && apol_vector_get_size(level->unmodified_cats) > 0) ||
	    (level->added_cats != NULL && apol_vector_get_size(level->added_cats) > 0) ||
	    (level->removed_cats != NULL && apol_vector_get_size(level->removed_cats) > 0)) {
		if (apol_str_append(s, len, " : ") < 0) {
			return -1;
		}
		for (i = 0; level->unmodified_cats != NULL && i < apol_vector_get_size(level->unmodified_cats); i++) {
			cat = apol_vector_get_element(level->unmodified_cats, i);
			if (apol_str_appendf(s, len, "%s%s", sep, cat) < 0) {
				return -1;
			}
			sep = ",";
		}
		for (i = 0; level->added_cats != NULL && i < apol_vector_get_size(level->added_cats); i++) {
			cat = apol_vector_get_element(level->added_cats, i);
			if (apol_str_appendf(s, len, "%s+%s", sep, cat) < 0) {
				return -1;
			}
			sep = ",";
		}
		for (i = 0; level->removed_cats != NULL && i < apol_vector_get_size(level->removed_cats); i++) {
			cat = apol_vector_get_element(level->removed_cats, i);
			if (apol_str_appendf(s, len, "%s-%s", sep, cat) < 0) {
				return -1;
			}
			sep = ",";
		}
	}
	if (apol_str_append(s, len, "\n") < 0) {
		return -1;
	}
	return 0;
}

static char *range_to_string(poldiff_t * diff, poldiff_range_t * range)
{
	char *r1 = NULL, *r2 = NULL;
	char *s = NULL;
	size_t len = 0, i;
	if (range->orig_range != NULL && (r1 = apol_mls_range_render(diff->orig_pol, range->orig_range)) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (range->mod_range != NULL && (r2 = apol_mls_range_render(diff->mod_pol, range->mod_range)) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (r1 == NULL) {
		if (apol_str_appendf(&s, &len, "   range: %s\n", r2) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
	} else if (r2 == NULL) {
		if (apol_str_appendf(&s, &len, "   range: %s\n", r1) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
	} else {
		if (apol_str_appendf(&s, &len, "   range: %s -> %s\n", r1, r2) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
	}
	for (i = 0; i < apol_vector_get_size(range->levels); i++) {
		poldiff_level_t *level = apol_vector_get_element(range->levels, i);
		if (user_level_to_modified_string(diff, level, &s, &len) < 0) {
			goto cleanup;
		}
	}
      cleanup:
	free(r1);
	free(r2);
	return s;
}

/**
 * Generate the to_string for a modified user.
 */
static char *user_to_modified_string(poldiff_t * diff, poldiff_user_t * u)
{
	size_t len = 0, i;
	char *s = NULL, *role, *range = NULL;
	size_t num_added_roles = apol_vector_get_size(u->added_roles);
	size_t num_removed_roles = apol_vector_get_size(u->removed_roles);
	if (apol_str_appendf(&s, &len, "* %s\n", u->name) < 0) {
		goto err;
	}
	if (num_added_roles > 0 || num_removed_roles > 0) {
		if (apol_str_append(&s, &len, "   roles {") < 0) {
			goto err;
		}
		for (i = 0; i < apol_vector_get_size(u->unmodified_roles); i++) {
			role = (char *)apol_vector_get_element(u->unmodified_roles, i);
			if (apol_str_appendf(&s, &len, " %s", role) < 0) {
				goto err;
			}
		}
		for (i = 0; i < num_added_roles; i++) {
			role = (char *)apol_vector_get_element(u->added_roles, i);
			if (apol_str_appendf(&s, &len, " +%s", role) < 0) {
				goto err;
			}
		}
		for (i = 0; i < num_removed_roles; i++) {
			role = (char *)apol_vector_get_element(u->removed_roles, i);
			if (apol_str_appendf(&s, &len, " -%s", role) < 0) {
				goto err;
			}
		}
		if (apol_str_append(&s, &len, " }\n") < 0) {
			goto err;
		}
	}
	if ((u->mod_default_level != NULL || u->orig_default_level != NULL) && apol_str_append(&s, &len, "   level:\n") < 0) {
		goto err;
	}
	if (u->mod_default_level != NULL && user_level_to_modified_string(diff, u->mod_default_level, &s, &len) < 0) {
		goto err;
	}
	if (u->orig_default_level != NULL && user_level_to_modified_string(diff, u->orig_default_level, &s, &len) < 0) {
		goto err;
	}
	if (u->range != NULL) {
		if ((range = range_to_string(diff, u->range)) == NULL || (apol_str_appendf(&s, &len, "%s", range) < 0)) {
			free(range);
			goto err;
		}
		free(range);
	}
	return s;
      err:
	free(s);
	return NULL;
}

char *poldiff_user_to_string(poldiff_t * diff, const void *user)
{
	poldiff_user_t *u = (poldiff_user_t *) user;
	size_t len = 0;
	char *s = NULL;
	if (diff == NULL || user == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (u->form) {
	case POLDIFF_FORM_ADDED:{
			if (apol_str_appendf(&s, &len, "+ %s", u->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (apol_str_appendf(&s, &len, "- %s", u->name) < 0) {
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if ((s = user_to_modified_string(diff, u)) == NULL) {
				goto err;
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

apol_vector_t *poldiff_get_user_vector(poldiff_t * diff)
{
	if (diff == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return diff->user_diffs->diffs;
}

const char *poldiff_user_get_name(const poldiff_user_t * user)
{
	if (user == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return user->name;
}

poldiff_form_e poldiff_user_get_form(const void *user)
{
	if (user == NULL) {
		errno = EINVAL;
		return 0;
	}
	return ((const poldiff_user_t *)user)->form;
}

apol_vector_t *poldiff_user_get_added_roles(const poldiff_user_t * user)
{
	if (user == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return user->added_roles;
}

apol_vector_t *poldiff_user_get_removed_roles(const poldiff_user_t * user)
{
	if (user == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return user->removed_roles;
}

/*************** protected functions for users ***************/

poldiff_user_summary_t *user_create(void)
{
	poldiff_user_summary_t *us = calloc(1, sizeof(*us));
	if (us == NULL) {
		return NULL;
	}
	if ((us->diffs = apol_vector_create()) == NULL) {
		user_destroy(&us);
		return NULL;
	}
	return us;
}

static void range_free(poldiff_range_t * range)
{
	if (range != NULL) {
		apol_mls_range_destroy(&range->orig_range);
		apol_mls_range_destroy(&range->mod_range);
		apol_vector_destroy(&range->levels, level_free);
		free(range);
	}
}

static void user_free(void *elem)
{
	if (elem != NULL) {
		poldiff_user_t *u = (poldiff_user_t *) elem;
		free(u->name);
		apol_vector_destroy(&u->added_roles, free);
		apol_vector_destroy(&u->removed_roles, free);
		apol_vector_destroy(&u->unmodified_roles, free);
		level_free(u->orig_default_level);
		level_free(u->mod_default_level);
		range_free(u->range);
		free(u);
	}
}

void user_destroy(poldiff_user_summary_t ** us)
{
	if (us != NULL && *us != NULL) {
		apol_vector_destroy(&(*us)->diffs, user_free);
		free(*us);
		*us = NULL;
	}
}

int user_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	user_destroy(&diff->user_diffs);
	diff->user_diffs = user_create();
	if (diff->user_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Comparison function for two users from the same policy.
 */
static int user_name_comp(const void *x, const void *y, void *arg)
{
	qpol_user_t *u1 = (qpol_user_t *) x;
	qpol_user_t *u2 = (qpol_user_t *) y;
	apol_policy_t *p = (apol_policy_t *) arg;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	char *name1, *name2;
	if (qpol_user_get_name(q, u1, &name1) < 0 || qpol_user_get_name(q, u2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *user_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;
	if (qpol_policy_get_user_iter(q, &iter) < 0) {
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
	apol_vector_sort(v, user_name_comp, policy);
	return v;
}

int user_comp(const void *x, const void *y, poldiff_t * diff)
{
	qpol_user_t *u1 = (qpol_user_t *) x;
	qpol_user_t *u2 = (qpol_user_t *) y;
	char *name1, *name2;
	if (qpol_user_get_name(diff->orig_qpol, u1, &name1) < 0 || qpol_user_get_name(diff->mod_qpol, u2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

/**
 * Allocate and return a new user difference object.
 *
 * @param diff Policy diff error handler.
 * @param form Form of the difference.
 * @param name Name of the user that is different.
 *
 * @return A newly allocated and initialized diff, or NULL upon error.
 * The caller is responsible for calling user_free() upon the returned
 * value.
 */
static poldiff_user_t *make_diff(poldiff_t * diff, poldiff_form_e form, char *name)
{
	poldiff_user_t *pu;
	int error;
	if ((pu = calloc(1, sizeof(*pu))) == NULL ||
	    (pu->name = strdup(name)) == NULL ||
	    (pu->added_roles = apol_vector_create_with_capacity(1)) == NULL ||
	    (pu->removed_roles = apol_vector_create_with_capacity(1)) == NULL ||
	    (pu->unmodified_roles = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		user_free(pu);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	pu->form = form;
	return pu;
}

int user_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	qpol_user_t *u = (qpol_user_t *) item;
	char *name = NULL;
	poldiff_user_t *pu;
	int error;
	if ((form == POLDIFF_FORM_ADDED &&
	     qpol_user_get_name(diff->mod_qpol, u, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_user_get_name(diff->orig_qpol, u, &name) < 0)) {
		return -1;
	}
	pu = make_diff(diff, form, name);
	if (pu == NULL) {
		return -1;
	}
	if (apol_vector_append(diff->user_diffs->diffs, pu) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		user_free(pu);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->user_diffs->num_added++;
	} else {
		diff->user_diffs->num_removed++;
	}
	return 0;
}

/**
 * Given a user, return a vector of its allowed roles (in the form of
 * strings).
 *
 * @param diff Policy diff error handler.
 * @param p Policy from which the user came.
 * @param user User whose roles to get.
 *
 * @return Vector of role strings for the user.  The caller is
 * responsible for calling apol_vector_destroy(), passing NULL as the
 * second parameter.  On error, return NULL.
 */
static apol_vector_t *user_get_roles(poldiff_t * diff, apol_policy_t * p, qpol_user_t * user)
{
	qpol_iterator_t *iter = NULL;
	qpol_role_t *role;
	char *role_name;
	apol_vector_t *v = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(p);
	int retval = -1, error = 0;

	if ((v = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_user_get_role_iter(q, user, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&role) < 0 || qpol_role_get_name(q, role, &role_name)) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_append(v, role_name) < 0) {
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

/**
 * Perform a deep diff of the roles assigned to the two users.
 *
 * @param diff Diff structure containing the original and modified
 * policies.
 * @param u1 User from original policy to examine.
 * @param u2 User from modified policy to examine.
 * @param u Result structure where differences are to be recorded.
 *
 * @return Greater than zero if a diff was found, zero if none found,
 * less than zero for errors.
 */
static int user_deep_diff_roles(poldiff_t * diff, qpol_user_t * u1, qpol_user_t * u2, poldiff_user_t * u)
{
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *role1, *role2;
	size_t i, j;
	int retval = -1, error = 0, compval;

	if ((v1 = user_get_roles(diff, diff->orig_pol, u1)) == NULL || (v2 = user_get_roles(diff, diff->mod_pol, u2)) == NULL) {
		error = errno;
		goto cleanup;
	}
	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1);) {
		if (j >= apol_vector_get_size(v2))
			break;
		role1 = (char *)apol_vector_get_element(v1, i);
		role2 = (char *)apol_vector_get_element(v2, j);
		compval = strcmp(role1, role2);
		if (compval < 0) {
			if ((role1 = strdup(role1)) == NULL || apol_vector_append(u->removed_roles, role1) < 0) {
				error = errno;
				free(role1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		} else if (compval > 0) {
			if ((role2 = strdup(role2)) == NULL || apol_vector_append(u->added_roles, role2) < 0) {
				error = errno;
				free(role2);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		} else {
			if ((role1 = strdup(role1)) == NULL || apol_vector_append(u->unmodified_roles, role1) < 0) {
				error = errno;
				free(role1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
			j++;
		}
	}
	for (; i < apol_vector_get_size(v1); i++) {
		role1 = (char *)apol_vector_get_element(v1, i);
		if ((role1 = strdup(role1)) == NULL || apol_vector_append(u->removed_roles, role1) < 0) {
			error = errno;
			free(role1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		role2 = (char *)apol_vector_get_element(v2, j);
		if ((role2 = strdup(role2)) == NULL || apol_vector_append(u->added_roles, role2) < 0) {
			error = errno;
			free(role2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (apol_vector_get_size(u->removed_roles) > 0 || apol_vector_get_size(u->added_roles) > 0) {
		retval = 1;
	} else {
		retval = 0;
	}
      cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	errno = error;
	return retval;
}

/**
 * Allocate and return a poldiff_level_t object.  If the form is added
 * or removed, set its unmodified_cats vector to be all of the
 * categories from the given level.
 */
static poldiff_level_t *user_level_create(qpol_policy_t * q, qpol_mls_level_t * level, poldiff_form_e form)
{
	char *sens;
	qpol_iterator_t *cats;
	poldiff_level_t *pl = NULL;
	if (qpol_mls_level_get_sens_name(q, level, &sens) < 0 ||
	    qpol_mls_level_get_cat_iter(q, level, &cats) < 0 ||
	    (pl = calloc(1, sizeof(*pl))) == NULL ||
	    (pl->name = strdup(sens)) == NULL || (pl->unmodified_cats = apol_vector_create()) == NULL) {
		level_free(pl);
		return NULL;;
	}
	pl->form = form;
	for (; !qpol_iterator_end(cats); qpol_iterator_next(cats)) {
		qpol_cat_t *cat;
		char *c, *c2 = NULL;
		if (qpol_iterator_get_item(cats, (void **)&cat) < 0 ||
		    qpol_cat_get_name(q, cat, &c) < 0 ||
		    (c2 = strdup(c)) == NULL || apol_vector_append(pl->unmodified_cats, c2) < 0) {
			free(c2);
			level_free(pl);
			qpol_iterator_destroy(&cats);
			return NULL;
		}
	}
	qpol_iterator_destroy(&cats);
	return pl;
}

/**
 * Perform a deep diff of two levels.  This will first compare the
 * sensitivity names; if they match then it compares the vectors of
 * category names.  If the sensitivities do not match, then generate
 * two poldiff_level_ts, one for the original level and one for
 * modified level.  If they do match then create just one
 * poldiff_level_t and write it to orig_uld.
 *
 * @param diff Poldiff object, used for error reporting and for
 * sorting the categories to policy order.
 * @param sens1 Sensitivity name for the original level.
 * @param cats1 Vector of categories (type char *) for the original
 * level.  Note that this vector will be modified.
 * @param sens2 Sensitivity name for the modified level.
 * @param cats2 Vector of categories (type char *) for the modified
 * level.  Note that this vector will be modified.
 * @param orig_pl Destination to where to write the poldiff_level_t,
 * if the sensitivites do not match or if the categories do not match.
 * @param mod_pl Destination to where to write the poldiff_level_t,
 * if the sensitivities do not match.
 *
 * @return 0 on success, < 0 on error.
 */
static int user_level_deep_diff(poldiff_t * diff, const char *sens1, apol_vector_t * cats1, const char *sens2,
				apol_vector_t * cats2, poldiff_level_t ** orig_pl, poldiff_level_t ** mod_pl)
{
	poldiff_level_t *u1 = NULL, *u2 = NULL;
	size_t i, j;
	char *cat1, *cat2, *s;
	apol_vector_t *added, *removed, *unmodified;
	int retval = -1, compval;

	if (strcmp(sens1, sens2) != 0) {
		/* sensitivities do not match, so don't check categories */
		if ((u1 = calloc(1, sizeof(*u1))) == NULL ||
		    (u1->name = strdup(sens1)) == NULL ||
		    (u1->unmodified_cats = apol_vector_create_from_vector(cats1, apol_str_strdup, NULL)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			level_free(u1);
			level_free(u2);
			return -1;
		}
		if ((u2 = calloc(1, sizeof(*u2))) == NULL ||
		    (u2->name = strdup(sens2)) == NULL ||
		    (u2->unmodified_cats = apol_vector_create_from_vector(cats2, apol_str_strdup, NULL)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			level_free(u1);
			level_free(u2);
			return -1;
		}
		apol_vector_sort(u1->unmodified_cats, level_cat_comp, diff->orig_qpol);
		apol_vector_sort(u2->unmodified_cats, level_cat_comp, diff->mod_qpol);
		u1->form = POLDIFF_FORM_REMOVED;
		u2->form = POLDIFF_FORM_ADDED;
		*orig_pl = u1;
		*mod_pl = u2;
		return 0;
	}

	apol_vector_sort(cats1, apol_str_strcmp, NULL);
	apol_vector_sort(cats2, apol_str_strcmp, NULL);
	/* diff the categories from cats1 and cats2 */
	if ((added = apol_vector_create()) == NULL ||
	    (removed = apol_vector_create()) == NULL || (unmodified = apol_vector_create()) == NULL) {
		goto cleanup;
	}
	for (i = j = 0; i < apol_vector_get_size(cats1);) {
		if (j >= apol_vector_get_size(cats2))
			break;
		cat1 = (char *)apol_vector_get_element(cats1, i);
		cat2 = (char *)apol_vector_get_element(cats2, j);
		compval = strcmp(cat1, cat2);
		if (compval < 0) {
			if ((s = strdup(cat1)) == NULL || apol_vector_append(removed, s) < 0) {
				ERR(diff, "%s", strerror(errno));
				free(s);
				goto cleanup;
			}
			i++;
		} else if (compval > 0) {
			if ((s = strdup(cat2)) == NULL || apol_vector_append(added, s) < 0) {
				ERR(diff, "%s", strerror(errno));
				free(s);
				goto cleanup;
			}
			j++;
		} else {
			if ((s = strdup(cat1)) == NULL || apol_vector_append(unmodified, s) < 0) {
				ERR(diff, "%s", strerror(errno));
				free(s);
				goto cleanup;
			}
			i++;
			j++;
		}
	}
	for (; i < apol_vector_get_size(cats1); i++) {
		cat1 = (char *)apol_vector_get_element(cats1, i);
		if ((s = strdup(cat1)) == NULL || apol_vector_append(removed, s) < 0) {
			ERR(diff, "%s", strerror(errno));
			free(s);
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(cats2); j++) {
		cat2 = (char *)apol_vector_get_element(cats2, j);
		if ((s = strdup(cat2)) == NULL || apol_vector_append(added, s) < 0) {
			ERR(diff, "%s", strerror(errno));
			free(s);
			goto cleanup;
		}
	}
	if (apol_vector_get_size(added) > 0 || apol_vector_get_size(removed) > 0) {
		if ((u1 = calloc(1, sizeof(*u1))) == NULL || (u1->name = strdup(sens1)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			level_free(u1);
			goto cleanup;
		}
		apol_vector_sort(added, level_cat_comp, diff->mod_qpol);
		apol_vector_sort(removed, level_cat_comp, diff->orig_qpol);
		apol_vector_sort(unmodified, level_cat_comp, diff->orig_qpol);
		u1->added_cats = added;
		u1->removed_cats = removed;
		u1->unmodified_cats = unmodified;
		u1->form = POLDIFF_FORM_MODIFIED;
		*orig_pl = u1;
		return 0;
	}
	/* if reached this point, then no differences were found */
	retval = 0;
      cleanup:
	apol_vector_destroy(&added, free);
	apol_vector_destroy(&removed, free);
	apol_vector_destroy(&unmodified, free);
	return retval;
}

/**
 * Perform a deep diff of the default MLS levels assigned to the two
 * users.
 *
 * @param diff Diff structure containing the original and modified
 * policies.
 * @param u1 User from original policy to examine.
 * @param u2 User from modified policy to examine.
 * @param u Result structure where differences are to be recorded.
 *
 * @return Greater than zero if a diff was found, zero if none found,
 * less than zero for errors.
 */
static int user_deep_diff_default_levels(poldiff_t * diff, qpol_user_t * u1, qpol_user_t * u2, poldiff_user_t * u)
{
	qpol_mls_level_t *l1 = NULL, *l2 = NULL;
	poldiff_level_t *pl = NULL;
	char *sens1 = "", *sens2 = "";
	qpol_iterator_t *cats1 = NULL, *cats2 = NULL;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	int retval = -1;
	if (qpol_user_get_dfltlevel(diff->orig_qpol, u1, &l1) < 0 || qpol_user_get_dfltlevel(diff->mod_qpol, u2, &l2) < 0) {
		return -1;
	}
	if (l1 == NULL && l2 == NULL) {
		/* neither policy is MLS */
		return 0;
	}
	if (l1 == NULL) {
		if ((pl = user_level_create(diff->mod_qpol, l2, POLDIFF_FORM_ADDED)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		u->mod_default_level = pl;
		retval = 1;
	} else if (l2 == NULL) {
		if ((pl = user_level_create(diff->orig_qpol, l1, POLDIFF_FORM_REMOVED)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		u->orig_default_level = pl;
		retval = 1;
	} else {
		size_t size1, size2;
		/* do a deep diff of the given level */
		if (qpol_mls_level_get_sens_name(diff->orig_qpol, l1, &sens1) < 0 ||
		    qpol_mls_level_get_sens_name(diff->mod_qpol, l2, &sens2) < 0 ||
		    qpol_mls_level_get_cat_iter(diff->orig_qpol, l1, &cats1) < 0 ||
		    qpol_mls_level_get_cat_iter(diff->mod_qpol, l2, &cats2) < 0 ||
		    qpol_iterator_get_size(cats1, &size1) < 0 || qpol_iterator_get_size(cats2, &size2) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		if ((v1 = apol_vector_create_with_capacity(size1)) == NULL ||
		    (v2 = apol_vector_create_with_capacity(size2)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		for (; !qpol_iterator_end(cats1); qpol_iterator_next(cats1)) {
			qpol_cat_t *cat;
			char *c, *c2 = NULL;
			if (qpol_iterator_get_item(cats1, (void **)&cat) < 0 ||
			    qpol_cat_get_name(diff->orig_qpol, cat, &c) < 0 ||
			    (c2 = strdup(c)) == NULL || apol_vector_append(v1, c2) < 0) {
				ERR(diff, "%s", strerror(errno));
				free(c2);
				goto cleanup;
			}
		}
		for (; !qpol_iterator_end(cats2); qpol_iterator_next(cats2)) {
			qpol_cat_t *cat;
			char *c, *c2 = NULL;
			if (qpol_iterator_get_item(cats2, (void **)&cat) < 0 ||
			    qpol_cat_get_name(diff->mod_qpol, cat, &c) < 0 ||
			    (c2 = strdup(c)) == NULL || apol_vector_append(v2, c2) < 0) {
				ERR(diff, "%s", strerror(errno));
				free(c2);
				goto cleanup;
			}
		}
		if (user_level_deep_diff(diff, sens1, v1, sens2, v2, &u->orig_default_level, &u->mod_default_level) < 0) {
			goto cleanup;
		}
		if (u->orig_default_level != NULL) {
			retval = 1;
		}
	}
	if (retval == -1) {
		/* if reach this point, then no differences were found */
		retval = 0;
	}
      cleanup:
	qpol_iterator_destroy(&cats1);
	qpol_iterator_destroy(&cats2);
	apol_vector_destroy(&v1, free);
	apol_vector_destroy(&v2, free);
	if (retval < 0) {
		level_free(pl);
	}
	return retval;
}

/**
 * Allocate and return a poldiff_range_t object.  This will fill in
 * the orig_range and mod_range strings.
 */
static poldiff_range_t *range_create(poldiff_t * diff, qpol_mls_range_t * orig_range, qpol_mls_range_t * mod_range,
				     poldiff_form_e form)
{
	poldiff_range_t *pr = NULL;
	int retval = -1;
	if ((pr = calloc(1, sizeof(*pr))) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (orig_range != NULL && (pr->orig_range = apol_mls_range_create_from_qpol_mls_range(diff->orig_pol, orig_range)) == NULL) {
		goto cleanup;
	}
	if (mod_range != NULL && (pr->mod_range = apol_mls_range_create_from_qpol_mls_range(diff->mod_pol, mod_range)) == NULL) {
		goto cleanup;
	}
	/* FIX ME
	 * if (form == POLDIFF_FORM_ADDED) {
	 * if ((pr->levels = apol_mls_range_get_levels(diff->mod_pol, pr->mod_range)) == NULL) {
	 * goto cleanup;
	 * }
	 * }
	 * else if (form == POLDIFF_FORM_REMOVED) {
	 * if ((pr->levels = apol_mls_range_get_levels(diff->orig_pol, pr->orig_range)) == NULL) {
	 * goto cleanup;
	 * }
	 * }
	 * else {
	 * assert(form == POLDIFF_FORM_MODIFIED);
	 * if ((pr->levels = apol_vector_create()) == NULL) {
	 * ERR(diff, "%s", strerror(errno));
	 * }
	 * }
	 */
	retval = 0;
      cleanup:
	if (retval != 0) {
		range_free(pr);
		return NULL;
	}
	return pr;
}

/**
 * Perform a deep diff of the MLS ranges assigned to the two users.
 * This involves two things: changes in the expanded levels, and
 * changes to minimum category sets.
 *
 * @param diff Diff structure containing the original and modified
 * policies.
 * @param u1 User from original policy to examine.
 * @param u2 User from modified policy to examine.
 * @param u Result structure where differences are to be recorded.
 *
 * @return Greater than zero if a diff was found, zero if none found,
 * less than zero for errors.
 */
static int user_deep_diff_ranges(poldiff_t * diff, qpol_user_t * u1, qpol_user_t * u2, poldiff_user_t * u)
{
	qpol_mls_range_t *r1 = NULL, *r2 = NULL;
	poldiff_range_t *pr = NULL;
	int retval = -1;
	if (qpol_user_get_range(diff->orig_qpol, u1, &r1) < 0 || qpol_user_get_range(diff->mod_qpol, u2, &r2) < 0) {
		return -1;
	}
	if (r1 == NULL && r2 == NULL) {
		/* neither policy is MLS */
		return 0;
	}
	if (r1 == NULL) {
		if ((pr = range_create(diff, r1, r2, POLDIFF_FORM_ADDED)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		u->range = pr;
		retval = 1;
	} else if (r2 == NULL) {
		if ((pr = range_create(diff, r1, r2, POLDIFF_FORM_REMOVED)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		u->range = pr;
		retval = 1;
	} else {
	}
	if (retval == -1) {
		/* if reach this point, then no differences were found */
		retval = 0;
	}
      cleanup:
	if (retval < 0) {
		range_free(pr);
	}
	return retval;
}

int user_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_user_t *u1 = (qpol_user_t *) x;
	qpol_user_t *u2 = (qpol_user_t *) y;
	char *name;
	poldiff_user_t *u = NULL;
	int retval = -1, r1 = 0, r2 = 0, r3 = 0, error = 0;
	if (qpol_user_get_name(diff->orig_qpol, u1, &name) < 0 || (u = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((r1 = user_deep_diff_roles(diff, u1, u2, u)) < 0 || (r2 = user_deep_diff_default_levels(diff, u1, u2, u)) < 0 ||
	    (r3 = user_deep_diff_ranges(diff, u1, u2, u)) < 0) {
		error = errno;
		goto cleanup;
	}
	if (r1 > 0 || r2 > 0 || r3 > 0) {
		if (apol_vector_append(diff->user_diffs->diffs, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->user_diffs->num_modified++;
	} else {
		/* no differences found */
		user_free(u);
	}
	retval = 0;
      cleanup:
	if (retval != 0) {
		user_free(u);
	}
	errno = error;
	return retval;
}
