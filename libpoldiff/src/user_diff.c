/**
 *  @file user_diff.c
 *  Implementation for computing a semantic differences in users.
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

struct poldiff_user_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_user
{
	char *name;
	poldiff_form_e form;
	apol_vector_t *added_roles;
	apol_vector_t *removed_roles;
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

char *poldiff_user_to_string(poldiff_t * diff, const void *user)
{
	poldiff_user_t *u = (poldiff_user_t *) user;
	size_t num_added, num_removed, len, i;
	char *s = NULL, *t = NULL, *role;
	if (diff == NULL || user == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(u->added_roles);
	num_removed = apol_vector_get_size(u->removed_roles);
	switch (u->form) {
	case POLDIFF_FORM_ADDED:{
			if (asprintf(&s, "+ %s", u->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_REMOVED:{
			if (asprintf(&s, "- %s", u->name) < 0) {
				s = NULL;
				break;
			}
			return s;
		}
	case POLDIFF_FORM_MODIFIED:{
			if (asprintf(&s, "* %s (", u->name) < 0) {
				s = NULL;
				break;
			}
			len = strlen(s);
			if (num_added > 0) {
				if (asprintf(&t, "%d Added Roles", num_added) < 0) {
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
				if (asprintf(&t, "%s%d Removed Roles", (num_added > 0 ? ", " : ""), num_removed) < 0) {
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
			for (i = 0; i < apol_vector_get_size(u->added_roles); i++) {
				role = (char *)apol_vector_get_element(u->added_roles, i);
				if (asprintf(&t, "\t+ %s\n", role) < 0) {
					t = NULL;
					goto err;
				}
				if (apol_str_append(&s, &len, t) < 0) {
					goto err;
				}
				free(t);
				t = NULL;
			}
			for (i = 0; i < apol_vector_get_size(u->removed_roles); i++) {
				role = (char *)apol_vector_get_element(u->removed_roles, i);
				if (asprintf(&t, "\t- %s\n", role) < 0) {
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
	default:{
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

static void user_free(void *elem)
{
	if (elem != NULL) {
		poldiff_user_t *u = (poldiff_user_t *) elem;
		free(u->name);
		apol_vector_destroy(&u->added_roles, free);
		apol_vector_destroy(&u->removed_roles, free);
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
	char *name1, *name2;
	if (qpol_user_get_name(p->p, u1, &name1) < 0 || qpol_user_get_name(p->p, u2, &name2) < 0) {
		return 0;
	}
	return strcmp(name1, name2);
}

apol_vector_t *user_get_items(poldiff_t * diff, apol_policy_t * policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *v = NULL;
	int error = 0;
	if (qpol_policy_get_user_iter(policy->p, &iter) < 0) {
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
	if (qpol_user_get_name(diff->orig_pol->p, u1, &name1) < 0 || qpol_user_get_name(diff->mod_pol->p, u2, &name2) < 0) {
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
	    (pu->removed_roles = apol_vector_create_with_capacity(1)) == NULL) {
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
	     qpol_user_get_name(diff->mod_pol->p, u, &name) < 0) ||
	    ((form == POLDIFF_FORM_REMOVED || form == POLDIFF_FORM_MODIFIED) &&
	     qpol_user_get_name(diff->orig_pol->p, u, &name) < 0)) {
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
	int retval = -1, error = 0;

	if ((v = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (qpol_user_get_role_iter(p->p, user, &iter) < 0) {
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&role) < 0 || qpol_role_get_name(p->p, role, &role_name)) {
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

int user_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	qpol_user_t *u1 = (qpol_user_t *) x;
	qpol_user_t *u2 = (qpol_user_t *) y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *role1, *role2, *name;
	poldiff_user_t *u = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	if (qpol_user_get_name(diff->orig_pol->p, u1, &name) < 0 ||
	    (v1 = user_get_roles(diff, diff->orig_pol, u1)) == NULL || (v2 = user_get_roles(diff, diff->mod_pol, u2)) == NULL) {
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
		if (compval != 0 && u == NULL) {
			if ((u = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
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
			i++;
			j++;
		}
	}
	for (; i < apol_vector_get_size(v1); i++) {
		role1 = (char *)apol_vector_get_element(v1, i);
		if (u == NULL) {
			if ((u = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((role1 = strdup(role1)) == NULL || apol_vector_append(u->removed_roles, role1) < 0) {
			error = errno;
			free(role1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		role2 = (char *)apol_vector_get_element(v2, j);
		if (u == NULL) {
			if ((u = make_diff(diff, POLDIFF_FORM_MODIFIED, name)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((role2 = strdup(role2)) == NULL || apol_vector_append(u->added_roles, role2) < 0) {
			error = errno;
			free(role2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (u != NULL) {
		apol_vector_sort(u->removed_roles, apol_str_strcmp, NULL);
		apol_vector_sort(u->added_roles, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->user_diffs->diffs, u) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->user_diffs->num_modified++;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	if (retval != 0) {
		user_free(u);
	}
	errno = error;
	return retval;
}
