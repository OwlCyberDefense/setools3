/**
 *  @file role_allow_diff.h
 *  Implementation for computing a semantic differences in roles allow rules.
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
#include <apol/bst.h>
#include <qpol/policy_query.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_role_allow_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_role_allow {
	char *source_role;
	poldiff_form_e form;
	apol_vector_t *orig_roles;
	apol_vector_t *added_roles;
	apol_vector_t *removed_roles;
};

void poldiff_role_allow_get_stats(poldiff_t *diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->role_allow_diffs->num_added;
	stats[1] = diff->role_allow_diffs->num_removed;
	stats[2] = diff->role_allow_diffs->num_modified;
	stats[3] = 0;
	stats[4] = 0;
}

char *poldiff_role_allow_to_string(poldiff_t *diff, const void *role_allow)
{
	const poldiff_role_allow_t *ra = role_allow;
	size_t num_added, num_removed, len, i;
	char *s = NULL, *t = NULL, *role;
	if (diff == NULL || role_allow == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	num_added = apol_vector_get_size(ra->added_roles);
	num_removed = apol_vector_get_size(ra->removed_roles);
	switch (ra->form) {
		case POLDIFF_FORM_ADDED: {
											 if (asprintf(&s, "+ allow %s { ", ra->source_role) < 0) {
												 s = NULL;
												 break;
											 }
											 len = strlen(s);
											 for (i = 0; i < apol_vector_get_size(ra->orig_roles); i++) {
												 role = apol_vector_get_element(ra->orig_roles, i);
												 if (asprintf(&t, "%s ", role) < 0) {
													 t = NULL;
													 break;
												 }
												 if (apol_str_append(&s, &len, t) < 0) {
													 break;
												 }
												 free(t);
												 t = NULL;
											 }
											 if (apol_str_append(&s, &len, "};") < 0) {
												 break;
											 }
											 return s;
										 }
		case POLDIFF_FORM_REMOVED: {
												if (asprintf(&s, "- allow %s { ", ra->source_role) < 0) {
													s = NULL;
													break;
												}
												len = strlen(s);
												for (i = 0; i < apol_vector_get_size(ra->orig_roles); i++) {
													role = apol_vector_get_element(ra->orig_roles, i);
													if (asprintf(&t, "%s ", role) < 0) {
														t = NULL;
														break;
													}
													if (apol_str_append(&s, &len, t) < 0) {
														break;
													}
													free(t);
													t = NULL;
												}
												if (apol_str_append(&s, &len, "};") < 0) {
													break;
												}
												return s;
											}
		case POLDIFF_FORM_MODIFIED: {
												 if (asprintf(&s, "* allow %s { ", ra->source_role) < 0) {
													 s = NULL;
													 break;
												 }
												 len = strlen(s);
												 for (i = 0; i < apol_vector_get_size(ra->orig_roles); i++) {
													 role = apol_vector_get_element(ra->orig_roles, i);
													 if (asprintf(&t, "%s ", role) < 0) {
														 t = NULL;
														 break;
													 }
													 if (apol_str_append(&s, &len, t) < 0) {
														 break;
													 }
													 free(t);
													 t = NULL;
												 }
												 for (i = 0; i < apol_vector_get_size(ra->added_roles); i++) {
													 role = apol_vector_get_element(ra->added_roles, i);
													 if (asprintf(&t, "+%s ", role) < 0) {
														 t = NULL;
														 break;
													 }
													 if (apol_str_append(&s, &len, t) < 0) {
														 break;
													 }
													 free(t);
													 t = NULL;
												 }
												 for (i = 0; i < apol_vector_get_size(ra->removed_roles); i++) {
													 role = apol_vector_get_element(ra->removed_roles, i);
													 if (asprintf(&t, "-%s ", role) < 0) {
														 t = NULL;
														 break;
													 }
													 if (apol_str_append(&s, &len, t) < 0) {
														 break;
													 }
													 free(t);
													 t = NULL;
												 }
												 if (apol_str_append(&s, &len, "};") < 0) {
													 break;
												 }
												 return s;
											 }
		default: {
						ERR(diff, "%s", strerror(ENOTSUP));
						errno = ENOTSUP;
						return NULL;
					}
	}
	/* if this is reached then an error occurred */
	free(s);
	free(t);
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_role_allow_vector(poldiff_t *diff)
{
	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->role_allow_diffs->diffs;
}


const char *poldiff_role_allow_get_name(const poldiff_role_allow_t *role_allow)
{
	if (role_allow == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_allow->source_role;
}

poldiff_form_e poldiff_role_allow_get_form(const poldiff_role_allow_t *role_allow)
{
	if (role_allow == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return role_allow->form;
}

apol_vector_t *poldiff_role_allow_get_added_roles(const poldiff_role_allow_t *role_allow)
{
	if (role_allow == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_allow->added_roles;
}

apol_vector_t *poldiff_role_allow_get_removed_roles(const poldiff_role_allow_t *role_allow)
{
	if (role_allow == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_allow->removed_roles;
}

poldiff_role_allow_summary_t *role_allow_create(void)
{
	poldiff_role_allow_summary_t *ras = calloc(1, sizeof(*ras));
	if (ras == NULL) {
		return NULL;
	}
	if ((ras->diffs = apol_vector_create()) == NULL) {
		role_allow_destroy(&ras);
		return NULL;
	}
	return ras;
}

static void role_allow_free(void *elem)
{
	if (elem != NULL) {
		poldiff_role_allow_t *r = (poldiff_role_allow_t *) elem;
		apol_vector_destroy(&r->orig_roles, NULL);
		apol_vector_destroy(&r->added_roles, NULL);
		apol_vector_destroy(&r->removed_roles, NULL);
		free(r);
	}
}

void role_allow_destroy(poldiff_role_allow_summary_t **ras)
{
	if (ras != NULL && *ras != NULL) {
		apol_vector_destroy(&(*ras)->diffs, role_allow_free);
		free(*ras);
		*ras = NULL;
	}
}

typedef struct pseudo_role_allow {
	char *source_role;
	apol_vector_t *target_roles;
} pseudo_role_allow_t;

void role_allow_free_item(void *item)
{
	pseudo_role_allow_t *pra = item;

	if (!item)
		return;

	/* no need to free source name or target role names */
	apol_vector_destroy(&pra->target_roles, NULL);
	free(item);
}

static int role_allow_source_comp(const void *x, const void *y, void *arg __attribute__((unused)))
{
	const pseudo_role_allow_t *p1 = x;
	const pseudo_role_allow_t *p2 = y;

	return strcmp(p1->source_role, p2->source_role);
}

apol_vector_t *role_allow_get_items(poldiff_t *diff, apol_policy_t *policy)
{
	qpol_iterator_t *iter = NULL;
	apol_vector_t *tmp = NULL, *v = NULL;
	int error = 0, retv;
	size_t i;
	apol_bst_t *bst = NULL;
	pseudo_role_allow_t *pra = NULL;
	qpol_role_t *sr = NULL, *tr = NULL;
	char *sr_name = NULL, *tr_name = NULL;
	qpol_role_allow_t *qra = NULL;

	if (qpol_policy_get_role_allow_iter(policy->qh, policy->p, &iter) < 0) {
		return NULL;
	}

	tmp = apol_vector_create_from_iter(iter);
	if (tmp == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		qpol_iterator_destroy(&iter);
		errno = error;
		return NULL;
	}
	qpol_iterator_destroy(&iter);

	bst = apol_bst_create(role_allow_source_comp);

	for (i = 0; i < apol_vector_get_size(tmp); i++) {
		qra = apol_vector_get_element(tmp, i);
		if (!(pra = calloc(1, sizeof(*pra))) ||
				(!(pra->target_roles = apol_vector_create_with_capacity(1)))) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		if (qpol_role_allow_get_source_role(policy->qh, policy->p, qra, &sr) ||
				qpol_role_get_name(policy->qh, policy->p, sr, &sr_name)) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		sr = NULL;
		if (qpol_role_allow_get_target_role(policy->qh, policy->p, qra, &tr) ||
				qpol_role_get_name(policy->qh, policy->p, tr, &tr_name)) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		tr = NULL;
		pra->source_role = sr_name;
		retv = apol_bst_insert_and_get(bst, (void**)&pra, NULL, role_allow_free_item);
		if (retv < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		apol_vector_append_unique(pra->target_roles, tr_name, apol_str_strcmp, NULL);
		pra = NULL;
	}
	apol_vector_destroy(&tmp, NULL);

	v = apol_bst_get_vector(bst);
	if (!v) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto err;
	}
	apol_bst_destroy(&bst, NULL);

	return v;

err:
	role_allow_free_item(pra);
	apol_bst_destroy(&bst, role_allow_free_item);
	errno = error;
	return NULL;
}

int role_allow_comp(const void *x, const void *y, poldiff_t *diff __attribute__((unused)))
{
	const pseudo_role_allow_t *p1 = x;
	const pseudo_role_allow_t *p2 = y;

	return strcmp(p1->source_role, p2->source_role);
}

/**
 *  Allocate and return a new role allow rule difference object.
 *
 *  @param diff Policy diff error handler.
 *  @param form Form of the difference.
 *  @param source_role Name of the source role in the role allow rule.
 *
 *  @return A newly allocated and initialized diff, or NULL upon error.
 *  The caller is responsible for calling role_allow_free() upon the returned
 *  value.
 */
static poldiff_role_allow_t *make_diff(poldiff_t *diff, poldiff_form_e form, char *source_role)
{
	poldiff_role_allow_t *ra = NULL;
	int error = 0;
	if ((ra = calloc(1, sizeof(*ra))) == NULL ||
			(ra->source_role = source_role) == NULL ||
			(ra->added_roles = apol_vector_create_with_capacity(1)) == NULL ||
			(ra->orig_roles = apol_vector_create_with_capacity(1)) == NULL ||
			(ra->removed_roles = apol_vector_create_with_capacity(1)) == NULL) {
		error = errno;
		role_allow_free(ra);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	ra->form = form;
	return ra;
}

int role_allow_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item)
{
	pseudo_role_allow_t *ra = (pseudo_role_allow_t *) item;
	poldiff_role_allow_t *pra;
	int error;

	pra = make_diff(diff, form, ra->source_role);
	if (pra == NULL) {
		return -1;
	}
	apol_vector_cat(pra->orig_roles, ra->target_roles);
	if (apol_vector_append(diff->role_allow_diffs->diffs, pra) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		role_allow_free(pra);
		errno = error;
		return -1;
	}
	if (form == POLDIFF_FORM_ADDED) {
		diff->role_allow_diffs->num_added++;
	}
	else {
		diff->role_allow_diffs->num_removed++;
	}
	return 0;
}

int role_allow_deep_diff(poldiff_t *diff, const void *x, const void *y)
{
	const pseudo_role_allow_t *p1 = x;
	const pseudo_role_allow_t *p2 = y;
	apol_vector_t *v1 = NULL, *v2 = NULL;
	char *role1, *role2;
	poldiff_role_allow_t *pra = NULL;
	size_t i, j;
	int retval = -1, error = 0, compval;

	v1 = p1->target_roles;
	v2 = p2->target_roles;

	apol_vector_sort(v1, apol_str_strcmp, NULL);
	apol_vector_sort(v2, apol_str_strcmp, NULL);
	for (i = j = 0; i < apol_vector_get_size(v1); ) {
		if (j >= apol_vector_get_size(v2))
			break;
		role1 = (char *) apol_vector_get_element(v1, i);
		role2 = (char *) apol_vector_get_element(v2, j);
		compval = strcmp(role1, role2);
		if (compval != 0 && pra == NULL) {
			if ((pra = make_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if (compval < 0) {
			if (apol_vector_append(pra->removed_roles, role1) < 0) {
				error = errno;
				free(role1);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		}
		else if (compval > 0) {
			if (apol_vector_append(pra->added_roles, role2) < 0) {
				error = errno;
				free(role2);
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		}
		else {
			if (apol_vector_append(pra->orig_roles, role1) < 0) {
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
		role1 = (char *) apol_vector_get_element(v1, i);
		if (pra == NULL) {
			if ((pra = make_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((role1 = strdup(role1)) == NULL ||
				apol_vector_append(pra->removed_roles, role1) < 0) {
			error = errno;
			free(role1);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	for (; j < apol_vector_get_size(v2); j++) {
		role2 = (char *) apol_vector_get_element(v2, j);
		if (pra == NULL) {
			if ((pra = make_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if ((role2 = strdup(role2)) == NULL ||
				apol_vector_append(pra->added_roles, role2) < 0) {
			error = errno;
			free(role2);
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
	}
	if (pra != NULL) {
		apol_vector_sort(pra->removed_roles, apol_str_strcmp, NULL);
		apol_vector_sort(pra->added_roles, apol_str_strcmp, NULL);
		apol_vector_sort(pra->orig_roles, apol_str_strcmp, NULL);
		if (apol_vector_append(diff->role_allow_diffs->diffs, pra) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->role_allow_diffs->num_modified++;
	}
	retval = 0;
cleanup:
	apol_vector_destroy(&v1, NULL);
	apol_vector_destroy(&v2, NULL);
	if (retval != 0) {
		role_allow_free(pra);
	}
	errno = error;
	return retval;
}

