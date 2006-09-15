/**
 *  @file rbac_diff.h
 *  Implementation for computing a semantic differences in roles allow rules
 *  and role_transition rules.
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
#include <assert.h>

struct poldiff_role_allow_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	apol_vector_t *diffs;
};

struct poldiff_role_trans_summary {
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	apol_vector_t *diffs;
};

struct poldiff_role_allow {
	char *source_role;
	poldiff_form_e form;
	apol_vector_t *orig_roles;
	apol_vector_t *added_roles;
	apol_vector_t *removed_roles;
};

struct poldiff_role_trans {
	char *source_role;
	char *target_type;
	char *orig_default;
	char *mod_default;
	poldiff_form_e form;
};

/**************** role allow functions *******************/

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
		case POLDIFF_FORM_ADDED:
			{
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
		case POLDIFF_FORM_REMOVED:
			{
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
		case POLDIFF_FORM_MODIFIED:
			{
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
		default:
			{
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

poldiff_form_e poldiff_role_allow_get_form(const void *role_allow)
{
	if (role_allow == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_role_allow_t *) role_allow)->form;
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
static poldiff_role_allow_t *make_ra_diff(poldiff_t *diff, poldiff_form_e form, char *source_role)
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

	pra = make_ra_diff(diff, form, ra->source_role);
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
			if ((pra = make_ra_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
				error = errno;
				goto cleanup;
			}
		}
		if (compval < 0) {
			if (apol_vector_append(pra->removed_roles, role1) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			i++;
		}
		else if (compval > 0) {
			if (apol_vector_append(pra->added_roles, role2) < 0) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto cleanup;
			}
			j++;
		}
		else {
			if (apol_vector_append(pra->orig_roles, role1) < 0) {
				error = errno;
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
			if ((pra = make_ra_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
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
			if ((pra = make_ra_diff(diff, POLDIFF_FORM_MODIFIED, p1->source_role)) == NULL) {
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
	if (retval != 0) {
		role_allow_free(pra);
	}
	errno = error;
	return retval;
}

/**************** role_transition functions *******************/

void poldiff_role_trans_get_stats(poldiff_t *diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->role_trans_diffs->num_added;
	stats[1] = diff->role_trans_diffs->num_removed;
	stats[2] = diff->role_trans_diffs->num_modified;
	stats[3] = diff->role_trans_diffs->num_added_type;
	stats[4] = diff->role_trans_diffs->num_removed_type;
}

extern char *poldiff_role_trans_to_string(poldiff_t *diff, const void *role_trans)
{
	const poldiff_role_trans_t *rt = role_trans;
	char *s = NULL;

	if (diff == NULL || role_trans == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (rt->form) {
		case POLDIFF_FORM_ADDED:
		case POLDIFF_FORM_ADD_TYPE:
			{
				if (asprintf(&s, "+ role_transition %s %s %s;", rt->source_role, rt->target_type, rt->mod_default) < 0)
					break;
				return s;
			}
		case POLDIFF_FORM_REMOVED:
		case POLDIFF_FORM_REMOVE_TYPE:
			{
				if (asprintf(&s, "- role_transition %s %s %s;", rt->source_role, rt->target_type, rt->orig_default) < 0)
					break;
				return s;
			}
		case POLDIFF_FORM_MODIFIED:
			{
				if (asprintf(&s, "* role_transition %s %s { -%s +%s };", rt->source_role, rt->target_type, rt->orig_default, rt->mod_default) < 0)
					break;
				return s;
			}
		case POLDIFF_FORM_NONE:
		default:
			{
				ERR(diff, "%s", strerror(ENOTSUP));
				errno = ENOTSUP;
				return NULL;
			}
	}
	/* if this is reached then an error occurred */
	free(s);
	ERR(diff, "%s", strerror(ENOMEM));
	errno = ENOMEM;
	return NULL;
}

apol_vector_t *poldiff_get_role_trans_vector(poldiff_t *diff)
{
	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->role_trans_diffs->diffs;
}

extern const char *poldiff_role_trans_get_source_role(const poldiff_role_trans_t *role_trans)
{
	if (role_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_trans->source_role;
}

extern const char *poldiff_role_trans_get_target_type(const poldiff_role_trans_t *role_trans)
{
	if (role_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_trans->target_type;
}

extern poldiff_form_e poldiff_role_trans_get_form(const void *role_trans)
{
	if (role_trans == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_role_trans_t *) role_trans)->form;
}

extern const char *poldiff_role_trans_get_original_default(const poldiff_role_trans_t *role_trans)
{
	if (role_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_trans->orig_default;
}

extern const char *poldiff_role_trans_get_modified_default(const poldiff_role_trans_t *role_trans)
{
	if (role_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return role_trans->mod_default;
}

poldiff_role_trans_summary_t *role_trans_create(void)
{
	poldiff_role_trans_summary_t *rts = calloc(1, sizeof(*rts));
	if (rts == NULL) {
		return NULL;
	}
	if ((rts->diffs = apol_vector_create()) == NULL) {
		role_trans_destroy(&rts);
		return NULL;
	}
	return rts;
}

void role_trans_destroy(poldiff_role_trans_summary_t **rts)
{
	if (rts != NULL && *rts != NULL) {
		apol_vector_destroy(&(*rts)->diffs, free);
		free(*rts);
		*rts = NULL;
	}
}

typedef struct pseudo_role_trans {
	char *source_role;
	uint32_t pseudo_target;
	char *default_role;
} pseudo_role_trans_t;

/**
 *  Get the first valid name that can be found for a pseudo type value.
 *
 *  @param diff Policy difference structure associated with the value.
 *  @param pseudo_val Value for which to get a name.
 *
 *  @return A valid name of a type from either policy that maps to the
 *  specified value. Original policy is searched first, then modified.
 */
static const char *get_valid_name(poldiff_t *diff, uint32_t pseudo_val)
{
	apol_vector_t *v = NULL;
	char *name = NULL;
	qpol_type_t *t;
	int pol = POLDIFF_POLICY_ORIG;

	v = type_map_lookup_reverse(diff, pseudo_val, pol);
	if (!apol_vector_get_size(v)) {
		pol = POLDIFF_POLICY_MOD;
		v = type_map_lookup_reverse(diff, pseudo_val, pol);
	}
	if (!apol_vector_get_size(v)) {
		ERR(diff, "%s", strerror(ERANGE));
		errno = ERANGE;
		return NULL;
	}
	t = apol_vector_get_element(v, 0);
	if (pol == POLDIFF_POLICY_ORIG)
		qpol_type_get_name(diff->orig_pol->qh, diff->orig_pol->p, t, &name);
	else
		qpol_type_get_name(diff->mod_pol->qh, diff->mod_pol->p, t, &name);
	return name;
}

/**
 *  Compare two pseudo role_transition rules from the same policy.
 *  Compares the source role name and then pseudo type value of the target.
 *
 *  @param x A pseudo_role_trans_t entry.
 *  @param y A pseudo_role_trans_t entry.
 *  @param arg The policy difference structure.
 *
 *  @return < 0, 0, or > 0 if the first rule is respectively less than,
 *  equal to, or greater than the second. If the return value would be 0
 *  but the default role is different a warning is issued.
 */
static int pseudo_role_trans_comp(const void *x, const void *y, void *arg)
{
	int retv = 0;
	const pseudo_role_trans_t *a = x;
	const pseudo_role_trans_t *b = y;
	poldiff_t *diff = arg;

	retv = strcmp(a->source_role, b->source_role);
	if (!retv)
		retv = a->pseudo_target - b->pseudo_target;
	else
		return retv;
	if (!retv && strcmp(a->default_role, b->default_role))
		WARN(diff, "Multiple role_transition rules for %s %s with different default roles", a->source_role, get_valid_name(diff, a->pseudo_target));
	return retv;
}

apol_vector_t *role_trans_get_items(poldiff_t *diff, apol_policy_t *policy)
{
	qpol_iterator_t *iter = NULL, *attr_types = NULL;
	apol_vector_t *v = NULL;
	qpol_role_trans_t *qrt = NULL;
	pseudo_role_trans_t *tmp_prt = NULL;
	char *tmp_name = NULL;
	qpol_role_t *tmp_role = NULL;
	qpol_type_t *tmp_type = NULL;
	int error = 0, which_pol;
	unsigned char isattr = 0;

	which_pol = (policy == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	if (qpol_policy_get_role_trans_iter(policy->qh, policy->p, &iter)) {
		error = errno;
		goto err;
	}
	v = apol_vector_create();
	if (!v) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		isattr = 0;
		if (qpol_iterator_get_item(iter, (void**)&qrt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		if (qpol_role_trans_get_target_type(policy->qh, policy->p, qrt, &tmp_type) < 0) {
			error = errno;
			goto err;
		}
		qpol_type_get_isattr(policy->qh, policy->p, tmp_type, &isattr);
		if (isattr) {
			qpol_type_get_type_iter(policy->qh, policy->p, tmp_type, &attr_types);
			for (; !qpol_iterator_end(attr_types); qpol_iterator_next(attr_types)) {
				qpol_iterator_get_item(attr_types, (void**)&tmp_type);
				if (!(tmp_prt = calloc(1, sizeof(*tmp_prt)))) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				tmp_prt->pseudo_target = type_map_lookup(diff, tmp_type, which_pol);
				qpol_role_trans_get_source_role(policy->qh, policy->p, qrt, &tmp_role);
				qpol_role_get_name(policy->qh, policy->p, tmp_role, &tmp_name);
				tmp_prt->source_role = tmp_name;
				qpol_role_trans_get_default_role(policy->qh, policy->p, qrt, &tmp_role);
				qpol_role_get_name(policy->qh, policy->p, tmp_role, &tmp_name);
				tmp_prt->default_role = tmp_name;
				if (apol_vector_append(v, tmp_prt)) {
					error = errno;
					ERR(diff, "%s", strerror(error));
					goto err;
				}
				tmp_prt = NULL;
			}
			qpol_iterator_destroy(&attr_types);
		} else {
			if (!(tmp_prt = calloc(1, sizeof(*tmp_prt)))) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto err;
			}
			tmp_prt->pseudo_target = type_map_lookup(diff, tmp_type, which_pol);
			qpol_role_trans_get_source_role(policy->qh, policy->p, qrt, &tmp_role);
			qpol_role_get_name(policy->qh, policy->p, tmp_role, &tmp_name);
			tmp_prt->source_role = tmp_name;
			qpol_role_trans_get_default_role(policy->qh, policy->p, qrt, &tmp_role);
			qpol_role_get_name(policy->qh, policy->p, tmp_role, &tmp_name);
			tmp_prt->default_role = tmp_name;
			if (apol_vector_append(v, tmp_prt)) {
				error = errno;
				ERR(diff, "%s", strerror(error));
				goto err;
			}
			tmp_prt = NULL;
		}
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort_uniquify(v, pseudo_role_trans_comp, diff, free);

	return v;

err:
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&attr_types);
	apol_vector_destroy(&v, free);
	free(tmp_prt);
	errno = error;
	return NULL;
}

void role_trans_free_item(void *item)
{
	/* no need to free members of a pseudo role_transition */
	free(item);
}

int role_trans_comp(const void *x, const void *y, poldiff_t *diff __attribute__((unused)))
{
	int retv = 0;
	const pseudo_role_trans_t *a = x;
	const pseudo_role_trans_t *b = y;

	retv = strcmp(a->source_role, b->source_role);
	if (!retv)
		return a->pseudo_target - b->pseudo_target;
	else
		return retv;
}

/**
 *  Allocate and return a new role_transition rule difference object.
 *
 *  @param diff Policy difference error handler.
 *  @param form Form of the difference.
 *  @param src Name of the source role.
 *  @param tgt Name of the target type.
 *
 *  @return A newly allocated and initialised diff or NULL upon error.
 *  The caller is responsible for calling free() upon the returned value.
 */
static poldiff_role_trans_t *make_rt_diff(poldiff_t *diff, poldiff_form_e form, char *src, char *tgt)
{
	poldiff_role_trans_t *rt = NULL;
	int error = 0;
	if ((rt = calloc(1, sizeof(*rt))) == NULL ||
			(rt->source_role = src) == NULL ||
			(rt->target_type = tgt) == NULL) {
		error = errno;
		free(rt);
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	rt->form = form;
	return rt;
}

int role_trans_new_diff(poldiff_t *diff, poldiff_form_e form, const void *item)
{
	const pseudo_role_trans_t *rt = item;
	poldiff_role_trans_t *prt = NULL;
	char *tgt_name = NULL;
	qpol_type_t *tgt;
	apol_vector_t *mapped_types, *other;
	int error = 0;

	/* get tgt_name from type_map */
	switch (form) {
		case POLDIFF_FORM_ADDED:
		case POLDIFF_FORM_ADD_TYPE:
			{
				mapped_types = type_map_lookup_reverse(diff, rt->pseudo_target, POLDIFF_POLICY_MOD);
				other = type_map_lookup_reverse(diff, rt->pseudo_target, POLDIFF_POLICY_ORIG);
				if (!apol_vector_get_size(other))
					form = POLDIFF_FORM_ADD_TYPE;
				break;
			}
		case POLDIFF_FORM_REMOVED:
		case POLDIFF_FORM_REMOVE_TYPE:
			{
				mapped_types = type_map_lookup_reverse(diff, rt->pseudo_target, POLDIFF_POLICY_ORIG);
				other = type_map_lookup_reverse(diff, rt->pseudo_target, POLDIFF_POLICY_MOD);
				if (!apol_vector_get_size(other))
					form = POLDIFF_FORM_REMOVE_TYPE;
				break;
			}
		case POLDIFF_FORM_MODIFIED: /* not supported here */
		case POLDIFF_FORM_NONE:
		default:
			{
				ERR(diff, "%s", strerror(ENOTSUP));
				errno = ENOTSUP;
				return -1;
			}
	}
	if (!mapped_types)
		return -1;
	tgt = apol_vector_get_element(mapped_types, 0);
	if (!tgt) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	switch (form) {
		case POLDIFF_FORM_ADDED:
		case POLDIFF_FORM_ADD_TYPE:
			{
				qpol_type_get_name(diff->mod_pol->qh, diff->mod_pol->p, tgt, &tgt_name);
				break;
			}
		case POLDIFF_FORM_REMOVED:
		case POLDIFF_FORM_REMOVE_TYPE:
			{
				qpol_type_get_name(diff->orig_pol->qh, diff->orig_pol->p, tgt, &tgt_name);
				break;
			}
		case POLDIFF_FORM_MODIFIED:
		case POLDIFF_FORM_NONE:
		default:
			{
				/* not reachable */
				assert(0);
			}
	}

	/* create a new diff */
	prt = make_rt_diff(diff, form, rt->source_role, tgt_name);
	if (!prt)
		return -1;

	/* set the appropriate default */
	switch (form) {
		case POLDIFF_FORM_ADDED:
		case POLDIFF_FORM_ADD_TYPE:
			{
				prt->mod_default = rt->default_role;
				break;
			}
		case POLDIFF_FORM_REMOVED:
		case POLDIFF_FORM_REMOVE_TYPE:
			{
				prt->orig_default = rt->default_role;
				break;
			}
		case POLDIFF_FORM_MODIFIED:
		case POLDIFF_FORM_NONE:
		default:
			{
				/* not reachable */
				assert(0);
			}
	}
	if (apol_vector_append(diff->role_trans_diffs->diffs, prt)) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		free(prt);
		errno = error;
		return -1;
	};

	/* increment appropriate counter */
	switch (form) {
		case POLDIFF_FORM_ADDED:
			{
				diff->role_trans_diffs->num_added++;
				break;
			}
		case POLDIFF_FORM_ADD_TYPE:
			{
				diff->role_trans_diffs->num_added_type++;
				break;
			}
		case POLDIFF_FORM_REMOVED:
			{
				diff->role_trans_diffs->num_removed++;
				break;
			}
		case POLDIFF_FORM_REMOVE_TYPE:
			{
				diff->role_trans_diffs->num_removed_type++;
				break;
			}
		case POLDIFF_FORM_MODIFIED:
		case POLDIFF_FORM_NONE:
		default:
			{
				/* not reachable */
				assert(0);
			}
	}

	return 0;
}

int role_trans_deep_diff(poldiff_t *diff, const void *x, const void *y)
{
	const pseudo_role_trans_t *prt1 = x;
	const pseudo_role_trans_t *prt2 = y;
	char *default1 = NULL, *default2 = NULL;
	poldiff_role_trans_t *rt = NULL;
	apol_vector_t *mapped_tgts = NULL;
	qpol_type_t *tgt_type = NULL;
	char *tgt = NULL;
	int error = 0;

	default1 = prt1->default_role;
	default2 = prt2->default_role;

	if (!strcmp(default1, default2))
		return 0; /* no difference */

	mapped_tgts = type_map_lookup_reverse(diff, prt1->pseudo_target, POLDIFF_POLICY_ORIG);
	if (!mapped_tgts)
		return -1; /* errors already reported */
	tgt_type = apol_vector_get_element(mapped_tgts, 0);
	if (!tgt_type) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}
	qpol_type_get_name(diff->orig_pol->qh, diff->orig_pol->p, tgt_type, &tgt);
	rt = make_rt_diff(diff, POLDIFF_FORM_MODIFIED, prt1->source_role, tgt);
	if (!rt)
		return -1; /* errors already reported */
	rt->orig_default = default1;
	rt->mod_default = default2;
	if (apol_vector_append(diff->role_trans_diffs->diffs, rt)) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		free(rt);
		errno = error;
		return -1;
	};
	diff->role_trans_diffs->num_modified++;

	return 0;
}
