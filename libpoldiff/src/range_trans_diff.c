/**
 *  @file
 *  Implementation for computing a semantic differences in range
 *  transition rules.
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

#include <apol/mls-query.h>
#include <apol/util.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

struct poldiff_range_trans_summary
{
	size_t num_added;
	size_t num_removed;
	size_t num_modified;
	size_t num_added_type;
	size_t num_removed_type;
	apol_vector_t *diffs;
};

struct poldiff_range_trans
{
	char *source;
	char *target;
	char *target_class;
	poldiff_form_e form;
	poldiff_range_t *range;
};

void poldiff_range_trans_get_stats(const poldiff_t * diff, size_t stats[5])
{
	if (diff == NULL || stats == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return;
	}
	stats[0] = diff->range_trans_diffs->num_added;
	stats[1] = diff->range_trans_diffs->num_removed;
	stats[2] = diff->range_trans_diffs->num_modified;
	stats[3] = diff->range_trans_diffs->num_added_type;
	stats[4] = diff->range_trans_diffs->num_removed_type;
}

char *poldiff_range_trans_to_string(const poldiff_t * diff, const void *range_trans)
{
	const poldiff_range_trans_t *rt = range_trans;
	const poldiff_range_t *range = poldiff_range_trans_get_range(rt);
	const apol_mls_range_t *orig_range = poldiff_range_get_original_range(range);
	const apol_mls_range_t *mod_range = poldiff_range_get_modified_range(range);
	size_t len = 0;
	char *s = NULL;
	if (diff == NULL || range_trans == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	switch (rt->form) {
	case POLDIFF_FORM_ADDED:
	case POLDIFF_FORM_ADD_TYPE:
	{
		char *t = NULL;
		if ((t = apol_mls_range_render(diff->mod_pol, mod_range)) == NULL ||
		    apol_str_appendf(&s, &len, "+ range_transition %s %s : %s %s;", rt->source, rt->target,
				     rt->target_class, t) < 0) {
			free(t);
			goto cleanup;
		}
		free(t);
		return s;
	}
	case POLDIFF_FORM_REMOVED:
	case POLDIFF_FORM_REMOVE_TYPE:
	{
		char *t = NULL;
		if ((t = apol_mls_range_render(diff->orig_pol, orig_range)) == NULL ||
		    apol_str_appendf(&s, &len, "- range_transition %s %s : %s %s;", rt->source, rt->target,
				     rt->target_class, t) < 0) {
			free(t);
			goto cleanup;
		}
		free(t);
		return s;
	}
	case POLDIFF_FORM_MODIFIED:
	{
		char *t;
		if ((t = poldiff_range_to_string_brief(diff, range)) == NULL ||
		    apol_str_appendf(&s, &len, "* range_transition %s %s : %s\n%s", rt->source, rt->target,
				     rt->target_class, t) < 0) {
			free(t);
			goto cleanup;
		}
		free(t);
		return s;
	}
	default:
	{
		ERR(diff, "%s", strerror(ENOTSUP));
		errno = ENOTSUP;
		return NULL;
	}
	}
      cleanup:
	/* if this is reached then an error occurred */
	ERR(diff, "%s", strerror(ENOMEM));
	free(s);
	errno = ENOMEM;
	return NULL;
}

const apol_vector_t *poldiff_get_range_trans_vector(const poldiff_t * diff)
{
	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}
	return diff->range_trans_diffs->diffs;
}

const char *poldiff_range_trans_get_source_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->source;
}

const char *poldiff_range_trans_get_target_type(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->target;
}

const char *poldiff_range_trans_get_target_class(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->target_class;
}

const poldiff_range_t *poldiff_range_trans_get_range(const poldiff_range_trans_t * range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range_trans->range;
}

poldiff_form_e poldiff_range_trans_get_form(const void *range_trans)
{
	if (range_trans == NULL) {
		errno = EINVAL;
		return POLDIFF_FORM_NONE;
	}
	return ((const poldiff_range_trans_t *)range_trans)->form;
}

/**
 * Destroy all space used by a poldiff_range_trans_t, including the
 * pointer itself.
 */
static void range_trans_free(void *elem)
{
	if (elem != NULL) {
		poldiff_range_trans_t *rt = (poldiff_range_trans_t *) elem;
		free(rt->source);
		free(rt->target);
		free(rt->target_class);
		range_destroy(&rt->range);
		free(rt);
	}
}

poldiff_range_trans_summary_t *range_trans_create(void)
{
	poldiff_range_trans_summary_t *rts = calloc(1, sizeof(*rts));
	if (rts == NULL) {
		return NULL;
	}
	if ((rts->diffs = apol_vector_create(range_trans_free)) == NULL) {
		range_trans_destroy(&rts);
		return NULL;
	}
	return rts;
}

void range_trans_destroy(poldiff_range_trans_summary_t ** rts)
{
	if (rts != NULL && *rts != NULL) {
		apol_vector_destroy(&(*rts)->diffs);
		free(*rts);
		*rts = NULL;
	}
}

typedef struct pseudo_range_trans
{
	uint32_t source_type, target_type;
	/* pointer into a policy's class's symbol table */
	const char *target_class;
	const qpol_mls_range_t *range;
} pseudo_range_trans_t;

static void range_trans_free_item(void *item)
{
	if (item != NULL) {
		pseudo_range_trans_t *prt = item;
		free(prt);
	}
}

int range_trans_comp(const void *x, const void *y, const poldiff_t * diff __attribute__ ((unused)))
{
	const pseudo_range_trans_t *p1 = x;
	const pseudo_range_trans_t *p2 = y;

	if (p1->source_type != p2->source_type) {
		return p1->source_type - p2->source_type;
	}
	if (p1->target_type != p2->target_type) {
		return p1->target_type - p2->target_type;
	}
	return strcmp(p1->target_class, p2->target_class);
}

int range_trans_reset(poldiff_t * diff)
{
	int error = 0;

	if (diff == NULL) {
		ERR(diff, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	range_trans_destroy(&diff->range_trans_diffs);
	diff->range_trans_diffs = range_trans_create();
	if (diff->range_trans_diffs == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return -1;
	}

	return 0;
}

/**
 * Allocate and return a new range trans difference object.  If the
 * pseudo-range trans's source and/or target expands to multiple read
 * types, then just choose the first one for display.
 */
static poldiff_range_trans_t *make_range_trans_diff(const poldiff_t * diff, poldiff_form_e form, const pseudo_range_trans_t * prt)
{
	poldiff_range_trans_t *rt = NULL;
	const char *n1, *n2;
	int error;
	if (form == POLDIFF_FORM_ADDED || form == POLDIFF_FORM_ADD_TYPE) {
		n1 = type_map_get_name(diff, prt->source_type, POLDIFF_POLICY_MOD);
		n2 = type_map_get_name(diff, prt->target_type, POLDIFF_POLICY_MOD);
	} else {
		n1 = type_map_get_name(diff, prt->source_type, POLDIFF_POLICY_ORIG);
		n2 = type_map_get_name(diff, prt->target_type, POLDIFF_POLICY_ORIG);
	}
	assert(n1 != NULL && n2 != NULL);
	if ((rt = calloc(1, sizeof(*rt))) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		errno = error;
		return NULL;
	}
	if ((rt->source = strdup(n1)) == NULL ||
	    (rt->target = strdup(n2)) == NULL || (rt->target_class = strdup(prt->target_class)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(errno));
		range_trans_free(rt);
		errno = error;
		return NULL;
	}
	rt->form = form;
	return rt;
}

int range_trans_new_diff(poldiff_t * diff, poldiff_form_e form, const void *item)
{
	const pseudo_range_trans_t *prt = (const pseudo_range_trans_t *)item;
	const apol_vector_t *v1, *v2;
	const qpol_mls_range_t *orig_range = NULL, *mod_range = NULL;
	poldiff_range_trans_t *rt = NULL;
	int error;

	/* check if form should really become ADD_TYPE / REMOVE_TYPE,
	 * by seeing if the /other/ policy's reverse lookup is
	 * empty */
	if (form == POLDIFF_FORM_ADDED) {
		if ((v1 = type_map_lookup_reverse(diff, prt->source_type, POLDIFF_POLICY_ORIG)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, prt->target_type, POLDIFF_POLICY_ORIG)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_ADD_TYPE;
		}
		mod_range = prt->range;
	} else {
		if ((v1 = type_map_lookup_reverse(diff, prt->source_type, POLDIFF_POLICY_MOD)) == NULL ||
		    (v2 = type_map_lookup_reverse(diff, prt->target_type, POLDIFF_POLICY_MOD)) == NULL) {
			error = errno;
			goto cleanup;
		}
		if (apol_vector_get_size(v1) == 0 || apol_vector_get_size(v2) == 0) {
			form = POLDIFF_FORM_REMOVE_TYPE;
		}
		orig_range = prt->range;
	}
	if ((rt = make_range_trans_diff(diff, form, prt)) == NULL ||
	    (rt->range = range_create(diff, orig_range, mod_range, form)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if (apol_vector_append(diff->range_trans_diffs->diffs, rt) < 0) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto cleanup;
	}
	/* increment appropriate counter */
	switch (form) {
	case POLDIFF_FORM_ADDED:
	{
		diff->range_trans_diffs->num_added++;
		break;
	}
	case POLDIFF_FORM_ADD_TYPE:
	{
		diff->range_trans_diffs->num_added_type++;
		break;
	}
	case POLDIFF_FORM_REMOVED:
	{
		diff->range_trans_diffs->num_removed++;
		break;
	}
	case POLDIFF_FORM_REMOVE_TYPE:
	{
		diff->range_trans_diffs->num_removed_type++;
		break;
	}
	default:
	{
		/* not reachable */
		assert(0);
	}
	}
	return 0;
      cleanup:
	range_trans_free(rt);
	errno = error;
	return -1;
}

/**
 *  Compare two pseudo range transition rules from the same policy.
 *  Compares the pseudo source type, pseudo target type, and target
 *  class.
 *
 *  @param x A pseudo_range_trans_t entry.
 *  @param y A pseudo_range_trans_t entry.
 *  @param arg The policy difference structure.
 *
 *  @return < 0, 0, or > 0 if the first rule is respectively less than,
 *  equal to, or greater than the second. If the return value would be 0
 *  but the default role is different a warning is issued.
 */
static int pseudo_range_trans_comp(const void *x, const void *y, void *arg)
{
	const pseudo_range_trans_t *a = x;
	const pseudo_range_trans_t *b = y;
	poldiff_t *diff = arg;
	int retval = range_trans_comp(a, b, diff);
	return retval;
}

apol_vector_t *range_trans_get_items(poldiff_t * diff, const apol_policy_t * policy)
{
	apol_vector_t *v = NULL;
	qpol_iterator_t *iter = NULL;
	const qpol_range_trans_t *qrt = NULL;
	const qpol_type_t *source_type, *target_type;
	const qpol_class_t *target_class;
	const char *class_name;
	const qpol_mls_range_t *range;
	pseudo_range_trans_t *prt = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0, which_pol;

	which_pol = (policy == diff->orig_pol ? POLDIFF_POLICY_ORIG : POLDIFF_POLICY_MOD);
	if (qpol_policy_get_range_trans_iter(q, &iter)) {
		error = errno;
		goto err;
	}
	if ((v = apol_vector_create(range_trans_free_item)) == NULL) {
		error = errno;
		ERR(diff, "%s", strerror(error));
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&qrt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		if (qpol_range_trans_get_source_type(q, qrt, &source_type) < 0 ||
		    qpol_range_trans_get_target_type(q, qrt, &target_type) < 0 ||
		    qpol_range_trans_get_target_class(q, qrt, &target_class) < 0 ||
		    qpol_class_get_name(q, target_class, &class_name) < 0 || qpol_range_trans_get_range(q, qrt, &range) < 0) {
			error = errno;
			goto err;
		}
		if (!(prt = calloc(1, sizeof(*prt)))) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt->source_type = type_map_lookup(diff, source_type, which_pol);
		prt->target_type = type_map_lookup(diff, target_type, which_pol);
		prt->target_class = class_name;
		prt->range = range;
		if (apol_vector_append(v, prt)) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto err;
		}
		prt = NULL;
	}
	qpol_iterator_destroy(&iter);
	apol_vector_sort_uniquify(v, pseudo_range_trans_comp, diff);
	return v;

      err:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&v);
	free(prt);
	errno = error;
	return NULL;
}

int range_trans_deep_diff(poldiff_t * diff, const void *x, const void *y)
{
	const pseudo_range_trans_t *prt1 = x;
	const pseudo_range_trans_t *prt2 = y;
	poldiff_range_t *range = NULL;
	poldiff_range_trans_t *rt = NULL;
	int error = 0, retval = -1;

	if ((range = range_create(diff, prt1->range, prt2->range, POLDIFF_FORM_MODIFIED)) == NULL) {
		error = errno;
		goto cleanup;
	}
	if ((retval = range_deep_diff(diff, range)) < 0) {
		error = errno;
		goto cleanup;
	}
	if (retval > 0) {
		if ((rt = make_range_trans_diff(diff, POLDIFF_FORM_MODIFIED, prt1)) == NULL) {
			error = errno;
			goto cleanup;
		}
		rt->range = range;
		range = NULL;
		if (apol_vector_append(diff->range_trans_diffs->diffs, rt) < 0) {
			error = errno;
			ERR(diff, "%s", strerror(error));
			goto cleanup;
		}
		diff->range_trans_diffs->num_modified++;
		rt = NULL;
	}
	retval = 0;
      cleanup:
	range_destroy(&range);
	range_trans_free(rt);
	if (retval != 0) {
		errno = error;
	}
	return retval;
}
