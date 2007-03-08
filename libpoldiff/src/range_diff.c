/**
 *  @file
 *  Implementation for computing a semantic differences in ranges.
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
#include <assert.h>
#include <errno.h>

struct poldiff_range
{
	apol_mls_range_t *orig_range;
	apol_mls_range_t *mod_range;
	/** a vector of poldiff_level_t */
	apol_vector_t *levels;
	int mincats_differ;
};

apol_vector_t *poldiff_range_get_levels(poldiff_range_t * range)
{
	if (range == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return range->levels;
}

/**
 * Allocate and return a poldiff_range_t object.  This will fill in
 * the orig_range and mod_range strings.  If the form is modified,
 * then this will allocate the levels vector but leave it empty.
 * Otherwise the levels vector will be filled with the levels that
 * were added/removed.
 */
poldiff_range_t *range_create(poldiff_t * diff, qpol_mls_range_t * orig_range, qpol_mls_range_t * mod_range, poldiff_form_e form)
{
	poldiff_range_t *pr = NULL;
	apol_policy_t *p;
	apol_mls_range_t *range;
	apol_vector_t *levels = NULL;
	poldiff_level_t *pl = NULL;
	size_t i;
	int retval = -1;
	if ((pr = calloc(1, sizeof(*pr))) == NULL || (pr->levels = apol_vector_create()) == NULL) {
		ERR(diff, "%s", strerror(errno));
		goto cleanup;
	}
	if (orig_range != NULL && (pr->orig_range = apol_mls_range_create_from_qpol_mls_range(diff->orig_pol, orig_range)) == NULL) {
		goto cleanup;
	}
	if (mod_range != NULL && (pr->mod_range = apol_mls_range_create_from_qpol_mls_range(diff->mod_pol, mod_range)) == NULL) {
		goto cleanup;
	}
	if (form == POLDIFF_FORM_ADDED) {
		p = diff->mod_pol;
		range = pr->mod_range;
	} else if (form == POLDIFF_FORM_REMOVED) {
		p = diff->orig_pol;
		range = pr->orig_range;
	} else if (form == POLDIFF_FORM_MODIFIED) {
		/* don't fill in the range's levels here */
		return pr;
	} else {
		/* should never get here */
		assert(0);
		return pr;
	}
	if ((levels = apol_mls_range_get_levels(p, range)) == NULL) {
		goto cleanup;
	}
	for (i = 0; i < apol_vector_get_size(levels); i++) {
		apol_mls_level_t *l = apol_vector_get_element(levels, i);
		if ((pl = calloc(1, sizeof(*pl))) == NULL ||
		    (pl->name = strdup(l->sens)) == NULL || (pl->unmodified_cats = apol_vector_create_with_capacity(1)) == NULL) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		if (form == POLDIFF_FORM_ADDED) {
			if ((pl->added_cats = apol_vector_create_from_vector(l->cats, apol_str_strdup, NULL)) == NULL ||
			    (pl->removed_cats = apol_vector_create_with_capacity(1)) == NULL) {
				ERR(diff, "%s", strerror(errno));
				goto cleanup;
			}
		} else if (form == POLDIFF_FORM_REMOVED) {
			if ((pl->added_cats = apol_vector_create_with_capacity(1)) == NULL ||
			    (pl->removed_cats = apol_vector_create_from_vector(l->cats, apol_str_strdup, NULL)) == NULL) {
				ERR(diff, "%s", strerror(errno));
				goto cleanup;
			}
		}
		if (apol_vector_append(pr->levels, pl) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		pl = NULL;
	}
	retval = 0;
      cleanup:
	apol_vector_destroy(&levels, apol_mls_level_free);
	if (retval != 0) {
		level_free(pl);
		range_destroy(&pr);
		return NULL;
	}
	return pr;
}

void range_destroy(poldiff_range_t ** range)
{
	if (range != NULL && *range != NULL) {
		apol_mls_range_destroy(&(*range)->orig_range);
		apol_mls_range_destroy(&(*range)->mod_range);
		apol_vector_destroy(&(*range)->levels, level_free);
		free(*range);
		*range = NULL;
	}
}

char *range_to_string(poldiff_t * diff, poldiff_range_t * range)
{
	char *r1 = NULL, *r2 = NULL;
	char *s = NULL, *t = NULL;
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
		if ((t = level_to_string(diff, level)) == NULL) {
			goto cleanup;
		}
		if (apol_str_append(&s, &len, t) < 0) {
			ERR(diff, "%s", strerror(errno));
			goto cleanup;
		}
		free(t);
		t = NULL;
	}
      cleanup:
	free(r1);
	free(r2);
	free(t);
	return s;
}

/**
 * Comparison function for two apol_mls_level_t objects from the same
 * apol_mls_range_t.  Sorts the levels in alphabetical order according
 * to sensitivity.
 */
static int range_comp_alphabetize(const void *a, const void *b, void *data __attribute__ ((unused)))
{
	const apol_mls_level_t *l1 = a;
	const apol_mls_level_t *l2 = b;
	return strcmp(l1->sens, l2->sens);
}

/**
 * Comparison function for two levels from the same poldiff_range_t.
 * Sorts the levels by form; within each form sort them by policy
 * order.
 */
static int range_comp(const void *a, const void *b, void *data)
{
	const poldiff_level_t *l1 = a;
	const poldiff_level_t *l2 = b;
	poldiff_t *diff = data;
	qpol_policy_t *q;
	qpol_level_t *ql1, *ql2;
	uint32_t v1, v2;
	if (l1->form != l2->form) {
		return l1->form - l2->form;
	}
	if (l1->form == POLDIFF_FORM_ADDED) {
		q = diff->mod_qpol;
	} else {
		q = diff->orig_qpol;
	}
	qpol_policy_get_level_by_name(q, l1->name, &ql1);
	qpol_policy_get_level_by_name(q, l2->name, &ql2);
	qpol_level_get_value(q, ql1, &v1);
	qpol_level_get_value(q, ql2, &v2);
	assert(v1 != 0 && v2 != 0);
	return v1 - v2;
}

int range_deep_diff(poldiff_t * diff, poldiff_range_t * range)
{
	apol_vector_t *orig_levels = NULL, *mod_levels = NULL;
	apol_vector_t *added = NULL, *removed = NULL, *unmodified = NULL;
	apol_mls_level_t *l1, *l2;
	poldiff_level_t *pl1, *pl2;
	size_t i, j;
	int retval = -1, differences_found = 0, compval;
	if ((orig_levels = apol_mls_range_get_levels(diff->orig_pol, range->orig_range)) == NULL ||
	    (mod_levels = apol_mls_range_get_levels(diff->mod_pol, range->mod_range)) == NULL) {
		goto cleanup;
	}
	apol_vector_sort(orig_levels, range_comp_alphabetize, NULL);
	apol_vector_sort(mod_levels, range_comp_alphabetize, NULL);
	for (i = j = 0; i < apol_vector_get_size(orig_levels);) {
		if (j >= apol_vector_get_size(mod_levels))
			break;
		l1 = (apol_mls_level_t *) apol_vector_get_element(orig_levels, i);
		l2 = (apol_mls_level_t *) apol_vector_get_element(mod_levels, j);
		pl1 = pl2 = NULL;
		compval = strcmp(l1->sens, l2->sens);
		if (compval < 0) {
			if ((pl1 = level_create_from_apol_mls_level(l1, POLDIFF_FORM_REMOVED)) == NULL
			    || apol_vector_append(range->levels, pl1) < 0) {
				level_free(pl1);
				goto cleanup;
			}
			differences_found = 1;
			i++;
		} else if (compval > 0) {
			if ((pl2 = level_create_from_apol_mls_level(l2, POLDIFF_FORM_ADDED)) == NULL
			    || apol_vector_append(range->levels, pl2) < 0) {
				level_free(pl2);
				goto cleanup;
			}
			differences_found = 1;
			j++;
		} else {
			if (level_deep_diff_apol_mls_levels(diff, l1, l2, &pl1, &pl2) < 0) {
				goto cleanup;
			}
			assert(pl2 == NULL);
			if (pl1 != NULL) {
				if (apol_vector_append(range->levels, pl1) < 0) {
					level_free(pl1);
					goto cleanup;
				}
				differences_found = 1;
			}
			i++;
			j++;
		}
	}
	for (; i < apol_vector_get_size(orig_levels); i++) {
		l1 = (apol_mls_level_t *) apol_vector_get_element(orig_levels, i);
		if ((pl1 = level_create_from_apol_mls_level(l1, POLDIFF_FORM_REMOVED)) == NULL
		    || apol_vector_append(range->levels, pl1) < 0) {
			level_free(pl1);
			goto cleanup;
		}
		differences_found = 1;
	}
	for (; j < apol_vector_get_size(mod_levels); j++) {
		l2 = (apol_mls_level_t *) apol_vector_get_element(mod_levels, j);
		if ((pl2 = level_create_from_apol_mls_level(l2, POLDIFF_FORM_ADDED)) == NULL
		    || apol_vector_append(range->levels, pl2) < 0) {
			level_free(pl2);
			goto cleanup;
		}
		differences_found = 1;
	}
	/* now check minimum category sets */
	compval =
		level_deep_diff_cats(diff, range->orig_range->low->cats, range->mod_range->low->cats, &added, &removed,
				     &unmodified);
	if (compval < 0) {
		goto cleanup;
	} else if (compval > 0) {
		range->mincats_differ = 1;
		differences_found = 1;
	}
	if (differences_found) {
		apol_vector_sort(range->levels, range_comp, diff);
		retval = 1;
	} else {
		retval = 0;
	}
      cleanup:
	apol_vector_destroy(&orig_levels, apol_mls_level_free);
	apol_vector_destroy(&mod_levels, apol_mls_level_free);
	apol_vector_destroy(&added, NULL);
	apol_vector_destroy(&removed, NULL);
	apol_vector_destroy(&unmodified, NULL);
	return retval;
}
