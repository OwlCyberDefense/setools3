/**
 *  @file
 *  Implementation of apol_mls_range class.
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

#include <apol/mls_range.h>

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "policy-query-internal.h"

#include <qpol/iterator.h>
#include <apol/vector.h>

struct apol_mls_range
{
	apol_mls_level_t *low, *high;
};

apol_mls_range_t *apol_mls_range_create(void)
{
	return calloc(1, sizeof(apol_mls_range_t));
}

apol_mls_range_t *apol_mls_range_create_from_mls_range(const apol_mls_range_t * range)
{
	apol_mls_range_t *r;
	if ((r = apol_mls_range_create()) == NULL) {
		return NULL;
	}
	if (range != NULL &&
	    ((r->low = apol_mls_level_create_from_mls_level(range->low)) == NULL ||
	     (r->high = apol_mls_level_create_from_mls_level(range->high)) == NULL)) {
		apol_mls_range_destroy(&r);
		return NULL;
	}
	return r;
}

apol_mls_range_t *apol_mls_range_create_from_qpol_mls_range(apol_policy_t * p, qpol_mls_range_t * qpol_range)
{
	apol_mls_range_t *apol_range = NULL;
	qpol_mls_level_t *tmp = NULL;
	apol_mls_level_t *tmp_lvl = NULL;
	int error = 0;

	if (!p || !qpol_range) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	apol_range = calloc(1, sizeof(apol_mls_range_t));
	if (!apol_range) {
		ERR(p, "%s", strerror(ENOMEM));
		return NULL;
	}

	/* low */
	if (qpol_mls_range_get_low_level(p->p, qpol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_qpol_mls_level(p, tmp)) || apol_mls_range_set_low(p, apol_range, tmp_lvl)) {
		error = errno;
		apol_mls_level_destroy(&tmp_lvl);
		goto err;
	}
	tmp_lvl = NULL;

	/* high */
	if (qpol_mls_range_get_high_level(p->p, qpol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_qpol_mls_level(p, tmp)) || apol_mls_range_set_high(p, apol_range, tmp_lvl)) {
		error = errno;
		apol_mls_level_destroy(&tmp_lvl);
		goto err;
	}

	return apol_range;

      err:
	apol_mls_range_destroy(&apol_range);
	errno = error;
	return NULL;
}

void apol_mls_range_destroy(apol_mls_range_t ** range)
{
	if (!range || !(*range))
		return;

	if ((*range)->low != (*range)->high) {
		apol_mls_level_destroy(&((*range)->high));
	}
	apol_mls_level_destroy(&((*range)->low));
	free(*range);
	*range = NULL;
}

int apol_mls_range_set_low(apol_policy_t * p, apol_mls_range_t * range, apol_mls_level_t * level)
{
	if (!range) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (range->low != level) {
		apol_mls_level_destroy(&(range->low));
		range->low = level;
	}
	return 0;
}

int apol_mls_range_set_high(apol_policy_t * p, apol_mls_range_t * range, apol_mls_level_t * level)
{
	if (!range) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (range->high != level) {
		if (range->low != range->high) {
			apol_mls_level_destroy(&(range->high));
		}
		range->high = level;
	}
	return 0;
}

const apol_mls_level_t *apol_mls_range_get_low(const apol_mls_range_t * range)
{
	if (!range) {
		errno = EINVAL;
		return NULL;
	}
	return range->low;
}

const apol_mls_level_t *apol_mls_range_get_high(const apol_mls_range_t * range)
{
	if (!range) {
		errno = EINVAL;
		return NULL;
	}
	return range->high;
}

int apol_mls_range_compare(apol_policy_t * p, const apol_mls_range_t * target, const apol_mls_range_t * search,
			   unsigned int range_compare_type)
{
	int ans1 = -1, ans2 = -1;
	if (search == NULL) {
		return 1;
	}
	if (p == NULL || target == NULL || target->low == NULL || search->low == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	/* FIX ME:  intersect does not work */
	if ((range_compare_type & APOL_QUERY_SUB) || (range_compare_type & APOL_QUERY_INTERSECT)) {
		ans1 = apol_mls_range_contain_subrange(p, target, search);
		if (ans1 < 0) {
			return -1;
		}
	}
	if ((range_compare_type & APOL_QUERY_SUPER) || (range_compare_type & APOL_QUERY_INTERSECT)) {
		ans2 = apol_mls_range_contain_subrange(p, search, target);
		if (ans2 < 0) {
			return -1;
		}
	}
	/* EXACT has to come first because its bits are both SUB and SUPER */
	if ((range_compare_type & APOL_QUERY_EXACT) == APOL_QUERY_EXACT) {
		return (ans1 && ans2);
	} else if (range_compare_type & APOL_QUERY_SUB) {
		return ans1;
	} else if (range_compare_type & APOL_QUERY_SUPER) {
		return ans2;
	} else if (range_compare_type & APOL_QUERY_INTERSECT) {
		return (ans1 || ans2);
	}
	ERR(p, "%s", "Invalid range compare type argument.");
	errno = EINVAL;
	return -1;
}

static int apol_mls_range_does_include_level(apol_policy_t * p, const apol_mls_range_t * range, const apol_mls_level_t * level)
{
	int high_cmp = -1, low_cmp = -1;

	if (range->low != range->high) {
		low_cmp = apol_mls_level_compare(p, range->low, level);
		if (low_cmp < 0) {
			return -1;
		}
	}
	const apol_mls_level_t *high_level = (range->high != NULL ? range->high : range->low);
	high_cmp = apol_mls_level_compare(p, high_level, level);
	if (high_cmp < 0) {
		return -1;
	}

	if (high_cmp == APOL_MLS_EQ || high_cmp == APOL_MLS_DOM) {
		if ((low_cmp == APOL_MLS_EQ || low_cmp == APOL_MLS_DOMBY) && range->low != high_level) {
			return 1;
		} else if (range->low == high_level) {
			return apol_mls_sens_compare(p, apol_mls_level_get_sens(range->low), apol_mls_level_get_sens(level));
		}
	}

	return 0;
}

int apol_mls_range_contain_subrange(apol_policy_t * p, const apol_mls_range_t * range, const apol_mls_range_t * subrange)
{
	if (p == NULL || apol_mls_range_validate(p, subrange) != 1) {
		ERR(p, "%s", strerror(EINVAL));
		return -1;
	}
	/* parent range validity will be checked via
	 * apol_mls_range_include_level() */

	if (apol_mls_range_does_include_level(p, range, subrange->low)) {
		if (subrange->high == NULL || apol_mls_range_does_include_level(p, range, subrange->high)) {
			return 1;
		}
	}
	return 0;
}

int apol_mls_range_validate(apol_policy_t * p, const apol_mls_range_t * range)
{
	int retv;

	if (p == NULL || range == NULL || range->low == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if ((retv = apol_mls_level_validate(p, range->low)) != 1) {
		return retv;
	}

	if (range->high == NULL) {
		return retv;
	}
	if (range->high != range->low && (retv = apol_mls_level_validate(p, range->high)) != 1) {
		return retv;
	}

	/* both low and high levels exist, so now check that high
	 * dominates low */
	retv = apol_mls_level_compare(p, range->low, range->high);
	if (retv < 0) {
		return -1;
	} else if (retv != APOL_MLS_EQ && retv != APOL_MLS_DOMBY) {
		return 0;
	}

	return 1;
}

static int mls_range_comp(const void *a, const void *b, void *data)
{
	const apol_mls_level_t *l1 = (const apol_mls_level_t *)a;
	const apol_mls_level_t *l2 = (const apol_mls_level_t *)b;
	qpol_policy_t *q = (qpol_policy_t *) data;
	qpol_level_t *l;
	uint32_t low_value, high_value;
	qpol_policy_get_level_by_name(q, apol_mls_level_get_sens(l1), &l);
	qpol_level_get_value(q, l, &low_value);
	qpol_policy_get_level_by_name(q, apol_mls_level_get_sens(l2), &l);
	qpol_level_get_value(q, l, &high_value);
	assert(low_value != 0 && high_value != 0);
	return low_value - high_value;
}

static int mls_level_name_to_cat_comp(const void *a, const void *b, void *data)
{
	qpol_cat_t *cat = (qpol_cat_t *) a;
	const char *name = (const char *)b;
	qpol_policy_t *q = (qpol_policy_t *) data;
	char *cat_name = "";
	qpol_cat_get_name(q, cat, &cat_name);
	return strcmp(name, cat_name);
}

static void mls_level_free(void *elem)
{
	apol_mls_level_t *level = elem;
	apol_mls_level_destroy(&level);
}

apol_vector_t *apol_mls_range_get_levels(apol_policy_t * p, const apol_mls_range_t * range)
{
	qpol_policy_t *q = apol_policy_get_qpol(p);
	apol_vector_t *v = NULL, *catv = NULL;
	qpol_level_t *l;
	uint32_t low_value, high_value, value;
	int error = 0;
	qpol_iterator_t *iter = NULL, *catiter = NULL;

	if (p == NULL || range == NULL || range->low == NULL) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	apol_mls_level_t *low_level, *high_level;
	low_level = range->low;
	if (range->high == NULL) {
		high_level = low_level;
	} else {
		high_level = range->high;
	}
	if (qpol_policy_get_level_by_name(q, apol_mls_level_get_sens(low_level), &l) < 0 ||
	    qpol_level_get_value(q, l, &low_value) < 0) {
		error = errno;
		goto err;
	}
	if (qpol_policy_get_level_by_name(q, apol_mls_level_get_sens(high_level), &l) < 0 ||
	    qpol_level_get_value(q, l, &high_value) < 0) {
		error = errno;
		goto err;
	}
	assert(low_value <= high_value);
	if ((v = apol_vector_create(mls_level_free)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	if (qpol_policy_get_level_iter(q, &iter) < 0) {
		error = errno;
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		char *name;
		apol_mls_level_t *ml;
		if (qpol_iterator_get_item(iter, (void **)&l) < 0 ||
		    qpol_level_get_value(q, l, &value) < 0 || qpol_level_get_name(q, l, &name) < 0) {
			error = errno;
			goto err;
		}
		if (value < low_value || value > high_value) {
			continue;
		}
		if ((ml = apol_mls_level_create()) == NULL || (apol_mls_level_set_sens(p, ml, name) < 0)) {
			error = errno;
			apol_mls_level_destroy(&ml);
			ERR(p, "%s", strerror(error));
			goto err;
		}

		if (qpol_level_get_cat_iter(q, l, &catiter) < 0 || (catv = apol_vector_create_from_iter(catiter, NULL)) == NULL) {
			error = errno;
			goto err;
		}

		const apol_vector_t *high_cats = apol_mls_level_get_cats(high_level);
		for (size_t i = 0; i < apol_vector_get_size(high_cats); i++) {
			char *name = apol_vector_get_element(high_cats, i);

			size_t j;
			/* do not add categories that are not members of
			   the level */
			if (apol_vector_get_index(catv, name, mls_level_name_to_cat_comp, q, &j) < 0) {
				/* this category is not legal under the given policy */
				continue;
			}
			if (apol_mls_level_append_cats(p, ml, name) < 0) {
				error = errno;
				apol_mls_level_destroy(&ml);
				ERR(p, "%s", strerror(error));
				goto err;
			}
		}

		qpol_iterator_destroy(&catiter);
		apol_vector_destroy(&catv);

		if (apol_vector_append(v, ml) < 0) {
			error = errno;
			apol_mls_level_destroy(&ml);
			ERR(p, "%s", strerror(error));
			goto err;
		}
	}
	apol_vector_sort(v, mls_range_comp, q);
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&catiter);
	apol_vector_destroy(&catv);
	return v;
      err:
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&catiter);
	apol_vector_destroy(&v);
	apol_vector_destroy(&catv);
	errno = error;
	return NULL;
}

char *apol_mls_range_render(apol_policy_t * p, const apol_mls_range_t * range)
{
	char *rt = NULL, *retval = NULL;
	char *sub_str = NULL;
	int retv;
	size_t sz = 0;

	if (!range || range->low == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		goto cleanup;
	}
	if (p == NULL && apol_mls_range_is_literal(range) != 1) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		goto cleanup;
	}

	if ((sub_str = apol_mls_level_render(p, range->low)) == NULL) {
		goto cleanup;
	}
	if (apol_str_append(&rt, &sz, sub_str)) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	free(sub_str);
	sub_str = NULL;
	if (range->high == NULL) {
		/* no high level set, so skip the rest of this render
		 * function */
		retval = rt;
		goto cleanup;
	}
	if (p == NULL) {
		// no policy, so assume that high level dominates low level
		retv = APOL_MLS_DOM;
	} else {
		retv = apol_mls_level_compare(p, range->low, range->high);
		if (retv < 0) {
			goto cleanup;
		}
	}
	/* if (high level != low level) */
	if ((retv == APOL_MLS_DOM || retv == APOL_MLS_DOMBY) && range->high != NULL) {
		sub_str = apol_mls_level_render(p, range->high);
		if (!sub_str)
			goto cleanup;
		if (apol_str_appendf(&rt, &sz, " - %s", sub_str)) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
	}
	retval = rt;
      cleanup:
	if (retval != rt) {
		free(rt);
	}
	free(sub_str);
	return retval;
}

int apol_mls_range_is_literal(const apol_mls_range_t * range)
{
	if (range == NULL) {
		return -1;
	}
	int ret;
	if ((ret = apol_mls_level_is_literal(range->low)) != 0) {
		return ret;
	}
	if (range->high != NULL) {
		ret = apol_mls_level_is_literal(range->high);
	}
	return ret;
}
