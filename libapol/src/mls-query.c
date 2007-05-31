/**
 *  @file
 *  Implementation for querying MLS components.
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include <qpol/iterator.h>

#include "policy-query-internal.h"
#include <apol/vector.h>

struct apol_mls_level
{
	char *sens;
	apol_vector_t *cats;	// if NULL, then level is still a literal string
	char *literal_cats;
};

struct apol_mls_range
{
	apol_mls_level_t *low, *high;
};

struct apol_level_query
{
	char *sens_name, *cat_name;
	unsigned int flags;
	regex_t *sens_regex, *cat_regex;
};

struct apol_cat_query
{
	char *cat_name;
	unsigned int flags;
	regex_t *regex;
};

/********************* miscellaneous routines *********************/

/* Given a category datum and a category name, returns < 0 if a has
 * higher value than b, > 0 if b is higher according to the given
 * policy.  If the two are equal or upon error, return 0.
 */
static int apol_mls_cat_vector_compare(const void *a, const void *b, void *data)
{
	qpol_cat_t *cat1 = (qpol_cat_t *) a;
	const char *cat2_name = (const char *)b;
	apol_policy_t *p = (apol_policy_t *) data;
	qpol_cat_t *cat2;
	uint32_t cat_value1, cat_value2;
	if (qpol_policy_get_cat_by_name(p->p, cat2_name, &cat2) < 0) {
		return 0;
	}
	if (qpol_cat_get_value(p->p, cat1, &cat_value1) < 0 || qpol_cat_get_value(p->p, cat2, &cat_value2) < 0) {
		return 0;
	}
	return (cat_value2 - cat_value1);
}

/**
 * Given two category names, returns < 0 if a has higher value than b,
 * > 0 if b is higher. The comparison is against the categories'
 * values according to the supplied policy.  If the two are equal or
 * upon error, return 0.
 *
 * @param a First category name to compare.
 * @param b Other name to compare.
 * @param data Pointer to a policy to which use for comparison.
 *
 * @return <0, 0, or >0 if a is less than, equal, or greater than b,
 * respectively.
 */
static int apol_mls_cat_name_compare(const void *a, const void *b, void *data)
{
	const char *cat1 = (const char *)a;
	const char *cat2 = (const char *)b;
	apol_policy_t *p = (apol_policy_t *) data;
	qpol_cat_t *qcat1, *qcat2;
	uint32_t cat_value1, cat_value2;
	if (qpol_policy_get_cat_by_name(p->p, cat1, &qcat1) < 0 || qpol_policy_get_cat_by_name(p->p, cat2, &qcat2) < 0) {
		return 0;
	}
	if (qpol_cat_get_value(p->p, qcat1, &cat_value1) < 0 || qpol_cat_get_value(p->p, qcat2, &cat_value2) < 0) {
		return 0;
	}
	return (cat_value1 - cat_value2);
}

/********************* level *********************/

apol_mls_level_t *apol_mls_level_create(void)
{
	apol_mls_level_t *l;
	if ((l = calloc(1, sizeof(*l))) == NULL || (l->cats = apol_vector_create(free)) == NULL) {
		apol_mls_level_destroy(&l);
		return NULL;
	}
	return l;
}

apol_mls_level_t *apol_mls_level_create_from_mls_level(const apol_mls_level_t * level)
{
	apol_mls_level_t *l;
	if (level != NULL && level->cats == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((l = apol_mls_level_create()) == NULL) {
		return NULL;
	}
	if (level != NULL &&
	    ((l->sens = strdup(level->sens)) == NULL ||
	     (l->cats = apol_vector_create_from_vector(level->cats, apol_str_strdup, NULL, free)) == NULL)) {
		apol_mls_level_destroy(&l);
		return NULL;
	}
	return l;
}

apol_mls_level_t *apol_mls_level_create_from_string(apol_policy_t * p, const char *mls_level_string)
{
	if (p == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return NULL;
	}

	apol_mls_level_t *l = apol_mls_level_create_from_literal(mls_level_string);
	if (l == NULL) {
		ERR(p, "%s", strerror(errno));
		return NULL;
	}

	if (apol_mls_level_convert(p, l) < 0) {
		apol_mls_level_destroy(&l);
		return NULL;
	}
	free(l->literal_cats);
	l->literal_cats = NULL;
	return l;
}

apol_mls_level_t *apol_mls_level_create_from_literal(const char *mls_level_string)
{
	apol_mls_level_t *l;
	char *colon;
	if (mls_level_string == NULL) {
		errno = EINVAL;
		return NULL;
	}
	if ((l = calloc(1, sizeof(*l))) == NULL) {
		return NULL;
	}
	if ((colon = strchr(mls_level_string, ':')) != NULL) {
		if (colon == mls_level_string) {
			apol_mls_level_destroy(&l);
			errno = EINVAL;
			return NULL;
		}
		if ((l->sens = strndup(mls_level_string, colon - mls_level_string)) == NULL) {
			apol_mls_level_destroy(&l);
			return NULL;
		}
		// store everything after the colon as the category string
		if ((l->literal_cats = strdup(colon + 1)) == NULL) {
			apol_mls_level_destroy(&l);
			return NULL;
		}
		apol_str_trim(l->literal_cats);
	} else {
		// no category, just a sensitivity
		if ((l->sens = strdup(mls_level_string)) == NULL || (l->literal_cats = strdup("")) == NULL) {
			apol_mls_level_destroy(&l);
			return NULL;
		}
	}
	return l;
}

apol_mls_level_t *apol_mls_level_create_from_qpol_mls_level(apol_policy_t * p, qpol_mls_level_t * qpol_level)
{
	apol_mls_level_t *lvl = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_cat_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!p || !qpol_level) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		goto err;
	}

	if ((lvl = apol_mls_level_create()) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	if (qpol_mls_level_get_sens_name(p->p, qpol_level, &tmp) || qpol_mls_level_get_cat_iter(p->p, qpol_level, &iter)) {
		error = errno;
		goto err;
	}
	if (apol_mls_level_set_sens(p, lvl, tmp) < 0) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&tmp_cat) < 0 || qpol_cat_get_name(p->p, tmp_cat, &tmp) < 0) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(p, lvl, tmp) < 0) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
	}

	qpol_iterator_destroy(&iter);
	return lvl;

      err:
	apol_mls_level_destroy(&lvl);
	qpol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

apol_mls_level_t *apol_mls_level_create_from_qpol_level_datum(apol_policy_t * p, qpol_level_t * qpol_level)
{
	apol_mls_level_t *lvl = NULL;
	qpol_iterator_t *iter = NULL;
	qpol_cat_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!p || !qpol_level) {
		errno = EINVAL;
		return NULL;
	}

	if ((lvl = apol_mls_level_create()) == NULL) {
		ERR(p, "%s", strerror(error));
		return NULL;
	}
	if (qpol_level_get_name(p->p, qpol_level, &tmp)) {
		error = errno;
		goto err;
	}
	if ((lvl->sens = strdup(tmp)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}

	if (qpol_level_get_cat_iter(p->p, qpol_level, &iter)) {
		error = errno;
		goto err;
	}

	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		if (qpol_iterator_get_item(iter, (void **)&tmp_cat)) {
			error = errno;
			goto err;
		}
		if (qpol_cat_get_name(p->p, tmp_cat, &tmp)) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(p, lvl, tmp)) {
			error = errno;
			goto err;
		}
	}
	qpol_iterator_destroy(&iter);
	return lvl;

      err:
	apol_mls_level_destroy(&lvl);
	qpol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

static void mls_level_free(void *level)
{
	if (level != NULL) {
		apol_mls_level_t *l = level;
		free(l->sens);
		apol_vector_destroy(&l->cats);
		free(l->literal_cats);
		free(l);
	}
}

void apol_mls_level_destroy(apol_mls_level_t ** level)
{
	if (!level || !(*level))
		return;
	mls_level_free(*level);
	*level = NULL;
}

int apol_mls_level_set_sens(apol_policy_t * p, apol_mls_level_t * level, const char *sens)
{
	if (!level) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	return apol_query_set(p, &level->sens, NULL, sens);
}

const char *apol_mls_level_get_sens(const apol_mls_level_t * level)
{
	if (!level) {
		errno = EINVAL;
		return NULL;
	}
	return level->sens;
}

int apol_mls_level_append_cats(apol_policy_t * p, apol_mls_level_t * level, const char *cats)
{
	char *new_cat = NULL;
	if (!level || !cats || level->cats == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (level->cats == NULL && (level->cats = apol_vector_create(free)) == NULL) {
		ERR(p, "%s", strerror(errno));
		return -1;
	}
	if ((new_cat = strdup(cats)) == NULL || apol_vector_append(level->cats, (void *)new_cat) < 0) {
		ERR(p, "%s", strerror(errno));
		free(new_cat);
		return -1;
	}
	apol_vector_sort(level->cats, apol_str_strcmp, NULL);
	return 0;
}

const apol_vector_t *apol_mls_level_get_cats(const apol_mls_level_t * level)
{
	if (!level || level->cats == NULL) {
		errno = EINVAL;
		return NULL;
	}
	return level->cats;
}

int apol_mls_level_compare(apol_policy_t * p, const apol_mls_level_t * l1, const apol_mls_level_t * l2)
{
	qpol_level_t *level_datum1, *level_datum2;
	int level1_sens, level2_sens, sens_cmp;
	size_t l1_size, l2_size, i, j;
	int m_list, ucat = 0;
	apol_vector_t *cat_list_master, *cat_list_subset;
	if (l2 == NULL) {
		return APOL_MLS_EQ;
	}
	if ((l1 != NULL && l1->cats == NULL) || (l2->cats == NULL)) {
		errno = EINVAL;
		return -1;
	}
	if (qpol_policy_get_level_by_name(p->p, l1->sens, &level_datum1) < 0 ||
	    qpol_policy_get_level_by_name(p->p, l2->sens, &level_datum2) < 0) {
		return -1;
	}

	/* compare the level's senstitivity value */
	if (qpol_level_get_value(p->p, level_datum1, (uint32_t *) (&level1_sens)) < 0 ||
	    qpol_level_get_value(p->p, level_datum2, (uint32_t *) (&level2_sens)) < 0) {
		return -1;
	}
	sens_cmp = level1_sens - level2_sens;

	/* determine if all the categories in one level are in the other set */
	l1_size = apol_vector_get_size(l1->cats);
	l2_size = apol_vector_get_size(l2->cats);
	if (l1_size < l2_size) {
		m_list = 2;
		cat_list_master = l2->cats;
		cat_list_subset = l1->cats;
	} else {
		m_list = 1;
		cat_list_master = l1->cats;
		cat_list_subset = l2->cats;
	}
	for (i = 0; i < apol_vector_get_size(cat_list_subset); i++) {
		char *cat = (char *)apol_vector_get_element(cat_list_subset, i);
		if (apol_vector_get_index(cat_list_master, cat, apol_mls_cat_name_compare, p, &j) < 0) {
			ucat = 1;
			break;
		}
	}

	if (!sens_cmp && !ucat && l1_size == l2_size)
		return APOL_MLS_EQ;
	if (sens_cmp >= 0 && m_list == 1 && !ucat)
		return APOL_MLS_DOM;
	if (sens_cmp <= 0 && (m_list == 2 || l1_size == l2_size) && !ucat)
		return APOL_MLS_DOMBY;
	return APOL_MLS_INCOMP;
}

int apol_mls_level_validate(apol_policy_t * p, const apol_mls_level_t * level)
{
	qpol_level_t *level_datum;
	qpol_iterator_t *iter = NULL;
	apol_vector_t *cat_vector;
	int retval = -1;
	size_t i, j;

	if (p == NULL || level == NULL || level->cats == NULL) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (qpol_policy_get_level_by_name(p->p, level->sens, &level_datum) < 0 ||
	    qpol_level_get_cat_iter(p->p, level_datum, &iter) < 0) {
		return -1;
	}
	if ((cat_vector = apol_vector_create_from_iter(iter, NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		char *cat_name = (char *)apol_vector_get_element(level->cats, i);
		if (apol_vector_get_index(cat_vector, cat_name, apol_mls_cat_vector_compare, p, &j) < 0) {
			retval = 0;
			goto cleanup;
		}
	}

	retval = 1;
      cleanup:
	qpol_iterator_destroy(&iter);
	apol_vector_destroy(&cat_vector);
	return retval;
}

char *apol_mls_level_render(apol_policy_t * p, const apol_mls_level_t * level)
{
	char *rt = NULL, *name = NULL, *sens_name = NULL, *cat_name = NULL;
	char *retval = NULL;
	int cur;
	qpol_cat_t *cur_cat = NULL, *next_cat = NULL;
	uint32_t cur_cat_val, next_cat_val, far_cat_val;
	apol_vector_t *cats = NULL;
	size_t sz = 0, n_cats = 0, i;

	if (!level || (p == NULL && level->cats != NULL)) {
		ERR(p, "%s", strerror(EINVAL));
		errno = EINVAL;
		goto cleanup;
	}

	sens_name = level->sens;
	if (!sens_name)
		goto cleanup;
	if (apol_str_append(&rt, &sz, sens_name)) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}

	if (level->cats != NULL) {
		if ((cats = apol_vector_create_from_vector(level->cats, apol_str_strdup, NULL, free)) == NULL) {
			ERR(p, "%s", strerror(errno));
			goto cleanup;
		}
		n_cats = apol_vector_get_size(cats);
	}
	if (n_cats == 0) {
		if (level->literal_cats != NULL && level->literal_cats[0] != '\0') {
			if (apol_str_appendf(&rt, &sz, ":%s", level->literal_cats)) {
				ERR(p, "%s", strerror(errno));
				goto cleanup;
			}

		}
		retval = rt;
		goto cleanup;
	}
	apol_vector_sort(cats, apol_mls_cat_name_compare, p);

	cat_name = (char *)apol_vector_get_element(cats, 0);
	if (!cat_name)
		goto cleanup;

	if (apol_str_appendf(&rt, &sz, ":%s", cat_name)) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	cur = 0;		       /* current value to compare with cat[i] */
	for (i = 1; i < n_cats; i++) { /* we've already appended the first category */
		/* get the value of cats[cur] */
		cat_name = (char *)apol_vector_get_element(cats, cur);
		if (qpol_policy_get_cat_by_name(p->p, cat_name, &cur_cat))
			goto cleanup;
		if (qpol_cat_get_value(p->p, cur_cat, &cur_cat_val))
			goto cleanup;

		/* get the value of cats[i] */
		cat_name = (char *)apol_vector_get_element(cats, i);
		if (qpol_policy_get_cat_by_name(p->p, cat_name, &next_cat))
			goto cleanup;
		if (qpol_cat_get_value(p->p, next_cat, &next_cat_val))
			goto cleanup;

		if (next_cat_val == cur_cat_val + 1) {
			if (i + 1 == n_cats) {	/* last category is next; append "." */
				if (qpol_cat_get_name(p->p, next_cat, &name))
					goto cleanup;
				if (apol_str_appendf(&rt, &sz, ".%s", name)) {
					ERR(p, "%s", strerror(errno));
					goto cleanup;
				}
				cur = i;
			} else {
				qpol_cat_t *far_cat = NULL;	/* category 2 in front of cur */
				cat_name = (char *)apol_vector_get_element(cats, i + 1);
				if (qpol_policy_get_cat_by_name(p->p, cat_name, &far_cat))
					goto cleanup;
				if (qpol_cat_get_value(p->p, far_cat, &far_cat_val))
					goto cleanup;
				if (far_cat_val == cur_cat_val + 2) {
					cur++;
				} else {	/* far_cat isn't consecutive wrt cur/next_cat; append it */
					if (qpol_cat_get_name(p->p, next_cat, &name))
						goto cleanup;
					if (apol_str_appendf(&rt, &sz, ".%s", name)) {
						ERR(p, "%s", strerror(errno));
						goto cleanup;
					}
					cur = i;
				}
			}
		} else {	       /* next_cat isn't consecutive to cur_cat; append it */
			if (qpol_cat_get_name(p->p, next_cat, &name))
				goto cleanup;
			if (apol_str_appendf(&rt, &sz, ", %s", name)) {
				ERR(p, "%s", strerror(errno));
				goto cleanup;
			}
			cur = i;
		}
	}

	retval = rt;
      cleanup:
	apol_vector_destroy(&cats);
	if (retval != rt) {
		free(rt);
	}
	return retval;
}

int apol_mls_level_convert(apol_policy_t * p, apol_mls_level_t * level)
{
	int error = 0;
	if (p == NULL || level == NULL || level->literal_cats == NULL) {
		error = EINVAL;
		ERR(p, "%s", strerror(error));
		goto err;
	}

	apol_vector_destroy(&level->cats);
	if (level->literal_cats[0] == '\0') {
		if ((level->cats = apol_vector_create_with_capacity(1, free)) == NULL) {
			error = errno;
			ERR(p, "%s", strerror(error));
			goto err;
		}
		return 0;
	}

	const char *tmp;
	char *cat_name, **tokens = NULL, *next = NULL;
	size_t num_tokens = 1, i;
	qpol_iterator_t *iter = NULL;
	qpol_level_t *sens = NULL;
	qpol_cat_t *cat1 = NULL, *cat2 = NULL, *tmp_cat = NULL;
	uint32_t val1 = 0, val2 = 0, tmp_val = 0;
	unsigned char tmp_isalias = 0;

	for (tmp = level->literal_cats; *tmp; tmp++) {
		if ((next = strchr(tmp, ','))) {
			tmp = next;
			num_tokens++;
		}
	}
	tokens = calloc(num_tokens, sizeof(char *));
	if (!tokens) {
		error = errno;
		ERR(p, "%s", strerror(ENOMEM));
		goto err;
	}
	if ((level->cats = apol_vector_create_with_capacity(num_tokens, free)) == NULL) {
		error = errno;
		ERR(p, "%s", strerror(error));
		goto err;
	}

	for (tmp = level->literal_cats, i = 0; *tmp && i < num_tokens; tmp++) {
		if (isspace(*tmp))
			continue;
		next = strchr(tmp, ',');
		if (next) {
			tokens[i] = strndup(tmp, next - tmp);
			if (!tokens[i]) {
				error = errno;
				goto err;
			}
			tmp = next;
			next = NULL;
			i++;
		} else {
			tokens[i] = strdup(tmp);
			if (!tokens[i]) {
				error = errno;
				ERR(p, "%s", strerror(ENOMEM));
				goto err;
			}
			i++;
			if (i != num_tokens) {
				error = EIO;
				goto err;
			}
		}
	}

	if (qpol_policy_get_level_by_name(p->p, level->sens, &sens)) {
		error = errno;
		goto err;
	}

	for (i = 0; i < num_tokens; i++) {
		next = strchr(tokens[i], '.');
		if (next) {
			*next = '\0';
			next++;

			/* get end points of cat range */
			if (qpol_policy_get_cat_by_name(p->p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (qpol_policy_get_cat_by_name(p->p, next, &cat2)) {
				error = errno;
				goto err;
			}

			/* get end point values */
			if (qpol_cat_get_value(p->p, cat1, &val1)) {
				error = errno;
				goto err;
			}
			if (qpol_cat_get_value(p->p, cat2, &val2)) {
				error = errno;
				goto err;
			}
			if (val1 >= val2) {
				error = EINVAL;
				ERR(p, "%s", strerror(error));
				goto err;
			}
			if (apol_mls_level_append_cats(p, level, tokens[i])) {
				error = errno;
				goto err;
			}
			if (qpol_policy_get_cat_iter(p->p, &iter)) {
				error = errno;
				goto err;
			}
			for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
				if (qpol_iterator_get_item(iter, (void **)&tmp_cat)) {
					error = errno;
					goto err;
				}
				if (qpol_cat_get_isalias(p->p, tmp_cat, &tmp_isalias)) {
					error = errno;
					goto err;
				}
				if (tmp_isalias)
					continue;
				if (qpol_cat_get_value(p->p, tmp_cat, &tmp_val)) {
					error = errno;
					goto err;
				}
				if (tmp_val > val1 && tmp_val < val2) {
					if (qpol_cat_get_name(p->p, tmp_cat, &cat_name)) {
						error = errno;
						goto err;
					}
					if (apol_mls_level_append_cats(p, level, cat_name)) {
						error = errno;
						goto err;
					}
				}
			}
			if (apol_mls_level_append_cats(p, level, next)) {
				error = errno;
				goto err;
			}
		} else {
			if (qpol_policy_get_cat_by_name(p->p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (apol_mls_level_append_cats(p, level, tokens[i])) {
				error = errno;
				goto err;
			}
		}
	}

	if (tokens) {
		for (i = 0; i < num_tokens; i++)
			free(tokens[i]);
		free(tokens);
	}

	qpol_iterator_destroy(&iter);
	return 0;

      err:
	if (tokens) {
		for (i = 0; i < num_tokens; i++)
			free(tokens[i]);
		free(tokens);
	}
	qpol_iterator_destroy(&iter);
	errno = error;
	return -1;
}

int apol_mls_sens_compare(apol_policy_t * p, const char *sens1, const char *sens2)
{
	qpol_level_t *level_datum1, *level_datum2;
	if (qpol_policy_get_level_by_name(p->p, sens1, &level_datum1) < 0 ||
	    qpol_policy_get_level_by_name(p->p, sens2, &level_datum2) < 0) {
		return -1;
	}
	if (level_datum1 == level_datum2) {
		return 1;
	}
	return 0;
}

int apol_mls_cats_compare(apol_policy_t * p, const char *cat1, const char *cat2)
{
	qpol_cat_t *qcat1, *qcat2;
	if (qpol_policy_get_cat_by_name(p->p, cat1, &qcat1) < 0 || qpol_policy_get_cat_by_name(p->p, cat2, &qcat2) < 0) {
		return -1;
	}
	if (qcat1 == qcat2) {
		return 1;
	}
	return 0;
}

/********************* range *********************/

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
			return apol_mls_sens_compare(p, range->low->sens, level->sens);
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
	qpol_policy_get_level_by_name(q, l1->sens, &l);
	qpol_level_get_value(q, l, &low_value);
	qpol_policy_get_level_by_name(q, l2->sens, &l);
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
	if (qpol_policy_get_level_by_name(q, low_level->sens, &l) < 0 || qpol_level_get_value(q, l, &low_value) < 0) {
		error = errno;
		goto err;
	}
	if (qpol_policy_get_level_by_name(q, high_level->sens, &l) < 0 || qpol_level_get_value(q, l, &high_value) < 0) {
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
		if ((ml = calloc(1, sizeof(*ml))) == NULL ||
		    (ml->sens = strdup(name)) == NULL ||
		    (ml->cats = apol_vector_create_from_vector(high_level->cats, apol_str_strdup, NULL, free)) == NULL ||
		    apol_vector_append(v, ml) < 0) {
			error = errno;
			apol_mls_level_destroy(&ml);
			ERR(p, "%s", strerror(error));
			goto err;
		}
		/* now go through the category vector and remove those
		 * are not members of the level */
		size_t i, j;
		for (i = 0; i < apol_vector_get_size(ml->cats); i++) {
			name = apol_vector_get_element(ml->cats, i);
			if (qpol_level_get_cat_iter(q, l, &catiter) < 0 ||
			    (catv = apol_vector_create_from_iter(catiter, NULL)) == NULL) {
				error = errno;
				goto err;
			}
			if (apol_vector_get_index(catv, name, mls_level_name_to_cat_comp, q, &j) < 0) {
				/* this category is not legal under the given policy */
				free(name);
				apol_vector_remove(ml->cats, i);
				i--;
			}
			qpol_iterator_destroy(&catiter);
			apol_vector_destroy(&catv);
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
	if (p == NULL) {
		if (range->low->cats != NULL || (range->high != NULL && range->high->cats != NULL)) {
			ERR(p, "%s", strerror(EINVAL));
			errno = EINVAL;
			goto cleanup;
		}
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

/******************** level queries ********************/

int apol_level_get_by_query(apol_policy_t * p, apol_level_query_t * l, apol_vector_t ** v)
{
	qpol_iterator_t *iter, *cat_iter = NULL;
	int retval = -1, append_level;
	*v = NULL;
	if (qpol_policy_get_level_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_level_t *level;
		unsigned char isalias;
		if (qpol_iterator_get_item(iter, (void **)&level) < 0 || qpol_level_get_isalias(p->p, level, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		append_level = 1;
		if (l != NULL) {
			int compval = apol_compare_level(p,
							 level, l->sens_name,
							 l->flags, &(l->sens_regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
			if (qpol_level_get_cat_iter(p->p, level, &cat_iter) < 0) {
				goto cleanup;
			}
			append_level = 0;
			for (; !qpol_iterator_end(cat_iter); qpol_iterator_next(cat_iter)) {
				qpol_cat_t *cat;
				if (qpol_iterator_get_item(cat_iter, (void **)&cat) < 0) {
					goto cleanup;
				}
				compval = apol_compare_cat(p, cat, l->cat_name, l->flags, &(l->cat_regex));
				if (compval < 0) {
					goto cleanup;
				} else if (compval == 1) {
					append_level = 1;
					break;
				}
			}
			qpol_iterator_destroy(&cat_iter);
		}
		if (append_level && apol_vector_append(*v, level)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	qpol_iterator_destroy(&cat_iter);
	return retval;
}

apol_level_query_t *apol_level_query_create(void)
{
	return calloc(1, sizeof(apol_level_query_t));
}

void apol_level_query_destroy(apol_level_query_t ** l)
{
	if (*l != NULL) {
		free((*l)->sens_name);
		free((*l)->cat_name);
		apol_regex_destroy(&(*l)->sens_regex);
		apol_regex_destroy(&(*l)->cat_regex);
		free(*l);
		*l = NULL;
	}
}

int apol_level_query_set_sens(apol_policy_t * p, apol_level_query_t * l, const char *name)
{
	return apol_query_set(p, &l->sens_name, &l->sens_regex, name);
}

int apol_level_query_set_cat(apol_policy_t * p, apol_level_query_t * l, const char *name)
{
	return apol_query_set(p, &l->cat_name, &l->cat_regex, name);
}

int apol_level_query_set_regex(apol_policy_t * p, apol_level_query_t * l, int is_regex)
{
	return apol_query_set_regex(p, &l->flags, is_regex);
}

/******************** category queries ********************/

int apol_cat_get_by_query(apol_policy_t * p, apol_cat_query_t * c, apol_vector_t ** v)
{
	qpol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (qpol_policy_get_cat_iter(p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create(NULL)) == NULL) {
		ERR(p, "%s", strerror(errno));
		goto cleanup;
	}
	for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
		qpol_cat_t *cat;
		unsigned char isalias;
		if (qpol_iterator_get_item(iter, (void **)&cat) < 0 || qpol_cat_get_isalias(p->p, cat, &isalias) < 0) {
			goto cleanup;
		}
		if (isalias) {
			continue;
		}
		if (c != NULL) {
			int compval = apol_compare_cat(p,
						       cat, c->cat_name,
						       c->flags, &(c->regex));
			if (compval < 0) {
				goto cleanup;
			} else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cat)) {
			ERR(p, "%s", strerror(ENOMEM));
			goto cleanup;
		}
	}

	retval = 0;
      cleanup:
	if (retval != 0) {
		apol_vector_destroy(v);
	}
	qpol_iterator_destroy(&iter);
	return retval;
}

apol_cat_query_t *apol_cat_query_create(void)
{
	return calloc(1, sizeof(apol_cat_query_t));
}

void apol_cat_query_destroy(apol_cat_query_t ** c)
{
	if (*c != NULL) {
		free((*c)->cat_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cat_query_set_cat(apol_policy_t * p, apol_cat_query_t * c, const char *name)
{
	return apol_query_set(p, &c->cat_name, &c->regex, name);
}

int apol_cat_query_set_regex(apol_policy_t * p, apol_cat_query_t * c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}
