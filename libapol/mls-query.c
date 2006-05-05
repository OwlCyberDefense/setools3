/**
 *  @file mls-query.c
 *  Implementation for querying MLS components.
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

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/iterator.h>

#include "component-query.h"
#include "mls-query.h"
#include "vector.h"

struct apol_level_query {
	char *sens_name, *cat_name;
	unsigned int flags;
	regex_t *sens_regex, *cat_regex;
};

struct apol_cat_query {
	char *cat_name;
	unsigned int flags;
	regex_t *regex;
};

/********************* miscellaneous routines *********************/

/* Given two category names, returns < 0 if a has higher value than b,
 * > 0 if b is higher.	If the two are equal or upon error, return 0.
 */
static int apol_mls_cat_vector_compare(const void *a, const void *b, void *data)
{
	const char *cat1 = (const char *) a;
	const char *cat2 = (const char *) b;
	apol_policy_t *p = (apol_policy_t *) data;
	sepol_cat_datum_t *cat_datum1, *cat_datum2;
	uint32_t cat_value1, cat_value2;
	if (sepol_policydb_get_cat_by_name(p->sh, p->p, cat1, &cat_datum1) < 0 ||
	    sepol_policydb_get_cat_by_name(p->sh, p->p, cat2, &cat_datum2) < 0) {
		return 0;
	}
	if (sepol_cat_datum_get_value(p->sh, p->p, cat_datum1, &cat_value1) < 0 ||
	    sepol_cat_datum_get_value(p->sh, p->p, cat_datum2, &cat_value2) < 0) {
		return 0;
	}
	return (cat_value2 - cat_value1);
}

/* Given a category datum and a names, returns < 0 if a has higher
 * value than b, > 0 if b is higher.  If the two are equal or upon
 * error, return 0.
 */
static int apol_mls_cat_datum_vector_compare(const void *a, const void *b, void *data)
{
	sepol_cat_datum_t *cat_datum1 = (sepol_cat_datum_t *) a;
	const char *cat2 = (const char *) b;
	apol_policy_t *p = (apol_policy_t *) data;
	sepol_cat_datum_t *cat_datum2;
	uint32_t cat_value1, cat_value2;
	if (sepol_policydb_get_cat_by_name(p->sh, p->p, cat2, &cat_datum2) < 0) {
		return 0;
	}
	if (sepol_cat_datum_get_value(p->sh, p->p, cat_datum1, &cat_value1) < 0 ||
	    sepol_cat_datum_get_value(p->sh, p->p, cat_datum2, &cat_value2) < 0) {
		return 0;
	}
	return (cat_value2 - cat_value1);
}

/**
 * Given a level, determine if it is legal according to the supplied
 * policy.  This function will convert from aliases to canonical forms
 * as necessary.  This function differs from apol_mls_level_compare()
 * in that the supplied level must contain a sensitivity.
 *
 * @param h Error reporting handler.
 * @param p Policy within which to look up MLS information.
 * @param level Level to check.
 *
 * @return 1 If level is legal, 0 if not; < 0 on error.
 */
static int apol_mls_level_validate(apol_policy_t *p,
				   apol_mls_level_t *level)
{
	sepol_level_datum_t *level_datum;
	sepol_iterator_t *iter = NULL;
	apol_vector_t *cat_vector;
	int retval = -1;
	size_t i;

	if (level == NULL) {
		ERR(p, "Invalid argument.");
		return -1;
	}
	if (sepol_policydb_get_level_by_name(p->sh, p->p, level->sens, &level_datum) < 0 ||
	    sepol_level_datum_get_cat_iter(p->sh, p->p, level_datum, &iter) < 0) {
		return -1;
	}
	if ((cat_vector = apol_vector_create_from_iter(iter)) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}

	for (i = 0; i < apol_vector_get_size(level->cats); i++) {
		char *cat_name = (char *) apol_vector_get_element(level->cats, i);
		if (apol_vector_get_index(cat_vector, cat_name,
					  apol_mls_cat_datum_vector_compare, p) == -1) {
			retval = 0;
			goto cleanup;
		}
	}

	retval = 1;
 cleanup:
	sepol_iterator_destroy(&iter);
	apol_vector_destroy(&cat_vector, NULL);
	return retval;
}

/**
 * Equivalent to the non-ANSI strdup() function.
 * @param p Policy handler.
 * @param s String to duplicate.
 * @return Pointer to newly allocated string, or NULL on error.
 */
static char *apol_strdup(apol_policy_t *p, const char *s)
{
	char *t;
	if ((t = malloc(strlen(s) + 1)) == NULL) {
		ERR(p, "Out of memory!");
		return NULL;
	}
	return strcpy(t, s);
}

/********************* level *********************/

apol_mls_level_t *apol_mls_level_create(void)
{
	return calloc(1, sizeof(apol_mls_level_t));
}

apol_mls_level_t *apol_mls_level_create_from_string(apol_policy_t *p, char *mls_level_string)
{
	apol_mls_level_t *lvl = NULL;
	int error = 0;
	char *tmp = NULL, **tokens = NULL, *next = NULL;
	size_t num_tokens = 1, i;
	sepol_iterator_t *iter = NULL;
	sepol_level_datum_t *sens = NULL;
	sepol_cat_datum_t *cat1 = NULL, *cat2 = NULL, *tmp_cat = NULL;
	uint32_t val1 = 0, val2 = 0, tmp_val = 0;
	unsigned char tmp_isalias = 0;

	if (!p || !mls_level_string) {
		errno = EINVAL;
		return NULL;
	}

	if ((lvl = apol_mls_level_create()) == NULL)
		return NULL;

	for (tmp = mls_level_string; *tmp; tmp++) {
		if ((next = strpbrk(tmp, ",:"))) {
			tmp = next;
			num_tokens++;
		}
	}
	tokens = calloc(num_tokens, sizeof(char*));
	if (!tokens) {
		error = errno;
		goto err;
	}
	for (tmp = mls_level_string, i = 0; *tmp && i < num_tokens; tmp++) {
		if (isspace(*tmp))
			continue;
		next = strpbrk(tmp, ",:");
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
				goto err;
			}
			i++;
			if (i != num_tokens) {
				error = EIO;
				goto err;
			}
		}
	}

	if (sepol_policydb_get_level_by_name(p->sh, p->p, tokens[0], &sens)) {
		error = errno;
		goto err;
	}
	lvl->sens = tokens[0];
	tokens[0] = NULL;

	for (i = 1; i < num_tokens; i++) {
		next = strchr(tokens[i], '.');
		if (next) {
			*next = '\0';
			next++;

			/* get end points of cat range */
			if (sepol_policydb_get_cat_by_name(p->sh, p->p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (sepol_policydb_get_cat_by_name(p->sh, p->p, next, &cat2)) {
				error = errno;
				goto err;
			}

			/* get end point values*/
			if (sepol_cat_datum_get_value(p->sh, p->p, cat1, &val1)) {
				error = errno;
				goto err;
			}
			if (sepol_cat_datum_get_value(p->sh, p->p, cat2, &val2)) {
				error = errno;
				goto err;
			}
			if (val1 >= val2) {
				error = EINVAL;
				goto err;
			}
			if (apol_mls_level_append_cats(p, lvl, tokens[i])) {
				error = errno;
				goto err;
			}
			if (sepol_policydb_get_cat_iter(p->sh, p->p, &iter)) {
				error = errno;
				goto err;
			}
			for (; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
					error = errno;
					goto err;
				}
				if (sepol_cat_datum_get_isalias(p->sh, p->p, tmp_cat, &tmp_isalias)) {
					error = errno;
					goto err;
				}
				if (tmp_isalias)
					continue;
				if (sepol_cat_datum_get_value(p->sh, p->p, tmp_cat, &tmp_val)) {
					error = errno;
					goto err;
				}
				if (tmp_val > val1 && tmp_val < val2) {
					if (sepol_cat_datum_get_name(p->sh, p->p, tmp_cat, &tmp)) {
						error = errno;
						goto err;
					}
					if (apol_mls_level_append_cats(p, lvl, tmp)) {
						error = errno;
						goto err;
					}
				}
			}
			if (apol_mls_level_append_cats(p, lvl, next)) {
				error = errno;
				goto err;
			}			 
		} else {
			if (sepol_policydb_get_cat_by_name(p->sh, p->p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (apol_mls_level_append_cats(p, lvl, tokens[i])) {
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

	sepol_iterator_destroy(&iter);
	return lvl;

err:
	apol_mls_level_destroy(&lvl);
	if (tokens) {
		for (i = 0; i < num_tokens; i++)
			free(tokens[i]);
		free(tokens);
	}
	sepol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

apol_mls_level_t *apol_mls_level_create_from_sepol_mls_level(apol_policy_t *p, sepol_mls_level_t *sepol_level)
{
	apol_mls_level_t *lvl = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_cat_datum_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!p || !sepol_level) {
		errno = EINVAL;
		return NULL;
	}

	if ((lvl = apol_mls_level_create()) == NULL)
		return NULL;

	if (sepol_mls_level_get_sens_name(p->sh, p->p, sepol_level, &tmp)) {
		error = errno;
		goto err;
	}
	if ((lvl->sens = strdup(tmp)) == NULL) {
		error = errno;
		goto err;
	}

	if (sepol_mls_level_get_cat_iter(p->sh, p->p, sepol_level, &iter)) {
		error = errno;
		goto err;
	}

	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
			error = errno;
			goto err;
		}
		if (sepol_cat_datum_get_name(p->sh, p->p, tmp_cat, &tmp)) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(p, lvl, tmp)) {
			error = errno;
			goto err;
		}
	}

	sepol_iterator_destroy(&iter);
	return lvl;

err:
	apol_mls_level_destroy(&lvl);
	sepol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

apol_mls_level_t *apol_mls_level_create_from_sepol_level_datum(apol_policy_t *p, sepol_level_datum_t *sepol_level)
{
	apol_mls_level_t *lvl = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_cat_datum_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!p || !sepol_level) {
		errno = EINVAL;
		return NULL;
	}

	if ((lvl = apol_mls_level_create()) == NULL)
		return NULL;

	if (sepol_level_datum_get_name(p->sh, p->p, sepol_level, &tmp)) {
		error = errno;
		goto err;
	}
	if ((lvl->sens = strdup(tmp)) == NULL) {
		error = errno;
		goto err;
	}

	if (sepol_level_datum_get_cat_iter(p->sh, p->p, sepol_level, &iter)) {
		error = errno;
		goto err;
	}

	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
			error = errno;
			goto err;
		}
		if (sepol_cat_datum_get_name(p->sh, p->p, tmp_cat, &tmp)) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(p, lvl, tmp)) {
			error = errno;
			goto err;
		}
	}
	sepol_iterator_destroy(&iter);
	return lvl;

err:
	apol_mls_level_destroy(&lvl);
	sepol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

void apol_mls_level_destroy(apol_mls_level_t **level)
{
	if (!level || !(*level))
		return;

	free((*level)->sens);
	apol_vector_destroy(&(*level)->cats, free);
	free(*level);
	*level = NULL;
}

int apol_mls_level_set_sens(apol_policy_t *p, apol_mls_level_t *level, const char *sens)
{
	if (!level) {
		ERR(p, "Invalid argument.");
		errno = EINVAL;
		return -1;
	}

	free(level->sens);
	level->sens = NULL;
	if (sens != NULL && (level->sens = apol_strdup(p, sens)) == NULL) {
		return -1;
	}

	return 0;
}

int apol_mls_level_append_cats(apol_policy_t *p, apol_mls_level_t *level, const char *cats)
{
	char *new_cat = NULL;
	if (!level || !cats) {
		ERR(p, "Invalid argument.");
		errno = EINVAL;
		return -1;
	}

	if (level->cats == NULL &&
	    (level->cats = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		return -1;
	}
	if ((new_cat = apol_strdup(p, cats)) == NULL ||
	    apol_vector_append(level->cats, (void *) new_cat) < 0) {
		ERR(p, "Out of memory!");
		free(new_cat);
		return -1;
	}
	return 0;
}

int apol_mls_level_compare(apol_policy_t *p, apol_mls_level_t *l1, apol_mls_level_t *l2)
{
	sepol_level_datum_t *level_datum1, *level_datum2;
	int level1_sens, level2_sens, sens_cmp;
	size_t l1_size, l2_size, i;
	int m_list, ucat = 0;
	apol_vector_t *cat_list_master, *cat_list_subset;
	if (l2 == NULL) {
		return APOL_MLS_EQ;
	}
	if (sepol_policydb_get_level_by_name(p->sh, p->p, l1->sens, &level_datum1) < 0 ||
	    sepol_policydb_get_level_by_name(p->sh, p->p, l2->sens, &level_datum2) < 0) {
		return -1;
	}

	/* compare the level's senstitivity value */
	if (sepol_level_datum_get_value(p->sh, p->p, level_datum1, (uint32_t *) (&level1_sens)) < 0 ||
	    sepol_level_datum_get_value(p->sh, p->p, level_datum2, (uint32_t *) (&level2_sens)) < 0) {
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
		char *cat = (char *) apol_vector_get_element(cat_list_subset, i);
		if (apol_vector_get_index(cat_list_master, cat,
					  apol_mls_cat_vector_compare, p) == -1) {
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

int apol_mls_sens_compare(apol_policy_t *p,
			  const char *sens1,
			  const char *sens2)
{
	sepol_level_datum_t *level_datum1, *level_datum2;
	if (sepol_policydb_get_level_by_name(p->sh, p->p, sens1, &level_datum1) < 0 ||
	    sepol_policydb_get_level_by_name(p->sh, p->p, sens2, &level_datum2) < 0) {
		return -1;
	}
	if (level_datum1 == level_datum2) {
		return 1;
	}
	return 0;
}

int apol_mls_cats_compare(apol_policy_t *p,
			  const char *cat1,
			  const char *cat2)
{
	sepol_cat_datum_t *cat_datum1, *cat_datum2;
	if (sepol_policydb_get_cat_by_name(p->sh, p->p, cat1, &cat_datum1) < 0 ||
	    sepol_policydb_get_cat_by_name(p->sh, p->p, cat2, &cat_datum2) < 0) {
		return -1;
	}
	if (cat_datum1 == cat_datum2) {
		return 1;
	}
	return 0;
}

/********************* range *********************/

apol_mls_range_t *apol_mls_range_create(void)
{
	return calloc(1, sizeof(apol_mls_range_t));
}

apol_mls_range_t *apol_mls_range_create_from_sepol_mls_range(apol_policy_t *p, sepol_mls_range_t *sepol_range)
{
	apol_mls_range_t *apol_range = NULL;
	sepol_mls_level_t *tmp = NULL;
	apol_mls_level_t *tmp_lvl = NULL;
	int error = 0;

	if (!p || !sepol_range) {
		errno = EINVAL;
		return NULL;
	}

	apol_range = calloc(1, sizeof(apol_mls_range_t));
	if (!apol_range) {
		return NULL;
	}

	/* low */
	if (sepol_mls_range_get_low_level(p->sh, p->p, sepol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_sepol_mls_level(p, tmp)) ||
	    apol_mls_range_set_low(p, apol_range, tmp_lvl)) {	      
		error = errno;
		goto err;
	}
	tmp_lvl = NULL;

	/* high */
	if (sepol_mls_range_get_high_level(p->sh, p->p, sepol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_sepol_mls_level(p, tmp)) ||
	    apol_mls_range_set_high(p, apol_range, tmp_lvl)) {
		error = errno;
		goto err;
	}

	return apol_range;

err:
	apol_mls_range_destroy(&apol_range);
	errno = error;
	return NULL;
}

void apol_mls_range_destroy(apol_mls_range_t **range)
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

int apol_mls_range_set_low(apol_policy_t *p, apol_mls_range_t *range, apol_mls_level_t *level)
{
	if (!range) {
		ERR(p, "Invalid argument.");
		errno = EINVAL;
		return -1;
	}

	apol_mls_level_destroy(&(range->low));
	range->low = level;

	return 0;
}

int apol_mls_range_set_high(apol_policy_t *p, apol_mls_range_t *range, apol_mls_level_t *level)
{
	if (!range) {
		ERR(p, "Invalid argument.");
		errno = EINVAL;
		return -1;
	}

	if (range->low != range->high) {
		apol_mls_level_destroy(&(range->high));
	}
	range->high = level;

	return 0;
}

int apol_mls_range_compare(apol_policy_t *p,
			   apol_mls_range_t *target, apol_mls_range_t *search,
			   unsigned int range_compare_type)
{
	int ans1 = -1, ans2 = -1;
	if (search == NULL) {
		return 1;
	}
	/* FIX ME:  intersect does not work */
	if ((range_compare_type & APOL_QUERY_SUB) ||
	    (range_compare_type & APOL_QUERY_INTERSECT)) {
		ans1 = apol_mls_range_contain_subrange(p, target, search);
		if (ans1 < 0) {
			return -1;
		}
	}
	if ((range_compare_type & APOL_QUERY_SUPER) ||
	    (range_compare_type & APOL_QUERY_INTERSECT)) {
		ans2 = apol_mls_range_contain_subrange(p, search, target);
		if (ans2 < 0) {
			return -1;
		}
	}
	/* EXACT has to come first because its bits are both SUB and SUPER */
	if ((range_compare_type & APOL_QUERY_EXACT) == APOL_QUERY_EXACT) {
		return (ans1 && ans2);
	}
	else if (range_compare_type & APOL_QUERY_SUB) {
		return ans1;
	}
	else if (range_compare_type & APOL_QUERY_SUPER) {
		return ans2;
	}
	else if (range_compare_type & APOL_QUERY_INTERSECT) {
		return (ans1 || ans2);
	}
	ERR(p, "Invalid range compare type argument.");
	return -1;
}

static int apol_mls_range_does_include_level(apol_policy_t *p,
					     apol_mls_range_t *range,
					     apol_mls_level_t *level)
{
	int high_cmp = -1, low_cmp = -1;

	if (p == NULL || apol_mls_range_validate(p, range) != 1) {
		ERR(p, "Invalid argument.");
		return -1;
	}

	if (range->low != range->high) {
		low_cmp = apol_mls_level_compare(p, range->low, level);
		if (low_cmp < 0) {
			return -1;
		}
	}

	high_cmp = apol_mls_level_compare(p, range->high, level);
	if (high_cmp < 0) {
		return -1;
	}

	if (high_cmp == APOL_MLS_EQ || high_cmp == APOL_MLS_DOM) {
		if ((low_cmp == APOL_MLS_EQ || low_cmp == APOL_MLS_DOMBY) && range->low != range->high) {
			return 1;
		}
		else if (range->low == range->high) {
			return apol_mls_sens_compare(p, range->low->sens, level->sens);
		}
	}

	return 0;
}

int apol_mls_range_contain_subrange(apol_policy_t *p,
				    apol_mls_range_t *range,
				    apol_mls_range_t *subrange)
{
	if (p == NULL || apol_mls_range_validate(p, subrange) != 1) {
		ERR(p, "Invalid argument.");
		return -1;
	}
	/* parent range validity will be checked via
	 * apol_mls_range_include_level() */

	if (apol_mls_range_does_include_level(p, range, subrange->low) &&
	    apol_mls_range_does_include_level(p, range, subrange->high)) {
		return 1;
	}
	return 0;
}

int apol_mls_range_validate(apol_policy_t *p,
			    apol_mls_range_t *range)
{
	int retv;

	if (p == NULL || range == NULL) {
		ERR(p, "Invalid argument.");
		return -1;
	}

	if ((retv = apol_mls_level_validate(p, range->low)) != 1) {
		return retv;
	}

	if (range->high != range->low &&
	    (retv = apol_mls_level_validate(p, range->high)) != 1) {
		return retv;
	}

	retv = apol_mls_level_compare(p, range->low, range->high);
	if (retv < 0) {
		return -1;
	}
	else if (retv != APOL_MLS_EQ && retv != APOL_MLS_DOMBY) {
		return 0;
	}

	return 1;
}

/******************** level queries ********************/

int apol_get_level_by_query(apol_policy_t *p,
			    apol_level_query_t *l,
			    apol_vector_t **v)
{
	sepol_iterator_t *iter, *cat_iter = NULL;
	int retval = -1, append_level;
	*v = NULL;
	if (sepol_policydb_get_level_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_level_datum_t *level;
		unsigned char isalias;
		if (sepol_iterator_get_item(iter, (void **) &level) < 0 ||
		    sepol_level_datum_get_isalias(p->sh, p->p, level, &isalias) < 0) {
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
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_level_datum_get_cat_iter(p->sh, p->p, level, &cat_iter) < 0) {
				goto cleanup;
			}
			append_level = 0;
			for ( ; !sepol_iterator_end(cat_iter); sepol_iterator_next(cat_iter)) {
				sepol_cat_datum_t *cat;
				if (sepol_iterator_get_item(cat_iter, (void **) &cat) < 0) {
					goto cleanup;
				}
				compval = apol_compare_cat(p,
							   cat, l->cat_name,
							   l->flags, &(l->cat_regex));
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 1) {
					append_level = 1;
					break;
				}
			}
			sepol_iterator_destroy(&cat_iter);
		}
		if (append_level && apol_vector_append(*v, level)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	sepol_iterator_destroy(&cat_iter);
	return retval;
}

apol_level_query_t *apol_level_query_create(void)
{
	return calloc(1, sizeof(apol_level_query_t));
}

void apol_level_query_destroy(apol_level_query_t **l)
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

int apol_level_query_set_sens(apol_policy_t *p, apol_level_query_t *l, const char *name)
{
	return apol_query_set(p, &l->sens_name, &l->sens_regex, name);
}

int apol_level_query_set_cat(apol_policy_t *p, apol_level_query_t *l, const char *name)
{
	return apol_query_set(p, &l->cat_name, &l->cat_regex, name);
}

int apol_level_query_set_regex(apol_policy_t *p, apol_level_query_t *l, int is_regex)
{
	return apol_query_set_regex(p, &l->flags, is_regex);
}

/******************** category queries ********************/

int apol_get_cat_by_query(apol_policy_t *p,
			  apol_cat_query_t *c,
			  apol_vector_t **v)
{
	sepol_iterator_t *iter;
	int retval = -1;
	*v = NULL;
	if (sepol_policydb_get_cat_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_cat_datum_t *cat;
		unsigned char isalias;
		if (sepol_iterator_get_item(iter, (void **) &cat) < 0 ||
		    sepol_cat_datum_get_isalias(p->sh, p->p, cat, &isalias) < 0) {
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
			}
			else if (compval == 0) {
				continue;
			}
		}
		if (apol_vector_append(*v, cat)) {
			ERR(p, "Out of memory!");
			goto cleanup;
		}
	}

	retval = 0;
 cleanup:
	if (retval != 0) {
		apol_vector_destroy(v, NULL);
	}
	sepol_iterator_destroy(&iter);
	return retval;
}

apol_cat_query_t *apol_cat_query_create(void)
{
	return calloc(1, sizeof(apol_cat_query_t));
}

void apol_cat_query_destroy(apol_cat_query_t **c)
{
	if (*c != NULL) {
		free((*c)->cat_name);
		apol_regex_destroy(&(*c)->regex);
		free(*c);
		*c = NULL;
	}
}

int apol_cat_query_set_cat(apol_policy_t *p, apol_cat_query_t *c, const char *name)
{
	return apol_query_set(p, &c->cat_name, &c->regex, name);
}

int apol_cat_query_set_regex(apol_policy_t *p, apol_cat_query_t *c, int is_regex)
{
	return apol_query_set_regex(p, &c->flags, is_regex);
}
