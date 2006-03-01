/**
 *  @file mls-query.c
 *  Public Interface for querying MLS components.
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

#include "mls-query.h"
#include "vector.h"

struct apol_sens_query {
	char *sens_name;
	unsigned int flags;
	regex_t *sens_regex;
};

struct apol_cats_query {
	char *cats_name;
	unsigned int flags;
	regex_t *cats_regex;
};


/* level */
apol_mls_level_t *apol_mls_level_create(void)
{
	return calloc(1, sizeof(apol_mls_level_t));
}

apol_mls_level_t *apol_mls_level_create_from_string(sepol_handle_t *h, sepol_policydb_t *p, char *mls_level_string)
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

	if (!h || !p || !mls_level_string) {
		errno = EINVAL;
		return NULL;
	}

	lvl = calloc(1, sizeof(apol_mls_level_t));
	if (!lvl)
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

	if (sepol_policydb_get_level_by_name(h, p, tokens[0], &sens)) {
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
			if (sepol_policydb_get_cat_by_name(h, p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (sepol_policydb_get_cat_by_name(h, p, next, &cat2)) {
				error = errno;
				goto err;
			}

			/* get end point values*/
			if (sepol_cat_datum_get_value(h, p, cat1, &val1)) {
				error = errno;
				goto err;
			}
			if (sepol_cat_datum_get_value(h, p, cat2, &val2)) {
				error = errno;
				goto err;
			}
			if (val1 >= val2) {
				error = EINVAL;
				goto err;
			}
			if (!apol_mls_level_append_cats(lvl, tokens[i])) {
				error = errno;
				goto err;
			}
			if (sepol_policydb_get_cat_iter(h, p, &iter)) {
				error = errno;
				goto err;
			}
			for (; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
				if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
					error = errno;
					goto err;
				}
				if (sepol_cat_datum_get_isalias(h, p, tmp_cat, &tmp_isalias)) {
					error = errno;
					goto err;
				}
				if (tmp_isalias)
					continue;
				if (sepol_cat_datum_get_value(h, p, tmp_cat, &tmp_val)) {
					error = errno;
					goto err;
				}
				if (tmp_val > val1 && tmp_val < val2) {
					if (sepol_cat_datum_get_name(h, p, tmp_cat, &tmp)) {
						error = errno;
						goto err;
					}
					if (apol_mls_level_append_cats(lvl, tmp)) {
						error = errno;
						goto err;
					}
				}
			}
			if (apol_mls_level_append_cats(lvl, next)) {
				error = errno;
				goto err;
			}			 
		} else {
			if (sepol_policydb_get_cat_by_name(h, p, tokens[i], &cat1)) {
				error = errno;
				goto err;
			}
			if (apol_mls_level_append_cats(lvl, tokens[i])) {
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

apol_mls_level_t *apol_mls_level_create_from_sepol_mls_level(sepol_handle_t *h, sepol_policydb_t *p, sepol_mls_level_t *sepol_level)
{
	apol_mls_level_t *lvl = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_cat_datum_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!h || !p || !sepol_level) {
		errno = EINVAL;
		return NULL;
	}

	if (!(lvl = calloc(1, sizeof(apol_mls_level_t))))
		return NULL;

	if (sepol_mls_level_get_sens_name(h, p, sepol_level, &tmp)) {
		error = errno;
		goto err;
	}
	if ((lvl->sens = strdup(tmp)) == NULL) {
		error = errno;
		goto err;
	}

	if (sepol_mls_level_get_cat_iter(h, p, sepol_level, &iter)) {
		error = errno;
		goto err;
	}

	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
			error = errno;
			goto err;
		}
		if (sepol_cat_datum_get_name(h, p, tmp_cat, &tmp)) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(lvl, tmp)) {
			error = errno;
			goto err;
		}
	}

	return lvl;

err:
	apol_mls_level_destroy(&lvl);
	sepol_iterator_destroy(&iter);
	errno = error;
	return NULL;
}

apol_mls_level_t *apol_mls_level_create_from_sepol_level_datum(sepol_handle_t *h, sepol_policydb_t *p, sepol_level_datum_t *sepol_level)
{
	apol_mls_level_t *lvl = NULL;
	sepol_iterator_t *iter = NULL;
	sepol_cat_datum_t *tmp_cat = NULL;
	char *tmp = NULL;
	int error = 0;

	if (!h || !p || !sepol_level) {
		errno = EINVAL;
		return NULL;
	}

	if (sepol_level_datum_get_name(h, p, sepol_level, &tmp)) {
		error = errno;
		goto err;
	}
	if ((lvl->sens = strdup(tmp)) == NULL) {
		error = errno;
		goto err;
	}

	if (sepol_level_datum_get_cat_iter(h, p, sepol_level, &iter)) {
		error = errno;
		goto err;
	}

	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		if (sepol_iterator_get_item(iter, (void**)&tmp_cat)) {
			error = errno;
			goto err;
		}
		if (sepol_cat_datum_get_name(h, p, tmp_cat, &tmp)) {
			error = errno;
			goto err;
		}
		if (apol_mls_level_append_cats(lvl, tmp)) {
			error = errno;
			goto err;
		}
	}

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

int apol_mls_level_set_sens(apol_mls_level_t *level, char *sens)
{
	if (!level) {
		errno = EINVAL;
		return -1;
	}

	free(level->sens);
	level->sens = NULL;
	if (sens != NULL && (level->sens = strdup(sens)) == NULL) {
		return -1;
	}

	return 0;
}

int apol_mls_level_append_cats(apol_mls_level_t *level, char *cats)
{
	char *new_cat = NULL;
	if (!level || !cats) {
		errno = EINVAL;
		return -1;
	}

	if (level->cats == NULL &&
	    (level->cats = apol_vector_create()) == NULL) {
		return -1;
	}
	if ((new_cat = strdup(cats)) == NULL ||
	    apol_vector_append(level->cats, (void *) new_cat) < 0) {
		free(new_cat);
		return -1;
	}
	return 0;
}

int apol_mls_compare_level(sepol_handle_t *h, sepol_policydb_t *p,
			   apol_mls_level_t *target, apol_mls_level_t *search)
{
        char *target_name, *search_name;
	if (search == NULL) {
		return 1;
	}
	if (search->sens != NULL) {
		sepol_level_datum_t *search_level;
                target_name = target->sens;
		if (sepol_policydb_get_level_by_name(h, p, search->sens, &search_level) < 0 ||
		    sepol_level_datum_get_name(h, p, search_level, &search_name) < 0) {
			return -1;
		}
		if (strcmp(target_name, search_name) != 0) {
			return 0;
		}
	}
	if (apol_vector_get_size(search->cats) > 0) {
		apol_vector_t *search_cats;
		size_t i, j, num_cats = apol_vector_get_size(search->cats);
		int cat_found;
		char *orig_name, *cat_name;
		
		/* first convert search categories to canonical form */
		if ((search_cats = apol_vector_create_with_capacity(num_cats)) == NULL) {
			return -1;
		}
		for (i = 0; i < num_cats; i++) {
			sepol_cat_datum_t *cat;
			orig_name = (char *) apol_vector_get_element(search->cats, i);
			if (sepol_policydb_get_cat_by_name(h, p, orig_name, &cat) < 0 ||
			    sepol_cat_datum_get_name(h, p, cat, &cat_name) < 0 ||
			    apol_vector_append_unique(search_cats, (void *) cat_name, (apol_vector_comp_func *)strcmp) < 0)
			{
				apol_vector_destroy(&search_cats, NULL);
				return -1;
			}
		}

		/* not the most elegant of solutions; luckily levels
		 * have at most 256 categories */
		for (i = 0; i < apol_vector_get_size(search_cats); i++) {
			cat_found = 0;
			cat_name = (char *) apol_vector_get_element(search_cats, i);
			for (j = 0; j < apol_vector_get_size(target->cats); j++) {
                                target_name = (char *) apol_vector_get_element(target->cats, j);
                                
				if (strcmp(cat_name, target_name) == 0) {
					cat_found = 1;
					break;
				}
			}
			if (!cat_found) {
				apol_vector_destroy(&search_cats, NULL);
				return 0;
			}
		}
		apol_vector_destroy(&search_cats, NULL);
	}
	return 1;
}


/* range */
apol_mls_range_t *apol_mls_range_create(void)
{
	return calloc(1, sizeof(apol_mls_range_t));
}

apol_mls_range_t *apol_mls_range_create_from_sepol_mls_range(sepol_handle_t *h, sepol_policydb_t *p, sepol_mls_range_t *sepol_range)
{
	apol_mls_range_t *apol_range = NULL;
	sepol_mls_level_t *tmp = NULL;
	apol_mls_level_t *tmp_lvl = NULL;
	int error = 0;

	if (!h || !p || !sepol_range) {
		errno = EINVAL;
		return NULL;
	}

	apol_range = calloc(1, sizeof(apol_mls_range_t));
	if (!apol_range) {
		return NULL;
	}

	/* low */
	if (sepol_mls_range_get_low_level(h, p, sepol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_sepol_mls_level(h, p, tmp)) ||
	    apol_mls_range_set_low(apol_range, tmp_lvl)) {	      
		error = errno;
		goto err;
	}
	tmp_lvl = NULL;

	/* high */
	if (sepol_mls_range_get_high_level(h, p, sepol_range, &tmp) ||
	    !(tmp_lvl = apol_mls_level_create_from_sepol_mls_level(h, p, tmp)) ||
	    apol_mls_range_set_high(apol_range, tmp_lvl)) {
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

	apol_mls_level_destroy(&((*range)->low));
	apol_mls_level_destroy(&((*range)->high));

	free(*range);
	*range = NULL;
}

int apol_mls_range_set_low(apol_mls_range_t *range, apol_mls_level_t *level)
{
	if (!range) {
		errno = EINVAL;
		return -1;
	}

	apol_mls_level_destroy(&(range->low));
	range->low = level;

	return 0;
}

int apol_mls_range_set_high(apol_mls_range_t *range, apol_mls_level_t *level)
{
	if (!range) {
		errno = EINVAL;
		return -1;
	}

	apol_mls_level_destroy(&(range->high));
	range->high = level;

	return 0;
}
