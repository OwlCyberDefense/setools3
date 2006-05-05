/**
 * @file user-query.c
 *
 * Provides a way for setools to make queries about users within a
 * policy.  The caller obtains a query object, fills in its
 * parameters, and then runs the query; it obtains a vector of
 * results.  Searches are conjunctive -- all fields of the search
 * query must match for a datum to be added to the results query.
 *
 * @author Kevin Carr  kcarr@tresys.com
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006 Tresys Technology, LLC
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

#include "component-query.h"

struct apol_user_query {
	char *user_name, *role_name;
	apol_mls_level_t *default_level;
	apol_mls_range_t *range;
	unsigned int flags;
	regex_t *user_regex, *role_regex;
};

/******************** user queries ********************/

int apol_get_user_by_query(apol_policy_t *p,
			   apol_user_query_t *u,
			   apol_vector_t **v)
{
	sepol_iterator_t *iter = NULL, *role_iter = NULL;
	apol_mls_level_t *default_level = NULL;
	apol_mls_range_t *range = NULL;
	int retval = -1, append_user;
	*v = NULL;
	if (sepol_policydb_get_user_iter(p->sh, p->p, &iter) < 0) {
		return -1;
	}
	if ((*v = apol_vector_create()) == NULL) {
		ERR(p, "Out of memory!");
		goto cleanup;
	}
	for ( ; !sepol_iterator_end(iter); sepol_iterator_next(iter)) {
		sepol_user_datum_t *user;
		if (sepol_iterator_get_item(iter, (void **) &user) < 0) {
			goto cleanup;
		}
		append_user = 1;
		if (u != NULL) {
			char *user_name;
			int compval;
			sepol_mls_level_t *mls_default_level;
			sepol_mls_range_t *mls_range;

			sepol_iterator_destroy(&role_iter);
			apol_mls_level_destroy(&default_level);
			apol_mls_range_destroy(&range);

			if (sepol_user_datum_get_name(p->sh, p->p, user, &user_name) < 0) {
				goto cleanup;
			}
			compval = apol_compare(p, user_name, u->user_name,
					       u->flags, &(u->user_regex));
			if (compval < 0) {
				goto cleanup;
			}
			else if (compval == 0) {
				continue;
			}
			if (sepol_user_datum_get_role_iter(p->sh, p->p, user, &role_iter) < 0) {
				goto cleanup;
			}
			if (u->role_name != NULL && u->role_name[0] != '\0') {
				append_user = 0;
				for ( ; !sepol_iterator_end(role_iter); sepol_iterator_next(role_iter)) {
					sepol_role_datum_t *role;
					char *role_name;
					if (sepol_iterator_get_item(role_iter, (void **) &role) < 0 ||
					    sepol_role_datum_get_name(p->sh, p->p, role, &role_name) < 0) {
						goto cleanup;
					}
					compval = apol_compare(p, role_name, u->role_name,
							       u->flags, &(u->role_regex));
					if (compval < 0) {
						goto cleanup;
					}
					else if (compval == 1) {
						append_user = 1;
						break;
					}
				}
				if (!append_user) {
					continue;
				}
			}
			if (apol_policy_is_mls(p)) {
				if (sepol_user_datum_get_dfltlevel(p->sh, p->p, user, &mls_default_level) < 0 ||
				    (default_level = apol_mls_level_create_from_sepol_mls_level(p, mls_default_level)) == NULL) {
					goto cleanup;
				}
				compval = apol_mls_level_compare(p, default_level,
								 u->default_level);
				apol_mls_level_destroy(&default_level);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval != APOL_MLS_EQ) {
					continue;
				}

				if (sepol_user_datum_get_range(p->sh, p->p, user, &mls_range) < 0 ||
				    (range = apol_mls_range_create_from_sepol_mls_range(p, mls_range)) == NULL) {
					goto cleanup;
				}
				compval = apol_mls_range_compare(p,
								 range, u->range,
								 u->flags);
				apol_mls_range_destroy(&range);
				if (compval < 0) {
					goto cleanup;
				}
				else if (compval == 0) {
					continue;
				}
			}
		}
		if (append_user && apol_vector_append(*v, user)) {
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
	sepol_iterator_destroy(&role_iter);
	apol_mls_level_destroy(&default_level);
	apol_mls_range_destroy(&range);
	return retval;
}

apol_user_query_t *apol_user_query_create(void)
{
	return calloc(1, sizeof(apol_user_query_t));
}

void apol_user_query_destroy(apol_user_query_t **u)
{
	if (*u != NULL) {
		free((*u)->user_name);
		free((*u)->role_name);
		apol_mls_level_destroy(&((*u)->default_level));
		apol_mls_range_destroy(&((*u)->range));
		apol_regex_destroy(&(*u)->user_regex);
		apol_regex_destroy(&(*u)->role_regex);
		free(*u);
		*u = NULL;
	}
}

int apol_user_query_set_user(apol_policy_t *p, apol_user_query_t *u, const char *name)
{
	return apol_query_set(p, &u->user_name, &u->user_regex, name);
}

int apol_user_query_set_role(apol_policy_t *p, apol_user_query_t *u, const char *role)
{
	return apol_query_set(p, &u->role_name, &u->role_regex, role);
}

int apol_user_query_set_default_level(apol_policy_t *p __attribute__ ((unused)),
				      apol_user_query_t *u,
				      apol_mls_level_t *level)
{
	u->default_level = level;
	return 0;
}

int apol_user_query_set_range(apol_policy_t *p __attribute__ ((unused)),
			      apol_user_query_t *u,
			      apol_mls_range_t *range,
			      unsigned int range_match)
{
	if (u->range != NULL) {
		apol_mls_range_destroy(&u->range);
	}
	u->range = range;
	u->flags = (u->flags & ~APOL_QUERY_FLAGS) | range_match;
	return 0;
}

int apol_user_query_set_regex(apol_policy_t *p, apol_user_query_t *u, int is_regex)
{
	return apol_query_set_regex(p, &u->flags, is_regex);
}
