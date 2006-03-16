/**
 *  @file context-query.c
 *  Implementation for querying aspects of a context.
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "component-query.h"
#include "context-query.h"
#include "mls-query.h"

/********************* miscellaneous routines *********************/

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

apol_context_t *apol_context_create(void)
{
	return calloc(1, sizeof(apol_context_t));
}

void apol_context_destroy(apol_context_t **context)
{
	if (*context != NULL) {
		free((*context)->user);
		free((*context)->role);
		free((*context)->type);
		apol_mls_range_destroy(&((*context)->range));
		*context = NULL;
	}
}

int apol_context_set_user(apol_policy_t *p,
			  apol_context_t *context,
			  const char *user)
{
	free(context->user);
	context->user = NULL;
	if (user != NULL && (context->user = apol_strdup(p, user)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_context_set_role(apol_policy_t *p,
			  apol_context_t *context,
			  const char *role)
{
	free(context->role);
	context->role = NULL;
	if (role != NULL && (context->role = apol_strdup(p, role)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_context_set_type(apol_policy_t *p,
			  apol_context_t *context,
			  const char *type)
{
	free(context->type);
	context->type = NULL;
	if (type != NULL && (context->type = apol_strdup(p, type)) == NULL) {
		return -1;
	}
	return 0;
}

int apol_context_set_range(apol_policy_t *p,
			   apol_context_t *context,
			   apol_mls_range_t *range)
{
	apol_mls_range_destroy(&(context->range));
	context->range = range;
	return 0;
}

int apol_context_validate(apol_policy_t *p,
			  apol_context_t *context)
{
	if (context == NULL ||
	    context->user == NULL ||
	    context->role == NULL ||
	    context->type == NULL ||
	    (apol_policy_is_mls(p) && context->range == NULL)) {
		ERR(p, "Invalid argument.");
		errno = EINVAL;
		return -1;
	}
	return apol_context_validate_partial(p, context);
}

int apol_context_validate_partial(apol_policy_t *p,
				  apol_context_t *context)
{
	apol_user_query_t *user_query = NULL;
	apol_role_query_t *role_query = NULL;
	apol_vector_t *user_v = NULL, *role_v = NULL;
	sepol_user_datum_t *user;
	sepol_type_datum_t *type;
	sepol_mls_range_t *user_range;
	apol_mls_range_t *user_apol_range = NULL;
	int retval = -1, retval2;

	if (context == NULL) {
		return 1;
	}
	if (context->user != NULL) {
		if ((user_query = apol_user_query_create()) == NULL) {
			ERR(p, "Out of memory!");
		}
		if (apol_user_query_set_user(p, user_query, context->user) < 0 ||
		    (context->role != NULL && apol_user_query_set_role(p, user_query, context->role) < 0) ||
		    apol_get_user_by_query(p, user_query, &user_v) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_size(user_v) == 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (context->role != NULL) {
		if ((role_query = apol_role_query_create()) == NULL) {
			ERR(p, "Out of memory!");
		}
		if (apol_role_query_set_role(p, role_query, context->role) < 0 ||
		    (context->type != NULL && apol_role_query_set_type(p, role_query, context->type) < 0) ||
		    apol_get_role_by_query(p, role_query, &role_v) < 0) {
			goto cleanup;
		}
		if (apol_vector_get_size(role_v) == 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (context->type != NULL) {
		if (sepol_policydb_get_type_by_name(p->sh, p->p, context->type, &type) < 0) {
			retval = 0;
			goto cleanup;
		}
	}
	if (apol_policy_is_mls(p) && context->range != NULL) {
		retval2 = apol_mls_range_validate(p, context->range);
		if (retval2 != 1) {
			retval = retval2;
			goto cleanup;
		}
		/* next check that the user has access to this context */
		if (context->user != NULL) {
			if (sepol_policydb_get_user_by_name(p->sh, p->p, context->user, &user) < 0 ||
			    sepol_user_datum_get_range(p->sh, p->p, user, &user_range) < 0) {
				goto cleanup;
			}
			user_apol_range = apol_mls_range_create_from_sepol_mls_range(p, user_range);
			if (user_apol_range == NULL) {
				ERR(p, "Out of memory!");
				goto cleanup;
			}
			retval2 = apol_mls_range_compare(p, user_apol_range, context->range, APOL_QUERY_SUB);
			if (retval2 != 1) {
				retval = retval2;
				goto cleanup;
			}
		}
	}
	retval = 1;
 cleanup:
	apol_user_query_destroy(&user_query);
	apol_role_query_destroy(&role_query);
	apol_vector_destroy(&user_v, NULL);
	apol_vector_destroy(&role_v, NULL);
	apol_mls_range_destroy(&user_apol_range);
	return retval;
}
