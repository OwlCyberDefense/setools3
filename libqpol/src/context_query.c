/**
*  @file context_query.c
*  Defines the public interface for accessing contexts.
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

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>
#include <qpol/user_query.h>
#include <qpol/role_query.h>
#include <qpol/type_query.h>
#include <qpol/mls_query.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/context.h>
#include "debug.h"

int qpol_context_get_user(qpol_handle_t *handle, qpol_policy_t *policy, qpol_context_t *context, qpol_user_t **user)
{
	policydb_t *db = NULL;
	context_struct_t *internal_context = NULL;

	if (user != NULL)
		*user = NULL;

	if (handle == NULL || policy == NULL || context == NULL || user == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_context = (context_struct_t*)context;
	db = (policydb_t*)&policy->p;

	*user = (qpol_user_t*)db->user_val_to_struct[internal_context->user - 1];

	return STATUS_SUCCESS;
}

int qpol_context_get_role(qpol_handle_t *handle, qpol_policy_t *policy, qpol_context_t *context, qpol_role_t **role)
{
	policydb_t *db = NULL;
	context_struct_t *internal_context = NULL;

	if (role != NULL)
		*role = NULL;

	if (handle == NULL || policy == NULL || context == NULL || role == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_context = (context_struct_t*)context;
	db = (policydb_t*)&policy->p;

	*role = (qpol_role_t*)db->role_val_to_struct[internal_context->role - 1];

	return STATUS_SUCCESS;
}

int qpol_context_get_type(qpol_handle_t *handle, qpol_policy_t *policy, qpol_context_t *context, qpol_type_t **type)
{
	policydb_t *db = NULL;
	context_struct_t *internal_context = NULL;

	if (type != NULL)
		*type = NULL;

	if (handle == NULL || policy == NULL || context == NULL || type == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_context = (context_struct_t*)context;
	db = (policydb_t*)&policy->p;

	*type = (qpol_type_t*)db->type_val_to_struct[internal_context->type - 1];

	return STATUS_SUCCESS;
}

int qpol_context_get_range(qpol_handle_t *handle, qpol_policy_t *policy, qpol_context_t *context, qpol_mls_range_t **range)
{
	context_struct_t *internal_context = NULL;

	if (range != NULL)
		*range = NULL;

	if (handle == NULL || policy == NULL || context == NULL || range == NULL) {
		ERR(handle, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_context = (context_struct_t*)context;

	*range = (qpol_mls_range_t*)&internal_context->range;

	return STATUS_SUCCESS;
}
 
