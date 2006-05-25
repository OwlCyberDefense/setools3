/**
*  @file netifcon_query.c
*  Defines the public interface for searching and iterating over netifcon statements.
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
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>
#include <qpol/netifcon_query.h>
#include <sepol/policydb/policydb.h>
#include "debug.h"
#include "iterator_internal.h"

int qpol_policy_get_netifcon_by_name(qpol_handle_t *handle, qpol_policy_t *policy, const char *name, qpol_netifcon_t **ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (handle == NULL || policy == NULL || name == NULL || ocon == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;
	for (tmp = db->ocontexts[OCON_NETIF]; tmp; tmp = tmp->next) {
		if (!strcmp(name, tmp->u.name))
			break;
	}

	*ocon = (qpol_netifcon_t *)tmp;

	if (*ocon == NULL) {
		ERR(handle, "cound not find netifcon statement for %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_netifcon_iter(qpol_handle_t *handle, qpol_policy_t *policy, qpol_iterator_t **iter)
{
	policydb_t *db = NULL;
	int error = 0;
	ocon_state_t *os = NULL;

	if (iter != NULL) 
		*iter = NULL;

	if (handle == NULL || policy == NULL || iter == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = (policydb_t*)&policy->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(handle, "memory error");
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_NETIF];

	if (qpol_iterator_create(handle, db, (void*)os, ocon_state_get_cur,
		ocon_state_next, ocon_state_end, ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_netifcon_get_name(qpol_handle_t *handle, qpol_policy_t *policy, qpol_netifcon_t *ocon, char **name)
{
	ocontext_t *internal_ocon = NULL;

	if (name != NULL)
		*name = NULL;

	if (handle == NULL || policy == NULL || ocon == NULL || name == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t*)ocon;
	*name = internal_ocon->u.name;

	return STATUS_SUCCESS;
}

int qpol_netifcon_get_msg_con(qpol_handle_t *handle, qpol_policy_t *policy, qpol_netifcon_t *ocon, qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (handle == NULL || policy == NULL || ocon == NULL || context == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t*)ocon;
	*context = (qpol_context_t*)&(internal_ocon->context[1]);

	return STATUS_SUCCESS;
}

int qpol_netifcon_get_if_con(qpol_handle_t *handle, qpol_policy_t *policy, qpol_netifcon_t *ocon, qpol_context_t **context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (handle == NULL || policy == NULL || ocon == NULL || context == NULL) {
		ERR(handle, strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t*)ocon;
	*context = (qpol_context_t*)&(internal_ocon->context[0]);

	return STATUS_SUCCESS;
}

