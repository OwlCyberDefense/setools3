/**
*  @file
*  Defines the public interface for searching and iterating over initial SIDs.
*
*  @author Kevin Carr kcarr@tresys.com
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

#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <qpol/context_query.h>
#include <qpol/isid_query.h>
#include <sepol/policydb/policydb.h>
#include "qpol_internal.h"
#include "iterator_internal.h"

int qpol_policy_get_isid_by_name(const qpol_policy_t * policy, const char *name, const qpol_isid_t ** ocon)
{
	ocontext_t *tmp = NULL;
	policydb_t *db = NULL;

	if (ocon != NULL)
		*ocon = NULL;

	if (policy == NULL || name == NULL || ocon == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;
	for (tmp = db->ocontexts[OCON_ISID]; tmp; tmp = tmp->next) {
		if (!strcmp(name, tmp->u.name))
			break;
	}

	*ocon = (qpol_isid_t *) tmp;

	if (*ocon == NULL) {
		ERR(policy, "could not find initial SID statement for %s", name);
		errno = ENOENT;
		return STATUS_ERR;
	}

	return STATUS_SUCCESS;
}

int qpol_policy_get_isid_iter(const qpol_policy_t * policy, qpol_iterator_t ** iter)
{
	policydb_t *db = NULL;
	ocon_state_t *os = NULL;
	int error = 0;

	if (iter != NULL)
		*iter = NULL;

	if (policy == NULL || iter == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p->p;

	os = calloc(1, sizeof(ocon_state_t));
	if (os == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return STATUS_ERR;
	}

	os->head = os->cur = db->ocontexts[OCON_ISID];

	if (qpol_iterator_create(policy, (void *)os, ocon_state_get_cur,
				 ocon_state_next, ocon_state_end, ocon_state_size, free, iter)) {
		free(os);
		return STATUS_ERR;
	}
	return STATUS_SUCCESS;
}

int qpol_isid_get_name(const qpol_policy_t * policy, const qpol_isid_t * ocon, const char **name)
{
	ocontext_t *internal_ocon = NULL;

	if (name != NULL)
		*name = NULL;

	if (policy == NULL || ocon == NULL || name == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*name = internal_ocon->u.name;

	return STATUS_SUCCESS;
}

int qpol_isid_get_context(const qpol_policy_t * policy, const qpol_isid_t * ocon, const qpol_context_t ** context)
{
	ocontext_t *internal_ocon = NULL;

	if (context != NULL)
		*context = NULL;

	if (policy == NULL || ocon == NULL || context == NULL) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return STATUS_ERR;
	}

	internal_ocon = (ocontext_t *) ocon;
	*context = (qpol_context_t *) & (internal_ocon->context[0]);

	return STATUS_SUCCESS;
}
