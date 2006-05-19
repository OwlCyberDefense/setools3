 /**
 *  @file avrule_query.c
 *  Implementation for the public interface for searching and iterating over avrules.
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

#include "iterator_internal.h"
#include <qpol/iterator.h>
#include <qpol/policy.h>
#include <sepol/handle.h>
#include <stdlib.h>
#include "debug.h"

int qpol_get_avrule_iter(sepol_handle_t *handle, qpol_policy_t *policy, uint32_t rule_type_mask, qpol_iterator_t **iter)
{
	policydb_t *db;
	avtab_state_t *state;

	if (iter) {
		*iter = NULL;
	}
	if (handle == NULL || policy == NULL || iter == NULL) {
	        errno = EINVAL;
		return -1;
	}
	db = &policy->p;

	state = calloc(1, sizeof(avtab_state_t));
	if (state == NULL) {
		ERR(handle, "memory error");
		errno = ENOMEM;
		return STATUS_ERR;
	}
	state->rule_type_mask = rule_type_mask;
	state->node = db->te_avtab.htable[0];

	if (qpol_iterator_create(handle, db, state, avtab_state_get_cur, avtab_state_next, avtab_state_end, avtab_state_size, free, iter)) {
		free(state);
		return STATUS_ERR;
	}
	if (state->node == NULL) {
		avtab_state_next(*iter);
	}
	return STATUS_SUCCESS;
}
