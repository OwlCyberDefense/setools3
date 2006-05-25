/**
 * @file expand.c
 * 
 * Provides a way for setools to expand policy.
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

#include <qpol/expand.h>
#include <sepol/policydb/expand.h>
#include <stdlib.h>
#include "debug.h"

#include "debug.h"

int qpol_expand_module(qpol_handle_t *handle, qpol_policy_t *base)
{
	unsigned int i;
	avrule_block_t *curblock;
	uint32_t *typemap;
	int rt;
	policydb_t *db;

	if (handle == NULL || base == NULL) {
		errno = EINVAL;
		return -1;
	}
	db = &((sepol_policydb_t*)base)->p;

	/* activate the global branch before expansion */
	db->global->branch_list->enabled = 1;
	db->global->enabled = db->global->branch_list;

	/* Build the typemap such that we can expand into the same policy */
	typemap = (uint32_t *)calloc(db->p_types.nprim, sizeof(uint32_t));
	if (typemap == NULL) {
		ERR("Error: out of memory\n");
		goto err;
	}
	for (i = 0; i < db->p_types.nprim; i++) {
		typemap[i] = i+1;
	}
	
	for (curblock = db->global; curblock != NULL; curblock = curblock->next) {
		avrule_decl_t *decl = curblock->branch_list;
		avrule_t *cur_avrule;

		/* find the first decl thats enabled */
		while (decl != NULL) {
			if (decl->enabled)
				break;
			decl = decl->next;
		}
		if (decl == NULL) {
			/* nothing was enabled within this block */
			continue;
		}
		for (cur_avrule = decl->avrules; cur_avrule != NULL; cur_avrule = cur_avrule->next) {
/*			if (cur_avrule->specified & AVRULE_NEVERALLOW) //FIXME: Why?
				continue; */
			if (convert_and_expand_rule(handle, db, db, typemap,
						    cur_avrule, &db->te_avtab,
						    NULL, NULL, 0) != 1) {
				goto err;
			}
		}
	}
exit:
	rt = 0;
	free(typemap);
	return rt;
err:
	rt = -1;
	goto exit;
}
