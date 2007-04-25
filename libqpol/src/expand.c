/**
 * @file
 *
 * Provides a way for setools to expand policy.
 *
 * @author Jeremy A. Mowery jmowery@tresys.com
 * @author Jason Tang  jtang@tresys.com
 *
 * Copyright (C) 2006-2007 Tresys Technology, LLC
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

#include <sepol/policydb/expand.h>
#include <sepol/policydb.h>
#include <stdlib.h>
#include "qpol_internal.h"

static int type_attr_map(hashtab_key_t key __attribute__ ((unused)), hashtab_datum_t datum, void *ptr)
{
	type_datum_t *type = NULL, *orig_type;
	policydb_t *db = (policydb_t *) ptr;
	ebitmap_node_t *node = NULL;
	uint32_t bit = 0;

	type = (type_datum_t *) datum;
	/* if this is an attribute go through its list
	 * of types and put in reverse mappings */
	if (type->flavor == TYPE_ATTRIB) {
		ebitmap_for_each_bit(&type->types, node, bit) {
			if (ebitmap_node_get_bit(node, bit)) {
				orig_type = db->type_val_to_struct[bit];
				if (ebitmap_set_bit(&orig_type->types, type->s.value - 1, 1)) {
					return -1;
				}
			}
		}
	}
	return 0;
}

int qpol_expand_module(qpol_policy_t * base)
{
	unsigned int i;
	uint32_t *typemap = NULL, *boolmap = NULL;
	policydb_t *db;
	int rt;

	INFO(base, "%s", "Expanding policy. (Step 3 of 5)");
	if (base == NULL) {
		ERR(base, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	db = &base->p->p;

	/* activate the global branch before expansion */
	db->global->branch_list->enabled = 1;
	db->global->enabled = db->global->branch_list;

	/* expand out the types to include all the attributes */
	if (hashtab_map(db->p_types.table, type_attr_map, (db))) {
		ERR(base, "%s", "Error expanding attributes for types.");
		goto err;
	}

	/* Build the typemap such that we can expand into the same policy */
	typemap = (uint32_t *) calloc(db->p_types.nprim, sizeof(uint32_t));
	if (typemap == NULL) {
		ERR(base, "%s", strerror(errno));
		goto err;
	}
	for (i = 0; i < db->p_types.nprim; i++) {
		typemap[i] = i + 1;
	}
#ifdef HAVE_SEPOL_BOOLMAP
	boolmap = (uint32_t *) calloc(db->p_bools.nprim, sizeof(uint32_t));
	if (boolmap == NULL) {
		ERR(base, "%s", strerror(errno));
		goto err;
	}
	for (i = 0; i < db->p_bools.nprim; i++) {
		boolmap[i] = i + 1;
	}
	rt = expand_module_avrules(base->sh, db, db, typemap, boolmap, 0, 1);
#else
	rt = expand_module_avrules(base->sh, db, db, typemap, 0, 1);
#endif
	if (rt < 0) {
		goto err;
	}
	rt = 0;

      exit:
	free(typemap);
	free(boolmap);
	return rt;
      err:
	rt = -1;
	errno = EIO;
	goto exit;
}
