/**
 *  @file policy_extend.c
 *  Implementation of the interface for loading and using an extended
 *  policy image. 
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

#include <qpol/policy_extend.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/flask.h>
#include <qpol/policy.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include "debug.h"

/**
 *  Builds data for the attributes and inserts them into the policydb. 
 *  This function modifies the policydb. Names created for attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param handle Error handler for the policy.
 *  @param policy The policy from which to read the attribute map and 
 *  create the type data for the attributes. This policy will be altered
 *  by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent 
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_build_attrs_from_map(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	size_t i;
	uint32_t bit = 0, count = 0;
	ebitmap_node_t *node = NULL;
	type_datum_t *tmp_type = NULL, *orig_type;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv;

	if (handle == NULL || policy == NULL) {
		errno = EINVAL;
		return -1;
	}

	db = &policy->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		count = 0;
		ebitmap_for_each_bit(&db->attr_type_map[i], node, bit) {
			if (ebitmap_node_get_bit(node, bit))
				count++;
		}
		if (count == 0) {
			continue;
		}
		/* first create a new type_datum_t for the attribute,
		   with the attribute's type_list consisting of types
		   with this attribute */
		if (db->type_val_to_struct[i] != NULL) {
			continue; /* datum already exists? */
		}
		snprintf(buff, 9, "@ttr%04d", i+1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if(!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = tmp_type->isattr = 1;
		tmp_type->value = i+1;
		if (ebitmap_cpy(&tmp_type->types, &db->attr_type_map[i])) {
			error = ENOMEM;
			goto err;
		}

		/* now go through each of the member types, and set
		   their type_list bit to point back */
		ebitmap_for_each_bit(&tmp_type->types, node, bit) {
			if (ebitmap_node_get_bit(node, bit)) {
				orig_type = db->type_val_to_struct[bit];
				if (ebitmap_set_bit(&orig_type->types, tmp_type->value - 1, 1)) {
					error = ENOMEM;
					goto err;
				}
			}
		}

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t)tmp_name, (hashtab_datum_t)tmp_type);
		if (retv) {
			if (retv == HASHTAB_OVERFLOW)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

err:
	free(tmp_name);
	type_datum_destroy(tmp_type);
	free(tmp_type);
	errno = error;
	return STATUS_ERR;
};

/**
 *  Builds data for empty attributes and inserts them into the policydb.
 *  This function modifies the policydb. Names created for the attributes
 *  are of the form @ttr<value> where value is the value of the attribute
 *  as a four digit number (prepended with 0's as needed).
 *  @param handle Error handler for the policy.
 *  @param policy The policy to which to add type data for attributes.
 *  This policy will be altered by this function.
 *  @return Returns 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent
 *  especially in the case where the hashtab functions return the error.
 */
static int qpol_policy_fill_attr_holes(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	char *tmp_name = NULL, buff[10];
	int error = 0, retv = 0;
	ebitmap_t tmp_bmap = {NULL,0};
	type_datum_t *tmp_type = NULL;
	size_t i;

	if (handle == NULL || policy == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	memset(&buff, 0, 10 * sizeof(char));

	for (i = 0; i < db->p_types.nprim; i++) {
		if (db->type_val_to_struct[i])
			continue;
		snprintf(buff, 9, "@ttr%04d", i+1);
		tmp_name = strdup(buff);
		if (!tmp_name) {
			error = errno;
			goto err;
		}
		tmp_type = calloc(1, sizeof(type_datum_t));
		if (!tmp_type) {
			error = errno;
			goto err;
		}
		tmp_type->primary = tmp_type->isattr = 1;
		tmp_type->value = i+1;
		tmp_type->types = tmp_bmap;

		retv = hashtab_insert(db->p_types.table, (hashtab_key_t)tmp_name, (hashtab_datum_t)tmp_type);
		if (retv) {
			if (retv == HASHTAB_OVERFLOW)
				error = db->p_types.table ? ENOMEM : EINVAL;
			else
				error = EEXIST;
			goto err;
		}
		db->p_type_val_to_name[i] = tmp_name;
		db->type_val_to_struct[i] = tmp_type;

		/* memory now owned by symtab do not free */
		tmp_name = NULL;
		tmp_type = NULL;
	}

	return STATUS_SUCCESS;

err:
	free(tmp_type);
	free(tmp_name);
	errno = error;
	return STATUS_ERR;
}

static char *sidnames[] = 
{
"undefined",
"kernel", 
"security",
"unlabeled",
"fs",
"file",
"file_labels",
"init",
"any_socket",
"port",
"netif",
"netmsg",
"node",
"igmp_packet",
"icmp_socket",
"tcp_socket",
"sysctl_modprobe",
"sysctl",
"sysctl_fs",
"sysctl_kernel",
"sysctl_net",
"sysctl_net_unix",
"sysctl_vm",
"sysctl_dev",
"kmod",
"policy",
"scmp_packet",
"devnull"
};

/**
 *  Uses names from flask to fill in the isid names which are not normally 
 *  saved. This function modified the policydb.
 *  @param handle Error handler for the policy.
 *  @param policy Policy to which to add sid names.
 *  This policy will be altered by this function.
 *  @return 0 on success and < 0 on failure; if the call fails,
 *  errno will be set. On failure, the policy state may be inconsistent.
 */
static int qpol_policy_add_isid_names(qpol_handle_t *handle, qpol_policy_t *policy)
{
	policydb_t *db = NULL;
	ocontext_t *sid = NULL;
	uint32_t val = 0;
	int error = 0;

	if (handle == NULL || policy == NULL) {
		errno = EINVAL;
		return STATUS_ERR;
	}

	db = &policy->p;

	for (sid = db->ocontexts[OCON_ISID]; sid; sid = sid->next) {
		val = (uint32_t)sid->sid[0];
		if (val > SECINITSID_NUM)
			val = 0;

		if (!sid->u.name) {
			sid->u.name = strdup(sidnames[val]);
			if (!sid->u.name) {
				error = errno;
				ERR(handle, "%s","memory error");
				errno = error;
				return STATUS_ERR;
			}
		}
	}

	return 0;
}

int qpol_policy_extend(qpol_handle_t *handle, qpol_policy_t *policy, qpol_extended_image_t *ext)
{
	int retv, error;
	policydb_t *db = NULL;

	if (handle == NULL || policy == NULL) {
		errno = EINVAL;
		return -1;
	}

	db = &policy->p;

	if (ext == NULL) {
		retv = qpol_policy_build_attrs_from_map(handle, policy);
		if (retv) {
			error = errno;
			goto err;
		}
		if (db->policy_type == POLICY_KERN) {
			retv = qpol_policy_fill_attr_holes(handle, policy);
			if (retv) {
				error = errno;
				goto err;
			}
		}
		retv = qpol_policy_add_isid_names(handle, policy);
		if (retv) {
			error = errno;
			goto err;
		}

		return STATUS_SUCCESS;
	} else {
		/* TODO Marked as an error for now until the extended format is done. */
		errno = ENOTSUP;
		return STATUS_ERR;
	}

err:
	//TODO cleanup code here

	errno = error;
	return STATUS_ERR;
}
