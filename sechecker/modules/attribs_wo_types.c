/**
 *  @file
 *  Implementation of the attributes without types module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "attribs_wo_types.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "attribs_wo_types";

/* The register function registers all of a module's functions
 * with the library. */
int attribs_wo_types_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "attributes with no types";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds attributes in the policy that are not associated with any\n"
		"types.  Attributes without types can cause type fields in rules to expand to\n"
		"empty sets and thus become unreachable.  This makes for misleading policy source\n" "files.\n";
	mod->opt_description =
		"Module requirements:\n" "   attribute names\n" "Module dependencies:\n" "   none\n" "Module options:\n"
		"   none\n";
	mod->severity = SECHK_SEV_LOW;
	/* assign requirements */
	if (apol_vector_append(mod->requirements, sechk_name_value_new(SECHK_REQ_POLICY_CAP, SECHK_REQ_CAP_ATTRIB_NAMES)) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = attribs_wo_types_init;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = attribs_wo_types_run;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = attribs_wo_types_print;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = attribs_wo_types_get_list;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int attribs_wo_types_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int attribs_wo_types_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;
	apol_vector_t *attr_vector = NULL;
	qpol_iterator_t *types = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	int error = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_types_run_fail;
	}
	res->item_type = SECHK_ITEM_ATTRIB;
	if (!(res->items = apol_vector_create(sechk_item_free))) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_types_run_fail;
	}

	apol_attr_get_by_query(policy, NULL, &attr_vector);
	for (i = 0; i < apol_vector_get_size(attr_vector); i++) {
		qpol_type_t *attr;
		const char *attr_name;
		int at_end;

		attr = apol_vector_get_element(attr_vector, i);
		qpol_type_get_name(q, attr, &attr_name);
		qpol_type_get_type_iter(q, attr, &types);
		at_end = qpol_iterator_end(types);
		qpol_iterator_destroy(&types);
		if (!at_end)
			continue;

		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_types_run_fail;
		}
		proof->type = SECHK_ITEM_ATTRIB;
		proof->text = (char *)calloc(strlen("attribute  has no types") + strlen(attr_name) + 1, sizeof(char));
		sprintf(proof->text, "attribute %s has no types", attr_name);
		item = sechk_item_new(NULL);
		if (!item) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_types_run_fail;
		}
		if (!item->proof) {
			if (!(item->proof = apol_vector_create(sechk_proof_free))) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto attribs_wo_types_run_fail;
			}
		}
		item->item = (void *)attr;
		item->test_result = 1;
		if (apol_vector_append(item->proof, (void *)proof) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_types_run_fail;
		}
		if (apol_vector_append(res->items, (void *)item) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_types_run_fail;
		}
	}
	qpol_iterator_destroy(&types);
	apol_vector_destroy(&attr_vector);

	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      attribs_wo_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int attribs_wo_types_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k = 0, l = 0, num_items;
	qpol_type_t *type;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	const char *type_name;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0;	       /* not an error - no output is requested */

	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %zd attributes.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following attributes are not associated with any types.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(q, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (k = 0; k < num_items; k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if (item) {
				type = item->item;
				qpol_type_get_name(q, type, &type_name);
				printf("%s\n", type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof, l);
					if (proof)
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}
	type = NULL;
	type_name = NULL;

	return 0;
}

int attribs_wo_types_get_list(sechk_module_t * mod, apol_policy_t * polciy __attribute__ ((unused)), void *arg)
{
	apol_vector_t **v = arg;

	if (!mod || !arg) {
		ERR(NULL, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(NULL, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}
	if (!mod->result) {
		ERR(NULL, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	v = &mod->result->items;

	return 0;
}
