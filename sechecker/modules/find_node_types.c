/**
 *  @file
 *  Implementation of the node types utility module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author David Windsor dwindsor@tresys.com
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

#include "find_node_types.h"
#include <apol/netcon-query.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "find_node_types";

/* The register function registers all of a module's functions
 * with the library.  You should not need to edit this function
 * unless you are adding additional functions you need other modules
 * to call. See the note at the bottom of this function to do so. */
int find_node_types_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Unknown module");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */

	/* assign the descriptions */
	mod->brief_description = "utility module";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all types in a policy treated as a node type.  A type is\n"
		"considered a node type if it is used in the context of a nodecon statement or\n"
		"the context of the node initial sid.\n";
	mod->opt_description =
		"  Module requirements:\n" "    none\n" "  Module dependencies:\n" "    none\n" "  Module options:\n" "    none\n";
	mod->severity = SECHK_SEV_NONE;

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
	fn_struct->fn = find_node_types_init;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = find_node_types_run;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = find_node_types_print;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = find_node_types_get_list;
	apol_vector_append(mod->functions, (void *)fn_struct);

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file.
 * Add any option processing logic as indicated below. */
int find_node_types_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
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

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data.
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed"	- some negative results found */
int find_node_types_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *buff = NULL;
	size_t i, buff_sz = 0;
	apol_vector_t *nodecon_vector = NULL;
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
		goto find_node_types_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if (!(res->items = apol_vector_create(sechk_item_free))) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto find_node_types_run_fail;
	}

	/* search initial SIDs */
	const qpol_isid_t *isid = NULL;

	buff = NULL;
	qpol_policy_get_isid_by_name(q, "node", &isid);
	if (isid) {
		const qpol_context_t *context;
		apol_context_t *a_context;
		const qpol_type_t *context_type;
		const char *context_type_name;
		char *tmp;

		proof = NULL;
		qpol_isid_get_context(q, isid, &context);
		qpol_context_get_type(q, context, &context_type);
		qpol_type_get_name(q, context_type, &context_type_name);
		a_context = apol_context_create_from_qpol_context(policy, context);

		if (apol_str_append(&buff, &buff_sz, "sid node ") != 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			apol_context_destroy(&a_context);
			goto find_node_types_run_fail;
		}

		tmp = apol_context_render(policy, a_context);
		if (apol_str_append(&buff, &buff_sz, tmp) != 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			apol_context_destroy(&a_context);
			free(tmp);
			goto find_node_types_run_fail;
		}
		apol_context_destroy(&a_context);
		free(tmp);
		tmp = NULL;

		if (!item) {
			item = sechk_item_new(NULL);
			if (!item) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_node_types_run_fail;
			}
			item->test_result = 1;
		}

		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_node_types_run_fail;
		}

		proof->type = SECHK_ITEM_ISID;
		proof->elem = (void*)isid;
		proof->text = buff;

		item->item = (void *)context_type;
		if (!item->proof) {
			if (!(item->proof = apol_vector_create(sechk_proof_free))) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_node_types_run_fail;
			}
		}
		if (apol_vector_append(item->proof, (void *)proof) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_node_types_run_fail;
		}
		if (apol_vector_append(res->items, (void *)item) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_node_types_run_fail;
		}
	}

	if (apol_nodecon_get_by_query(policy, NULL, &nodecon_vector) < 0) {
		error = errno;
		goto find_node_types_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(nodecon_vector); i++) {
		const char *type_name;
		size_t j;
		const qpol_context_t *context;
		const qpol_type_t *context_type;
		qpol_nodecon_t *nodecon = apol_vector_get_element(nodecon_vector, i);
		qpol_nodecon_get_context(q, nodecon, &context);
		qpol_context_get_type(q, context, &context_type);
		qpol_type_get_name(q, context_type, &type_name);

		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_node_types_run_fail;
		}
		proof->type = SECHK_ITEM_NONE;
		proof->text = apol_nodecon_render(policy, nodecon);

		for (j = 0; j < apol_vector_get_size(res->items); j++) {
			sechk_item_t *res_item;
			const qpol_type_t *res_type;
			const char *res_type_name;

			res_item = apol_vector_get_element(res->items, j);
			res_type = res_item->item;
			qpol_type_get_name(q, res_type, &res_type_name);
			if (!strcmp(res_type_name, type_name))
				item = res_item;
		}
		if (!item) {
			item = sechk_item_new(NULL);
			if (!item) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_node_types_run_fail;
			}
			item->test_result = 1;
			item->item = (void *)context_type;
			if (apol_vector_append(res->items, (void *)item) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_node_types_run_fail;
			}
		}
		if (!item->proof) {
			if (!(item->proof = apol_vector_create(sechk_proof_free))) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_node_types_run_fail;
			}
		}
		if (apol_vector_append(item->proof, (void *)proof) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_node_types_run_fail;
		}
		item = NULL;
	}
	apol_vector_destroy(&nodecon_vector);

	mod->result = res;

	return 0;

      find_node_types_run_fail:
	apol_vector_destroy(&nodecon_vector);
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print function generates the text and prints the results to stdout. */
int find_node_types_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k = 0, num_items = 0;
	const qpol_type_t *type;
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

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i node types.\n", num_items);
	}

	/* The list renode component is a display of all items
	 * found without any supnodeing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t *) item->item;
			qpol_type_get_name(q, type, &type_name);
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	/* The proof renode component is a display of a list of items
	 * with an indented list of proof statements supnodeing the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (j = 0; j < num_items; j++) {
			item = apol_vector_get_element(mod->result->items, j);
			type = (qpol_type_t *) item->item;
			qpol_type_get_name(q, type, &type_name);
			if (item) {
				printf("%s\n", type_name);
				for (k = 0; k < apol_vector_get_size(item->proof); k++) {
					proof = apol_vector_get_element(item->proof, k);
					if (proof)
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}

	return 0;
}

int find_node_types_get_list(sechk_module_t * mod, apol_policy_t * policy __attribute__ ((unused)), void *arg)
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
