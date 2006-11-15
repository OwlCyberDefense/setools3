/**
 *  @file roles_wo_allow.c
 *  Implementation of the roles without allow rules module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
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

#include "roles_wo_allow.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "roles_wo_allow";

/* The register function registers all of a module's functions
 * with the library. */
int roles_wo_allow_register(sechk_lib_t * lib)
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
	mod->brief_description = "roles with no roleallow rules";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds roles defined in the policy that are not used in any role\n"
		"allow rules.  It is not possible to transition to or from any role that does not\n" "have any role allow rules.\n";
	mod->opt_description =
		"Module requirements:\n" "   none\n" "Module dependencies:\n" "   none\n" "Module options:\n" "   none\n";
	mod->severity = SECHK_SEV_LOW;
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
	fn_struct->fn = roles_wo_allow_init;
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
	fn_struct->fn = roles_wo_allow_run;
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
	fn_struct->fn = roles_wo_allow_print;
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
	fn_struct->fn = roles_wo_allow_get_list;
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
int roles_wo_allow_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
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
int roles_wo_allow_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;
	apol_vector_t *role_vector;
	apol_vector_t *role_allow_vector;
	apol_role_allow_query_t *role_allow_query = NULL;
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
		goto roles_wo_allow_run_fail;
	}
	res->item_type = SECHK_ITEM_ROLE;

	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto roles_wo_allow_run_fail;
	}

	if (apol_role_get_by_query(policy, NULL, &role_vector) < 0) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto roles_wo_allow_run_fail;
	}
	if ((role_allow_query = apol_role_allow_query_create()) == NULL) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto roles_wo_allow_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(role_vector); i++) {
		qpol_role_t *role;
		char *role_name;

		role = apol_vector_get_element(role_vector, i);
		qpol_role_get_name(apol_policy_get_qpol(policy), role, &role_name);

		if (!strcmp(role_name, "object_r"))
			continue;

		apol_role_allow_query_set_source(policy, role_allow_query, role_name);
		apol_role_allow_query_set_source_any(policy, role_allow_query, 1);
		apol_role_allow_get_by_query(policy, role_allow_query, &role_allow_vector);
		if (apol_vector_get_size(role_allow_vector) > 0) {
			apol_vector_destroy(&role_allow_vector, NULL);
			continue;
		}
		apol_vector_destroy(&role_allow_vector, NULL);

		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_allow_run_fail;
		}
		proof->type = SECHK_ITEM_ROLE;
		proof->text = strdup("Role has no allow.\n");
		item = sechk_item_new(NULL);
		if (!item) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_allow_run_fail;
		}
		item->item = (void *)role;
		if (!item->proof) {
			if (!(item->proof = apol_vector_create())) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto roles_wo_allow_run_fail;
			}
		}
		if (apol_vector_append(item->proof, (void *)proof) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_allow_run_fail;
		}
		if (apol_vector_append(res->items, (void *)item) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_allow_run_fail;
		}
		item = NULL;
		proof = NULL;
	}
	apol_vector_destroy(&role_vector, NULL);
	apol_vector_destroy(&role_allow_vector, NULL);
	apol_role_allow_query_destroy(&role_allow_query);
	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      roles_wo_allow_run_fail:
	apol_vector_destroy(&role_vector, NULL);
	apol_vector_destroy(&role_allow_vector, NULL);
	apol_role_allow_query_destroy(&role_allow_query);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int roles_wo_allow_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	size_t i = 0, j = 0, num_items;
	qpol_role_t *role;
	char *role_name;

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
		printf("Found %i roles.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following roles do not appear in any allow rules.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST | SECHK_OUT_PROOF)) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			role = (qpol_role_t *) item->item;
			qpol_role_get_name(apol_policy_get_qpol(policy), role, &role_name);
			printf("%s%s", role_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	return 0;
}

int roles_wo_allow_get_list(sechk_module_t * mod, apol_policy_t * policy __attribute__ ((unused)), void *arg)
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
