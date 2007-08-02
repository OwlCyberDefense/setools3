/**
 *  @file
 *  Defines the interface for the roles without users module.
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

#include "roles_wo_users.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "roles_wo_users";

/* The register function registers all of a module's functions
 * with the library. */
int roles_wo_users_register(sechk_lib_t * lib)
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
	mod->brief_description = "roles not assigned to users";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds roles that are not assigned to users.  If a role is not       \n"
		"assigned to a user it cannot form a valid context.\n";
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
	fn_struct->fn = roles_wo_users_init;
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
	fn_struct->fn = roles_wo_users_run;
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
	fn_struct->fn = roles_wo_users_print;
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
	fn_struct->fn = roles_wo_users_get_list;
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
int roles_wo_users_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
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
int roles_wo_users_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;
	apol_vector_t *role_vector;
	apol_vector_t *user_vector;
	apol_user_query_t *user_query = NULL;
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
		goto roles_wo_users_run_fail;
	}
	res->item_type = SECHK_ITEM_ROLE;
	if (!(res->items = apol_vector_create(sechk_item_free))) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto roles_wo_users_run_fail;
	}

	if (!(user_query = apol_user_query_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto roles_wo_users_run_fail;
	}

	if (apol_role_get_by_query(policy, NULL, &role_vector) < 0) {
		error = errno;
		ERR(policy, "%s", "Unable to retrieve roles");
		return -1;
	}

	for (i = 0; i < apol_vector_get_size(role_vector); i++) {
		const qpol_role_t *role;
		const char *role_name;

		role = apol_vector_get_element(role_vector, i);
		qpol_role_get_name(apol_policy_get_qpol(policy), role, &role_name);

		if (!strcmp(role_name, "object_r"))
			continue;

		apol_user_query_set_role(policy, user_query, role_name);
		apol_user_get_by_query(policy, user_query, &user_vector);
		if (apol_vector_get_size(user_vector) > 0) {
			apol_vector_destroy(&user_vector);
			continue;
		}
		apol_vector_destroy(&user_vector);

		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_users_run_fail;
		}
		item = sechk_item_new(NULL);
		if (!item) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_users_run_fail;
		}
		item->item = (void *)role;
		item->test_result = 1;
		proof->type = SECHK_ITEM_ROLE;
		proof->text = strdup("This role is not assigned to any user.");
		if (!proof->text) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_users_run_fail;
		}
		if (!item->proof) {
			if (!(item->proof = apol_vector_create(sechk_proof_free))) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto roles_wo_users_run_fail;
			}
		}
		if (apol_vector_append(item->proof, (void *)proof) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_users_run_fail;
		}
		if (apol_vector_append(res->items, (void *)item) < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto roles_wo_users_run_fail;
		}
		item = NULL;
		proof = NULL;
	}
	apol_vector_destroy(&role_vector);
	apol_vector_destroy(&user_vector);
	apol_user_query_destroy(&user_query);
	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      roles_wo_users_run_fail:
	apol_vector_destroy(&role_vector);
	apol_vector_destroy(&user_vector);
	apol_user_query_destroy(&user_query);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print function generates the text printed in the
 * report and prints it to stdout. */
int roles_wo_users_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	const qpol_role_t *role;
	const char *role_name;
	size_t i = 0, j = 0, num_items;

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
		printf("Found %zd roles.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following roles are not associated with any users.\n");
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

int roles_wo_users_get_list(sechk_module_t * mod, apol_policy_t * policy __attribute__ ((unused)), void *arg)
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
