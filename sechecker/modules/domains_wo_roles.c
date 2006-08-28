/**
 *  @file domain_wo_roles.c
 *  Implementation of the domains without roles module. 
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
#include "domains_wo_roles.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "domains_wo_roles";

/* The register function registers all of a module's functions
 * with the library. */
int domains_wo_roles_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "domains with no roles";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all domains in the policy not associated with a role.  These  \n"
		"domains cannot have a valid security context.  The object_r role is not         \n"
		"considered in this check.\n";
	mod->opt_description =
		"Module requirements:\n"
		"   none\n"
		"Module dependencies:\n"
		"   none\n"
		"Module options:\n"
		"   none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign dependencies */
	apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_domains"));

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = domains_wo_roles_init;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = domains_wo_roles_run;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = domains_wo_roles_print;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int domains_wo_roles_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int domains_wo_roles_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, retv, error;
	sechk_module_t *mod_ptr = NULL;
	sechk_mod_fn_t run_fn = NULL;
	apol_vector_t *domain_vector;
	apol_vector_t *role_vector;
	apol_role_query_t *role_query = NULL;
	sechk_result_t *find_domains_res = NULL;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto domains_wo_roles_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if ( !(res->items = apol_vector_create()) ) {
		error = errno;
		ERR(policy, "Error: %s\n", strerror(error));
		goto domains_wo_roles_run_fail;
	}

	run_fn = sechk_lib_get_module_function("find_domains", SECHK_MOD_FN_RUN, mod->parent_lib);
	if (!run_fn) {
		ERR(policy, "%s", "Unable to find run function for module find_domains");
		goto domains_wo_roles_run_fail;
	}

	retv = run_fn((mod_ptr = sechk_lib_get_module("find_domains", mod->parent_lib)), policy, NULL);
	if (retv) {
		ERR(policy, "%s", "Unable to run module find_domains");
		goto domains_wo_roles_run_fail;
	}

	if ( !(find_domains_res = sechk_lib_get_module_result("find_domains", mod->parent_lib)) ) {
		ERR(policy, "%s", "Unable to get results for module find_domains");
		goto domains_wo_roles_run_fail;
	}

	domain_vector = (apol_vector_t *)find_domains_res->items;

	if ( !(role_query = apol_role_query_create()) ) {
		error = errno;
		ERR(policy, "Error: %s\n", strerror(error));
		goto domains_wo_roles_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(domain_vector); i++) {
		qpol_type_t *domain;
		char *domain_name;

		item = apol_vector_get_element(domain_vector, i);
		domain = item->item;
		qpol_type_get_name(policy->qh, policy->p, domain, &domain_name);

		apol_role_query_set_type(policy, role_query, domain_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		if ( apol_vector_get_size(role_vector) > 0 ) continue;

		proof = sechk_proof_new(NULL);
		if (!proof) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto domains_wo_roles_run_fail;
		}
		proof->type = SECHK_ITEM_ROLE;
		proof->text = strdup("Domain has no role.\n");
		if ( !proof->text ) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto domains_wo_roles_run_fail;

		}
		item = sechk_item_new(NULL);
		if (!item) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto domains_wo_roles_run_fail;
		}
		item->item = (void *)domain;
		if ( !item->proof ) {
			if ( !(item->proof = apol_vector_create()) ) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto domains_wo_roles_run_fail;
			}
		}
		if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			ERR(NULL, "%s", strerror(ENOMEM));
			goto domains_wo_roles_run_fail;
		}
		if ( apol_vector_append(res->items, (void*)item) < 0 ) {
			ERR(NULL, "%s", strerror(ENOMEM));
			goto domains_wo_roles_run_fail;
		}
	}
	apol_role_query_destroy(&role_query);
	mod->result = res;

	return 0;

domains_wo_roles_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout.  */
int domains_wo_roles_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	size_t i = 0, j = 0, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are domains but not associated with any roles.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (i=0;i<num_items;i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t*)item->item;
			qpol_type_get_name(policy->qh, policy->p, type, &type_name);
			printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
		}
		printf("\n");
	}

	return 0;
}

