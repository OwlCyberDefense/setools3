/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "domains_wo_roles.h"
#include <stdio.h>
#include <string.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "domains_wo_roles";

/* The register function registers all of a module's functions
 * with the library. */
int domains_wo_roles_register(sechk_lib_t *lib)
{
#if 0
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	
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
	mod->dependencies = sechk_name_value_new("module", "find_domains");

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_print_output;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int domains_wo_roles_init(sechk_module_t *mod, policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	domains_wo_roles_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = domains_wo_roles_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

#endif
	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int domains_wo_roles_run(sechk_module_t *mod, policy_t *policy)
{
#if 0
	domains_wo_roles_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int *domain_list = NULL, domain_list_sz = 0;
	int i, j, retv;
	sechk_module_t *mod_ptr = NULL;
	sechk_run_fn_t run_fn = NULL;
	int (*get_list_fn)(sechk_module_t *mod, int **array, int *size) = NULL;
	bool_t used = FALSE;
	int object_r_idx = -1;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (domains_wo_roles_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto domains_wo_roles_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	run_fn = sechk_lib_get_module_function("find_domains", SECHK_MOD_FN_RUN, library);
	if (!run_fn)
		goto domains_wo_roles_run_fail;
	get_list_fn = sechk_lib_get_module_function("find_domains", "get_list", library);
	if (!get_list_fn)
		goto domains_wo_roles_run_fail;

	retv = run_fn((mod_ptr = sechk_lib_get_module("find_domains", library)), policy);
	if (retv) {
		fprintf(stderr, "Error: dependency failed\n");
		goto domains_wo_roles_run_fail;
	}
	retv = get_list_fn(mod_ptr, &domain_list, &domain_list_sz);
	if (retv) {
		fprintf(stderr, "Error: unable to get list\n");
		goto domains_wo_roles_run_fail;
	}

	object_r_idx = get_role_idx("object_r", policy);

	for (i = 0; i < domain_list_sz; i++) {
		used = FALSE;
		for (j = 0; j < policy->num_roles; j++) {
			if (j == object_r_idx)
				continue;
			if (does_role_use_type(j, domain_list[i], policy)) {
				used = TRUE;
				break;
			}
		}
		if (used)
			continue;
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto domains_wo_roles_run_fail;
		}
		item->item_id = domain_list[i];
		item->test_result = 1;
		item->proof = sechk_proof_new();
		item->proof->idx = -1;
		item->proof->type = SECHK_TYPE_NONE;
		item->proof->text = strdup("Type is a domain but not associated with a role.");
		if (!item->proof->text) {
			fprintf(stderr, "Error: out of memory\n");
			goto domains_wo_roles_run_fail;
		}
		item->next = res->items;
		res->items = item;
		res->num_items++;
		item = NULL;
	}
	mod->result = res;

	if (res->num_items > 0)
		return 1;

#endif
	return 0;

#if 0
domains_wo_roles_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
#endif
}

/* The free function frees the private data of a module */
void domains_wo_roles_data_free(void *data)
{
#if 0
	domains_wo_roles_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (domains_wo_roles_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text printed in the
 * report and prints it to stdout.  */
int domains_wo_roles_print_output(sechk_module_t *mod, policy_t *policy) 
{
#if 0
	domains_wo_roles_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (domains_wo_roles_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are domains but not associated with any roles.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->types[item->item_id].name, (i&&item->next)? ", " : "\n"); 
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *domains_wo_roles_get_result(sechk_module_t *mod) 
{
#if 0
	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
#endif
	return NULL;
}

/* The domains_wo_roles_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
domains_wo_roles_data_t *domains_wo_roles_data_new(void)
{
#if 0
	domains_wo_roles_data_t *datum = NULL;

	datum = (domains_wo_roles_data_t*)calloc(1,sizeof(domains_wo_roles_data_t));

	return datum;
#endif
	return NULL;
}

