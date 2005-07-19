/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "roles_wo_types.h"

#include <stdio.h>
#include <string.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "roles_wo_types";

/* The register function registers all of a module's functions
 * with the library. */
int roles_wo_types_register(sechk_lib_t *lib) 
{
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
	fn_struct->fn = &roles_wo_types_init;
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
	fn_struct->fn = &roles_wo_types_run;
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
	fn_struct->fn = &roles_wo_types_free;
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
	fn_struct->fn = &roles_wo_types_print_output;
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
	fn_struct->fn = &roles_wo_types_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. It also checks that the requirements and dependencies are met.
 * This function also defines the module header, which provides a brief
 * explanation of the check performed by the module. */
int roles_wo_types_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	roles_wo_types_data_t *datum = NULL;
	bool_t test = FALSE;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = roles_wo_types_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->requirements;
	while (opt) {
		test = FALSE;
		test = sechk_lib_check_requirement(opt, library);
		if (!test) {
			return -1;
		}
		opt = opt->next;
	}

	opt = mod->dependencies;
	while (opt) {
		test = FALSE;
		test = sechk_lib_check_dependency(opt, library);
		if (!test) {
			return -1;
		}
		opt = opt->next;
	}

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int roles_wo_types_run(sechk_module_t *mod, policy_t *policy)
{
	roles_wo_types_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, retv, num_types = 0, *types = NULL;

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

	datum = (roles_wo_types_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto roles_wo_types_run_fail;
	}
	res->item_type  = POL_LIST_ROLES;

	for (i = policy->num_roles - 1; i > -1; i--) {
		if (!strcmp("object_r", policy->roles[i].name))
			continue;
		num_types = 0;
		free(types);
		types = NULL;
		retv = get_role_types(i, &num_types, &types, policy);
		if (retv) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_types_run_fail;
		}
		if (num_types) 
			continue;
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_types_run_fail;
		}
		proof->idx = i;
		proof->type = POL_LIST_ROLES;
		proof->severity = SECHK_SEV_LOW;
		proof->text = (char*)calloc(strlen("role  has no types")+strlen(policy->roles[i].name)+1, sizeof(char));
		sprintf(proof->text, "role %s has no types", policy->roles[i].name);
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_types_run_fail;
		}
		item->item_id = i;
		item->test_result = 1;
		proof->next = item->proof;
		item->proof = proof;
		item->next = res->items;
		res->items = item;
		(res->num_items)++;
	}

	mod->result = res;

	return 0;

roles_wo_types_run_fail:
	free(types);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void roles_wo_types_free(sechk_module_t *mod)
{
	roles_wo_types_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (roles_wo_types_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int roles_wo_types_print_output(sechk_module_t *mod, policy_t *policy) 
{
	roles_wo_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (roles_wo_types_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!outformat)
		return 0; /* not an error - no output is requested */

	if (!mod->result && (outformat & ~(SECHK_OUT_HEADER))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	printf("Module: %s\n", mod_name);
	/* print the header */
	if (outformat & SECHK_OUT_HEADER) {
		printf("%s\n\n", mod->header);
	}
	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i roles.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->roles[item->item_id].name, (i ? ", " : "\n")); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", policy->roles[item->item_id].name);
			printf(" - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *roles_wo_types_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

/* The roles_wo_types_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
roles_wo_types_data_t *roles_wo_types_data_new(void)
{
	roles_wo_types_data_t *datum = NULL;

	datum = (roles_wo_types_data_t*)calloc(1,sizeof(roles_wo_types_data_t));

	return datum;
}

 
