/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"

#include "roles_wo_users.h"

#include <stdio.h>
#include <string.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "roles_wo_users";

/* The register function registers all of a module's functions
 * with the library. */
int roles_wo_users_register(sechk_lib_t *lib)
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
	mod->brief_description = "roles not assigned to users";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds roles that are not assigned to users.  If a role is not       \n"
"assigned to a user it cannot form a valid context.\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_LOW;
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
	fn_struct->fn = &roles_wo_users_init;
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
	fn_struct->fn = &roles_wo_users_run;
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
	fn_struct->fn = &roles_wo_users_free;
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
	fn_struct->fn = &roles_wo_users_print_output;
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
	fn_struct->fn = &roles_wo_users_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &roles_wo_users_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int roles_wo_users_init(sechk_module_t *mod, apol_policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	roles_wo_users_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = roles_wo_users_data_new();
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
 * even if called multiple times. This function allocates the result 
 * structure and fills in all relavant item and proof data. */
int roles_wo_users_run(sechk_module_t *mod, apol_policy_t *policy)
{
#if 0
	roles_wo_users_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, j;
	bool_t used = FALSE;

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

	datum = (roles_wo_users_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto roles_wo_users_run_fail;
	}
	res->item_type = POL_LIST_ROLES;

	for (i = 0; i < policy->num_roles; i++) {
		used = FALSE;
		if (!strcmp(policy->roles[i].name, "object_r"))
			continue;
		for (j = 0; j < policy->num_users; j++) {
			if (does_user_have_role(j, i, policy)) {
				used = TRUE;
				break;
			}
		}
		if (used)
			continue;
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
		item->item_id = i;
		item->test_result = 1;
		proof->idx = -1;
		proof->type = SECHK_TYPE_NONE;
		proof->text = strdup("This role is not assigned to any user.");
		if (!proof->text) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
		item->proof = proof;
		item->next = res->items;
		res->items = item;
		(res->num_items)++;
		item = NULL;
		proof = NULL;
	}


	mod->result = res;

	if (res->num_items > 0)
		return 1;

#endif
	return 0;

#if 0
roles_wo_users_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
#endif
}

/* The free function frees the private data of a module */
void roles_wo_users_data_free(void *data)
{
#if 0
	roles_wo_users_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (roles_wo_users_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int roles_wo_users_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
#if 0
	roles_wo_users_data_t *datum = NULL;
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

	datum = (roles_wo_users_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i roles.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following roles are not associated with any users.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->roles[item->item_id].name, (i&&item->next) ? ", " : "\n"); 
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *roles_wo_users_get_result(sechk_module_t *mod) 
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

/* The roles_wo_users_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
roles_wo_users_data_t *roles_wo_users_data_new(void)
{
#if 0
	roles_wo_users_data_t *datum = NULL;

	datum = (roles_wo_users_data_t*)calloc(1,sizeof(roles_wo_users_data_t));

	return datum;
#endif
	return NULL;
}

int roles_wo_users_get_list(sechk_module_t *mod, apol_vector_t **v)
{
#if 0
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

#endif
	return 0;
}

