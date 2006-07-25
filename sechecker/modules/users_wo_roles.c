/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "users_wo_roles.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "users_wo_roles";

/* The register function registers all of a module's functions
 * with the library. */
int users_wo_roles_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "users with no roles";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds all the SELinux users in the policy that have no associated   \n"
"roles.  Users without roles may appear in the label of a file system object     \n"
"however the users cannot login to the system or run any processes.  Since these \n"
"users cannot be used on the system, a policy change is recomended to remove the \n"
"user or provide some intended access.                                           \n";
	mod->opt_description = 
"  Module requirements:\n"
"    none\n"
"  Module dependencies:\n"
"    none\n"
"  Module options:\n"
"    none\n";
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
	fn_struct->fn = &users_wo_roles_init;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
	fn_struct->fn = &users_wo_roles_run;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
	fn_struct->fn = &users_wo_roles_data_free;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
	fn_struct->fn = &users_wo_roles_print_output;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
	fn_struct->fn = &users_wo_roles_get_result;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int users_wo_roles_init(sechk_module_t *mod, apol_policy_t *policy)
{
	users_wo_roles_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = users_wo_roles_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. */
int users_wo_roles_run(sechk_module_t *mod, apol_policy_t *policy)
{
	users_wo_roles_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, error;
	apol_vector_t *user_vector;

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

	datum = (users_wo_roles_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto users_wo_roles_run_fail;
	}
	res->item_type = SECHK_ITEM_USER;
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto users_wo_roles_run_fail;
        }

	apol_get_user_by_query(policy, NULL, &user_vector);
	for (i=0;i<apol_vector_get_size(user_vector);i++) {
		qpol_user_t *user;
		qpol_iterator_t *role_iter;
	
		user = apol_vector_get_element(user_vector, i);
	 	qpol_user_get_role_iter(policy->qh, policy->p, user, &role_iter);
		if ( !qpol_iterator_end(role_iter) ) continue;		

                proof = sechk_proof_new(NULL);
                if (!proof) {
                        fprintf(stderr, "Error: out of memory\n");
                        goto users_wo_roles_run_fail;
                }
                proof->type = SECHK_ITEM_USER;
                proof->text = "User has no roles.\n";
                item = sechk_item_new(NULL);
                if (!item) {
                        fprintf(stderr, "Error: out of memory\n");
                        goto users_wo_roles_run_fail;
                }
                item->item = (void *)user;
                if ( !item->proof ) {
                        if ( !(item->proof = apol_vector_create()) ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto users_wo_roles_run_fail;
                        }
                }
                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto users_wo_roles_run_fail;
                }
                if ( apol_vector_append(res->items, (void*)item) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto users_wo_roles_run_fail;
		}
	}
	apol_vector_destroy(&user_vector, NULL);

	mod->result = res;

	return 0;

users_wo_roles_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void users_wo_roles_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int users_wo_roles_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	users_wo_roles_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j, num_items;
	qpol_user_t *user;
	char *user_name;

        if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (users_wo_roles_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i users.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following users have no associated roles.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
                printf("\n");
                for (i=0;i<num_items;i++) {
                        j++;
                        j %= 4;
                        item = apol_vector_get_element(mod->result->items, i);
                        user = (qpol_user_t*)item->item;
                        qpol_user_get_name(policy->qh, policy->p, user, &user_name);
                        printf("%s%s", user_name, (char *)( (j) ? ", " : "\n"));
                }
                printf("\n");
	}
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *users_wo_roles_get_result(sechk_module_t *mod) 
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

/* The users_wo_roles_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
users_wo_roles_data_t *users_wo_roles_data_new(void)
{
	users_wo_roles_data_t *datum = NULL;

	datum = (users_wo_roles_data_t*)calloc(1,sizeof(users_wo_roles_data_t));

	return datum;
}
