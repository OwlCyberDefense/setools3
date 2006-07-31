/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
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
int roles_wo_users_register(sechk_lib_t *lib)
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
	fn_struct->fn = &roles_wo_users_run;
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
	fn_struct->fn = &roles_wo_users_data_free;
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
	fn_struct->fn = &roles_wo_users_print_output;
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
	fn_struct->fn = &roles_wo_users_get_result;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

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
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int roles_wo_users_init(sechk_module_t *mod, apol_policy_t *policy)
{
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

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result 
 * structure and fills in all relavant item and proof data. */
int roles_wo_users_run(sechk_module_t *mod, apol_policy_t *policy)
{
	roles_wo_users_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, error;
	apol_vector_t *role_vector;
	apol_vector_t *user_vector;
	apol_user_query_t *user_query;

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
	res->item_type = SECHK_ITEM_ROLE;
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto roles_wo_users_run_fail;
        }

	if ( !(user_query = apol_user_query_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto roles_wo_users_run_fail;
	}

        if (apol_get_role_by_query(policy, NULL, &role_vector) < 0) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                return -1;
        }
	
	for (i=0; i<apol_vector_get_size(role_vector);i++) {
		qpol_role_t *role;
		char *role_name;

		role = apol_vector_get_element(role_vector, i);
		qpol_role_get_name(policy->qh, policy->p, role, &role_name);

		if (!strcmp(role_name, "object_r"))
			continue;

		apol_user_query_set_role(policy, user_query, role_name);
		apol_get_user_by_query(policy, user_query, &user_vector);
		if (apol_vector_get_size(user_vector) > 0 ) continue; 

		proof = sechk_proof_new(NULL);
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
		item = sechk_item_new(NULL);
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
		item->item = (void *)role;
		item->test_result = 1;
		proof->type = SECHK_ITEM_ROLE;
		proof->text = strdup("This role is not assigned to any user.");
		if (!proof->text) {
			fprintf(stderr, "Error: out of memory\n");
			goto roles_wo_users_run_fail;
		}
                if ( !item->proof ) {
	                if ( !(item->proof = apol_vector_create()) ) {
        	        	error = errno;
                		ERR(policy, "Error: %s\n", strerror(error));
                		goto roles_wo_users_run_fail;
                        }
                }
                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto roles_wo_users_run_fail;
                }
                if ( apol_vector_append(res->items, (void*)item) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto roles_wo_users_run_fail;
                }
		item = NULL;
		proof = NULL;
	}
	apol_vector_destroy(&role_vector, NULL);
	apol_vector_destroy(&user_vector, NULL);
	apol_user_query_destroy(&user_query);
	mod->result = res;

	return 0;

roles_wo_users_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void roles_wo_users_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int roles_wo_users_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	roles_wo_users_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	qpol_role_t *role;
	char *role_name;
	int i = 0,j, num_items;

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
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i roles.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following roles are not associated with any users.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
                printf("\n");
                for (i=0;i<num_items;i++) {
                        j++;
                        j %= 4;
                        item = apol_vector_get_element(mod->result->items, i);
			role = (qpol_role_t*)item->item;
			qpol_role_get_name(policy->qh, policy->p, role, &role_name);
                        printf("%s%s", role_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
                }
                printf("\n");
        }

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *roles_wo_users_get_result(sechk_module_t *mod) 
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

/* The roles_wo_users_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
roles_wo_users_data_t *roles_wo_users_data_new(void)
{
	roles_wo_users_data_t *datum = NULL;

	datum = (roles_wo_users_data_t*)calloc(1,sizeof(roles_wo_users_data_t));

	return datum;
}

int roles_wo_users_get_list(sechk_module_t *mod, apol_vector_t **v)
{
        if (!mod || !v) {
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

        v = &mod->result->items;

        return 0;
}
