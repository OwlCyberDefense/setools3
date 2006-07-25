/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
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
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domains_wo_roles_init;
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
	fn_struct->fn = &domains_wo_roles_run;
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
	fn_struct->fn = &domains_wo_roles_data_free;
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
	fn_struct->fn = &domains_wo_roles_print_output;
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
	fn_struct->fn = &domains_wo_roles_get_result;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int domains_wo_roles_init(sechk_module_t *mod, apol_policy_t *policy)
{
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

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int domains_wo_roles_run(sechk_module_t *mod, apol_policy_t *policy)
{
	domains_wo_roles_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, retv, error;
	sechk_module_t *mod_ptr = NULL;
	sechk_run_fn_t run_fn = NULL;
	sechk_result_t *(*get_result_fn)(sechk_module_t *mod) = NULL;
	apol_vector_t *domain_vector;
	apol_vector_t *role_vector;
	apol_role_query_t *role_query;
	sechk_result_t *find_domains_res = NULL;

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
	res->item_type = SECHK_ITEM_TYPE;
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto domains_wo_roles_run_fail;
        }

	run_fn = sechk_lib_get_module_function("find_domains", SECHK_MOD_FN_RUN, mod->parent_lib);
	if (!run_fn)
		goto domains_wo_roles_run_fail;

	retv = run_fn((mod_ptr = sechk_lib_get_module("find_domains", mod->parent_lib)), policy);
	if (retv) {
		fprintf(stderr, "Error: dependency failed\n");
		goto domains_wo_roles_run_fail;
	}

	get_result_fn = sechk_lib_get_module_function("find_domains", "get_result", mod->parent_lib);
	if ( !(find_domains_res = get_result_fn(mod_ptr)) ) {
		fprintf(stderr, "Error: unable to get list\n");
		goto domains_wo_roles_run_fail;
	}
	
	domain_vector = (apol_vector_t *)find_domains_res->items;

        if ( !(role_query = apol_role_query_create()) ) {
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
                goto domains_wo_roles_run_fail;
        }

	for (i = 0; i < apol_vector_get_size(domain_vector); i++) {
		sechk_item_t *item;
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
                        fprintf(stderr, "Error: out of memory\n");
                        goto domains_wo_roles_run_fail;
                }
                proof->type = SECHK_ITEM_ROLE;
                proof->text = strdup("Domain has no role.\n");
		if ( !proof->text ) {
	                error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto domains_wo_roles_run_fail;

		}
                item = sechk_item_new(NULL);
                if (!item) {
                        fprintf(stderr, "Error: out of memory\n");
                        goto domains_wo_roles_run_fail;
                }
                item->item = (void *)domain;
                if ( !item->proof ) {
                        if ( !(item->proof = apol_vector_create()) ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto domains_wo_roles_run_fail;
                        }
                }
                if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto domains_wo_roles_run_fail;
                }
                if ( apol_vector_append(res->items, (void*)item) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
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

/* The free function frees the private data of a module */
void domains_wo_roles_data_free(void *data)
{
	free(data);	
}

/* The print output function generates the text printed in the
 * report and prints it to stdout.  */
int domains_wo_roles_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	domains_wo_roles_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j, num_items;
	qpol_type_t *type;
	char *type_name;

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
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
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
                        printf("%s%s", type_name, (char *)( (j) ? ", " : "\n"));
                }
                printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *domains_wo_roles_get_result(sechk_module_t *mod) 
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

/* The domains_wo_roles_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
domains_wo_roles_data_t *domains_wo_roles_data_new(void)
{
	domains_wo_roles_data_t *datum = NULL;

	datum = (domains_wo_roles_data_t*)calloc(1,sizeof(domains_wo_roles_data_t));

	return datum;
}
