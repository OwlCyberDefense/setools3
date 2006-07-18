/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_assoc_types.h"
#include "render.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "find_assoc_types";

int find_assoc_types_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;
	int error;

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
	mod->brief_description = "utility module";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds types with an unlabeled initial sid. \n";
	mod->opt_description = 
"  Module requirements:\n"
"    none\n"
"  Module dependencies:\n"
"    none\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_NONE;
	/* assign requirements */
	nv = sechk_name_value_new("policy_type", "source");
	if ( apol_vector_append(mod->requirements, (void *)nv) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->fn = &find_assoc_types_init;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->fn = &find_assoc_types_run;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->fn = &find_assoc_types_data_free;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->fn = &find_assoc_types_print_output;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	fn_struct->fn = &find_assoc_types_get_result;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	fn_struct = sechk_fn_new();
        if (!fn_struct) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
        }
        fn_struct->name = strdup("get_list");
        if (!fn_struct->name) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
        }
        fn_struct->fn = &find_assoc_types_get_list;
	if ( apol_vector_append(mod->functions,(void*)fn_struct) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int find_assoc_types_init(sechk_module_t *mod, apol_policy_t *policy)
{
	find_assoc_types_data_t *datum = NULL;
	int error;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_assoc_types_data_new();
	if (!datum) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	mod->data = datum;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found */
int find_assoc_types_run(sechk_module_t *mod, apol_policy_t *policy)
{
	find_assoc_types_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *buff = NULL;
	size_t buff_sz = 0;
	qpol_isid_t *isid;
	char *type_name = NULL;
	qpol_type_t *type;
	qpol_context_t *context;
	int error;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (find_assoc_types_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto find_assoc_types_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;

	/* Initialize vectors */

	qpol_policy_get_isid_by_name(policy->qh, policy->p, "unlabeled", &isid);

	if ( !isid ) {
		goto find_assoc_types_run_fail;
	}

	if (apol_str_append(&buff, &buff_sz, "sid unlabeled ") != 0) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
		goto find_assoc_types_run_fail;
	}

	qpol_isid_get_context(policy->qh, policy->p, isid, &context);
	qpol_context_get_type(policy->qh, policy->p, context, &type);
	qpol_type_get_name(policy->qh, policy->p, type, &type_name);
	
	if (apol_str_append(&buff, &buff_sz, type_name) !=  0) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
		goto find_assoc_types_run_fail;
	}

	if (!item) {
		item = sechk_item_new(NULL);
		if (!item) {
	                error = errno;
        	        fprintf(stderr, "Error: %s\n", strerror(error));
			goto find_assoc_types_run_fail;
		}
	}

	proof = sechk_proof_new(NULL);
	if (!proof) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
		goto find_assoc_types_run_fail;
	}

	item->test_result = 1;
	item->item = (void*)type_name;
	proof->type = SECHK_ITEM_TYPE;
	proof->text = buff;
	if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
               	goto find_assoc_types_run_fail; 
	}
	if ( !(item->proof = apol_vector_create()) ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
		goto find_assoc_types_run_fail;
	}
	if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                goto find_assoc_types_run_fail;
        }
	if ( apol_vector_append(res->items, (void*)item) < 0 ) {
                error = errno;
                fprintf(stderr, "Error: %s\n", strerror(error));
                goto find_assoc_types_run_fail;
        }

	mod->result = res;

	if (apol_vector_get_size(res->items) > 0)
		return 1;
	return 0;

find_assoc_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	return -1;
}

/* The free function frees the private data of a module */
void find_assoc_types_data_free(void *data)
{
        free(data);
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a reassoc section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int find_assoc_types_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_assoc_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j = 0, k = 0;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	
	datum = (find_assoc_types_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		ERR(policy, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i assoc type(s).\n", apol_vector_get_size(mod->result->items));
	}
	/* The list reassoc component is a display of all items
	 * found without any supassocing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (j=0;j<sizeof(apol_vector_get_size(mod->result->items));j++) {
			i++;
			i %= 4;
			item = apol_vector_get_element(mod->result->items, j);
			if ( item )
                        printf("%s%s", (char *)item->item, (char *)( (j) ? ", " : "\n" ));
		}
		printf("\n");
	}
	/* The proof reassoc component is a display of a list of items
	 * with an indented list of proof statements supassocing the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (j=0;j<sizeof(apol_vector_get_size(mod->result->items));j++) {
			item = apol_vector_get_element(mod->result->items, j);
			if ( item ) {
				printf("%s\n", (char*)item->item);
				for (k=0; k<sizeof(item->proof);k++) {
					proof = apol_vector_get_element(item->proof,k);
					if ( proof )
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *find_assoc_types_get_result(sechk_module_t *mod) 
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

int find_assoc_types_get_list(sechk_module_t *mod, apol_vector_t **v)
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

/* The find_assoc_types_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic */
find_assoc_types_data_t *find_assoc_types_data_new(void)
{
	find_assoc_types_data_t *datum = NULL;

	datum = (find_assoc_types_data_t*)calloc(1,sizeof(find_assoc_types_data_t));

	return datum;
}

