/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_netif_types.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;
static const char *const mod_name = "find_netif_types";

/* The register function registers all of a module's functions
 * with the library. */
int find_netif_types_register(sechk_lib_t *lib)
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
	
	/* assign the descriptions */
	mod->brief_description = "utility module";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds all types in a policy treated as a netif type.  A type is     \n"
"a netif type if it is the type in a netifcon statement.                         \n";
	mod->opt_description = 
"  Module requirements:\n"
"    none\n"
"  Module dependencies:\n"
"    none\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_NONE;

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
	fn_struct->fn = &find_netif_types_init;
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
	fn_struct->fn = &find_netif_types_run;
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
	fn_struct->fn = &find_netif_types_free;
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
	fn_struct->fn = &find_netif_types_print_output;
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
	fn_struct->fn = &find_netif_types_get_result;
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
        fn_struct->fn = &find_netif_types_get_list;
        fn_struct->next = mod->functions;
        mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int find_netif_types_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	find_netif_types_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_netif_types_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	/* check module options */
	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

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
int find_netif_types_run(sechk_module_t *mod, policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	find_netif_types_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	ap_netifcon_t tmp_netifcon;
	char *buff = NULL;
	int i = 0, j = 0, isid_idx = 0, type_idx = 0, buff_sz = 0, idx[2];

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

	datum = (find_netif_types_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto find_netif_types_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	for (i = policy->num_netifcon - 1; i >= 0; i--) {
		tmp_netifcon = policy->netifcon[i];
		idx[0] = tmp_netifcon.device_context->type;
		idx[1] = tmp_netifcon.packet_context->type;

		for (j = 0; j < 2; j++) {
			proof = sechk_proof_new();
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto find_netif_types_run_fail;
			}

			proof->idx = idx[j];
			proof->type = POL_LIST_TYPE;
			buff = re_render_netifcon(&tmp_netifcon, policy);
			proof->text = buff;
		
			if (res->num_items > 0) {
				item = sechk_result_get_item(idx[j], POL_LIST_TYPE, res);
			}

			/* We have not encountered this type yet */
			if (!item) {
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_netif_types_run_fail;
				}

				item->item_id = idx[j];
				item->test_result = 1;
		
				if (item) {
					item->next = res->items;
					res->items = item;
					(res->num_items)++;
				}
			} 
	       	
			/* head insert proof */
			proof->next = item->proof;
			item->proof = proof;
		}
	}

	/* if we are provided a source policy, search initial SIDs */
	if (!is_binary_policy(policy)) {
		buff = NULL;
		isid_idx = get_initial_sid_idx("netif", policy);
		if (isid_idx >= 0) {
			proof = NULL;
			type_idx = policy->initial_sids[isid_idx].scontext->type;

			if (append_str(&buff, &buff_sz, "sid netif ") != 0) {
				fprintf(stderr, "Error: out of memory");
				goto find_netif_types_run_fail;
			}

			if (append_str(&buff, &buff_sz, re_render_initial_sid_security_context(isid_idx, policy)) != 0) {
				fprintf(stderr, "Error: out of memory");
				goto find_netif_types_run_fail;
			}

			if (res->num_items > 0) {
				item = sechk_result_get_item(type_idx, POL_LIST_TYPE, res);
			}

			if (!item) {
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_netif_types_run_fail;
				}

				item->item_id = type_idx;
				item->test_result = 1;
			}

			proof = sechk_proof_new();
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto find_netif_types_run_fail;
			}

			proof->idx = type_idx;
			proof->type = POL_LIST_TYPE;
			proof->text = buff;

			if (item) {
				item->next = res->items;
				res->items = item;
				(res->num_items)++;
			}

			proof->next = item->proof;
			item->proof = proof;
		}
	}

	mod->result = res;

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

	return 0;

find_netif_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	free(buff);
#endif
	return -1;
}

/* The free function frees the private data of a module */
void find_netif_types_free(sechk_module_t *mod)
{
	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a renetif section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int find_netif_types_print_output(sechk_module_t *mod, policy_t *policy) 
{
	find_netif_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, type_idx = 0;
	char *type_str = NULL;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	
	datum = (find_netif_types_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i netif types.\n", mod->result->num_items);
	}

	/* The list renetif component is a display of all items
	 * found without any supnetifing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;

			printf("%s%s", type_str, (i&&item->next)?", " : "\n");
		}
		printf("\n");
	}

	/* The proof renetif component is a display of a list of items
	 * with an indented list of proof statements supnetifing the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;

			printf("%s\n", type_str);
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
sechk_result_t *find_netif_types_get_result(sechk_module_t *mod) 
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

int find_netif_types_get_list(sechk_module_t *mod, int **array, int *size)
{
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

        return 0;
}

/* The find_netif_types_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic */
find_netif_types_data_t *find_netif_types_data_new(void)
{
	find_netif_types_data_t *datum = NULL;

	datum = (find_netif_types_data_t*)calloc(1,sizeof(find_netif_types_data_t));

	return datum;
}

 
