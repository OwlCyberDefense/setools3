/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "find_netif_types.h"
#include <apol/netcon-query.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

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
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = &find_netif_types_data_free;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	apol_vector_append(mod->functions, (void *)fn_struct);

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int find_netif_types_init(sechk_module_t *mod, apol_policy_t *policy)
{
	int error = 0;
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
                error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
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
int find_netif_types_run(sechk_module_t *mod, apol_policy_t *policy)
{
	find_netif_types_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *buff = NULL;
	int i = 0, error = 0;
	size_t buff_sz = 0;
	apol_vector_t *netifcon_vector;

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
		error = errno;
		ERR(policy, "Error: %s\n", strerror(error));
		goto find_netif_types_run_fail;
	}
	res->item_type = SECHK_ITEM_NETIFCON;
	if ( !(res->items = apol_vector_create()) ) {
	        error = errno;
                ERR(policy, "Error: %s\n", strerror(error));
		goto find_netif_types_run_fail;	
	}

	if ( apol_get_netifcon_by_query(policy, NULL, &netifcon_vector) < 0 ) {
		goto find_netif_types_run_fail;
	}

	for (i=0;i<apol_vector_get_size(netifcon_vector);i++) {
		char *msg_con_name = NULL;
		char *if_con_name = NULL;	
		qpol_netifcon_t *netifcon = NULL;
		qpol_context_t *msg_con = NULL;
		qpol_context_t *if_con = NULL;
		qpol_type_t *msg_type = NULL;
		qpol_type_t *if_type = NULL;
		int j = 0;

		netifcon = apol_vector_get_element(netifcon_vector, i);
		qpol_netifcon_get_msg_con(policy->qh, policy->p, netifcon, &msg_con);
		qpol_netifcon_get_if_con(policy->qh, policy->p, netifcon, &if_con);
	 	qpol_context_get_type(policy->qh, policy->p, msg_con, &msg_type);
		qpol_context_get_type(policy->qh, policy->p, if_con, &if_type);
		qpol_type_get_name(policy->qh, policy->p, msg_type, &msg_con_name);
		qpol_type_get_name(policy->qh, policy->p, if_type, &if_con_name);
		
                proof = sechk_proof_new(NULL);
                if ( !proof ) {
	                error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto find_netif_types_run_fail;
                }
                proof->type = SECHK_ITEM_NETIFCON;
                proof->text = apol_netifcon_render(policy, netifcon);
		item = NULL;

                for (j=0;j<apol_vector_get_size(res->items);j++) {
                        sechk_item_t *res_item = NULL;
			qpol_type_t *res_type;
			char *res_type_name;

                        res_item = apol_vector_get_element(res->items, j);
			res_type = (qpol_type_t *)res_item->item;
			qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
                        if (!strcmp(res_type_name, if_con_name)) item = res_item;
                }

		if ( !item) {
                	item = sechk_item_new(NULL);
                        if (!item) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
                        }
                        item->test_result = 1;
                        item->item = (void *)if_type;
                        if ( apol_vector_append(res->items, (void *)item) < 0 ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}
                }
                if ( !item->proof ) {
			if ( !(item->proof = apol_vector_create()) ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}
		}
                if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
                        error = errno;
                        ERR(policy, "Error: %s\n", strerror(error));
                        goto find_netif_types_run_fail;
		}
		item = NULL;
	}
	apol_vector_destroy(&netifcon_vector,NULL);
		
	/* if we are provided a source policy, search initial SIDs */
        if (policy) {
                qpol_isid_t *isid = NULL;

                buff = NULL;
                qpol_policy_get_isid_by_name(policy->qh, policy->p, "netif", &isid);
                if ( isid ) {
                        qpol_context_t *context;
			apol_context_t *a_context;
                        qpol_type_t *context_type;
                        char *context_type_name;

                        proof = NULL;
                        qpol_isid_get_context(policy->qh, policy->p, isid, &context);
                        qpol_context_get_type(policy->qh, policy->p, context, &context_type);
                        qpol_type_get_name(policy->qh, policy->p, context_type, &context_type_name);
			a_context = apol_context_create_from_qpol_context(policy, context);

                        if (apol_str_append(&buff, &buff_sz, "sid netif ") != 0) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
                        }

			if (apol_str_append(&buff, &buff_sz, apol_context_render(policy, a_context)) != 0 ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}

			item = sechk_item_new(NULL);
			if (!item) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}
			item->test_result = 1;

			proof = sechk_proof_new(NULL);
			if (!proof) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}

			proof->type = SECHK_ITEM_NETIFCON;
			proof->text = buff;

                        item->item = (void *)context_type;
                        if ( !item->proof ) {
				if ( !(item->proof = apol_vector_create()) ) {
                                	error = errno;
                                	ERR(policy, "Error: %s\n", strerror(error));
                                	goto find_netif_types_run_fail;
				}
			}
                        if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}
                        if ( apol_vector_append(res->items, (void*)item) < 0 ) {
                                error = errno;
                                ERR(policy, "Error: %s\n", strerror(error));
                                goto find_netif_types_run_fail;
			}
		}
	}

	mod->result = res;

	return 0;

find_netif_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	return -1;
}

/* The free function frees the private data of a module */
void find_netif_types_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a renetif section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int find_netif_types_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_netif_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j=0, k = 0, num_items = 0;
	qpol_type_t *type;
	char *type_name;

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

	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i netif types.\n", num_items);
	}

	/* The list renetif component is a display of all items
	 * found without any supnetifing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
                printf("\n");
                for (i=0;i<num_items;i++) {
                        j++;
                        j %= 4;
                        item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t *)item->item;
			qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                        printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
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
                for ( j=0;j<num_items;j++) {
                        item = apol_vector_get_element(mod->result->items, j);
			type = (qpol_type_t *)item->item;
			qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                        if ( item ) {
                                printf("%s\n", type_name);
                                for (k=0;k<apol_vector_get_size(item->proof);k++) {
                                        proof = apol_vector_get_element(item->proof, k);
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

int find_netif_types_get_list(sechk_module_t *mod, apol_vector_t **v)
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

