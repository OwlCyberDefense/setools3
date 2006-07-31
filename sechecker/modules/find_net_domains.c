/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "find_net_domains.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "find_net_domains";

int find_net_domains_register(sechk_lib_t *lib)
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
"This module finds all types in a policy considered to be network domains.       \n"
"A type is considered a network domain if it is the subject of TE rules          \n"
"involving certain object classes, which are currently defined as:\n"
"    1) netif\n"
"    2) tcp_socket\n"
"    3) udp_socket\n"
"    4) node\n"
"    5) association\n"
"These values can be overridden in this module's profile.";
	mod->opt_description = 
"  Module requirements:\n"
"    none\n"
"  Module dependencies:\n"
"    none\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_NONE;

	/* assign default options */
	apol_vector_append(mod->options, sechk_name_value_new("net_obj", "netif"));
	apol_vector_append(mod->options, sechk_name_value_new("net_obj", "tcp_socket"));
	apol_vector_append(mod->options, sechk_name_value_new("net_obj", "node"));
	apol_vector_append(mod->options, sechk_name_value_new("net_obj", "association"));

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
	fn_struct->fn = &find_net_domains_init;
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
	fn_struct->fn = &find_net_domains_run;
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
	fn_struct->fn = &find_net_domains_data_free;
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
	fn_struct->fn = &find_net_domains_print_output;
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
	fn_struct->fn = &find_net_domains_get_result;
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
        fn_struct->fn = &find_net_domains_get_list;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                fprintf(stderr, "Error: out of memory\n");
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int find_net_domains_init(sechk_module_t *mod, apol_policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	find_net_domains_data_t *datum = NULL;
	size_t i;

	if (!mod || !policy) {
		ERR(policy, "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = find_net_domains_data_new();
	if (!datum) {
		ERR(policy, "Out of memory");
		return -1;
	}

	if ( !(datum->net_objs = apol_vector_create()) ) {
		ERR(policy, "Out of memory");
		return -1;
	}

	mod->data = datum;

        for (i = 0; i < apol_vector_get_size(mod->options); i++) {
                opt = apol_vector_get_element(mod->options, i);
                if (!strcmp(opt->name, "net_obj")) {
	                if ( apol_vector_append(datum->net_objs, (void*) opt->value ) < 0 ) {
       		        	ERR(policy, "Out of memory");
                        	return -1;
                        }
                }
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
int find_net_domains_run(sechk_module_t *mod, apol_policy_t *policy)
{
	find_net_domains_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j = 0, k=0,  error;
	apol_vector_t *avrule_vector;
	apol_avrule_query_t *avrule_query;

	if (!mod || !policy) {
		ERR(policy, "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (find_net_domains_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		ERR(policy, "Out of memory");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		ERR(policy, "Out of memory");
		goto find_net_domains_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
        if ( !(res->items = apol_vector_create()) ) {
                error = errno;
                ERR(policy, "%s", strerror(error));
		goto find_net_domains_run_fail;
	}

	if ( !(avrule_query = apol_avrule_query_create()) ) {
                error = errno;
                ERR(policy, "%s", strerror(error));
		goto find_net_domains_run_fail;
	}
	apol_avrule_query_set_rules(policy, avrule_query, QPOL_RULE_ALLOW);
	apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
	for (k=0;k<apol_vector_get_size(avrule_vector);k++) {	
		qpol_avrule_t *avrule;
		qpol_class_t *class;
		char *class_name;

		avrule = apol_vector_get_element(avrule_vector, k);	
		qpol_avrule_get_object_class(policy->qh, policy->p, avrule, &class);
		qpol_class_get_name(policy->qh, policy->p, class, &class_name);
		for (i=0;i<apol_vector_get_size(datum->net_objs);i++) {
			char *net_obj_name;

			net_obj_name = apol_vector_get_element(datum->net_objs, i);
			if ( !strcmp(class_name, net_obj_name) ) {
				qpol_type_t *source;
				char *source_name;
			
				qpol_avrule_get_source_type(policy->qh, policy->p, avrule, &source);
				qpol_type_get_name(policy->qh, policy->p, source, &source_name);

	                	proof = sechk_proof_new(NULL);
		                if ( !proof ) {
		                        ERR(policy, "Out of memory");
		                        goto find_net_domains_run_fail;
	        	        }
	                	proof->type = SECHK_ITEM_TYPE;
		                proof->text = strdup(apol_avrule_render(policy, avrule));
				if ( !proof->text ) {
               	                        ERR(policy, "Out of memory");
                       	                goto find_net_domains_run_fail;
				}
                		item = NULL;

		                for (j=0;j<apol_vector_get_size(res->items);j++) {
               	        		sechk_item_t *res_item = NULL;
					qpol_type_t *res_type;
					char *res_type_name;

	        	                res_item = apol_vector_get_element(res->items, j);
					res_type = res_item->item;
					qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
	                	        if (!strcmp(res_type_name, source_name)) item = res_item;
				}	
               
				if ( !item) {
		                        item = sechk_item_new(NULL);
       			                if (!item) {
               	        	                ERR(policy, "Out of memory");
                       	        	        goto find_net_domains_run_fail;
                       			}
		                        item->test_result = 1;
                		        item->item = (void *)source;
	        	                if ( apol_vector_append(res->items, (void *)item) < 0 ) {
       		                                ERR(policy, "Out of memory");
                	                        goto find_net_domains_run_fail;
               			        }
                		}
		                if ( !item->proof ) {
               			        if ( !(item->proof = apol_vector_create()) ) {
                	                        ERR(policy, "Out of memory");
       	                	                goto find_net_domains_run_fail;
                       			}
                		}
		                if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
               	                        ERR(policy, "Out of memory");
                       	                goto find_net_domains_run_fail;
                		}
		                item = NULL;
			}
		}	
	}
	apol_avrule_query_destroy(&avrule_query);
	apol_vector_destroy(&avrule_vector, NULL);	
	mod->result = res;

	return 0;

find_net_domains_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void find_net_domains_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a renode section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int find_net_domains_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
	find_net_domains_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0, j = 0, k = 0, l = 0, num_items;
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
	
	datum = (find_net_domains_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("\nFound %i network domains.", num_items);
	}

	/* The list renode component is a display of all items
	 * found without any supnodeing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
                printf("\n");
                for (i = 0; i < num_items; i++) {
                        j++;
                        item  = apol_vector_get_element(mod->result->items, i);
                        type = item->item;
                        qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                        j %= 4;
                        printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
                }
                printf("\n");
	}

	/* The proof renode component is a display of a list of items
	 * with an indented list of proof statements supnodeing the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
                printf("\n");
                for (k=0;k< num_items;k++) {
                        item = apol_vector_get_element(mod->result->items, k);
                        if ( item ) {
                                type = item->item;
                                qpol_type_get_name(policy->qh, policy->p, type, &type_name);
                                printf("%s\n", (char*)type_name);
                                for (l=0; l<apol_vector_get_size(item->proof);l++) {
                                        proof = apol_vector_get_element(item->proof,l);
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
sechk_result_t *find_net_domains_get_result(sechk_module_t *mod) 
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

int find_net_domains_get_list(sechk_module_t *mod, apol_vector_t **v)
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

/* The find_net_domains_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic */
find_net_domains_data_t *find_net_domains_data_new(void)
{
	find_net_domains_data_t *datum = NULL;

	datum = (find_net_domains_data_t*)calloc(1,sizeof(find_net_domains_data_t));

	return datum;
}

