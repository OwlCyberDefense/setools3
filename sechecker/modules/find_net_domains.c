/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: dwindsor@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_net_domains.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

static const char *const mod_name = "find_net_domains";

int find_net_domains_register(sechk_lib_t *lib)
{
#if 0
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;

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
	mod->options = sechk_name_value_new("net_obj", "netif");
	nv = sechk_name_value_new("net_obj", "tcp_socket");
	nv->next = mod->options;
	mod->options = nv;

	nv = sechk_name_value_new("net_obj", "udp_socket");
	nv->next = mod->options;
	mod->options = nv;

	nv = sechk_name_value_new("net_obj", "node");
	nv->next = mod->options;
	mod->options = nv;
	
	nv = sechk_name_value_new("net_obj", "association");
	nv->next = mod->options;
	mod->options = nv;

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
	fn_struct->fn = &find_net_domains_run;
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
	fn_struct->fn = &find_net_domains_free;
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
	fn_struct->fn = &find_net_domains_print_output;
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
	fn_struct->fn = &find_net_domains_get_result;
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
        fn_struct->fn = &find_net_domains_get_list;
        fn_struct->next = mod->functions;
        mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int find_net_domains_init(sechk_module_t *mod, policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	find_net_domains_data_t *datum = NULL;
	int obj_idx = 0;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_net_domains_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	/* populate datum with domains defined in options */
	opt = mod->options;
	while (opt) {
		if (strcmp(opt->name, "net_obj") == 0) {
			if ((obj_idx = get_obj_class_idx(opt->value, policy)) <= 0) {
				fprintf(stderr, "Error: undefined object class %s\n", opt->value);
				return -1;
			}
			if (!is_valid_obj_class(policy, obj_idx)) {
				fprintf(stderr, "Error: invalid object class %s\n", opt->value);
				return -1;
			}      
			if (add_i_to_a(obj_idx, &(datum->num_net_objs), &(datum->net_objs)) != 0) {
				fprintf(stderr, "Error: out of memory\n");
				return -1;
			}
		}
		opt = opt->next;
	}

#endif
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
int find_net_domains_run(sechk_module_t *mod, policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	find_net_domains_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *buff = NULL;
	int i = 0, j = 0, idx = 0, obj = 0, retv = 0;
	int *obj_classes = NULL, obj_classes_sz = 0;
	int *src_types = NULL, src_types_sz = 0;

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

	datum = (find_net_domains_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto find_net_domains_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	/* iterate through av_access rules */
	for (i = 0; i < policy->num_av_access; i++) {
		retv = extract_obj_classes_from_te_rule(i, RULE_TE_ALLOW, &obj_classes, &obj_classes_sz, policy);
		if (retv == -1) {
			fprintf(stderr, "Error: cannot extract object class from rule\n");
			goto find_net_domains_run_fail;
		}

		/* is this obj class in net_domains[]? */
		for (obj = 0; obj < obj_classes_sz; obj++) {
			idx = find_int_in_array(obj_classes[obj], datum->net_objs, datum->num_net_objs);

			/* this obj class is in net_domains[]; extract src type, add to result set */
			if (idx > -1) {
				if (extract_types_from_te_rule(i, RULE_TE_ALLOW, SRC_LIST, &src_types, &src_types_sz, policy) != 0) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_net_domains_run_fail;
				}
				
				item = NULL;

				/* add to result set */
				for (j = 0; j < src_types_sz; j++) {	
					if (res->num_items > 0) {
						item = sechk_result_get_item(src_types[j], POL_LIST_TYPE, res);
					}

					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_net_domains_run_fail;
						}
						item->item_id = src_types[j];
						item->test_result = 1;
						item->next = res->items;
						res->items = item;
						(res->num_items)++;
					}

					/* only 1 proof element/item */
					if (!sechk_item_has_proof(src_types[j], POL_LIST_TYPE, item)) {
						proof = sechk_proof_new();
						if (!proof) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_net_domains_run_fail;
						}
						proof->idx = src_types[j];
						proof->type = POL_LIST_TYPE;
						buff = re_render_av_rule(1, i, RULE_TE_ALLOW, policy);
						if (!buff) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_net_domains_run_fail;
						}
						proof->text = buff;

						if (res->num_items > 0) {
							item = sechk_result_get_item(src_types[j], POL_LIST_TYPE, res);
						}

						proof->next = item->proof;
						item->proof = proof;	
					}
				}
				break;
			}
		}
	}
	
	mod->result = res;

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

#endif
	return 0;

#if 0
find_net_domains_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	if (buff)
		free(buff); 
	return -1;
#endif
}

/* The free function frees the private data of a module */
void find_net_domains_data_free(void *data)
{
#if 0
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
#endif
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a renode section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int find_net_domains_print_output(sechk_module_t *mod, policy_t *policy) 
{
#if 0
	find_net_domains_data_t *datum = NULL;
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
	
	datum = (find_net_domains_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("\nFound %i network domains.", mod->result->num_items);
	}

	/* The list renode component is a display of all items
	 * found without any supnodeing proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;
			printf("%s%s", type_str, (i&&item->next) ? ", " : "\n");

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
		for (item = mod->result->items; item; item = item->next) {
			type_idx = item->item_id;
			type_str = policy->types[type_idx].name;

			printf("\n%s\n", type_str);
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *find_net_domains_get_result(sechk_module_t *mod) 
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

int find_net_domains_get_list(sechk_module_t *mod, apol_vector_t **v)
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
#if 0
	find_net_domains_data_t *datum = NULL;

	datum = (find_net_domains_data_t*)calloc(1,sizeof(find_net_domains_data_t));

	return datum;
#endif
	return NULL;
}

