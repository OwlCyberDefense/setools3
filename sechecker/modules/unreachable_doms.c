/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "unreachable_doms.h"

#include <stdio.h>
#include <string.h>
#include <selinux/selinux.h>
#include <ctype.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "unreachable_doms";

int unreachable_doms_register(sechk_lib_t *lib)
{
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
	mod->brief_description = "unreachable domains";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds all domains in a policy which are unreachable.  A domain is\n"
"unreachable if any of the following apply:\n"
"1) There is insufficient type enforcement policy to allow a transition,\n"
"2) There is insufficient RBAC policy to allow a transition,\n"
"3) There are no users with proper roles to allow a transition.\n"
"However, if any of the above rules indicate an unreachable domain, yet the domain\n"
"appears in the system default contexts file, it is considered reachable.\n";
	mod->opt_description = 
"  Module requirements:\n"
"    source policy\n"
"    default contexts file\n"
"  Module dependencies:\n"
"    find_domains module\n"
"    inc_dom_trans module\n"
"  Module options:\n"
"    none\n";
	mod->severity = SECHK_SEV_LOW;

	/* assign requirements */
	/* find_domains requires source policy.. */
	mod->requirements = sechk_name_value_new("policy_type", "source");
	nv = sechk_name_value_new("default_ctx", NULL);
	nv->next = mod->requirements;
	mod->requirements = nv; 
	
	/* assign dependencies */
	mod->dependencies = sechk_name_value_new("module", "find_domains");
	nv = sechk_name_value_new("module", "inc_dom_trans");
	nv->next = mod->dependencies;
	mod->dependencies = nv;

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
	fn_struct->fn = &unreachable_doms_init;
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
	fn_struct->fn = &unreachable_doms_run;
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
	fn_struct->fn = &unreachable_doms_free;
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
	fn_struct->fn = &unreachable_doms_print_output;
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
	fn_struct->fn = &unreachable_doms_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int unreachable_doms_init(sechk_module_t *mod, policy_t *policy)
{
	unreachable_doms_data_t *datum = NULL;
	bool_t retv;
	const char *ctx_file_path = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = unreachable_doms_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	/* Parse default contexts file */
	ctx_file_path = selinux_default_context_path();
	if (!ctx_file_path) {
		fprintf(stderr, "Error: could not get default contexts path\n");
		return -1;
	} else {
		retv = parse_default_contexts(ctx_file_path, &(datum->ctx_list), &(datum->ctx_list_sz), policy);
		if (!retv) {
			fprintf(stderr, "Error: could not parse default contexts file\n");
			return -1;
		}
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relevant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found */
int unreachable_doms_run(sechk_module_t *mod, policy_t *policy)
{
	unreachable_doms_data_t *datum;
	sechk_name_value_t *dep = NULL;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL, *tmp_item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_run_fn_t run_fn = NULL;
	int *domain_list = NULL, domain_list_sz = 0;
	int (*domain_list_fn)(sechk_module_t *, int **, int *) = NULL;
	sechk_result_t *inc_dom_trans_res = NULL;
	sechk_get_result_fn_t get_res = NULL;
	int *common_roles = NULL, common_roles_sz = 0, num_common_roles = 0;
	int retv, i, start_type = 0;
	dta_table_t *table = NULL;
	dta_trans_t *cur = NULL, *trans_list = NULL, *trans = NULL;
	bool_t found_valid_trans, found_invalid_trans;
	
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

	datum = (unreachable_doms_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto unreachable_doms_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	/* run dependencies */
        for (dep = mod->dependencies; dep; dep = dep->next) {
                run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, library);
                run_fn(sechk_lib_get_module(dep->value, library), policy);
        }

	/* get results */
	get_res = sechk_lib_get_module_function("inc_dom_trans", SECHK_MOD_FN_GET_RES, library);
	if (!get_res) {
		fprintf(stderr, "Error: unable to find get_result function\n");
		goto unreachable_doms_run_fail;
	}
	inc_dom_trans_res = get_res(sechk_lib_get_module("inc_dom_trans", library));
	if (!inc_dom_trans_res) {
		fprintf(stderr, "Error: unable to get results\n");
		goto unreachable_doms_run_fail;
	}

	/* get lists */
        domain_list_fn = sechk_lib_get_module_function("find_domains", "get_list", library);
        retv = domain_list_fn(sechk_lib_get_module("find_domains", library), &domain_list, &domain_list_sz);
        if (retv) {
                fprintf(stderr, "Error: unable to get domain list\n");
                goto unreachable_doms_run_fail;
        }

	table = dta_table_new(policy);
	if (!table) {
		fprintf(stderr, "Error: creating transition table\n");
		goto unreachable_doms_run_fail;
	}
	retv = dta_table_build(table, policy);
	if (retv) {
		fprintf(stderr, "Error: building transition table\n");
		goto unreachable_doms_run_fail;
	}

	/* first search incomplete domain transitions: 
	   those domains with no other domains transitioning to them are unreachable */
	for (tmp_item = inc_dom_trans_res->items; tmp_item; tmp_item = tmp_item->next) {
		trans = (dta_trans_t *)tmp_item->item_ptr;
		if (!trans)
			break; /* not fatal */
		
		dta_trans_destroy(&trans_list);
		retv = dta_table_get_all_reverse_trans(table, &trans_list, trans->start_type);
		if (retv < 0) {
			fprintf(stderr, "Error: finding domain transitions\n");
			goto unreachable_doms_run_fail;
		}
		
		found_valid_trans = FALSE;
		for (cur = trans_list; cur; cur = cur->next) {
			start_type = cur->start_type;
			if (cur->valid) {
				found_valid_trans = TRUE;
				if (has_common_role(cur->start_type, cur->end_type, policy)) {
					break;
				}
			}			
		}
		
		/* we did not find a valid transition to this domain */
		if (!found_valid_trans) {
			if (res->num_items > 0) {
				item = sechk_result_get_item(trans->start_type, POL_LIST_TYPE, res);
			}
			if (!item) {
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					goto unreachable_doms_run_fail;
				}

				item->item_id = trans->start_type;
				item->test_result = 1;

				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto unreachable_doms_run_fail;
				}
				proof->idx = -1;
				proof->type = POL_LIST_TYPE;
				proof->text = build_invalid_trans_proof_str(trans, policy);
				if (!proof->text) {
					goto unreachable_doms_run_fail;
				}
				
				proof->next = item->proof;
				item->proof = proof;
				item->next = res->items;
				res->items = item;
				(res->num_items)++;
			}
		}
	}

	
	/* for all domains: check to see if a valid transition to this domain exists */
	for (i = 0; i < domain_list_sz; i++) {
		dta_trans_destroy(&trans_list);
		
		/* Get table of all domains that transition to this domain */
		retv = dta_table_get_all_reverse_trans(table, &trans_list, domain_list[i]);
		if (retv) {
                        fprintf(stderr, "Error: finding domain transitions\n");
                        goto unreachable_doms_run_fail;
                }

		/* try to find a valid transition to this domain */
		found_valid_trans = FALSE;
		found_invalid_trans = FALSE;
		for (cur = trans_list; cur; cur = cur->next) {
			/* we re-verify that this entry is valid for sanity's sake */
			if (cur->valid) {
				found_valid_trans = TRUE;

				/* a valid transition exists - verify that a common role exists */
				num_common_roles = get_common_roles(&common_roles, &common_roles_sz, cur->start_type, cur->end_type, policy);
				if (num_common_roles == -1) {
					fprintf(stderr, "Error: getting common roles\n");
					goto unreachable_doms_run_fail;
				}

				/* a valid transition exists - verify roles */
				if (num_common_roles > 0) {
					/* a common role exists - verify that a user is assigned to this role */
					retv = 1;
					if (is_valid_role_idx(common_roles[0], policy)) 
						retv = get_valid_user(common_roles[0], policy);  /* Use the first role in common_roles */
					if (retv == -1) {
						fprintf(stderr, "Error: getting valid users\n");
						goto unreachable_doms_run_fail;
					}

					if (retv == 0) {
						break;  /* A valid user exists for this role - we're finished */
					} else {
						/* no valid users exist */
						/* create item and proof here */
						if (res->num_items > 0) {
							item = sechk_result_get_item(domain_list[i], POL_LIST_TYPE, res);
							if (item)
								break; /* We only need 1 item */
						}

						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto unreachable_doms_run_fail;
						}            
						item->item_id = domain_list[i];
						item->test_result = 1;
						proof = sechk_proof_new();
						if (!proof) {
							fprintf(stderr, "Error: out of memory\n");
							goto unreachable_doms_run_fail;
						}
						proof->idx = domain_list[i];
						proof->type = POL_LIST_TYPE;
						proof->text = build_no_user_proof_str(common_roles[0], policy);
						proof->next = item->proof;
						item->proof = proof;

						item->next = res->items;
						res->items = item;
						(res->num_items)++;
					}
				} else {					
					/* no common role exists - check role_transitions */
					if (has_role_trans(cur->ep_type, policy))
						break; /* no longer invalid */
					
					/* create item and proof here; rest of tests will not execute */
					if (res->num_items > 0) {
						item = sechk_result_get_item(domain_list[i], POL_LIST_TYPE, res);
						if (item)
							break; /* We only need 1 item */
					}

					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto unreachable_doms_run_fail;
					}
					item->item_id = domain_list[i];
					item->test_result = 1;
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto unreachable_doms_run_fail;
					}
					proof->idx = domain_list[i];
					proof->type = POL_LIST_TYPE;
					proof->text = build_common_role_proof_str(cur->start_type, cur->end_type, policy);
					proof->next = item->proof;
					item->proof = proof;
					
					item->next = res->items;
					res->items = item;
					(res->num_items)++;
				}
			} else {
				/* we have found an invalid transition */
				found_invalid_trans = TRUE;
			}
		}

		/* if we haven't found a valid transition to this type, check default ctxs */
		if (!found_valid_trans && !in_def_ctx(domain_list[i], datum) && !sechk_result_get_item(domain_list[i], POL_LIST_TYPE, res)) {
			item = sechk_item_new();
			if (!item) {
				fprintf(stderr, "Error: out of memory\n");
				goto unreachable_doms_run_fail;
			}

			item->item_id = domain_list[i];

			proof = sechk_proof_new();
                        if (!proof) {
                                fprintf(stderr, "Error: out of memory\n");
                                goto unreachable_doms_run_fail;
                        }
                        proof->idx = domain_list[i];
                        proof->type = POL_LIST_TYPE;

			/* We failed because an invalid transition exists, and no other valid transitions */
			if (found_invalid_trans) {
				for (cur = trans_list; cur; cur = cur->next) {
					if (!cur->valid) {
						proof->text = build_invalid_trans_proof_str(cur, policy);	
						if (!proof->text)
							goto unreachable_doms_run_fail;
						break; /* We only need 1 valid transition */
					}
				}
				
				if (!proof->text)
					goto unreachable_doms_run_fail;
			} else {
				/* We failed because no valid transitions exist, but no invalid transitions exist either */
				proof->text = build_no_trans_proof_str();
				if (!proof->text)
					goto unreachable_doms_run_fail;
			}
	
			proof->next = item->proof;
			item->proof = proof;
			item->next =  res->items;
			res->items = item;
			(res->num_items)++;			
		}
	}

	mod->result = res;
	dta_table_free(table);
	dta_trans_destroy(&trans_list);

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

	return 0;

unreachable_doms_run_fail:
	if (table)
		dta_table_free(table);
	if (proof)
		sechk_proof_free(proof);
	if (item)
		sechk_item_free(item);
	sechk_result_free(res);
	dta_trans_destroy(&trans_list);
	return -1;
}

/* The free function frees the private data of a module */
void unreachable_doms_free(sechk_module_t *mod)
{
	unreachable_doms_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (unreachable_doms_data_t*)mod->data;
	if (datum) {
		if (datum->ctx_file_path)
			free(datum->ctx_file_path);
		if (datum->ctx_list_sz > 0) 
			free(datum->ctx_list);
	}

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a report section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief) */
int unreachable_doms_print_output(sechk_module_t *mod, policy_t *policy) 
{
	unreachable_doms_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int j, i = 0, type_idx = 0;

	if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	
	datum = (unreachable_doms_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i unreachable domains.\n", mod->result->num_items);
	}

	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
                for (item = mod->result->items; item; item = item->next) {
			i++;
                        i %= 4;
			
                        printf("%s%s", policy->types[item->item_id].name, (i&&item->next) ? ", " : "\n");
                }
                printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		/* default contexts */
		if (datum->ctx_list_sz > 0) {
			printf("Found %d domains in %s:\n", datum->ctx_list_sz, selinux_default_context_path());
                        for (j = 0; j < datum->ctx_list_sz; j++) {
                                type_idx = datum->ctx_list[j];
				printf("\t%s\n", policy->types[type_idx].name);
                        }
		}

		for (item = mod->result->items; item; item = item->next) {
			printf("\n%s", policy->types[item->item_id].name);
		     
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\n\t%s", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check.
 * You should not need to modify this function. */
sechk_result_t *unreachable_doms_get_result(sechk_module_t *mod) 
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

/* The unreachable_doms_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic */
unreachable_doms_data_t *unreachable_doms_data_new(void)
{
	unreachable_doms_data_t *datum = NULL;

	datum = (unreachable_doms_data_t*)calloc(1,sizeof(unreachable_doms_data_t));

	return datum;
}

/* Returns a string representing a proof of no valid transitions to a domain */
static char *build_no_trans_proof_str(void)
{
	char *str;

	str = malloc(APOL_STR_SZ + 32);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}

	sprintf(str, "No transitions to this domain\n");
	return str;
} 

/* Returns a string representing a proof of no common roles existing between domains */
static char *build_common_role_proof_str(const int src_idx, const int dst_idx, policy_t *policy)
{
	char *str;

	str = malloc(APOL_STR_SZ + 32);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	memset(str, 0x0, APOL_STR_SZ + 32);
		
	snprintf(str, APOL_STR_SZ + 32, "role <<role_r>> types %s\n\trole <<role_r>> types %s\n", 
		 policy->types[src_idx].name, policy->types[dst_idx].name);
	return str;
}

/* Parses default_contexts and adds source domains to datum->ctx_list */
static bool_t parse_default_contexts(const char *ctx_file_path, int **doms, int *domain_list_sz, policy_t *policy)
{
	int *domain_list = NULL, retv, src_dom_idx, str_sz, i, charno;
	FILE *ctx_file;
	char *line = NULL, *src_role = NULL, *src_dom = NULL, *dst_role = NULL, *dst_dom = NULL;
	size_t line_len = 0;
	bool_t uses_mls = FALSE;

	printf("Using default contexts: %s\n", ctx_file_path);
	ctx_file = fopen(ctx_file_path, "r");
	if (!ctx_file) {
		fprintf(stderr, "Error: opening default contexts file %s\n", ctx_file_path);
		goto parse_default_contexts_fail;
	}
	
	while(!feof(ctx_file)) {
		retv = getline(&line, &line_len, ctx_file);
		if (retv == -1) {
			if (feof(ctx_file)) {
				break;
			} else {
				fprintf(stderr, "Error: reading default contexts file\n");
				goto parse_default_contexts_fail;
			}
		}

		uses_mls = FALSE;
		str_sz = APOL_STR_SZ + 128;
		i = 0;

		/* source role */
		src_role = malloc(str_sz);
		if (!src_role) {
			fprintf(stderr, "Error: out of memory\n");
			goto parse_default_contexts_fail;
		}
		memset(src_role, 0x0, str_sz);
		charno = 0;
		while (line[i] != ':') {
			if (!isspace(line[i])) {
				src_role[i] = line[i];
				charno++;
			}
			i++;
		}
		i++; /* skip ':' */

		/* source type */
		src_dom = malloc(str_sz);
		if (!src_dom) {
			fprintf(stderr, "Error: out of memory\n");
			goto parse_default_contexts_fail;
		}
		memset(src_dom, 0x0, str_sz);
		charno = 0;
		while (1) {
			if(isspace(line[i]))
				break;
			/* Check for MLS */
			if(line[i] == ':') {
				uses_mls = TRUE;
				i++; /* skip ':' */
				while (!isspace(line[i]))
				       i++;
			}
			if (uses_mls)
				break;

			src_dom[charno] = line[i];
			charno++;
			i++;
		}

		/* dest role */
		dst_role = malloc(str_sz);
		if (!dst_role) {
			fprintf(stderr, "Error: out of memory\n");
			goto parse_default_contexts_fail;
		}
		memset(dst_role, 0x0, str_sz);
		charno = 0;
		while (line[i] != ':') {
			if (!isspace(line[i])) {
				dst_role[charno] = line[i];
				charno++;
			}
	
			i++;
		}
		i++; /* skip ':' */

		/* dest type */
		dst_dom = malloc(str_sz);
		if (!dst_dom) {
			fprintf(stderr, "Error: out of memory\n");
			goto parse_default_contexts_fail;
		}
		memset(dst_dom, 0x0, str_sz);
		charno = 0;
		while (line[i]) {
			if (uses_mls)
				if (line[i] == ':')
					break;

			if (!isspace(line[i]))
			    dst_dom[charno] = line[i];
			
			charno++;
			i++;
		}
		
		src_dom_idx = get_type_idx(src_dom, policy);
		if (is_valid_type_idx(src_dom_idx, policy)) {
			retv = add_i_to_a(src_dom_idx, domain_list_sz, &domain_list);
			if (retv < 0) {
				fprintf(stderr, "Error: adding domain index\n");
				goto parse_default_contexts_fail;
			}
		}
	}
	
	(*doms) = domain_list;
	free(src_role);
	free(src_dom);
	free(dst_role);
	free(dst_dom);
	return TRUE;
parse_default_contexts_fail:
	if (src_role)
		free(src_dom);
	if (src_dom)
		free(src_dom);
	if (dst_role)
		free(dst_role);
	if (dst_dom)
		free(dst_dom);
	return FALSE;
}

/* Returns true if type_idx is in datum->ctx_list */
static bool_t in_def_ctx(const int type_idx, unreachable_doms_data_t *datum)
{
	int retv;

	retv = find_int_in_array(type_idx, datum->ctx_list, datum->ctx_list_sz);
	if (retv > -1) 
		return TRUE;
        else
		return FALSE;
}

static int get_common_roles(int **common_roles, int *common_roles_sz, const int src_idx, const int dst_idx, policy_t *policy)
{
	int i, role_idx, roles_sz = 0;

	for (i = 0; i < policy->num_roles; i++) {
		role_idx = get_role_idx(policy->roles[i].name, policy);
		if (is_valid_role_idx(role_idx, policy)) {
			if (does_role_use_type(role_idx, src_idx, policy) &&
			    does_role_use_type(role_idx, dst_idx, policy))
				add_i_to_a(role_idx, &roles_sz, common_roles);
		}
	}
	
	*common_roles_sz = roles_sz;
	return *common_roles_sz;
}

/*
 * Determines whether there exists a user in policy that has a role in common_roles
 * Returns 0 if such a user is found
 * Returns 1 if no such user can be found
 * Returns -1 on error
 */
static int get_valid_user(const int role_idx, policy_t *policy)
{
	int user_idx;
	
	for (user_idx = 0; user_idx < policy->num_users; user_idx++) {
		if (is_valid_user_idx(user_idx, policy) && is_valid_role_idx(role_idx, policy)) {
			if (does_user_have_role(user_idx, role_idx, policy))
				return 0; /* success */
		} else {
			fprintf(stderr, "Error: invalid index\n");
			return -1;
		}
	}

	return 1;
}

/* 
 * Returns true if source domain and dest domain have a common role in policy
 * and if there is at least one user associated with this role
 */
static bool_t has_common_role(const int src_idx, const int dst_idx, policy_t *policy)
{
	int i, role_idx; 

	for (i = 0; i < policy->num_roles; i++) {
		role_idx = get_role_idx(policy->roles[i].name, policy);
		if (does_role_use_type(role_idx, src_idx, policy) &&
		    does_role_use_type(role_idx, dst_idx, policy)) {
			/* A common role exists; check if at least 1 user */
			if (get_valid_user(role_idx, policy))
				return TRUE;
		}
	}
	
	return FALSE;
}

/*
 * Returns a string used in proofs when no users can be found
 * having a common role.  
 */
static char *build_no_user_proof_str(const int role_idx, policy_t *policy)
{
	char *str = NULL, *role_name = NULL;
	int str_sz = APOL_STR_SZ + 128;

	str = malloc(str_sz);
	if (!str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	memset(str, 0x0, str_sz);

	if (get_role_name(role_idx, &role_name, policy) == -1) {
		fprintf(stderr, "Error: getting role name\n");
		free(str);
		return NULL;
	}

	snprintf(str, str_sz, "No users were found having role %s:\n\tuser <<user_u>> roles %s\n",
		 role_name, role_name);
	free(role_name);
	return str;		       
}

/* 
 * Returns a string representing an invalid domain transition
 * Stolen from the inc_dom_trans sechecker module
 */
static char *build_invalid_trans_proof_str(dta_trans_t *trans, policy_t *policy)
{
	unsigned char test_result;
	char *str = NULL, *tmp_str = NULL;
	int i, str_sz, tmp_str_sz;

	if (!trans || !policy) 
		return NULL;
	
	test_result = 0;
	if (trans->type_trans_rule != -1)
		test_result |= SECHK_INC_DOM_TRANS_HAS_TT;
	if (trans->ep_rules)
		test_result |= SECHK_INC_DOM_TRANS_HAS_EP;
	if (trans->exec_rules)
		test_result |= SECHK_INC_DOM_TRANS_HAS_EXEC;
	if (trans->proc_trans_rules)
		test_result |= SECHK_INC_DOM_TRANS_HAS_TRANS;
	
	str_sz = APOL_STR_SZ + 128;
	tmp_str_sz = str_sz + 1024;
	tmp_str = malloc(tmp_str_sz);
	if (!tmp_str) {
		fprintf(stderr, "Error: out of memory\n");
		return NULL;
	}
	
	memset(tmp_str, 0x0, tmp_str_sz);
	snprintf(tmp_str, tmp_str_sz, "From %s to %s via %s\n",
	       policy->types[trans->start_type].name,
	       trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>",
	       trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
	append_str(&str, &str_sz, tmp_str);

	memset(tmp_str, 0x0, tmp_str_sz);
	snprintf(tmp_str, tmp_str_sz, "\t%s: allow %s %s : process transition; ",
	       (test_result & SECHK_INC_DOM_TRANS_HAS_TRANS)?"has":"missing",
	       policy->types[trans->start_type].name,
	       trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>");
	append_str(&str, &str_sz, tmp_str);

	if (!is_binary_policy(policy)) {
		fflush(stdout);
		if (trans->proc_trans_rules)
			append_str(&str, &str_sz, "[");
		for (i = 0; i < trans->num_proc_trans_rules; i++) {
			memset(tmp_str, 0x0, tmp_str_sz);
			if (is_valid_av_rule_idx(trans->proc_trans_rules[i], 1, policy)) {
				snprintf(tmp_str, tmp_str_sz, "%s%ld", i>0?", ":"", policy->av_access[trans->proc_trans_rules[i]].lineno);
				append_str(&str, &str_sz, tmp_str);
			}
		}
		if (trans->proc_trans_rules)
			append_str(&str, &str_sz, "]");
	}
	
	memset(tmp_str, 0x0, tmp_str_sz);
	snprintf(tmp_str, tmp_str_sz, "\n\t%s: allow %s %s : file entrypoint; ",
	       (test_result & SECHK_INC_DOM_TRANS_HAS_EP)?"has":"missing",
	       trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>",
	       trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
	append_str(&str, &str_sz, tmp_str);

	if (!is_binary_policy(policy)) {
		if (trans->ep_rules)
			append_str(&str, &str_sz, "[");
		for (i = 0; i < trans->num_ep_rules; i++) {
			memset(tmp_str, 0x0, tmp_str_sz);
			if (is_valid_av_rule_idx(trans->ep_rules[i], 1, policy)) {
				snprintf(tmp_str, tmp_str_sz, "%s%ld", i>0?", ":"", policy->av_access[trans->ep_rules[i]].lineno);
				append_str(&str, &str_sz, tmp_str);
			}
		}
		if (trans->ep_rules)
			append_str(&str, &str_sz, "]");
	}

	memset(tmp_str, 0x0, tmp_str_sz);
	snprintf(tmp_str, tmp_str_sz, "\n\t%s: allow %s %s : file execute; ",
	       (test_result & SECHK_INC_DOM_TRANS_HAS_EXEC)?"has":"missing",
	       policy->types[trans->start_type].name,
	       trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
	append_str(&str, &str_sz, tmp_str);

	if (!is_binary_policy(policy)) {
		if (trans->exec_rules)
			append_str(&str, &str_sz, "[");
		for (i = 0; i < trans->num_exec_rules; i++) {
			memset(tmp_str, 0x0, tmp_str_sz);
			if (is_valid_av_rule_idx(trans->exec_rules[i], 1, policy)) {
				snprintf(tmp_str, tmp_str_sz, "%s%ld", i>0?", ":"", policy->av_access[trans->exec_rules[i]].lineno);
				append_str(&str, &str_sz, tmp_str);
			}			
		}
		if (trans->exec_rules)
			append_str(&str, &str_sz, "]");
	}

	append_str(&str, &str_sz, "\n");
	if (test_result & SECHK_INC_DOM_TRANS_HAS_TT) {
		memset(tmp_str, 0x0, tmp_str_sz);
		snprintf(tmp_str, tmp_str_sz, "\thas: type_transition %s %s : process %s; ",
		       policy->types[trans->start_type].name,
		       policy->types[trans->ep_type].name,
		       policy->types[trans->end_type].name);
		append_str(&str, &str_sz, tmp_str);
		if (!is_binary_policy(policy)) {
			memset(tmp_str, tmp_str_sz, 0x0);
			snprintf(tmp_str, tmp_str_sz, "[%ld]", policy->te_trans[trans->type_trans_rule].lineno);
			append_str(&str, &str_sz, tmp_str);
		}
		append_str(&str, &str_sz, "\n");
	}
	append_str(&str, &str_sz, "\n");
	
	free(tmp_str);
	return str;
}

/*
 * Returns true if domain with index ep_type has
 * a valid role transition. 
 * Valid role transitions are defined as: 
 *   having a role transition rule of the form:   
 *       role_transition <<r1>> <<ep_type>> <<r2>>
 *   having a role allow rule permitting the two roles in the
 *   role transition rule above:
 *       allow <<r1>> <<r2>>
 *   having a user associated with both roles above:
 *       user <<u1>> roles { <<r1>> <<r2>> }
 */
static bool_t has_role_trans(const int ep_type, policy_t *policy)
{
	rbac_query_t *rbac_query = NULL;
	rbac_results_t rbac_results;
	ta_item_t *src_r, *tgt_r;
	int i, role_allow_idx;

	rbac_query = (rbac_query_t *) malloc(sizeof(rbac_query_t));
	if (!rbac_query) {
		fprintf(stderr, "Error: out of memory\n");
		return FALSE;
	}
	init_rbac_query(rbac_query);

	/* search for role transitions by ep_type */
	rbac_query->src = NULL;
	rbac_query->tgt_role = NULL;
	rbac_query->tgt_ta = policy->types[ep_type].name;
	rbac_query->use_regex = FALSE;
	rbac_query->indirect = TRUE;
	rbac_query->rule_select |= RBACQ_BOTH;

	init_rbac_results(&rbac_results);

	if (search_rbac_rules(rbac_query, &rbac_results, policy) < 0) {
		fprintf(stderr, "Error during rbac search: %s\n", rbac_results.errmsg);
		free(rbac_query);
		return FALSE;
	}
	
	/* check if any role transitions/role allow rules exist */
	if (rbac_results.num_role_trans == 0 || rbac_results.num_role_allows == 0) {
		free(rbac_query);
		return FALSE;
	}

	/* verify that a role allow rule exists, user exists having src_role */
	for (i = 0; i < rbac_results.num_role_allows; i++) {
		role_allow_idx = rbac_results.role_allows[i];

		/* see if a user exists having roles in src_r, tgt_r */
		for (src_r = policy->role_allow[role_allow_idx].src_roles; src_r; src_r = src_r->next) {
			for (tgt_r = policy->role_allow[role_allow_idx].tgt_roles; tgt_r; tgt_r = tgt_r->next) {
				if (roles_have_user(src_r, tgt_r, policy)) {
					free(rbac_query);
					return TRUE;
				}				
			}
		}		
	}

        free(rbac_query);
	return FALSE;
}

/*
 * Returns true of roles src_r and tgt_r have a common user
 */
static bool_t roles_have_user(ta_item_t *src_r, ta_item_t *tgt_r, policy_t *policy)
{
	ta_item_t *src = NULL, *tgt = NULL;
	int i;

	for (src = src_r; src; src = src->next) {
		for (tgt = tgt_r; tgt; tgt = tgt->next) {
			/* see if a user exists with roles src, tgt */
			for (i = 0; i < policy->num_users; i++) {
				if (is_valid_user_idx(i, policy)) {
					if (does_user_have_role(i, src->idx, policy) && does_user_have_role(i, tgt->idx, policy))
						return TRUE;
				} 	
			}
		}
	}

	return FALSE;
}
