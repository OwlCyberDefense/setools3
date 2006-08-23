/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "inc_dom_trans.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "inc_dom_trans";

/* The register function registers all of a module's functions
 * with the library. */
int inc_dom_trans_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "domains with partial transition permissions";
	mod->detailed_description =
"--------------------------------------------------------------------------------\n"
"This module finds potential domain transitions missing key permissions.  A valid\n"
"domain transition requires the following.\n"
"\n"
"   1) the starting domain can transition to the end domain for class process\n"
"   2) the end domain has some type as an entrypoint\n"
"   3) the starting domain can execute that extrypoint type\n"
"   4) (optional) a type transition rules specifying these three types\n";
	mod->opt_description =
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_MED;
	/* Dependencies */
	apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_domains"));

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_dom_trans_init;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_dom_trans_run;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_dom_trans_data_free;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_dom_trans_print_output;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
                ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &inc_dom_trans_get_result;
        if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
                ERR(NULL, "%s", strerror(ENOMEM));
                return -1;
        }

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_dom_trans_init(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_dom_trans_data_t *datum = NULL;

	if (!mod || !policy) {
                ERR(policy, "%s", "Invalid paramaters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = inc_dom_trans_data_new();
	if (!datum) {
                ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
	mod->data = datum;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int inc_dom_trans_run(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_dom_trans_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i, j, k, retv;
        sechk_module_t *mod_ptr = NULL;
        sechk_run_fn_t run_fn = NULL;
        sechk_result_t *(*get_result_fn)(sechk_module_t *) = NULL;
	sechk_result_t *find_domains_res = NULL;
	apol_domain_trans_analysis_t *domain_trans = NULL;
	apol_vector_t *domain_vector = NULL, *role_vector = NULL, *user_vector = NULL, *rbac_vector = NULL;
	apol_user_query_t *user_query = NULL;
	apol_role_trans_query_t *role_trans_query = NULL;
	char *buff = NULL;
	int buff_sz;

	if (!mod || !policy) {
                ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (inc_dom_trans_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
                ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto inc_dom_trans_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
        if ( !(res->items = apol_vector_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
                goto inc_dom_trans_run_fail;
        }

	if ( apol_policy_domain_trans_table_build(policy) < 0 ) {
                ERR(policy, "%s", "Unable to build domain transition table");
		goto inc_dom_trans_run_fail;
	}

	if ( !(domain_trans = apol_domain_trans_analysis_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto inc_dom_trans_run_fail;
	}

	if ( !(user_query = apol_user_query_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto inc_dom_trans_run_fail;
	}

	if ( !(role_trans_query = apol_role_trans_query_create()) ) {
                ERR(policy, "%s", strerror(ENOMEM));
		goto inc_dom_trans_run_fail;
	}

        run_fn = sechk_lib_get_module_function("find_domains", SECHK_MOD_FN_RUN, mod->parent_lib);
        if (!run_fn)
                goto inc_dom_trans_run_fail;

        retv = run_fn((mod_ptr = sechk_lib_get_module("find_domains", mod->parent_lib)), policy);
        if (retv) {
		ERR(policy, "%s", "Unable to find module find_domains");
                goto inc_dom_trans_run_fail;
        }

        get_result_fn = sechk_lib_get_module_function("find_domains", "get_result", mod->parent_lib);
        if ( !(find_domains_res = get_result_fn(mod_ptr)) ) {
		ERR(policy, "%s", "Unable to get results from module find_domains");
                goto inc_dom_trans_run_fail;
        }

	domain_vector = (apol_vector_t *)find_domains_res->items;

	for (i=0;i<apol_vector_get_size(domain_vector);i++) {
		qpol_type_t *domain = NULL;
		char *domain_name = NULL;
		apol_vector_t *domain_trans_vector;

		item = apol_vector_get_element(domain_vector, i);
		domain = item->item;
		qpol_type_get_name(policy->qh, policy->p, domain, &domain_name);
		apol_domain_trans_analysis_set_start_type(policy, domain_trans, domain_name);
		apol_domain_trans_analysis_set_direction(policy, domain_trans, APOL_DOMAIN_TRANS_DIRECTION_FORWARD);
		apol_domain_trans_analysis_set_valid(policy, domain_trans, APOL_DOMAIN_TRANS_SEARCH_BOTH);
		apol_domain_trans_analysis_do(policy, domain_trans, &domain_trans_vector);

		for (j=0;j<apol_vector_get_size(domain_trans_vector);j++) {
			apol_domain_trans_result_t *dtr;
			qpol_type_t *start;
			qpol_type_t *ep;
			qpol_type_t *end;
			char *start_name;
			char *end_name;
			char *ep_name;
			int result;
			bool_t ok;

			ok = FALSE;
			dtr = apol_vector_get_element(domain_trans_vector, j);
			start = apol_domain_trans_result_get_start_type(dtr);
			ep = apol_domain_trans_result_get_entrypoint_type(dtr);
			end = apol_domain_trans_result_get_end_type(dtr);
			qpol_type_get_name(policy->qh, policy->p, start, &start_name);
			qpol_type_get_name(policy->qh, policy->p, end, &end_name);
			qpol_type_get_name(policy->qh, policy->p, ep, &ep_name);

			result = apol_domain_trans_table_verify_trans(policy, start, ep, end);
			if ( !result ) {
				apol_get_role_by_query(policy, NULL, &role_vector);
				for (k=0; (k<apol_vector_get_size(role_vector)) && !ok; k++) {
					qpol_role_t *role;
					char *role_name;

					role = apol_vector_get_element(role_vector, k);
					qpol_role_get_name(policy->qh, policy->p, role, &role_name);
					if ( apol_role_has_type(policy, role, start) || apol_role_has_type(policy, role, end) ) {
						apol_user_query_set_role(policy, user_query, role_name);
						apol_get_user_by_query(policy, user_query, &user_vector);
						if ( apol_vector_get_size(user_vector) > 0 ) {
							ok = TRUE;
						}
					}
				}
				if (!ok) {
					apol_role_trans_query_set_target(policy, role_trans_query, ep_name, 1);
					apol_get_role_trans_by_query(policy, role_trans_query, &rbac_vector);
					for ( k = 0; ( k < apol_vector_get_size(rbac_vector)) && !ok ; k++ ) {
						qpol_role_trans_t *role_trans;
						qpol_role_t *source_role;
						qpol_role_t *default_role;
						char *source_role_name;
						char *default_role_name;

						role_trans = apol_vector_get_element(rbac_vector, k);
						qpol_role_trans_get_source_role(policy->qh, policy->p, role_trans, &source_role);
						qpol_role_trans_get_default_role(policy->qh, policy->p, role_trans, &default_role);
						qpol_role_get_name(policy->qh, policy->p, source_role, &source_role_name);
						qpol_role_get_name(policy->qh, policy->p, default_role, &default_role_name);

						if ( apol_role_has_type(policy, source_role, start) &&
						     apol_role_has_type(policy, default_role, end) ) {
							apol_user_query_set_role(policy, user_query, source_role_name);
							apol_get_user_by_query(policy, user_query, &user_vector);
							if ( apol_vector_get_size(user_vector) > 0 ) {
								apol_user_query_set_role(policy, user_query, default_role_name);
								apol_get_user_by_query(policy, user_query, &user_vector);
								if ( apol_vector_get_size(user_vector) > 0 ) {
									ok = TRUE;
								}
							}
						}
					}
				}
				if ( !ok ) {
					item = sechk_item_new(NULL);
					if ( !item ) {
						ERR(policy, "%s", strerror(ENOMEM));
						goto inc_dom_trans_run_fail;
					}
					item->test_result = 1;
					item->item = (void *)dtr;
					if ( apol_vector_append(res->items, (void *)item) < 0 ) {
						ERR(policy, "%s", strerror(ENOMEM));
						goto inc_dom_trans_run_fail;
					}
				}
			}
			else  {
				item = sechk_item_new(NULL);
				if ( !item ) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_dom_trans_run_fail;
				}
				item->test_result = 1;
				item->item = (void *)dtr;
				if ( apol_vector_append(res->items, (void *)item) < 0 ) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_dom_trans_run_fail;
				}
				if ( !(item->proof = apol_vector_create()) ) {
			                ERR(policy, "%s", strerror(ENOMEM));
					goto inc_dom_trans_run_fail;
				}

				if ( result & APOL_DOMAIN_TRANS_RULE_PROC_TRANS ) {
					proof = sechk_proof_new(NULL);
					proof->type = SECHK_ITEM_OTHER;
					buff = NULL;
					buff_sz = 10 + strlen("allow  : process transition;") + strlen(start_name) + strlen(end_name);
					buff = (char *)calloc(buff_sz, sizeof(char));
					if ( !buff ) {
				                ERR(policy, "%s", strerror(ENOMEM));
						goto inc_dom_trans_run_fail;
					}
					snprintf(buff, buff_sz, "allow %s %s : process transition;", start_name, end_name);
					proof->text = strdup(buff);
					if ( !proof->text) {
				                ERR(policy, "%s", strerror(ENOMEM));
						goto inc_dom_trans_run_fail;
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
						goto inc_dom_trans_run_fail;
					}
				}

                                if ( result & APOL_DOMAIN_TRANS_RULE_EXEC ) {
                                        proof = sechk_proof_new(NULL);
                                        proof->type = SECHK_ITEM_OTHER;
                                        buff = NULL;
                                        buff_sz = 10 + strlen("allow  : file execute;") + strlen(start_name) + strlen(ep_name);
                                        buff = (char *)calloc(buff_sz, sizeof(char));
                                        if ( !buff ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        snprintf(buff, buff_sz, "allow %s %s : file execute;", start_name, ep_name);
                                        proof->text = strdup(buff);
                                        if ( !proof->text) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        if (apol_vector_append(item->proof, (void *)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                }

                                if ( result & APOL_DOMAIN_TRANS_RULE_ENTRYPOINT ) {
                                        proof = sechk_proof_new(NULL);
                                        proof->type = SECHK_ITEM_OTHER;
                                        buff = NULL;
                                        buff_sz = 10 + strlen("allow  : file entrypoint;") + strlen(end_name) + strlen(ep_name);
                                        buff = (char *)calloc(buff_sz, sizeof(char));
                                        if ( !buff ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        snprintf(buff, buff_sz, "allow %s %s : file entrypoint;", end_name, ep_name);
                                        proof->text = strdup(buff);
                                        if ( !proof->text) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        if (apol_vector_append(item->proof, (void *)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                }

                                if ( result & APOL_DOMAIN_TRANS_RULE_TYPE_TRANS ) {
                                        proof = sechk_proof_new(NULL);
                                        proof->type = SECHK_ITEM_OTHER;
                                        buff = NULL;
                                        buff_sz = 10 + strlen("type_transition  :process ;") + strlen(start_name) + strlen(end_name) + strlen(ep_name);
                                        buff = (char *)calloc(buff_sz, sizeof(char));
                                        if ( !buff ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        snprintf(buff, buff_sz, "type_transition %s %s : process %s;", start_name, ep_name, end_name);
                                        proof->text = strdup(buff);
                                        if ( !proof->text) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        if (apol_vector_append(item->proof, (void *)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                }

                                if ( result & APOL_DOMAIN_TRANS_RULE_SETEXEC ) {
                                        proof = sechk_proof_new(NULL);
                                        proof->type = SECHK_ITEM_OTHER;
                                        buff = NULL;
                                        buff_sz = 10 + strlen("allow  self : process setexec;") + strlen(start_name);
                                        buff = (char *)calloc(buff_sz, sizeof(char));
                                        if ( !buff ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        snprintf(buff, buff_sz, "allow %s self : process setexec;", start_name);
                                        proof->text = strdup(buff);
                                        if ( !proof->text) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                        if (apol_vector_append(item->proof, (void *)proof) < 0 ) {
				                ERR(policy, "%s", strerror(ENOMEM));
                                                goto inc_dom_trans_run_fail;
                                        }
                                }
			}
		}
	}

	mod->result = res;
	apol_domain_trans_analysis_destroy(&domain_trans);
	apol_user_query_destroy(&user_query);
	apol_role_trans_query_destroy(&role_trans_query);
	return 0;

inc_dom_trans_run_fail:
	sechk_item_free(item);
	return -1;
}

/* The free function frees the private data of a module */
void inc_dom_trans_data_free(void *data)
{
	free(data);
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_dom_trans_print_output(sechk_module_t *mod, apol_policy_t *policy)
{
	inc_dom_trans_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j = 0, num_items;

	if (!mod || !policy) {
                ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
                ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	datum = (inc_dom_trans_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
                ERR(policy, "%s", "Module has not been run");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i incomplete transitions.\n", num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
/*
		printf("\nStart Type\t\tEntrypoint\t\tEnd Type\t\tMissing Rules\n");
		printf("----------\t\t----------\t\t--------\t\t-------------\n");
*/
		printf("\n");
		for (i=0;i<num_items;i++) {
			qpol_type_t *start;
			qpol_type_t *end;
			qpol_type_t *ep;
			char *start_name, *end_name, *ep_name;
			apol_domain_trans_result_t *dtr;

			item = apol_vector_get_element(mod->result->items, i);
                        dtr = item->item;
                        start = apol_domain_trans_result_get_start_type(dtr);
                        ep = apol_domain_trans_result_get_entrypoint_type(dtr);
                        end = apol_domain_trans_result_get_end_type(dtr);
                        qpol_type_get_name(policy->qh, policy->p, start, &start_name);
                        qpol_type_get_name(policy->qh, policy->p, end, &end_name);
                        qpol_type_get_name(policy->qh, policy->p, ep, &ep_name);
			printf("%s -> %s\tentrypoint: %s\n", start_name, end_name, ep_name);
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type) */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (i=0;i<num_items;i++) {
                        qpol_type_t *start;
                        qpol_type_t *end;
                        qpol_type_t *ep;
                        char *start_name, *end_name, *ep_name;
                        apol_domain_trans_result_t *dtr;

			item = apol_vector_get_element(mod->result->items, i);
			dtr = item->item;
                        start = apol_domain_trans_result_get_start_type(dtr);
                        ep = apol_domain_trans_result_get_entrypoint_type(dtr);
                        end = apol_domain_trans_result_get_end_type(dtr);
                        qpol_type_get_name(policy->qh, policy->p, start, &start_name);
                        qpol_type_get_name(policy->qh, policy->p, end, &end_name);
                        qpol_type_get_name(policy->qh, policy->p, ep, &ep_name);
                        printf("%s -> %s\tentrypoint: %s\n\tMissing:\n", start_name, end_name, ep_name);
			for (j=0;j<apol_vector_get_size(item->proof);j++) {
				sechk_proof_t *proof;

				proof = apol_vector_get_element(item->proof, j);
				if ( proof ) {
					printf("\t%s\n", proof->text);
				}
			}
		}
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_dom_trans_get_result(sechk_module_t *mod)
{

	if (!mod) {
                ERR(NULL, "%s", "Invalid parameters");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(NULL, "Wrong module (%s)", mod->name);
		return NULL;
	}

	return mod->result;
}

/* The inc_dom_trans_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module.  */
inc_dom_trans_data_t *inc_dom_trans_data_new(void)
{
	inc_dom_trans_data_t *datum = NULL;

	datum = (inc_dom_trans_data_t*)calloc(1,sizeof(inc_dom_trans_data_t));

	return datum;
}
