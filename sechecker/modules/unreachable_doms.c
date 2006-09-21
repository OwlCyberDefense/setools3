/**
 *  @file unreachable_doms.c
 *  Implementation of the unreachable domains module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author David Windsor <dwindsor@tresys.com>
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <config.h>

#include "unreachable_doms.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

bool_t parse_default_contexts(const char *ctx_file_path, apol_vector_t **ctx_vector, apol_policy_t *policy);
bool_t in_isid_ctx(char *type_name, apol_policy_t *policy);
bool_t in_def_ctx(char *type_name, unreachable_doms_data_t *datum);
/* for some reason we have to define this here to remove compile warnings */
ssize_t getline(char **lineptr, size_t *n, FILE *stream);

/* This string is the name  f the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "unreachable_doms";

int unreachable_doms_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "unreachable domains";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all domains in a policy which are unreachable.  A domain is\n"
		"unreachable if any of the following apply:\n"
		"1) There is insufficient type enforcement policy to allow a transition,\n"
		"2) There is insufficient RBAC policy to allow a transition,\n"
		"3) There are no users with proper roles to allow a transition.\n"
		"However, if any of the above rules indicate an unreachable domain, yet the\n"
		"domain appears in the system default contexts file, it is considered reachable.\n";
	mod->opt_description =
		"  Module requirements:\n"
		"    source policy\n"
		"    default contexts file\n"
		"  Module dependencies:\n"
		"    find_domains module\n"
		"    inc_dom_trans module\n"
		"  Module options:\n"
		"    none\n";
	mod->severity = SECHK_SEV_MED;

	/* assign dependencies */
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_domains")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if ( apol_vector_append(mod->dependencies, sechk_name_value_new("module", "inc_dom_trans")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_init;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_run;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data_free = unreachable_doms_data_free;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = unreachable_doms_print;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int unreachable_doms_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	unreachable_doms_data_t *datum = NULL;
	bool_t retv;
	const char *ctx_file_path = NULL;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = unreachable_doms_data_new();
	if (!datum) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	mod->data = datum;

	/* Parse default contexts file */
	ctx_file_path = selinux_default_context_path();
	if ( !(datum->ctx_vector = apol_vector_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if (!ctx_file_path) {
		ERR(policy, "%s", "Unable to find default contexts file");
		errno = ENOENT;
		return -1;
	} else {
		retv = parse_default_contexts(ctx_file_path, &datum->ctx_vector, policy);
		if (!retv) {
			ERR(policy, "%s", "Unable to parse default contexts file");
			errno = EIO;
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
 *   1 The module "failed"		- some negative results found */
int unreachable_doms_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	unreachable_doms_data_t *datum;
	sechk_name_value_t *dep = NULL;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t retv, i, j, k;
	bool_t found_valid_trans, found_invalid_trans;
	sechk_mod_fn_t run_fn = NULL;
	sechk_result_t *find_domains_res = NULL, *inc_dom_trans_res = NULL;
	apol_vector_t *dom_vector = NULL, *idt_vector = NULL, *role_vector = NULL, *rbac_vector = NULL, *user_vector = NULL;
	apol_user_query_t *user_query = NULL;
	apol_role_trans_query_t *role_trans_query = NULL;
	apol_domain_trans_analysis_t *dta = NULL;
	int error = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (unreachable_doms_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if ( !(res->items = apol_vector_create()) ) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}

	if ( !(dta = apol_domain_trans_analysis_create()) ) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}

	if ( !(user_query = apol_user_query_create()) ) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}
	if ( !(role_trans_query = apol_role_trans_query_create()) ) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto unreachable_doms_run_fail;
	}

	/* run dependencies and get results */
	for (i=0;i<apol_vector_get_size(mod->dependencies);i++) {
		dep = apol_vector_get_element(mod->dependencies, i);
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, mod->parent_lib);
		run_fn(sechk_lib_get_module(dep->value, mod->parent_lib), policy, NULL);
	}

	find_domains_res = sechk_lib_get_module_result("find_domains", mod->parent_lib);
	if (!find_domains_res) {
		error = errno;
		ERR(policy, "%s", "Unable to get results for module find_domains");
		goto unreachable_doms_run_fail;
	}
	dom_vector = (apol_vector_t *)find_domains_res->items;

	inc_dom_trans_res = sechk_lib_get_module_result("inc_dom_trans", mod->parent_lib);
	if (!inc_dom_trans_res) {
		error = errno;
		ERR(policy, "%s", "Unable to get results for module inc_dom_trans");
		goto unreachable_doms_run_fail;
	}
	idt_vector = (apol_vector_t *)inc_dom_trans_res->items;

	/* first search incomplete domain transitions:
		those domains with no other domains transitioning to them are unreachable */
	for ( i = 0; i < apol_vector_get_size(idt_vector); i++ ) {
		apol_domain_trans_result_t *dtr;
		apol_vector_t *rev_dtr_vector;
		qpol_type_t *end_type;
		char *end_name;

		item = apol_vector_get_element(idt_vector, i);
		dtr = item->item;
		end_type = apol_domain_trans_result_get_end_type(dtr);
		qpol_type_get_name(policy->p, end_type, &end_name);

		apol_domain_trans_table_reset(policy);
		apol_domain_trans_analysis_set_start_type(policy, dta, end_name);
		apol_domain_trans_analysis_set_direction(policy, dta, APOL_DOMAIN_TRANS_DIRECTION_REVERSE);
		retv = apol_domain_trans_analysis_do(policy, dta, &rev_dtr_vector);
		if (retv < 0) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto unreachable_doms_run_fail;
		}

		found_valid_trans = FALSE;
		if ( apol_vector_get_size(rev_dtr_vector) > 0 ) found_valid_trans = TRUE;

		/* we did not find a valid transition to this domain */
		if (!found_valid_trans) {
			if (in_isid_ctx(end_name, policy))
				break;

			item = NULL;
			for (j=0;j<apol_vector_get_size(res->items);j++) {
				sechk_item_t *res_item;
				qpol_type_t *res_type;
				char *res_type_name;

				res_item = apol_vector_get_element(res->items, j);
				res_type = res_item->item;
				qpol_type_get_name(policy->p, res_type, &res_type_name);
				if (!strcmp(res_type_name, end_name)) item = res_item;
			}
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}

				item->item = (void *)end_type;
				item->test_result = 1;
				if ( apol_vector_append(res->items, (void*)item) < 0 ) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
			proof->type = SECHK_ITEM_TYPE;
			proof->text = strdup("There is insufficient TE policy for a transition to this domain to occur");
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
			if ( !item->proof ) {
				if ( !(item->proof = apol_vector_create()) ) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}
			}
			if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
		}
	}


	/* for all domains: check to see if a valid transition to this domain exists */
	for (i = 0; i < apol_vector_get_size(dom_vector); i++) {
		apol_vector_t *rev_dtr_vector;
		qpol_type_t *dom;
		char *dom_name;

		item = apol_vector_get_element(dom_vector, i);
		dom = (qpol_type_t *)item->item;
		qpol_type_get_name(policy->p, dom, &dom_name);

		apol_domain_trans_table_reset(policy);
		apol_domain_trans_analysis_set_start_type(policy, dta, dom_name);
		apol_domain_trans_analysis_set_direction(policy, dta, APOL_DOMAIN_TRANS_DIRECTION_REVERSE);
		retv = apol_domain_trans_analysis_do(policy, dta, &rev_dtr_vector);
		if (retv) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto unreachable_doms_run_fail;
		}

		/* try to find a valid transition to this domain */
		found_valid_trans = FALSE;
		found_invalid_trans = FALSE;
		for (j = 0; j < apol_vector_get_size(rev_dtr_vector); j++ ) {
			/* we re-verify that this entry is valid for sanity's sake */
			qpol_type_t *start = NULL, *end = NULL, *ep = NULL;
			char *start_name, *end_name, *ep_name;
			apol_domain_trans_result_t *rev_dtr;
			int result;

			rev_dtr = apol_vector_get_element(rev_dtr_vector, j);
			start = apol_domain_trans_result_get_start_type(rev_dtr);
			ep = apol_domain_trans_result_get_entrypoint_type(rev_dtr);
			end = apol_domain_trans_result_get_end_type(rev_dtr);
			qpol_type_get_name(policy->p, start, &start_name);
			qpol_type_get_name(policy->p, end, &end_name);
			qpol_type_get_name(policy->p, ep, &ep_name);
			result = apol_domain_trans_table_verify_trans(policy, start, ep, end);

			if ( apol_domain_trans_result_is_trans_valid(rev_dtr) ) {
				/* a valid transition exists - verify that a common role exists */
				apol_get_role_by_query(policy, NULL, &role_vector);
				for (k=0; (k<apol_vector_get_size(role_vector)) && !found_valid_trans; k++) {
					qpol_role_t *role;
					char *role_name;

					role = apol_vector_get_element(role_vector, k);
					qpol_role_get_name(policy->p, role, &role_name);
					if ( apol_role_has_type(policy, role, start) || apol_role_has_type(policy, role, end) ) {
						apol_user_query_set_role(policy, user_query, role_name);
						apol_get_user_by_query(policy, user_query, &user_vector);
						if ( apol_vector_get_size(user_vector) > 0 ) {
							found_valid_trans = TRUE;
						}
					}
				}
				if ( !found_valid_trans ) {
					apol_role_trans_query_set_target(policy, role_trans_query, ep_name, 1);
					apol_get_role_trans_by_query(policy, role_trans_query, &rbac_vector);
					for ( k = 0; ( k < apol_vector_get_size(rbac_vector)) && !found_valid_trans ; k++ ) {
						qpol_role_trans_t *role_trans;
						qpol_role_t *source_role;
						qpol_role_t *default_role;
						char *source_role_name;
						char *default_role_name;

						role_trans = apol_vector_get_element(rbac_vector, k);
						qpol_role_trans_get_source_role(policy->p, role_trans, &source_role);
						qpol_role_trans_get_default_role(policy->p, role_trans, &default_role);
						qpol_role_get_name(policy->p, source_role, &source_role_name);
						qpol_role_get_name(policy->p, default_role, &default_role_name);

						if ( apol_role_has_type(policy, source_role, start) &&
								apol_role_has_type(policy, default_role, end) ) {
							apol_user_query_set_role(policy, user_query, source_role_name);
							apol_get_user_by_query(policy, user_query, &user_vector);
							if ( apol_vector_get_size(user_vector) > 0 ) {
								apol_user_query_set_role(policy, user_query, default_role_name);
								apol_get_user_by_query(policy, user_query, &user_vector);
								if ( apol_vector_get_size(user_vector) > 0 ) {
									found_valid_trans = TRUE;
								}
							}
						}
					}
				}
			}
		}

		/* if we haven't found a valid transition to this type, check default ctxs */
		if (!found_valid_trans && !in_def_ctx(dom_name, datum)) {
			if (in_isid_ctx(dom_name, policy))
				break;

			item = NULL;
			for (j=0;j<apol_vector_get_size(res->items);j++) {
				sechk_item_t *res_item;
				qpol_type_t *res_type;
				char *res_type_name;

				res_item = apol_vector_get_element(res->items, j);
				res_type = res_item->item;
				qpol_type_get_name(policy->p, res_type, &res_type_name);
				if (!strcmp(res_type_name, dom_name)) item = res_item;
			}
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}

				item->item = (void *)dom;
				item->test_result = 1;
				if ( apol_vector_append(res->items, (void*)item) < 0 ) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}
			}
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
			proof->type = SECHK_ITEM_TYPE;
			proof->text = strdup("There is insufficient TE policy for a transition to this domain to occur");
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
			if ( !item->proof ) {
				if ( !(item->proof = apol_vector_create()) ) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto unreachable_doms_run_fail;
				}
			}
			if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto unreachable_doms_run_fail;
			}
		}
	}

	mod->result = res;
	apol_domain_trans_analysis_destroy(&dta);
	apol_user_query_destroy(&user_query);
	apol_role_trans_query_destroy(&role_trans_query);
	return 0;

unreachable_doms_run_fail:
	if (proof)
		sechk_proof_free(proof);
	if (item)
		sechk_item_free(item);
	errno = error;
	return -1;
}

/* The free function frees the private data of a module */
void unreachable_doms_data_free(void *data)
{
	free(data);
}

/* The print function generates the text and prints the results to stdout. */
int unreachable_doms_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	unreachable_doms_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k, l, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy){
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = (unreachable_doms_data_t*)mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i unreachable domains.\n", num_items);
	}

	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i=0;i<num_items;i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t *)item->item;
			qpol_type_get_name(policy->p, type, &type_name);
			printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		if (apol_vector_get_size(datum->ctx_vector) > 0 ) {
			printf("Found %d domains in %s:\n", apol_vector_get_size(datum->ctx_vector), selinux_default_context_path());
			for (j = 0; j < apol_vector_get_size(datum->ctx_vector); j++) {
				type_name = apol_vector_get_element(datum->ctx_vector, j);
				printf("\t%s\n", type_name);
			}
		}

		printf("\n");
		for (k=0;k<num_items;k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if ( item ) {
				type = item->item;
				qpol_type_get_name(policy->p, type, &type_name);
				printf("%s\n", (char*)type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof,l);
					if ( proof )
						printf("\t%s\n", proof->text);
				}
			}
			printf("\n");
		}
	}

	return 0;
}

/* The unreachable_doms_data_new function allocates and returns an initialized
 * private data storage structure for this module. */
unreachable_doms_data_t *unreachable_doms_data_new(void)
{
	unreachable_doms_data_t *datum = NULL;

	datum = (unreachable_doms_data_t*)calloc(1,sizeof(unreachable_doms_data_t));

	return datum;
}

/* Parses default_contexts and adds source domains to datum->ctx_list */
bool_t parse_default_contexts(const char *ctx_file_path, apol_vector_t **ctx_vector, apol_policy_t *policy)
{
	int str_sz, i, charno, error = 0;
	FILE *ctx_file;
	char *line = NULL, *src_role = NULL, *src_dom = NULL, *dst_role = NULL, *dst_dom = NULL;
	size_t retv, line_len = 0;
	bool_t uses_mls = FALSE;

	printf("Using default contexts: %s\n", ctx_file_path);
	ctx_file = fopen(ctx_file_path, "r");
	if (!ctx_file) {
		error = errno;
		ERR(policy, "Opening default contexts file %s", ctx_file_path);
		goto parse_default_contexts_fail;
	}

	while(!feof(ctx_file)) {
		retv = getline(&line, &line_len, ctx_file);
		if (retv == -1) {
			if (feof(ctx_file)) {
				break;
			} else {
				error = errno;
				ERR(policy, "%s", "Reading default contexts file");
				goto parse_default_contexts_fail;
			}
		}

		uses_mls = FALSE;
		str_sz = APOL_STR_SZ + 128;
		i = 0;

		/* source role */
		src_role = malloc(str_sz);
		if (!src_role) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
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
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
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
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
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
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
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

		/*
			if ( qpol_policy_get_type_by_name(policy->p, src_dom, &type) ) {
		 */
		if ( apol_vector_append(*ctx_vector, (void *)strdup(src_dom)) < 0 ) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto parse_default_contexts_fail;
		}
		/*
			}
		 */
	}
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
	errno = error;
	return FALSE;
}

/* Returns true if type_idx is in datum->ctx_list */
bool_t in_def_ctx(char *type_name, unreachable_doms_data_t *datum)
{
	int i;

	for (i = 0; i <apol_vector_get_size(datum->ctx_vector); i++ ) {
		char *dom_name;

		dom_name = (char *)apol_vector_get_element(datum->ctx_vector, i);
		if (dom_name && !strcmp(dom_name, type_name)) return TRUE;
	}

	return FALSE;
}

/* Returns true if type is a type assigned to an isid */
bool_t in_isid_ctx(char *type_name, apol_policy_t *policy)
{
	int i;
	apol_vector_t *isid_vector;

	apol_get_isid_by_query(policy, NULL, &isid_vector);

	for ( i = 0; i < apol_vector_get_size(isid_vector); i++ ) {
		qpol_isid_t *isid;
		qpol_context_t *context;
		qpol_type_t *context_type;
		char *context_type_name;

		isid = apol_vector_get_element(isid_vector, i);
		qpol_isid_get_context(policy->p, isid, &context);
		qpol_context_get_type(policy->p, context, &context_type);
		qpol_type_get_name(policy->p, context_type, &context_type_name);
		if ( !strcmp(type_name, context_type_name) ) return TRUE;
	}
	return FALSE;
}

