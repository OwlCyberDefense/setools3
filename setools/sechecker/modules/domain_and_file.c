/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "domain_and_file.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;
static const char *const mod_name = "domain_and_file";

int domain_and_file_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}
	
	/* assign descriptions */
	mod->brief_description = "types treated as a domain and file type";
	mod->detailed_description = "Finds all types in the policy treated as both a domain and a file type "
"\nSee domain_type and file_type modules for details about how "
"\ntypes are placed in these categories. It is considered bad security"
"\npractice to use the same type for a domain and its data objects, because"
"\nit requires that less restrictive access be granted."
"\n  Requirements:"
"\n    policy_type=source"
"\n  Dependencies:"
"\n    module=find_domains"
"\n    module=find_file_types"
"\n  Options:"
"\n    none";

	/* assign requirements */
	mod->requirements = sechk_name_value_prepend(NULL,"policy_type","source");

	/* assign dependencies */
	mod->dependencies = sechk_name_value_prepend(NULL,"module","find_domains");
	mod->dependencies = sechk_name_value_prepend(mod->dependencies,"module","find_file_types");

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
	fn_struct->fn = &domain_and_file_init;
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
	fn_struct->fn = &domain_and_file_run;
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
	fn_struct->fn = &domain_and_file_data_free;
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
	fn_struct->fn = &domain_and_file_print_output;
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
	fn_struct->fn = &domain_and_file_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int domain_and_file_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_name_value_t *opt = NULL;
	domain_and_file_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = domain_and_file_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

	return 0;
}

int domain_and_file_run(sechk_module_t *mod, policy_t *policy) 
{
	domain_and_file_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL, *tmp_item = NULL;
	sechk_proof_t *proof = NULL, *tmp_proof = NULL;
	int *domain_list = NULL, *file_type_list = NULL, *both_list = NULL;
	int domain_list_sz = 0, file_type_list_sz = 0, both_list_sz = 0;
	sechk_result_t *domain_res = NULL, *file_type_res = NULL;
	int i, retv;
	int (*domain_list_fn)(sechk_module_t*,int**, int*) = NULL;
	int (*file_type_list_fn)(sechk_module_t*,int**, int*) = NULL;
	sechk_run_fn_t run_fn = NULL;
	sechk_get_result_fn_t get_res = NULL;
	sechk_name_value_t *dep = NULL;

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

	datum = (domain_and_file_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto domain_and_file_run_fail;
	}
	res->item_type = POL_LIST_TYPE;
	

	/* run dependencies */
	for (dep = mod->dependencies; dep; dep = dep->next) {
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, library);
		run_fn(sechk_lib_get_module(dep->value, library), policy);
	}

	/* get results */
	get_res = sechk_lib_get_module_function("find_domains", SECHK_MOD_FN_GET_RES, library);
	if (!get_res) {
		fprintf(stderr, "Error: unable to find get_result function\n");
		goto domain_and_file_run_fail;
	}
	domain_res = get_res(sechk_lib_get_module("find_domains", library));
	if (!domain_res) {
		fprintf(stderr, "Error: unable to get results\n");
		goto domain_and_file_run_fail;
	}
	get_res = sechk_lib_get_module_function("find_file_types", SECHK_MOD_FN_GET_RES, library);
	if (!get_res) {
		fprintf(stderr, "Error: unable to find get_result function\n");
		goto domain_and_file_run_fail;
	}
	file_type_res = get_res(sechk_lib_get_module("find_file_types", library));
	if (!file_type_res) {
		fprintf(stderr, "Error: unable to get results\n");
		goto domain_and_file_run_fail;
	}

	/* get lists */
	domain_list_fn = sechk_lib_get_module_function("find_domains", "get_list", library);
	retv = domain_list_fn(sechk_lib_get_module("find_domains", library), &domain_list, &domain_list_sz);
	if (retv) {
		fprintf(stderr, "Error: unable to get domain list\n");
		goto domain_and_file_run_fail;
	}
	file_type_list_fn = sechk_lib_get_module_function("find_file_types", "get_list", library);
	retv = file_type_list_fn(sechk_lib_get_module("find_file_types", library), &file_type_list, &file_type_list_sz);
	if (retv) {
		fprintf(stderr, "Error: unable to get file type list\n");
		goto domain_and_file_run_fail;
	}

	/* build the both list */
	for (i = 0; i < domain_list_sz; i++) {
		if (find_int_in_array(domain_list[i], file_type_list, file_type_list_sz) != -1) {
			retv = add_i_to_a(domain_list[i], &both_list_sz, &both_list);
			if (retv) {
				fprintf(stderr, "Error: out of memory\n");
				goto domain_and_file_run_fail;
			}
		}
	}

	/* combine proofs and build result items */
	for (i = 0; i < both_list_sz; i++) {
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto domain_and_file_run_fail;
		}
		item->item_id = both_list[i];
		item->test_result = 1;

		/* include proof that it is a domain */
		tmp_item = sechk_result_get_item(both_list[i], POL_LIST_TYPE, domain_res);
		if (!tmp_item) {
			fprintf(stderr, "Error: internal logic failure\n");
			goto domain_and_file_run_fail;
		}
		for (tmp_proof = tmp_item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
			if (sechk_item_has_proof(tmp_proof->idx, tmp_proof->type, item))
				continue;
			proof = NULL;
			proof = sechk_proof_copy(tmp_proof);
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto domain_and_file_run_fail;
			}
			proof->next = item->proof;
			item->proof = proof;
		}

		/* include proof that it is a file type */
		tmp_item = sechk_result_get_item(both_list[i], POL_LIST_TYPE, file_type_res);
		if (!tmp_item) {
			fprintf(stderr, "Error: internal logic failure\n");
			goto domain_and_file_run_fail;
		}
		for (tmp_proof = tmp_item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
			if (sechk_item_has_proof(tmp_proof->idx, tmp_proof->type, item))
				continue;
			proof = NULL;
			proof = sechk_proof_copy(tmp_proof);
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto domain_and_file_run_fail;
			}
			proof->next = item->proof;
			item->proof = proof;
		}

		item->next = res->items;
		res->items = item;
		(res->num_items)++;
		item = NULL;
	}

	free(domain_list);
	free(file_type_list);
	free(both_list);

	mod->result = res;

	if (both_list_sz > 0)
		return 1;

	return 0;

domain_and_file_run_fail:
	free(domain_list);
	free(file_type_list);
	free(both_list);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

void domain_and_file_data_free(sechk_module_t *mod)
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

int domain_and_file_print_output(sechk_module_t *mod, policy_t *policy) 
{
	domain_and_file_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

        if (!mod || (!policy && (mod->outputformat & ~(SECHK_OUT_BRF_DESCP) &&
                                 (mod->outputformat & ~(SECHK_OUT_DET_DESCP))))){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (domain_and_file_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result && (outformat & ~(SECHK_OUT_BRF_DESCP)) && (outformat & ~(SECHK_OUT_DET_DESCP))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	printf("\nModule: %s\n", mod_name);
	/* print the brief description */
	if (outformat & SECHK_OUT_BRF_DESCP) {
		printf("%s\n\n", mod->brief_description);
	}
	/* print the detailed description */
	if (outformat & SECHK_OUT_DET_DESCP) {
		printf("%s\n\n", mod->detailed_description);
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			printf("%s%s", policy->types[item->item_id].name, i ? ", " : "\n");
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", policy->types[item->item_id].name);
			printf(" - severity: %s\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

sechk_result_t *domain_and_file_get_result(sechk_module_t *mod) 
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

domain_and_file_data_t *domain_and_file_data_new(void) 
{
	domain_and_file_data_t *datum = NULL;

	datum = (domain_and_file_data_t*)calloc(1,sizeof(domain_and_file_data_t));

	return datum;
}

 
