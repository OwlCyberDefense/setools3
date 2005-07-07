/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "domain_and_file_type.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int domain_and_file_type_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "domain_and_file_type_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module("domain_and_file_type", lib);
	if (!mod) {
		fprintf(stderr, "domain_and_file_type_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_and_file_type_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_and_file_type_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_and_file_type_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_and_file_type_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_and_file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_and_file_type_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int domain_and_file_type_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	domain_and_file_type_data_t *datum = NULL;
	bool_t header = TRUE;
	sechk_module_t *dep_mod = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "domain_and_file_type_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("domain_and_file_type", mod->name)) {
		fprintf(stderr, "domain_and_file_type_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_domain_and_file_type_data();
	if (!datum) {
		fprintf(stderr, "domain_and_file_type_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("Finds all types in the policy treated as both a domain and a file type\nSee domain_type and file_type modules for details about\nhow types are placed in these categories\n\n");

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "domain_and_file_type_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "domain_and_file_type_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "domain_and_file_type_init failed: invalid policy type specification %s\n", opt->value);
				return -1;
			}
		} else if (!strcmp(opt->name, "output_type")) {
			if (!strcmp(opt->value, "full")) {
				datum->outformat = (SECHK_OUT_LONG|SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "long")) {
				datum->outformat = (SECHK_OUT_LONG|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "short")) {
				datum->outformat = (SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "stats")) {
				datum->outformat = (SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
		} else if (!strcmp(opt->name, "output_header")) {
			if (!strcmp(opt->value, "no")) {
				header = FALSE;
			}
		} else if (!strcmp(opt->name, "depend_mod")) {
			dep_mod = sechk_lib_get_module(opt->value, library);
			if (!dep_mod) {
				fprintf(stderr, "domain_and_file_type_init failed: unable to resolve dependency %s\n", opt->value);
				return -1;
			}
			(datum->num_depend)++ ;
			datum->depend_names = (char**)realloc(datum->depend_names, datum->num_depend * sizeof(char*));
			if (!datum->depend_names) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_names[datum->num_depend -1] = strdup(opt->value);
			if (!datum->depend_names[datum->num_depend -1]) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_mods = (sechk_module_t**)realloc(datum->depend_mods, datum->num_depend * sizeof(sechk_module_t*));
			if (!datum->depend_mods) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_mods[datum->num_depend -1] = dep_mod;
			if (!datum->depend_names[datum->num_depend -1]) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_run_fns = (sechk_run_fn_t*)realloc(datum->depend_run_fns, datum->num_depend * sizeof(sechk_run_fn_t));
			if (!datum->depend_run_fns) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_run_fns[datum->num_depend -1] = sechk_lib_get_module_function(opt->value, "run", library);
			if (!datum->depend_run_fns[datum->num_depend -1]) {
				fprintf(stderr, "domain_and_file_type failed: unable to find required function\n");
				return -1;
			}
			datum->depend_get_res_fns = (sechk_get_result_fn_t*)realloc(datum->depend_get_res_fns, datum->num_depend * sizeof(sechk_get_result_fn_t));
			if (!datum->depend_run_fns) {
				fprintf(stderr, "domian_and_file_type_init failed: out of memory\n");
				return -1;
			}
			datum->depend_get_res_fns[datum->num_depend -1] = sechk_lib_get_module_function(opt->value, "get_result", library);
			if (!datum->depend_get_res_fns[datum->num_depend -1]) {
				fprintf(stderr, "domain_and_file_type failed: unable to find required function\n");
				return -1;
			}
		}
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int domain_and_file_type_run(sechk_module_t *mod, policy_t *policy) 
{
	domain_and_file_type_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL, *tmp_item = NULL;
	sechk_proof_t *proof = NULL, *tmp_proof = NULL;
	int *domain_list = NULL, *file_type_list = NULL, *both_list = NULL;
	int domain_list_sz = 0, file_type_list_sz = 0, both_list_sz = 0;
	sechk_result_t *domain_res = NULL, *file_type_res = NULL;
	int i, domain_idx = -1, file_type_idx = -1, retv;
	int (*domain_list_fn)(sechk_module_t*,int**, int*) = NULL;
	int (*file_type_list_fn)(sechk_module_t*,int**, int*) = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "domain_and_file_type_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("domain_and_file_type", mod->name)) {
		fprintf(stderr, "domain_and_file_type_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (domain_and_file_type_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
		return -1;
	}
	res->test_name = strdup("domain_and_file_type");
	if (!res->test_name) {
		fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
		goto domain_and_file_type_run_fail;
	}
	res->item_type = POL_LIST_TYPE;
	
	/* set indices of depencies */
	for (i = 0; i < datum->num_depend; i++) {
		if (!strcmp(datum->depend_names[i], "domain_type"))
			domain_idx = i;
		else if (!strcmp(datum->depend_names[i], "file_type"))
			file_type_idx = i;
	}

	if (file_type_idx == -1) {
		fprintf(stderr, "domain_and_file_type_run failed: missing dependency: file_type\n");
		goto domain_and_file_type_run_fail;
	}
	if (domain_idx == -1 ) {
		fprintf(stderr, "domain_and_file_type_run failed: missing dependency: domain_type\n");
		goto domain_and_file_type_run_fail;
	}

	/* run dependencies */
	for (i = 0; i < datum->num_depend; i++) {
		retv = datum->depend_run_fns[i](datum->depend_mods[i], policy);
	}

	/* get results */
	domain_res = datum->depend_get_res_fns[domain_idx](datum->depend_mods[domain_idx]);
	file_type_res = datum->depend_get_res_fns[file_type_idx](datum->depend_mods[file_type_idx]);

	/* get lists */
	domain_list_fn = sechk_lib_get_module_function("domain_type", "get_domain_list", library);
	retv = domain_list_fn(datum->depend_mods[domain_idx], &domain_list, &domain_list_sz);
	if (retv) {
		fprintf(stderr, "domain_and_file_type_run failed: unable to get domain list\n");
		goto domain_and_file_type_run_fail;
	}
	file_type_list_fn = sechk_lib_get_module_function("file_type", "get_file_type_list", library);
	retv = file_type_list_fn(datum->depend_mods[file_type_idx], &file_type_list, &file_type_list_sz);
	if (retv) {
		fprintf(stderr, "domain_and_file_type_run failed: unable to get file type list\n");
		goto domain_and_file_type_run_fail;
	}

	/* build the both list */
	for (i = 0; i < domain_list_sz; i++) {
		if (find_int_in_array(domain_list[i], file_type_list, file_type_list_sz) != -1) {
			retv = add_i_to_a(domain_list[i], &both_list_sz, &both_list);
			if (retv) {
				fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
				goto domain_and_file_type_run_fail;
			}
		}
	}

	/* combine proofs and build result items */
	for (i = 0; i < both_list_sz; i++) {
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
			goto domain_and_file_type_run_fail;
		}
		item->item_id = both_list[i];
		item->test_result = 1;

		/* include proof that it is a domain */
		tmp_item = get_sechk_item_from_result(both_list[i], POL_LIST_TYPE, domain_res);
		if (!tmp_item) {
			fprintf(stderr, "domain_and_file_type_run failed: internal logic failure\n");
			goto domain_and_file_type_run_fail;
		}
		for (tmp_proof = tmp_item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
			if (is_sechk_proof_in_item(tmp_proof->idx, tmp_proof->type, item))
				continue;
			proof = NULL;
			proof = copy_sechk_proof(tmp_proof);
			if (!proof) {
				fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
				goto domain_and_file_type_run_fail;
			}
			proof->next = item->proof;
			item->proof = proof;
		}

		/* include proof that it is a file type */
		tmp_item = get_sechk_item_from_result(both_list[i], POL_LIST_TYPE, file_type_res);
		if (!tmp_item) {
			fprintf(stderr, "domain_and_file_type_run failed: internal logic failure\n");
			goto domain_and_file_type_run_fail;
		}
		for (tmp_proof = tmp_item->proof; tmp_proof; tmp_proof = tmp_proof->next) {
			if (is_sechk_proof_in_item(tmp_proof->idx, tmp_proof->type, item))
				continue;
			proof = NULL;
			proof = copy_sechk_proof(tmp_proof);
			if (!proof) {
				fprintf(stderr, "domain_and_file_type_run failed: out of memory\n");
				goto domain_and_file_type_run_fail;
			}
			proof->next = item->proof;
			item->proof = proof;
		}

		item->next = res->items;
		res->items = item;
		(res->num_items)++;
	}

	free(domain_list);
	free(file_type_list);
	free(both_list);

	mod->result = res;

	return 0;

domain_and_file_type_run_fail:
	free(domain_list);
	free(file_type_list);
	free(both_list);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

void domain_and_file_type_free(sechk_module_t *mod) 
{

// TODO:	domain_and_file_type_data_free((domain_and_file_type_data_t**)&(mod->data));

}

char *domain_and_file_type_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	domain_and_file_type_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "domain_and_file_type_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("domain_and_file_type", mod->name)) {
		fprintf(stderr, "domain_and_file_type_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "domain_and_file_type_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (domain_and_file_type_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	buff_sz += strlen("Module: Domain and File Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  types.\n") + intlen(mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		buff_sz++; /* '\n' */
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += 2 + strlen(policy->types[item->item_id].name);
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		buff_sz += 2;
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += strlen(policy->types[item->item_id].name);
			buff_sz += strlen(" - severity: x\n");
			for (proof = item->proof; proof; proof = proof->next) {
				buff_sz += 2 + strlen(proof->text);
			}
		}
	}
	buff_sz++; /* '\0' */

	buff = (char*)calloc(buff_sz, sizeof(char));
	if (!buff) {
		fprintf(stderr, "domain_and_file_type_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: Domain and File Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		tmp += sprintf(tmp, "\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			tmp += sprintf(tmp, "%s %c", policy->types[item->item_id].name, i?' ':'\n');
		}
	}

	if (outformat & SECHK_OUT_LONG) {
		tmp += sprintf(tmp, "\n\n");
		for (item = mod->result->items; item; item = item->next) {
			tmp += sprintf(tmp,"%s", policy->types[item->item_id].name);
			tmp += sprintf(tmp, " - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				tmp += sprintf(tmp,"\t%s\n", proof->text);
			}
		}
	}

	return buff;
}

sechk_result_t *domain_and_file_type_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "domain_and_file_type_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("domain_and_file_type", mod->name)) {
		fprintf(stderr, "domain_and_file_type_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

domain_and_file_type_data_t *new_domain_and_file_type_data(void) 
{
	domain_and_file_type_data_t *datum = NULL;

	datum = (domain_and_file_type_data_t*)calloc(1,sizeof(domain_and_file_type_data_t));

	return datum;
}

void free_domain_and_file_type_data(domain_and_file_type_data_t **datum) 
{
	int i;

	if (!datum || !(*datum))
		return;

	for (i = 0; i < (*datum)->num_depend; i++) {
		free((*datum)->depend_names[i]);
	}
	free((*datum)->depend_run_fns);
	free((*datum)->depend_get_res_fns);
	free((*datum)->depend_mods);

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

 
