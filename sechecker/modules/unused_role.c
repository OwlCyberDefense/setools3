/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "unused_role.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int unused_role_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "unused_role_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module("unused_role", lib);
	if (!mod) {
		fprintf(stderr, "unused_role_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_unused_roles_list");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_role_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_role_get_unused_roles_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int unused_role_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	unused_role_data_t *datum = NULL;
	bool_t header = TRUE;
	int pol_ver = POL_VER_UNKNOWN;

	if (!mod || !policy) {
		fprintf(stderr, "unused_role_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_unused_role_data();
	if (!datum) {
		fprintf(stderr, "unused_role_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("Finds roles defined but not used in role allow rules in a policy.\nThis module also reports role_transition rules found for these roles.\n\n");/* TODO: add header text */

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "unused_role_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "unused_role_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "unused_role_init failed: invalid policy type specification %s\n", opt->value);
				return -1;
			}
		} else if (!strcmp(opt->name, "pol_ver")) {
			pol_ver = atoi(opt->value);
			if (pol_ver < 11)
				pol_ver = POL_VER_PRE_11;
			else if (pol_ver < 15)
				pol_ver = POL_VER_12;
			else if (pol_ver < 16)
				pol_ver = POL_VER_15;
			else if (pol_ver == 16)
				pol_ver = POL_VER_16;
			else if (pol_ver == 17)
				pol_ver = POL_VER_17;
			else if (pol_ver == 18)
				pol_ver = POL_VER_18;
			else if (pol_ver > 18)
				pol_ver = POL_VER_19;
			else
				pol_ver = POL_VER_UNKNOWN;
			if (policy->version < pol_ver) {
				fprintf(stderr, "unused_role_init failed: module requires newer policy version\n");
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
		}
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int unused_role_run(sechk_module_t *mod, policy_t *policy) 
{
	unused_role_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;


	/* TODO: vars */

	if (!mod || !policy) {
		fprintf(stderr, "unused_role_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (unused_role_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "unused_role_run failed: out of memory\n");
		return -1;
	}
	res->test_name = strdup("unused_role");
	if (!res->test_name) {
		fprintf(stderr, "unused_role_run failed: out of memory\n");
		goto unused_role_run_fail;
	}

	/* TODO: set result structure values */

	/* TODO: check logic here */

	mod->result = res;

	return 0;

unused_role_run_fail:
	/* TODO: free any allocations */
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

void unused_role_free(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "unused_role_free failed: invalid parameters\n");
		return;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_free failed: wrong module (%s)\n", mod->name);
		return;
	}
	
	free(mod->name);
	mod->name = NULL;
	sechk_result_free(mod->result);
	sechk_opt_free(mod->options);
	sechk_fn_free(mod->functions);
	free_unused_role_data((unused_role_data_t**)&(mod->data));
}

char *unused_role_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	unused_role_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "unused_role_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "unused_role_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (unused_role_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	buff_sz += strlen("Module: Unused Role\n");
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  roles.\n") + intlen(mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		buff_sz++; /* '\n' */
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += 2 + strlen(policy->roles[item->item_id].name);
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		buff_sz += 2;
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += strlen(policy->roles[item->item_id].name);
			buff_sz += strlen(" - severity: x\n");
			for (proof = item->proof; proof; proof = proof->next) {
				buff_sz += 2 + strlen(proof->text);
			}
		}
	}
	buff_sz++; /* '\0' */

	buff = (char*)calloc(buff_sz, sizeof(char));
	if (!buff) {
		fprintf(stderr, "unused_role_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: Unused Role\n");
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i roles.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		tmp += sprintf(tmp, "\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			tmp += sprintf(tmp, "%s %c", policy->roles[item->item_id].name, i?' ':'\n');
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		tmp += sprintf(tmp, "\n\n");
		for (item = mod->result->items; item; item = item->next) {
			tmp += sprintf(tmp,"%s", policy->roles[item->item_id].name);
			tmp += sprintf(tmp, " - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				tmp += sprintf(tmp,"\t%s\n", proof->text);
			}
		}
	}

	return buff;
}

sechk_result_t *unused_role_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "unused_role_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

unused_role_data_t *new_unused_role_data(void) 
{
	unused_role_data_t *datum = NULL;

	datum = (unused_role_data_t*)calloc(1,sizeof(unused_role_data_t));

	return datum;
}

void free_unused_role_data(unused_role_data_t **datum) 
{
	if (!datum || !(*datum))
		return;

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

int unused_role_get_unused_roles_list(sechk_module_t *mod, int **array, int *size)
{
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "unused_role_get_unused_types_list failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_role", mod->name)) {
		fprintf(stderr, "unused_role_get_unused_types_list failed: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "unused_role_get_unused_types_list failed: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "unused_role_get_unused_types_list failed: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

	return 0;
}
 
