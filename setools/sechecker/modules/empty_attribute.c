/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "empty_attribute.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int empty_attribute_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "empty_attribute_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module("empty_attribute", lib);
	if (!mod) {
		fprintf(stderr, "empty_attribute_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &empty_attribute_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &empty_attribute_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &empty_attribute_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &empty_attribute_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "empty_attribute_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &empty_attribute_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int empty_attribute_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	empty_attribute_data_t *datum = NULL;
	bool_t header = TRUE;
	int pol_ver = POL_VER_UNKNOWN;

	if (!mod || !policy) {
		fprintf(stderr, "empty_attribute_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("empty_attribute", mod->name)) {
		fprintf(stderr, "empty_attribute_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_empty_attribute_data();
	if (!datum) {
		fprintf(stderr, "empty_attribute_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("Finds empty attributes in the policy.\nAn attribute is considered empty if no type has that attribute.\n\n");

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "empty_attribute_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "empty_attribute_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "empty_attribute_init failed: invalid policy type specification %s\n", opt->value);
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
				fprintf(stderr, "empty_attribute_init failed: module requires newer policy version\n");
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

int empty_attribute_run(sechk_module_t *mod, policy_t *policy) 
{
	empty_attribute_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, retv, num_types = 0, *types = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "empty_attribute_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("empty_attribute", mod->name)) {
		fprintf(stderr, "empty_attribute_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (empty_attribute_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "empty_attribute_run failed: out of memory\n");
		return -1;
	}
	res->test_name = strdup("empty_attribute");
	if (!res->test_name) {
		fprintf(stderr, "empty_attribute_run failed: out of memory\n");
		goto empty_attribute_run_fail;
	}
	res->item_type = POL_LIST_ATTRIB;

	for (i = policy->num_attribs - 1; i >= 0; i--) {
		num_types = 0;
		free(types);
		types = NULL;
		retv = get_role_types(i, &num_types, &types, policy);
		if (retv) {
			fprintf(stderr, "empty_attribute_run failed: out of memory\n");
			goto empty_attribute_run_fail;
		}
		if (num_types) 
			continue;
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "empty_attribute_run failed: out of memory\n");
			goto empty_attribute_run_fail;
		}
		proof->idx = i;
		proof->type = POL_LIST_ATTRIB;
		proof->severity = SECHK_SEV_LOW;
		proof->text = (char*)calloc(strlen("attribute  has no types")+strlen(policy->attribs[i].name)+1, sizeof(char));
		sprintf(proof->text, "attribute %s has no types", policy->attribs[i].name);
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "empty_attribute_run failed: out of memory\n");
			goto empty_attribute_run_fail;
		}
		item->item_id = i;
		item->test_result = 1;
		proof->next = item->proof;
		item->proof = proof;
		item->next = res->items;
		res->items = item;
	}

	mod->result = res;

	return 0;

empty_attribute_run_fail:
	free(types);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

void empty_attribute_free(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "empty_attribute_free failed: invalid parameters\n");
		return;
	}
	if (strcmp("empty_attribute", mod->name)) {
		fprintf(stderr, "empty_attribute_free failed: wrong module (%s)\n", mod->name);
		return;
	}
	
	free(mod->name);
	mod->name = NULL;
	sechk_result_free(mod->result);
	sechk_opt_free(mod->options);
	sechk_fn_free(mod->functions);
	free_empty_attribute_data((empty_attribute_data_t**)&(mod->data));
}

char *empty_attribute_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	empty_attribute_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "empty_attribute_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("empty_attribute", mod->name)) {
		fprintf(stderr, "empty_attribute_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "empty_attribute_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (empty_attribute_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	buff_sz += strlen("Module: Empty Attribute\n"); 
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  attributes.\n") + intlen(mod->result->num_items); 
	}
	if (outformat & SECHK_OUT_LIST) {
		buff_sz++; /* '\n' */
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += 2 + strlen(policy->attribs[item->item_id].name); 
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		buff_sz += 2;
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += strlen(policy->attribs[item->item_id].name);
			buff_sz += strlen(" - severity: x\n");
			for (proof = item->proof; proof; proof = proof->next) {
				buff_sz += 2 + strlen(proof->text);
			}
		}
	}
	buff_sz++; /* '\0' */

	buff = (char*)calloc(buff_sz, sizeof(char));
	if (!buff) {
		fprintf(stderr, "empty_attribute_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: Empty Attribute\n");
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i attributes.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		tmp += sprintf(tmp, "\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			tmp += sprintf(tmp, "%s %c", policy->attribs[item->item_id].name, i?' ':'\n'); 
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		tmp += sprintf(tmp, "\n\n");
		for (item = mod->result->items; item; item = item->next) {
			tmp += sprintf(tmp,"%s", policy->attribs[item->item_id].name);
			tmp += sprintf(tmp, " - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				tmp += sprintf(tmp,"\t%s\n", proof->text);
			}
		}
	}

	return buff;
}

sechk_result_t *empty_attribute_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "empty_attribute_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("empty_attribute", mod->name)) {
		fprintf(stderr, "empty_attribute_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

empty_attribute_data_t *new_empty_attribute_data(void) 
{
	empty_attribute_data_t *datum = NULL;

	datum = (empty_attribute_data_t*)calloc(1,sizeof(empty_attribute_data_t));

	return datum;
}

void free_empty_attribute_data(empty_attribute_data_t **datum) 
{
	if (!datum || !(*datum))
		return;

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

 
