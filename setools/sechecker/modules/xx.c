/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "xx.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int xx_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "xx_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = get_module("xx", lib);
	if (!mod) {
		fprintf(stderr, "xx_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &xx_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &xx_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &xx_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &xx_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "xx_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &xx_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	/* TODO: add any other functions needed here*/


	return 0;
}

int xx_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	xx_data_t *datum = NULL;
	bool_t header = TRUE;
	int pol_ver = POL_VER_UNKNOWN;

	if (!mod || !policy) {
		fprintf(stderr, "xx_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("xx", mod->name)) {
		fprintf(stderr, "xx_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_xx_data();
	if (!datum) {
		fprintf(stderr, "xx_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("");/* TODO: add header text */

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "xx_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "xx_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "xx_init failed: invalid policy type specification %s\n", opt->value);
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
				fprintf(stderr, "xx_init failed: module requires newer policy version\n");
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
		/* TODO: check string name and set value in xx_data */
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int xx_run(sechk_module_t *mod, policy_t *policy) 
{
	xx_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;


	/* TODO: vars */

	if (!mod || !policy) {
		fprintf(stderr, "xx_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("xx", mod->name)) {
		fprintf(stderr, "xx_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (xx_data_t*)mod->data;
	res = new_sechk_result();
	if (!res) {
		fprintf(stderr, "xx_run failed: out of memory\n");
		return -1;
	}
	res->test_name = strdup("xx");
	if (!res->test_name) {
		fprintf(stderr, "xx_run failed: out of memory\n");
		goto xx_run_fail;
	}

	/* TODO: set result structure values */

	/* TODO: check logic here */

	mod->result = res;

	return 0;

xx_run_fail:
	/* TODO: free any allocations */
	free_sechk_proof(&proof);
	free_sechk_item(&item);
	free_sechk_result(&res);
	return -1;
}

void xx_free(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "xx_free failed: invalid parameters\n");
		return;
	}
	if (strcmp("xx", mod->name)) {
		fprintf(stderr, "xx_free failed: wrong module (%s)\n", mod->name);
		return;
	}
	
	free(mod->name);
	mod->name = NULL;
	free_sechk_result(&(mod->result));
	free_sechk_opt(&(mod->options));
	free_sechk_fn(&(mod->functions));
	free_xx_data((xx_data_t**)&(mod->data));
}

char *xx_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	xx_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "xx_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("xx", mod->name)) {
		fprintf(stderr, "xx_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "xx_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (xx_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	/* TODO: allocate and write results to buffer */
	buff_sz += strlen("Module: \n"); /* TODO: module name */
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  .\n") + intlen(mod->result->num_items); /* TODO: item type */
	}
	if (outformat & SECHK_OUT_LIST) {
		buff_sz++; /* '\n' */
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += 2 + strlen(""); /* TODO: item name */
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		buff_sz += 2;
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += strlen("");/* TODO: item name */
			buff_sz += strlen(" - severity: x\n");
			for (proof = item->proof; proof; proof = proof->next) {
				buff_sz += 2 + strlen(proof->text);
			}
		}
	}
	buff_sz++; /* '\0' */

	buff = (char*)calloc(buff_sz, sizeof(char));
	if (!buff) {
		fprintf(stderr, "xx_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: \n");/* TODO: module name */
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i .\n", mod->result->num_items);/* TODO: item type */
	}
	if (outformat & SECHK_OUT_LIST) {
		tmp += sprintf(tmp, "\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			tmp += sprintf(tmp, "%s %c", "", i?' ':'\n'); /* TODO: item name */
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		tmp += sprintf(tmp, "\n\n");
		for (item = mod->result->items; item; item = item->next) {
			tmp += sprintf(tmp,"%s", "");/* TODO: item name */
			tmp += sprintf(tmp, " - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				tmp += sprintf(tmp,"\t%s\n", proof->text);
			}
		}
	}

	return buff;
}

sechk_result_t *xx_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "xx_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("xx", mod->name)) {
		fprintf(stderr, "xx_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

xx_data_t *new_xx_data(void) 
{
	xx_data_t *datum = NULL;

	datum = (xx_data_t*)calloc(1,sizeof(xx_data_t));

	/* TODO: initialize any array indices to -1 and any other non-zero initialization data */

	return datum;
}

void free_xx_data(xx_data_t **datum) 
{
	if (!datum || !(*datum))
		return;

	/* TODO: free any allocated items in xx_data_t */

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

 
