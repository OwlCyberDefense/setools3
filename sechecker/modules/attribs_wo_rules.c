/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "attribs_wo_rules.h"

#include <stdio.h>
#include <string.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "attribs_wo_rules";

/* The register function registers all of a module's functions
 * with the library. */
int attribs_wo_rules_register(sechk_lib_t *lib)
{
#if 0
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

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
	mod->brief_description = "attributes not used in any rule";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds attributes in the policy that are not used in any rules  These\n"
"attributes will get thrown out by the compiler and have no effect on the \n"
"security environment however are unnecessary and should be removed.\n";
	mod->opt_description = 
"Module requirements:\n"
"   policy source\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_LOW;
	/* assign requirements */
	mod->requirements = sechk_name_value_new("policy_type","source");

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
	fn_struct->fn = &attribs_wo_rules_init;
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
	fn_struct->fn = &attribs_wo_rules_run;
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
	fn_struct->fn = &attribs_wo_rules_free;
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
	fn_struct->fn = &attribs_wo_rules_print_output;
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
	fn_struct->fn = &attribs_wo_rules_get_result;
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
	fn_struct->fn = &attribs_wo_rules_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int attribs_wo_rules_init(sechk_module_t *mod, policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	attribs_wo_rules_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = attribs_wo_rules_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

#endif
	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. */
int attribs_wo_rules_run(sechk_module_t *mod, policy_t *policy)
{
#if 0
	attribs_wo_rules_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, j, retv;
	bool_t used = FALSE;

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

	datum = (attribs_wo_rules_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto attribs_wo_rules_run_fail;
	}
	res->item_type = POL_LIST_ATTRIB;

	for (i = 0; i < policy->num_attribs; i++) {
		used = FALSE;
		/* access rules */
		for (j = 0; j < policy->num_av_access; j++) {
			if (does_av_rule_idx_use_type(j, 0, i, IDX_ATTRIB, BOTH_LISTS, 0, policy)) {
				used = TRUE;
				break;
			}
		}
		if (used)
			continue;

		/* audit rules */
		for (j = 0; j < policy->num_av_audit; j++) {
			if (does_av_rule_idx_use_type(j, 1, i, IDX_ATTRIB, BOTH_LISTS, 0, policy)) {
				used = TRUE;
				break;
			}
		}
		if (used)
			continue;

		/* type rules */
		for (j = 0; j < policy->num_te_trans; j++) {
			if (does_tt_rule_use_type(i, IDX_ATTRIB, BOTH_LISTS, 0, &(policy->te_trans[j]), &retv, policy)) {
				used = TRUE;
				break;
			}
		}
		if (used)
			continue;

		/* role trans */
		for (j = 0; j < policy->num_role_trans; j++) {
			if (does_role_trans_use_ta(i, IDX_ATTRIB, 0, &(policy->role_trans[j]), &retv, policy)) {
				used = TRUE;
				break;
			}
		}

		/* if we get here then the attrib was not found anywhere in a rule so add it */
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto attribs_wo_rules_run_fail;
		}
		item->item_id = i;
		item->test_result = 1;
		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			goto attribs_wo_rules_run_fail;
		}
		proof->idx = -1;
		proof->type = SECHK_TYPE_NONE;
		proof->text = strdup("attribute was not used in any rules.");
		if (!proof->text) {
			fprintf(stderr, "Error: out of memory\n");
			goto attribs_wo_rules_run_fail;
		}
		item->proof = proof;
		item->next = res->items;
		res->items = item;
		(res->num_items)++;
	}

	mod->result = res;
	if (res->num_items > 0)
		return 1;
#endif
	return 0;

#if 0
attribs_wo_rules_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
#endif
}

/* The free function frees the private data of a module */
void attribs_wo_rules_data_free(void *data)
{
#if 0
	attribs_wo_rules_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (attribs_wo_rules_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int attribs_wo_rules_print_output(sechk_module_t *mod, policy_t *policy) 
{
#if 0
	attribs_wo_rules_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0;

        if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (attribs_wo_rules_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i attributes.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following attrubutes do not appear in any rules.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->attribs[item->item_id].name, (i&&item->next)? ", " : "\n"); 
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *attribs_wo_rules_get_result(sechk_module_t *mod) 
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

/* The attribs_wo_rules_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
attribs_wo_rules_data_t *attribs_wo_rules_data_new(void)
{
#if 0
	attribs_wo_rules_data_t *datum = NULL;

	datum = (attribs_wo_rules_data_t*)calloc(1,sizeof(attribs_wo_rules_data_t));

	return datum;
#endif
	return NULL;
}

int attribs_wo_rules_get_list(sechk_module_t *mod, apol_vector_t **v)
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

