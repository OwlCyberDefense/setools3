/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"

#include "types_wo_allow.h"

#include <stdio.h>
#include <string.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "types_wo_allow";

/* The register function registers all of a module's functions
 * with the library. */
int types_wo_allow_register(sechk_lib_t *lib)
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
	mod->brief_description = "types with no allow rules";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds types defined in the policy that are not used in any allow    \n"
"rules.  A type that is never granted an allow rule in the policy is a dead type.\n"
"This means that all attempted acces to the type will be denied including        \n"
"attempts to relabel to a (usable) type.  The type may need to be removed from   \n"
"the policy or some intended access should be granted to the type.\n";		
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_LOW;
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
	fn_struct->fn = &types_wo_allow_init;
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
	fn_struct->fn = &types_wo_allow_run;
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
	fn_struct->fn = &types_wo_allow_free;
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
	fn_struct->fn = &types_wo_allow_print_output;
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
	fn_struct->fn = &types_wo_allow_get_result;
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
	fn_struct->fn = &types_wo_allow_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int types_wo_allow_init(sechk_module_t *mod, apol_policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	types_wo_allow_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = types_wo_allow_data_new();
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
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int types_wo_allow_run(sechk_module_t *mod, apol_policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	types_wo_allow_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, j, retv;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	avh_rule_t *hash_rule = NULL;
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

	datum = (types_wo_allow_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto types_wo_allow_run_fail;
	}
	res->item_type  = POL_LIST_TYPE;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto types_wo_allow_run_fail;
		}
	}

	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		used = FALSE;
		/* check for source */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
			for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
				switch (hash_idx->nodes[j]->key.rule_type) {
				case RULE_TE_ALLOW:
					used = TRUE;
					break;
				case RULE_AUDITALLOW:
				case RULE_AUDITDENY:
				case RULE_DONTAUDIT:
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (used)
					break;
			}
			if (used) 
				break;
		}
		if (used) {
			continue;
		}

		/* check for target */
		hash_idx = avh_tgt_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
			for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
				switch (hash_idx->nodes[j]->key.rule_type) {
				case RULE_TE_ALLOW:
					used = TRUE;
					break;
				case RULE_AUDITALLOW:
				case RULE_AUDITDENY:
				case RULE_DONTAUDIT:
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (used)
					break;
			}
			if (used) 
				break;
		}
		if (used) {
			continue;
		}

		/* not used anywhere*/
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "Error: out of memory\n");
			goto types_wo_allow_run_fail;
		}
		item->item_id = i;
		item->test_result = 1;

		proof = sechk_proof_new();
		if (!proof) {
			fprintf(stderr, "Error: out of memory\n");
			goto types_wo_allow_run_fail;
		}
		proof->idx = -1;
		proof->type = -1;
		proof->text = strdup("This type does not appear in any allow rules.");
		item->proof = proof;
		item->next = res->items;
		res->items = item;
		res->num_items++;
	}
	mod->result = res;

#endif
	return 0;

#if 0
types_wo_allow_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
#endif
}

/* The free function frees the private data of a module */
void types_wo_allow_data_free(void *data)
{
#if 0
	types_wo_allow_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (types_wo_allow_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int types_wo_allow_print_output(sechk_module_t *mod, apol_policy_t *policy) 
{
#if 0
	types_wo_allow_data_t *datum = NULL;
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

	datum = (types_wo_allow_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types do not appear in any allow rules.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->types[item->item_id].name, (i&&item->next) ? ", " : "\n"); 
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *types_wo_allow_get_result(sechk_module_t *mod) 
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

/* The types_wo_allow_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
types_wo_allow_data_t *types_wo_allow_data_new(void)
{
#if 0
	types_wo_allow_data_t *datum = NULL;

	datum = (types_wo_allow_data_t*)calloc(1,sizeof(types_wo_allow_data_t));

	return datum;
#endif
	return NULL;
}

int types_wo_allow_get_list(sechk_module_t *mod, apol_vector_t **v)
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
 
