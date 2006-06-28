/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "inc_dom_trans.h"
#include "render.h"
//#include "dta.h" FIXME

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
	fn_struct->fn = &inc_dom_trans_init;
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
	fn_struct->fn = &inc_dom_trans_run;
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
	fn_struct->fn = &inc_dom_trans_free;
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
	fn_struct->fn = &inc_dom_trans_print_output;
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
	fn_struct->fn = &inc_dom_trans_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

#endif
	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_dom_trans_init(sechk_module_t *mod, policy_t *policy)
{
#if 0
	sechk_name_value_t *opt = NULL;
	inc_dom_trans_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = inc_dom_trans_data_new();
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
 * even if called multiple times. */
int inc_dom_trans_run(sechk_module_t *mod, policy_t *policy)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	inc_dom_trans_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	int i, retv;
	dta_table_t *table = NULL;
	dta_trans_t *cur = NULL;

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

	datum = (inc_dom_trans_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto inc_dom_trans_run_fail;
	}
	res->item_type = SECHK_TYPE_DATUM;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto inc_dom_trans_run_fail;
		}
	}

	table = dta_table_new(policy);
	if (!table) {
		perror("creating transition table");
		goto inc_dom_trans_run_fail;
	}
	retv = dta_table_build(table, policy);
	if (retv) {
		perror("building transition table");
		goto inc_dom_trans_run_fail;
	}

	/* skip self (type 0) */
	for (i = policy->num_types - 1; i; i--) {
		retv = dta_table_get_all_trans(table, &(datum->trans_list), i);
		if (retv) {
			perror("finding transitions");
			goto inc_dom_trans_run_fail;
		}
	}/* end foreach type */

	/* filter out all valid transitions */
	retv = dta_trans_filter_valid(&(datum->trans_list), 0);
	if (retv) {
		perror("filtering transitions");
		goto inc_dom_trans_run_fail;
	}

	for (cur = datum->trans_list; cur; cur = cur->next) {
		item = sechk_item_new();
		if (!item) {
			fprintf(stderr, "out of memory\n");
			goto inc_dom_trans_run_fail;
		}
		item->item_ptr = cur;
		if (cur->type_trans_rule != -1)
			item->test_result |= SECHK_INC_DOM_TRANS_HAS_TT;
		if (cur->ep_rules)
			item->test_result |= SECHK_INC_DOM_TRANS_HAS_EP;
		if (cur->exec_rules)
			item->test_result |= SECHK_INC_DOM_TRANS_HAS_EXEC;
		if (cur->proc_trans_rules)
			item->test_result |= SECHK_INC_DOM_TRANS_HAS_TRANS;
		item->proof = sechk_proof_new();
		if (!item->proof) {
			fprintf(stderr, "out of memory\n");
			goto inc_dom_trans_run_fail;
		}
		item->proof->idx = -1;
		item->proof->type = SECHK_TYPE_NONE;
		/* other proof fields are not used and will be NULL */
		item->next = res->items;
		res->items = item;
		res->num_items++;
	}

	mod->result = res;

	/* If module finds something that would be considered a fail
	 * on the policy return 1 here */
	if (res->num_items > 0) {
		dta_table_free(table);
		free(table);
		return 1;
	}

	dta_table_free(table);
	free(table);
#endif
	return 0;

#if 0
inc_dom_trans_run_fail:
	dta_table_free(table);
	free(table);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
#endif
}
/* The free function frees the private data of a module */
void inc_dom_trans_data_free(void *data)
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	inc_dom_trans_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (inc_dom_trans_data_t*)mod->data;

	if (datum) {
		dta_trans_destroy(&(datum->trans_list));
	}

	free(mod->data);
	mod->data = NULL;
#endif
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_dom_trans_print_output(sechk_module_t *mod, policy_t *policy) 
{
#if 0
	inc_dom_trans_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	dta_trans_t *trans = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (inc_dom_trans_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i incomplete transitions.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\nStart Type\tEntrypoint\tEnd Type\tMissing Rules\n");
		printf("----------\t----------\t--------\t-------------\n");
		for (item = mod->result->items; item; item = item->next) {
			i = 0;
			trans = (dta_trans_t*)(item->item_ptr);
			printf("%-15s %-15s %-15s ",
				trans->start_type != -1? policy->types[trans->start_type].name:"none",
				trans->ep_type != -1? policy->types[trans->ep_type].name:"none",
				trans->end_type != -1? policy->types[trans->end_type].name:"none");
			if (!(item->test_result & SECHK_INC_DOM_TRANS_HAS_TRANS)) {
				printf("transition");
				i++;
			}
			if (!(item->test_result & SECHK_INC_DOM_TRANS_HAS_EP)) {
				printf("%sentrypoint", i?", ":"");
				i++;
			}
			if (!(item->test_result & SECHK_INC_DOM_TRANS_HAS_EXEC)) {
				printf("%sexecute", i?", ":"");
				i++;
			}
			printf("\n");
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type) */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			trans = (dta_trans_t*)(item->item_ptr);
			printf("From %s to %s via %s\n",
				policy->types[trans->start_type].name,
				trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>",
				trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
			printf("\t%s: allow %s %s : process transition; ",
				(item->test_result & SECHK_INC_DOM_TRANS_HAS_TRANS)?"has":"missing",
				policy->types[trans->start_type].name,
				trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>");
			if (!is_binary_policy(policy)) {
				if (trans->proc_trans_rules)
					printf("[");
				for (i = 0; i < trans->num_proc_trans_rules; i++) {
					printf("%s%ld", i>0?", ":"", policy->av_access[trans->proc_trans_rules[i]].lineno);
				}
				if (trans->proc_trans_rules)
					printf("]");
			}
			printf("\n");
			printf("\t%s: allow %s %s : file entrypoint; ",
				(item->test_result & SECHK_INC_DOM_TRANS_HAS_EP)?"has":"missing",
				trans->end_type != -1? policy->types[trans->end_type].name:"<<end_type>>",
				trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
			if (!is_binary_policy(policy)) {
				if (trans->ep_rules)
					printf("[");
				for (i = 0; i < trans->num_ep_rules; i++) {
					printf("%s%ld", i>0?", ":"", policy->av_access[trans->ep_rules[i]].lineno);
				}
				if (trans->ep_rules)
					printf("]");
			}
			printf("\n");
			printf("\t%s: allow %s %s : file execute; ",
				(item->test_result & SECHK_INC_DOM_TRANS_HAS_EXEC)?"has":"missing",
				policy->types[trans->start_type].name,
				trans->ep_type != -1? policy->types[trans->ep_type].name:"<<entrypoint_type>>");
			if (!is_binary_policy(policy)) {
				if (trans->exec_rules)
					printf("[");
				for (i = 0; i < trans->num_exec_rules; i++) {
					printf("%s%ld", i>0?", ":"", policy->av_access[trans->exec_rules[i]].lineno);
				}
				if (trans->exec_rules)
					printf("]");
			}
			printf("\n");
			if (item->test_result & SECHK_INC_DOM_TRANS_HAS_TT) {
				printf("\thas: type_transition %s %s : process %s; ",
					policy->types[trans->start_type].name,
					policy->types[trans->ep_type].name,
					policy->types[trans->end_type].name);
				if (!is_binary_policy(policy))
					printf("[%ld]", policy->te_trans[trans->type_trans_rule].lineno);
				printf("\n");
			}
			printf("\n");
		}
		printf("\n");
	}

#endif
	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_dom_trans_get_result(sechk_module_t *mod) 
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

/* The inc_dom_trans_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module.  */
inc_dom_trans_data_t *inc_dom_trans_data_new(void)
{
#if 0
	inc_dom_trans_data_t *datum = NULL;

	datum = (inc_dom_trans_data_t*)calloc(1,sizeof(inc_dom_trans_data_t));

	return datum;
#endif
	return NULL;
}

