/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

/* NOTE: TODO This is a module template, which includes all the necessary
 * infrastructure to implement a basic SEChecker module. To use this template
 * first replace all instances of the string xx with the name of the module,
 * then edit or complete all sections marked TODO as instructed. Do not forget
 * to add a block to the config file and to place the register function in
 * the register_list files (see these files for further instruction) */

#include "sechecker.h"
#include "policy.h"
#include "xx.h"

#include <stdio.h>
#include <string.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "xx";

/* The register function registers all of a module's functions
 * with the library.  You should not need to edit this function
 * unless you are adding additional functions you need other modules
 * to call. See the note at the bottom of this function to do so. */
int xx_register(sechk_lib_t *lib)
{
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
	mod->brief_description = "";
	mod->detailed_description = "";

	/* assign requirements */
	mod->requirements = sechk_name_value_new_prepend(NULL,"","");
	mod->requirements = sechk_name_value_new_prepend(mod->requirements,"","");

	/* assign dependencies */
	mod->dependencies = sechk_name_value_new_prepend(NULL,"","");
	mod->dependencies = sechk_name_value_new_prepxzend(mod->dependencies,"","");

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
	fn_struct->fn = &xx_init;
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
	fn_struct->fn = &xx_run;
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
	fn_struct->fn = &xx_free;
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
	fn_struct->fn = &xx_print_output;
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
	fn_struct->fn = &xx_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	/* TODO: (optional) add any other functions needed here,
	 * add a block as above for each additional function */


	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file.
 * Add any option processing logic as indicated below.
 * TODO: add options processing logic */
int xx_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	xx_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = xx_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		/* TODO: check options
		 * check strings opt->name and opt->value of each option
		 * to set the members of the private data storage object
		 * (pointed to by datum).
		 * i.e. if (!strcmp(...)) {} else if (!strcmp((...)) etc.
		 * There should be relatively few options for any one module.
		 * If too many options are needed consider splitting the check
		 * into multiple modules and using dependencies.  It is desirable
		 * for all checks to be a simple and granular as is possible */
		opt = opt->next;
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data.
 * TODO: add check logic */
int xx_run(sechk_module_t *mod, policy_t *policy)
{
	xx_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;


	/* TODO: define any aditional variables needed */

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

	datum = (xx_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto xx_run_fail;
	}
	/* TODO: set res->item_type to indicate which array the item_id indexes
	 * use values from the POL_LIST_ define set (see policy.h for list and
	 * sechecker.h for a set of extended values for components not in the
	 * source policy filesuch as file context entries) */

	/* TODO: check logic here 
	 * Perform check here. Create and initialize items and proof as found,
	 * be sure to update res->num_items as items are added for statistics
	 * tracking in the report. For examples of the type of code to use here
	 * see other modules. */

	mod->result = res;

	return 0;

xx_run_fail:
	/* TODO: free any other memory allocated during check logic */
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module
 * TODO: be sure to free any allocated space in the private data */
void xx_free(sechk_module_t *mod)
{
	xx_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (xx_data_t*)mod->data;
	if (datum) {
		/* TODO: free any allocated members of the module's
		 * private data structure */
	}

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text and prints the
 * results to stdout. The outline below prints
 * the standard format of a report section. Some modules may
 * not have results in a format that can be represented by this
 * outline and will need a different specification. It is
 * required that each of the flags for output components be
 * tested in this function (stats, list, proof, detailed, and brief)
 * TODO: fill in the indicated information in the report fields
 * as indicated below. Some alteration may be necessary for
 * checks that perform different analyses */
int xx_print_output(sechk_module_t *mod, policy_t *policy) 
{
	xx_data_t *datum = NULL;
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
	
	datum = (xx_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result && (outformat & ~(SECHK_OUT_BRF_DESCP)) && (outformat & ~(SECHK_OUT_DET_DESCP))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}
	
	if (!outformat)
		return 0; /* not an error - no output is requested */

	/* TODO: fill in output fields below */
	printf("\nModule: %s\n", mod_name);
	/* print the brief description */
	if (outformat & SECHK_OUT_BRF_DESCP) {
		printf("%s\n\n", mod->brief_description);
	}
	/* print the detailed description */
	if (outformat & SECHK_OUT_DET_DESCP) {
		printf("%s\n\n", mod->detailed_description);
	}
	/* TODO: display the statistics of the results
	 * typical text is "Found %i <itemtype>.\n"
	 * additional information may be printed here depending upon
	 * the amount of data gathered in the check */
	if (outformat & SECHK_OUT_STATS) {
		/* TODO: "Found %i <itemtype>.\n": enter itemtype */
		printf("Found %i .\n", mod->result->num_items);
		/* TODO: any additional generated statistics */
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. The default method
	 * is to display a comma separated list four items to a line
	 * this may need to be changed for longer items.
	 * TODO: you will need to enter the string representation of
	 * each item as the second parameter in the printf statement
	 * in place of the empty string.
	 * NOTE: if the item is a type of rule print only one per line. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			 /* TODO: (optional) change the number below to
			  * print more or less than 4 items per line */
			i %= 4;
			/* TODO: second parameter: item name */
			printf("%s%s", "", (i ? ", " : "\n")); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it.
	 * TODO: the name of the item should be entered below.
	 * NOTE: certain checks may need to further modify this
	 * report component if the results cannot be presented in this format */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", "");/* TODO: item name */
			printf(" - severity: %s\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check.
 * You should not need to modify this function. */
sechk_result_t *xx_get_result(sechk_module_t *mod) 
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

/* The xx_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. Initialization expected is as follows:
 * all arrays (including strings) are initialized to NULL
 * array sizes are set to 0
 * any other pointers should be NULL
 * indices into other arrays (such as type or permission indices)
 * should be initialized to -1
 * any other data should be initialized as needed by the check logic
 * TODO: initialize any non-zero/non-null data (if needed) below */
xx_data_t *xx_data_new(void)
{
	xx_data_t *datum = NULL;

	datum = (xx_data_t*)calloc(1,sizeof(xx_data_t));

	/* TODO: initialize any array indices to -1 and
	 * any other non-zero initialization data */

	return datum;
}

 
