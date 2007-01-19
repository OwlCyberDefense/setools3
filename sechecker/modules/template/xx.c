/**
 *  @file
 *  Implementation of the xx module.
 *
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *
 *  Copyright (C) 2005-2007 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/* NOTE: TODO This is a module template, which includes all the necessary
 * infrastructure to implement a basic SEChecker module. To use this template
 * first replace all instances of the string xx with the name of the module,
 * then edit or complete all sections marked TODO as instructed. */

#include <config.h>

#include "sechecker.h"
#include <apol/policy.h>
#include "xx.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem of the file
 * name; it should also match the prefix of all functions defined in this
 * module and the private data storage structure */
static const char *const mod_name = "xx";

/* The register function registers all of a module's functions
 * with the library. TODO: Edit the description fields to include all
 * options, requirements, and dependencies. Also provide a brief summary
 * of the steps performed in this module's checks. If you are adding
 * additional functions you need other modules to call, see the note at
 * the bottom of this function to do so. */
int xx_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;

	if (!lib) {
		ERR(NULL, "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the register list file and their name and options
	 * are stored in the module vector of the library. The name is looked up to
	 * determine where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(lib->policy, "Module unknown \"%s\"", mod_name);
		errno = ENOENT;
		return -1;
	}

	mod->parent_lib = lib;

	/* TODO: assign the descriptions */
	mod->brief_description = "";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"TODO: detailed description for this module.\n";
	mod->opt_description =
		"  Module requirements:\n" "    none\n" "  Module dependencies:\n" "    none\n" "  Module options:\n" "    none\n";
	mod->severity = "TODO: set proper severity";

	/* TODO: assign default options (remove if none)
	 * fill name and value and repeat as needed */
	nv = sechk_name_value_new("", "");
	apol_vector_append(mod->options, (void *)nv);

	/* TODO: assign requirements (remove if none)
	 * fill name and value and repeat as needed */
	nv = sechk_name_value_new("", "");
	apol_vector_append(mod->requirements, (void *)nv);

	/* TODO: assign dependencies (remove if not needed)
	 * fill name and value and repeat as needed */
	nv = sechk_name_value_new("", "");
	apol_vector_append(mod->dependencies, (void *)nv);

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = xx_init;
	apol_vector_append(mod->functions, (void *)fn_struct);

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = xx_run;
	apol_vector_append(mod->functions, (void *)fn_struct);

	/* TODO: if the module does not have a private data structure
	 * set this function pointer to NULL */
	mod->data_free = xx_data_free;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = xx_print;
	apol_vector_append(mod->functions, (void *)fn_struct);

	/* TODO: (optional) add any other functions needed here,
	 * add a block as above for each additional function */

	return 0;
}

/* The init function creates the module's private data storage object and
 * initializes its values.  Add any option processing logic as indicated below.
 * TODO: add options processing logic */
int xx_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_name_value_t *opt = NULL;
	xx_data_t *datum = NULL;
	int error = 0;
	size_t i = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)\n", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* If the module doesnot have a privte data sturcture replace the following
	 * block with "mod->data = NULL" */
	datum = xx_data_new();
	if (!datum) {
		error = errno;
		ERR(policy, "Error: %s\n", strerror(error));
		errno = error;
		return -1;
	}
	mod->data = datum;

	for (i = 0; i < apol_vector_get_size(mod->options); i++) {
		opt = apol_vector_get_element(mod->options, i);
		/* TODO: check options
		 * check strings opt->name and opt->value of each option
		 * to set the members of the private data storage object
		 * (pointed to by datum).
		 * i.e. if (!strcmp(...)) {} else if (!strcmp((...)) etc.
		 * There should be relatively few options for any one module.
		 * If too many options are needed consider splitting the check
		 * into multiple modules and using dependencies.  It is desirable
		 * for all checks to be a simple and granular as is possible */
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found
 * TODO: add check logic */
int xx_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	xx_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int error = 0;

	/* TODO: define any aditional variables needed */

	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (xx_data_t *) mod->data;
	res = sechk_result_new();
	if (!res) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		errno = error;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto xx_run_fail;
	}
	/* TODO: set res->item_type to indicate which array the item_id indexes
	 * use values from the sechk_item_type_e enum (see sechecker.h) */

	/* TODO: check logic here 
	 * Perform check here. Create and initialize items and proof as found,
	 * appending to the appropriate vectors.
	 * For examples of the type of code to use here see other modules. */

	mod->result = res;

	/* If module finds something that would be considered a failure
	 * of the policy return 1 here */
	if (apol_vector_get_size(res->items) > 0)
		return 1;

	return 0;

      xx_run_fail:
	/* TODO: free any other memory allocated during check logic */
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The free function frees the private data of a module
 * TODO: be sure to free any allocated space in the private data */
void xx_data_free(void *data)
{
	xx_data_t *datum = (xx_data_t *) data;

	if (datum) {
		/* TODO: free any allocated members of the module's
		 * private data structure */
	}

	free(data);
}

/* The print function generates the text and prints the results to stdout. The
 * outline below prints the standard format of a report section. Some modules
 * may not have results in a format that can be represented by this outline and
 * will need a different specification. It is required that each of the flags
 * for output components be tested in this function (stats, list, proof,
 * detailed, and brief) TODO: fill in the indicated information in the report
 * fields as indicated below. Some alteration may be necessary for checks that
 * perform different analyses */
int xx_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	xx_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = (xx_data_t *) mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		ERR(policy, "Module %s has not been run", mod->name);
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0;	       /* not an error - no output is requested */

	/* TODO: display the statistics of the results
	 * typical text is "Found %i <itemtype>.\n"
	 * additional information may be printed here depending upon
	 * the amount of data gathered in the check */
	if (outformat & SECHK_OUT_STATS) {
		/* TODO: "Found %i <itemtype>.\n": enter itemtype */
		printf("Found %zd .\n", apol_vector_get_size(mod->result->items));
		/* TODO: any additional generated statistics */
	}
	/* The list report component is a display of all items found without any
	 * supporting proof. The default method is to display a comma separated list
	 * four items to a line this may need to be changed for longer items.
	 * TODO: you will need to enter the string representation of
	 * each item as the second parameter in the printf statement
	 * in place of the empty string.
	 * NOTE: if the item is a type of rule print only one per line. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			item = apol_vector_get_element(mod->result->items, i);
			i++;
			/* TODO: (optional) change the number below to
			 * print more or less than 4 items per line */
			i %= 4;
			/* TODO: second parameter: item name */
			printf("%s%s", "", (i ? ", " : "\n"));
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items with an
	 * indented list of proof statements supporting the result of the check for
	 * that item (e.g. rules with a given type).  Each proof element is then
	 * displayed in an indented list one per line below it.
	 * TODO: the name of the item should be entered below.
	 * NOTE: certain checks may need to further modify this report component if
	 * the results cannot be presented in this format */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			item = apol_vector_get_element(mod->result->items, i);
			printf("%s", "");	/* TODO: item name */
			printf(" - severity: %s\n", sechk_item_sev(item));
			for (j = 0; j < apol_vector_get_size(item->proof); j++) {
				proof = apol_vector_get_element(item->proof, j);
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

/* The xx_data_new function allocates and returns an initialized private data
 * storage structure for this module. 
 * TODO: initialize any non-zero/non-null data (if needed) below */
xx_data_t *xx_data_new(void)
{
	xx_data_t *datum = NULL;

	datum = (xx_data_t *) calloc(1, sizeof(xx_data_t));

	/* TODO: initialize data */

	return datum;
}
