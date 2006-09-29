/**
 *  @file types_wo_allow.c
 *  Implementation of the types without allow rules module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2005-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "types_wo_allow.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "types_wo_allow";

/* The register function registers all of a module's functions
 * with the library. */
int types_wo_allow_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

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
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = types_wo_allow_init;
	if ( apol_vector_append(mod->functions, (void *)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = types_wo_allow_run;
	if ( apol_vector_append(mod->functions, (void *)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = types_wo_allow_print;
	if ( apol_vector_append(mod->functions, (void *)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	fn_struct->fn = types_wo_allow_get_list;
	if ( apol_vector_append(mod->functions, (void *)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int types_wo_allow_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int types_wo_allow_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;	
	bool_t used = FALSE;
	apol_vector_t *type_vector;
	apol_vector_t *avrule_vector;
	apol_avrule_query_t *avrule_query = NULL;
	int error = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto types_wo_allow_run_fail;
	}
	res->item_type  = SECHK_ITEM_TYPE;
	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto types_wo_allow_run_fail;
	}

	if (!(avrule_query = apol_avrule_query_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto types_wo_allow_run_fail;
	}


	if (apol_get_type_by_query(policy, NULL, &type_vector) < 0) {
		error = errno;
		goto types_wo_allow_run_fail;
	}

	for (i = 0 ; i < apol_vector_get_size(type_vector) ; i++) {
		qpol_type_t *type;
		char *type_name;
		size_t j;

		used = FALSE;
		type = apol_vector_get_element(type_vector, i);
		qpol_type_get_name(policy->p, type, &type_name);

		/* Check source for allow type */
		apol_avrule_query_set_source(policy, avrule_query, type_name, 1);
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j=0;j<apol_vector_get_size(avrule_vector);j++) {
			size_t rule_type;
			qpol_avrule_t *rule;

			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_rule_type(policy->p, rule, &rule_type);
			if ( rule_type == QPOL_RULE_ALLOW ) 
				used = TRUE;
		}
		apol_vector_destroy(&avrule_vector, NULL);
		if ( used )
			continue;

		/* Check target for allow type */
		apol_avrule_query_set_source(policy, avrule_query, NULL, 0);
		apol_avrule_query_set_target(policy, avrule_query, type_name, 1);
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			size_t rule_type;
			qpol_avrule_t *rule;

			rule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_rule_type(policy->p, rule, &rule_type);
			if ( rule_type == QPOL_RULE_ALLOW ) 
				used = TRUE;
		}
		apol_vector_destroy(&avrule_vector, NULL);
		apol_avrule_query_set_target(policy, avrule_query, NULL, 0);
		if ( used )
			continue;

		/* not used anywhere*/
		item = sechk_item_new(NULL);
		if (!item) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto types_wo_allow_run_fail;
		}
		item->test_result = 1;
		item->item = (void *)type;
		proof = sechk_proof_new(NULL);
		if (!proof) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto types_wo_allow_run_fail;
		}
		proof->type = SECHK_ITEM_TYPE;
		proof->text = strdup("This type does not appear in any allow rules.");
		if (!proof->text) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto types_wo_allow_run_fail;
		}
		if ( !item->proof ) {
			if ( !(item->proof = apol_vector_create()) ) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto types_wo_allow_run_fail;
			}
		}
		if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto types_wo_allow_run_fail;
		}
		if ( apol_vector_append(res->items, (void *)item) < 0 ) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto types_wo_allow_run_fail;
		}
	}
	apol_vector_destroy(&type_vector, NULL);
	apol_vector_destroy(&avrule_vector, NULL);
	apol_avrule_query_destroy(&avrule_query);

	mod->result = res;

	return 0;

types_wo_allow_run_fail:
	apol_vector_destroy(&type_vector, NULL);
	apol_vector_destroy(&avrule_vector, NULL);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print function generates the text printed in the
 * report and prints it to stdout. */
int types_wo_allow_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused))) 
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j=0, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy){
		ERR(policy, "%s", "Invalid parameters");
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types do not appear in any allow rules.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item  = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(policy->p, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
		}
		printf("\n");
	}
	return 0;
}

int types_wo_allow_get_list(sechk_module_t *mod, apol_policy_t *policy __attribute__((unused)), void *arg)
{
	apol_vector_t **v = arg;

	if (!mod || !arg) {
		ERR(NULL, "%s", "Invalid parameters"); 
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(NULL, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}
	if (!mod->result) {
		ERR(NULL, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	v = &mod->result->items;
	return 0;
}

