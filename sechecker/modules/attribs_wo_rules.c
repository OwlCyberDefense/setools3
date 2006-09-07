/**
 *  @file attribs_wo_rules.c
 *  Implementation of the attributes without rules module. 
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

#include "attribs_wo_rules.h"
#include <apol/type-query.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "attribs_wo_rules";

/* The register function registers all of a module's functions
 * with the library. */
int attribs_wo_rules_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;

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
	if ( apol_vector_append(mod->requirements, sechk_name_value_new("policy_type", "source")) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = attribs_wo_rules_init;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = attribs_wo_rules_run;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = attribs_wo_rules_print;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = &attribs_wo_rules_get_list;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int attribs_wo_rules_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. All test logic should be placed below
 * as instructed. This function allocates the result structure and fills
 * in all relavant item and proof data. */
int attribs_wo_rules_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;
	apol_vector_t *attr_vector;
	apol_role_query_t *role_query = NULL;
	apol_avrule_query_t *avrule_query = NULL;
	apol_terule_query_t *terule_query = NULL;
	apol_vector_t *avrule_vector;
	apol_vector_t *terule_vector;
	apol_vector_t *role_vector;
	qpol_iterator_t *constraint_iter;
	qpol_iterator_t *node_iter = NULL;
	qpol_iterator_t *name_iter = NULL;
	int found = 0;

	if (!mod || !policy) {
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	res = sechk_result_new();
	if (!res) {
		ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_rules_run_fail;
	}
	res->item_type = SECHK_ITEM_ATTRIB;
	if ( !(res->items = apol_vector_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_rules_run_fail;
	}

	if ( !(avrule_query = apol_avrule_query_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_rules_run_fail;
	}
	if ( !(terule_query = apol_terule_query_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_rules_run_fail;
	}
	if ( !(role_query = apol_role_query_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto attribs_wo_rules_run_fail;
	}

	apol_get_attr_by_query(policy, NULL, &attr_vector);
	for ( i = 0; i < apol_vector_get_size(attr_vector); i ++ ) {
		qpol_type_t *attr;
		char *attr_name;
		attr = apol_vector_get_element(attr_vector, i);
		qpol_type_get_name(policy->qh, policy->p, attr, &attr_name);

		/* access rules */
		apol_avrule_query_set_source(policy, avrule_query, attr_name, 0);
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		if (apol_vector_get_size(avrule_vector) > 0) {
			apol_vector_destroy(&avrule_vector, NULL);
			continue;
		}
		apol_vector_destroy(&avrule_vector, NULL);

		apol_avrule_query_set_source(policy, avrule_query, NULL, 0);
		apol_avrule_query_set_target(policy, avrule_query, attr_name, 0);
		apol_get_avrule_by_query(policy, avrule_query, &avrule_vector);
		if (apol_vector_get_size(avrule_vector) > 0) {
			apol_vector_destroy(&avrule_vector, NULL);
			continue;
		}
		apol_avrule_query_set_target(policy, avrule_query, NULL, 0);
		apol_vector_destroy(&avrule_vector, NULL);

		/* type rules */
		apol_terule_query_set_source(policy, terule_query, attr_name, 0);
		apol_get_terule_by_query(policy, terule_query, &terule_vector);
		if (apol_vector_get_size(terule_vector) > 0) {
			apol_vector_destroy(&terule_vector, NULL);
			continue;
		}
		apol_vector_destroy(&terule_vector, NULL);

		apol_terule_query_set_source(policy, terule_query, NULL, 0);
		apol_terule_query_set_target(policy, terule_query, attr_name, 0);
		apol_get_terule_by_query(policy, terule_query, &terule_vector);
		if ( apol_vector_get_size(terule_vector) > 0 ) {
			apol_vector_destroy(&terule_vector, NULL);
			continue;
		}
		apol_terule_query_set_target(policy, terule_query, NULL, 0);
		apol_vector_destroy(&terule_vector, NULL);

		/* role trans */
		apol_role_query_set_type(policy, role_query, attr_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		if ( apol_vector_get_size(role_vector) > 0 ) {
			apol_vector_destroy(&role_vector, NULL);
			continue;
		}
		apol_vector_destroy(&role_vector, NULL);

		/* Check constraints */
		constraint_iter = NULL;
		node_iter = NULL;
		name_iter = NULL;
		found = 0;
		qpol_policy_get_constraint_iter(policy->qh, policy->p, &constraint_iter);
		for ( ; !qpol_iterator_end(constraint_iter); qpol_iterator_next(constraint_iter) ) {
			qpol_constraint_t *constraint;

			qpol_iterator_get_item(constraint_iter, (void **)&constraint);
			qpol_constraint_get_expr_iter(policy->qh, policy->p, constraint, &node_iter);

			for ( ; !qpol_iterator_end(node_iter); qpol_iterator_next(node_iter) ) {
				qpol_constraint_expr_node_t *constraint_node;
				size_t node_type;

				qpol_iterator_get_item(node_iter, (void **)&constraint_node);
				qpol_constraint_expr_node_get_expr_type(policy->qh, policy->p, constraint_node, &node_type);

				if ( node_type == QPOL_CEXPR_TYPE_NAMES ) {
					qpol_constraint_expr_node_get_names_iter(policy->qh, policy->p, constraint_node, &name_iter);

					for ( ; !qpol_iterator_end(name_iter); qpol_iterator_next(name_iter)) {
						char *name;

						qpol_iterator_get_item(name_iter, (void **)&name);
						if (!strcmp(name, attr_name)) {
							found = 1;
							free(name);
							name = NULL;
							break;
						}
						free(name);
						name = NULL;
					}
					qpol_iterator_destroy(&name_iter);
					if (found)
						break;
				}
			}
			qpol_iterator_destroy(&node_iter);
			free(constraint);
			if (found)
				break;
		}
		qpol_iterator_destroy(&constraint_iter);
		if (found)
			continue;

		/* if we get here then the attrib was not found anywhere in a rule so add it */
		item = sechk_item_new(NULL);
		if (!item) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_rules_run_fail;
		}
		item->test_result = 1;
		item->item = (void *)attr;
		proof = sechk_proof_new(NULL);
		if (!proof) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_rules_run_fail;
		}
		proof->type = SECHK_ITEM_ATTRIB;
		proof->text = strdup("attribute was not used in any rules.");
		if (!proof->text) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_rules_run_fail;
		}
		if ( !item->proof ) {
			if ( !(item->proof = apol_vector_create()) ) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto attribs_wo_rules_run_fail;
			}
		}
		if ( apol_vector_append(item->proof, (void*)proof) < 0 ) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_rules_run_fail;
		}
		if ( apol_vector_append(res->items, (void *)item) < 0 ) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto attribs_wo_rules_run_fail;
		}
	}
	apol_avrule_query_destroy(&avrule_query);
	apol_role_query_destroy(&role_query);
	apol_terule_query_destroy(&terule_query);
	apol_vector_destroy(&attr_vector, NULL);

	mod->result = res;
	return 0;

attribs_wo_rules_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int attribs_wo_rules_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j=0, k=0, l=0, num_items;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy){
		ERR(policy, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		return -1;
	}

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", strerror(ENOMEM));
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i attributes.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following attributes do not appear in any rules.\n");
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item  = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(policy->qh, policy->p, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)( (j && i!=num_items-1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (k=0;k<num_items;k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if ( item ) {
				type = item->item;
				qpol_type_get_name(policy->qh, policy->p, type, &type_name);
				printf("%s\n", type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof,l);
					if ( proof )
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}
	type = NULL;
	type_name = NULL;

	return 0;
}

int attribs_wo_rules_get_list(sechk_module_t *mod, apol_policy_t *policy __attribute__((unused)), void *arg)
{
	apol_vector_t **v = arg;

	if (!mod || !arg) {
		ERR(NULL, "%s", "Invalid parameters");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(NULL, "Wrong module (%s)", mod->name);
		return -1;
	}
	if (!mod->result) {
		ERR(NULL, "%s", "Module has not been run");
		return -1;
	}

	v = &mod->result->items;

	return 0;
}
