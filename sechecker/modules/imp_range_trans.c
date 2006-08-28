/**
 *  @file imp_range_trans.c
 *  Implementation of the impossible range_transition module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author: David Windsor <dwindsor@tresys.com>
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

/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "imp_range_trans.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define SECHK_NO_ROLES          0x000002
#define SECHK_BAD_USER_MLS_LOW  0x000040
#define SECHK_BAD_USER_MLS_HIGH 0x000600
#define SECHK_NO_USERS          0x008000
#define SECHK_NO_EXEC_PERMS     0x020000

static const char *const mod_name = "imp_range_trans";

int imp_range_trans_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		return -1;
	}

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		return -1;
	}
	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "finds impossible range transitions";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds impossible range transitions in a policy.\n"
		"A range transition is possible if and only if all of the following conditions\n" 
		"are satisfied:\n"
		"   1) there exist TE rules allowing the range transition to occur\n"
		"   2) there exist RBAC rules allowing the range transition to occur\n"
		"   3) at least one user must be able to transition to the target MLS range\n";
	mod->opt_description = 
		"  Module requirements:\n"
		"    none\n"
		"  Module dependencies:\n"
		"    none\n"
		"  Module options:\n"
		"    none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign requirements */
	mod->requirements = NULL;

	/* assign dependencies */
	mod->dependencies = NULL;

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
	fn_struct->fn = imp_range_trans_init;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return - 1;
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
	fn_struct->fn = imp_range_trans_run;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return - 1;
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
	fn_struct->fn = imp_range_trans_print;
	if ( apol_vector_append(mod->functions, (void*)fn_struct) < 0 ) {
		ERR(NULL, "%s", strerror(ENOMEM));
		return - 1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int imp_range_trans_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
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
 * in all relavant item and proof data. 
 * Return Values:
 *  -1 System error
 *   0 The module "succeeded"	- no negative results found
 *   1 The module "failed" 		- some negative results found */
int imp_range_trans_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i;
	apol_vector_t *range_trans_vector = NULL;
	qpol_type_t *entry_point = NULL;
	qpol_class_t *class = NULL;

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
		goto imp_range_trans_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if ( !(res->items = apol_vector_create()) ) {
		ERR(policy, "%s", strerror(ENOMEM));
		goto imp_range_trans_run_fail;
	}

	/* resolve "file" object class to idx */
	if ( qpol_policy_get_class_by_name(policy->qh, policy->p, "file", &class) < 0 ) {
		ERR(policy, "%s", "Could not retrieve file class");
		goto imp_range_trans_run_fail;
	}

	if ( apol_get_range_trans_by_query(policy, NULL, &range_trans_vector) < 0  ) {
		ERR(policy, "%s", "Unable to retrieve range transitions");
		goto imp_range_trans_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(range_trans_vector); i++) {
		qpol_range_trans_t *rule;
		qpol_type_t *source;
		qpol_type_t *target;
		char *source_name;
		char *target_name;
		apol_vector_t *role_vector;
		apol_vector_t *rbac_vector;
		apol_vector_t *user_vector;
		apol_role_query_t *role_query = NULL;
		apol_user_query_t *user_query = NULL;
		apol_mls_range_t *range;
		qpol_mls_range_t *qpol_range;
		int info, j;

		rule = apol_vector_get_element(range_trans_vector, i);
		qpol_range_trans_get_source_type(policy->qh, policy->p, rule, &source);
		qpol_range_trans_get_target_type(policy->qh, policy->p, rule, &target);
		qpol_type_get_name(policy->qh, policy->p, source, &source_name);
		qpol_type_get_name(policy->qh, policy->p, target, &target_name);
		qpol_range_trans_get_range(policy->qh, policy->p, rule, &qpol_range);
		range = apol_mls_range_create_from_qpol_mls_range(policy, qpol_range);

		/* Check TE rules */
		info = apol_domain_trans_table_verify_trans(policy, source, entry_point, target);
		if ( info ) {
			/* Add item */
			proof = sechk_proof_new(NULL);
			if (!proof) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}
			proof->type = SECHK_ITEM_TYPE;
			proof->text = strdup(apol_range_trans_render(policy, rule));
			if (!proof->text) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}

			for (j = 0; j < apol_vector_get_size(res->items); j++) {
				sechk_item_t *res_item = NULL;
				qpol_type_t *res_type;
				char *res_type_name;

				res_item = apol_vector_get_element(res->items, j);
				res_type = res_item->item;
				qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
				if (!strcmp(res_type_name, source_name)) item = res_item;
			}
			if ( !item ) {
				item = sechk_item_new(NULL);
				if (!item) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}
				item->item = source;
				if ( apol_vector_append(res->items, (void *)item) < 0 ) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}
			}
			item->test_result = 1;

			if ( !item->proof ) {
				if ( !(item->proof = apol_vector_create()) ) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}
			}
			if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}
			item = NULL;
		}

		/* Check RBAC rules */
		role_query = apol_role_query_create();		
		apol_role_query_set_type(policy, role_query, source_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		for (j = 0; j < apol_vector_get_size(role_vector); j++) {
			qpol_role_t *role;
			apol_role_trans_query_t *rbac_query = NULL;
			char *role_name;

			rbac_query = apol_role_trans_query_create();
			role = apol_vector_get_element(role_vector, j);
			qpol_role_get_name(policy->qh, policy->p, role, &role_name);
			apol_role_trans_query_set_source(policy, rbac_query, role_name);
			apol_role_trans_query_set_target(policy, rbac_query, target_name, 1);
			apol_get_role_trans_by_query(policy, rbac_query, &rbac_vector);
			if ( apol_vector_get_size(rbac_vector) <= 0 ) {
				proof = sechk_proof_new(NULL);
				if (!proof) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}
				proof->type = SECHK_ITEM_TYPE;
				proof->text = strdup("No role\n");
				if (!proof->text) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}

				for (j = 0; j < apol_vector_get_size(res->items); j++) {
					sechk_item_t *res_item = NULL;
					qpol_type_t *res_type;
					char *res_type_name;

					res_item = apol_vector_get_element(res->items, j);
					res_type = res_item->item;
					qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
					if (!strcmp(res_type_name, source_name)) item = res_item;
				}
				if ( !item ) {
					item = sechk_item_new(NULL);
					if (!item) {
						ERR(policy, "%s", strerror(ENOMEM));
						goto imp_range_trans_run_fail;
					}	
					item->item = source;
					if ( apol_vector_append(res->items, (void *)item) < 0 ) {
						ERR(policy, "%s", strerror(ENOMEM));
						goto imp_range_trans_run_fail;
					}

				}
				item->test_result = 1;

				if ( !item->proof ) {
					if ( !(item->proof = apol_vector_create()) ) {
						ERR(policy, "%s", strerror(ENOMEM));
						goto imp_range_trans_run_fail;
					}
				}
				if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
					ERR(policy, "%s", strerror(ENOMEM));
					goto imp_range_trans_run_fail;
				}
				item = NULL;
			}
		}

		/* Check users allowed for this range */
		user_query = apol_user_query_create();
		apol_user_query_set_range(policy, user_query, range, APOL_QUERY_SUPER);
		apol_get_user_by_query(policy, user_query, &user_vector);
		if ( apol_vector_get_size(user_vector) > 0 ) continue;

		proof = sechk_proof_new(NULL);
		if (!proof) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto imp_range_trans_run_fail;
		}
		proof->type = SECHK_ITEM_TYPE;
		proof->text = strdup("No user\n");
		if (!proof->text) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto imp_range_trans_run_fail;
		}

		for (j = 0; j < apol_vector_get_size(res->items); j++) {
			sechk_item_t *res_item = NULL;
			qpol_type_t *res_type;
			char *res_type_name;

			res_item = apol_vector_get_element(res->items, j);
			res_type = res_item->item;
			qpol_type_get_name(policy->qh, policy->p, res_type, &res_type_name);
			if (!strcmp(res_type_name, source_name)) item = res_item;
		}
		if ( !item ) {
			item = sechk_item_new(NULL);
			if (!item) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}	
			item->item = source;
			if ( apol_vector_append(res->items, (void *)item) < 0 ) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}
		}
		item->test_result = 1;

		if ( !item->proof ) {
			if ( !(item->proof = apol_vector_create()) ) {
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}
		}
		if ( apol_vector_append(item->proof, (void *)proof) < 0 ) {
			ERR(policy, "%s", strerror(ENOMEM));
			goto imp_range_trans_run_fail;
		}
		proof = NULL;
		item = NULL;
	}
	mod->result = res;

	return 0;

imp_range_trans_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	return -1;
}

/* The print output function generates the text and prints the
 * results to stdout. */
int imp_range_trans_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused))) 
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	qpol_type_t *type;
	char *type_name;
	int i = 0, j=0, k=0, l=0, num_items;

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
		ERR(policy, "%s", "Module has not been run");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i impossible range transitions.\n", num_items);
	}

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
		for (k=0;k< num_items;k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if ( item ) {
				type = item->item;
				qpol_type_get_name(policy->qh, policy->p, type, &type_name);
				printf("%s\n", (char*)type_name);
				for (l=0; l<apol_vector_get_size(item->proof);l++) {
					proof = apol_vector_get_element(item->proof,l);
					if ( proof )
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}

	return 0;
}

