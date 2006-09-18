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
 *   0 The module "succeeded" - no negative results found
 *   1 The module "failed"    - some negative results found */
int imp_range_trans_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i, j;
	apol_vector_t *range_trans_vector = NULL, *role_vector = NULL, *tmp_v = NULL;
	apol_vector_t *user_vector = NULL, *users_w_roles = NULL, *users_w_range = NULL;
	apol_vector_t *rule_vector = NULL;
	qpol_range_trans_t *rule;
	qpol_type_t *source = NULL;
	qpol_type_t *target = NULL;
	qpol_role_t *role = NULL;
	char *source_name = NULL, *target_name = NULL, *role_name = NULL;
	apol_role_query_t *role_query = NULL;
	apol_user_query_t *user_query = NULL;
	apol_avrule_query_t *avrule_query = NULL;
	apol_mls_range_t *range;
	qpol_mls_range_t *qpol_range;
	int error = 0;

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

	/* if already run return */
	if (mod->result)
		return 0;

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
		goto imp_range_trans_run_fail;
	}
	res->item_type = SECHK_ITEM_RANGETRANS;
	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto imp_range_trans_run_fail;
	}

	if (apol_get_range_trans_by_query(policy, NULL, &range_trans_vector) < 0 ) {
		error = errno;
		ERR(policy, "%s", "Unable to retrieve range transitions");
		goto imp_range_trans_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(range_trans_vector); i++) {
		/* collect information about the rule */
		rule = apol_vector_get_element(range_trans_vector, i);
		qpol_range_trans_get_source_type(policy->p, rule, &source);
		qpol_range_trans_get_target_type(policy->p, rule, &target);
		qpol_type_get_name(policy->p, source, &source_name);
		qpol_type_get_name(policy->p, target, &target_name);
		qpol_range_trans_get_range(policy->p, rule, &qpol_range);
		range = apol_mls_range_create_from_qpol_mls_range(policy, qpol_range);

		/* find roles possible for source */
		role_query = apol_role_query_create();		
		apol_role_query_set_type(policy, role_query, source_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		apol_role_query_destroy(&role_query);

		/* find users with the possible roles */
		if ((users_w_roles = apol_vector_create()) == NULL) {
			error = errno;
			goto imp_range_trans_run_fail;
		}
		user_query = apol_user_query_create();
		for (j = 0; j < apol_vector_get_size(role_vector); j++) {
			role = apol_vector_get_element(role_vector, j);
			qpol_role_get_name(policy->p, role, &role_name);
			apol_user_query_set_role(policy, user_query, role_name);
			apol_get_user_by_query(policy, user_query, &tmp_v);
			apol_vector_cat(users_w_roles, tmp_v);
			apol_vector_destroy(&tmp_v, NULL);
		}
		apol_vector_sort_uniquify(users_w_roles, NULL, NULL, NULL);
		apol_user_query_destroy(&user_query);
		
		/* find users with the transition range */
		user_query = apol_user_query_create();
		apol_user_query_set_range(policy, user_query, range, APOL_QUERY_SUPER);
		apol_get_user_by_query(policy, user_query, &users_w_range);
		apol_user_query_destroy(&user_query);

		/* find intersection of user sets */
		user_vector = apol_vector_create_from_intersection(users_w_roles, users_w_range, NULL, NULL);

		/* find avrules for allow <source> <target> : file execute; */
		avrule_query = apol_avrule_query_create();
		apol_avrule_query_set_rules(policy, avrule_query, QPOL_RULE_ALLOW);
		apol_avrule_query_set_source(policy, avrule_query, source_name, 1);
		apol_avrule_query_set_target(policy, avrule_query, target_name, 1);
		apol_avrule_query_append_class(policy, avrule_query, "file");
		apol_avrule_query_append_perm(policy, avrule_query, "execute");
		apol_get_avrule_by_query(policy, avrule_query, &rule_vector);
		apol_avrule_query_destroy(&avrule_query);

		/* check avrules */
		if (!apol_vector_get_size(rule_vector)) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
				ERR(policy, "%s", strerror(ENOMEM));
				error = ENOMEM;
				goto imp_range_trans_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			asprintf(&proof->text, "Missing: allow %s %s : file execute;", source_name, target_name);
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
			item = sechk_item_new(NULL);
			if (!item) {
				ERR(policy, "%s", strerror(ENOMEM));
				error = ENOMEM;
				goto imp_range_trans_run_fail;
			}
			item->item = rule;
			item->test_result = 1;
			if (!item->proof) {
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto imp_range_trans_run_fail;
				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
			proof = NULL;
		}
		apol_vector_destroy(&rule_vector, NULL);

		/* check RBAC */
		if (!apol_vector_get_size(role_vector)) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
				ERR(policy, "%s", strerror(ENOMEM));
				error = ENOMEM;
				goto imp_range_trans_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			asprintf(&proof->text, "No role associated with type %s", source_name);
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					ERR(policy, "%s", strerror(ENOMEM));
					error = ENOMEM;
					goto imp_range_trans_run_fail;
				}
				item->item = rule;
				item->test_result = 1;
			}
			if (!item->proof) {
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto imp_range_trans_run_fail;
				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
			proof = NULL;
		}

		/* check users */
		if (!apol_vector_get_size(user_vector)) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
				ERR(policy, "%s", strerror(ENOMEM));
				error = ENOMEM;
				goto imp_range_trans_run_fail;
			}
			proof->type = SECHK_ITEM_NONE;
			if (!apol_vector_get_size(role_vector)) {
				proof->text =  strdup("No role also means no user");
			} else if (!apol_vector_get_size(users_w_roles)) {
				asprintf(&proof->text, "No users associated with roles for %s", source_name);
			} else if (!apol_vector_get_size(users_w_range)) {
				proof->text =  strdup("No user has access to specified MLS range");
			} else {
				proof->text =  strdup("No user meets MLS and RBAC requirements.");
			}
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					ERR(policy, "%s", strerror(ENOMEM));
					error = ENOMEM;
					goto imp_range_trans_run_fail;
				}
				item->item = rule;
				item->test_result = 1;
			}
			if (!item->proof) {
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto imp_range_trans_run_fail;
				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto imp_range_trans_run_fail;
			}
		}
		apol_vector_destroy(&role_vector, NULL);
		apol_vector_destroy(&user_vector, NULL);
		apol_vector_destroy(&users_w_roles, NULL);
		apol_vector_destroy(&users_w_range, NULL);

		if (item) {
			if (apol_vector_append(res->items, (void*)item) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto imp_range_trans_run_fail;
			}
		}
		item = NULL;
	}
	apol_vector_destroy(&range_trans_vector, NULL);
	mod->result = res;

	return 0;

imp_range_trans_run_fail:
	apol_vector_destroy(&range_trans_vector, NULL);
	apol_vector_destroy(&role_vector, NULL);
	apol_vector_destroy(&rule_vector, NULL);
	apol_vector_destroy(&user_vector, NULL);
	apol_vector_destroy(&users_w_roles, NULL);
	apol_vector_destroy(&users_w_range, NULL);
	sechk_proof_free(proof);
	sechk_item_free(item);
	errno = error;
	return -1;
}

/* The print output function generates the text and prints the
 * results to stdout. */
int imp_range_trans_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused))) 
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	qpol_range_trans_t *rt;
	char *tmp;
	int i = 0, k=0, j=0, num_items;

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
			item = apol_vector_get_element(mod->result->items, i);
			rt = item->item;
			printf("%s\n", (tmp = apol_range_trans_render(policy, rt)));
			free(tmp);
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (k = 0; k < num_items; k++) {
			item = apol_vector_get_element(mod->result->items, k);
			rt = item->item;
			printf("%s\n", (tmp = apol_range_trans_render(policy, rt)));
			free(tmp);
			for (j = 0; j < apol_vector_get_size(item->proof); j++) {
				proof = apol_vector_get_element(item->proof, j);
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

