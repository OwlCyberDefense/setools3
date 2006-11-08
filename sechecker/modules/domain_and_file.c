/**
 *  @file domain_and_file.c
 *  Implementation of the domain and file type module.
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

#include "domain_and_file.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "domain_and_file";

int domain_and_file_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "No library");
		errno = EINVAL;
		return -1;
	}

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s", "Module unknown");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign descriptions */
	mod->brief_description = "types treated as a domain and file type";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all types in the policy treated as both a domain and a file   \n"
		"type.  See find_domains and find_file_types modules for details about the       \n"
		"heuristics used to determine these types.  It is considered bad security\n"
		"practice to use the same type for a domain and its data objects because it \n"
		"requires that less restrictive access be granted to these types.\n";
	mod->opt_description =
		"Module requirements:\n"
		"   policy source\n"
		"Module dependencies:\n" "   find_domains module\n" "   find_file_types module\n" "Module options:\n" "   none\n";
	mod->severity = SECHK_SEV_LOW;
	/* assign requirements */
	apol_vector_append(mod->requirements, sechk_name_value_new("policy_type", "source"));

	/* assign dependencies */
	apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_domains"));
	apol_vector_append(mod->dependencies, sechk_name_value_new("module", "find_file_types"));

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
	fn_struct->fn = &domain_and_file_init;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
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
	fn_struct->fn = domain_and_file_run;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
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
	fn_struct->fn = domain_and_file_print;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

int domain_and_file_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
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

int domain_and_file_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *domain_res = NULL, *file_type_res = NULL;
	size_t i, j, k;
	sechk_mod_fn_t run_fn = NULL;
	sechk_name_value_t *dep = NULL;
	apol_vector_t *domain_vector;
	apol_vector_t *type_vector;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
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
		goto domain_and_file_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto domain_and_file_run_fail;
	}

	/* run dependencies */
	for (i = 0; i < apol_vector_get_size(mod->dependencies); i++) {
		dep = apol_vector_get_element(mod->dependencies, i);
		run_fn = sechk_lib_get_module_function(dep->value, SECHK_MOD_FN_RUN, mod->parent_lib);
		run_fn(sechk_lib_get_module(dep->value, mod->parent_lib), policy, NULL);
	}

	/* get results */
	domain_res = sechk_lib_get_module_result("find_domains", mod->parent_lib);
	if (!domain_res) {
		error = errno;
		ERR(policy, "%s", "Unable to get results for module find_domains");
		goto domain_and_file_run_fail;
	}
	file_type_res = sechk_lib_get_module_result("find_file_types", mod->parent_lib);
	if (!file_type_res) {
		error = errno;
		ERR(policy, "%s", "Unable to get results for module find_file_types");
		goto domain_and_file_run_fail;
	}

	/* get lists */
	domain_vector = (apol_vector_t *) domain_res->items;
	type_vector = (apol_vector_t *) file_type_res->items;

	/* build the both list */
	for (i = 0; i < apol_vector_get_size(type_vector); i++) {
		sechk_item_t *type_item;
		qpol_type_t *type;
		char *type_name;

		type_item = apol_vector_get_element(type_vector, i);
		type = type_item->item;
		qpol_type_get_name(q, type, &type_name);
		for (j = 0; j < apol_vector_get_size(domain_vector); j++) {
			sechk_item_t *domain_item;
			qpol_type_t *domain;
			char *domain_name;

			domain_item = apol_vector_get_element(domain_vector, j);
			domain = domain_item->item;
			qpol_type_get_name(q, domain, &domain_name);
			if (!strcmp(domain_name, type_name)) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto domain_and_file_run_fail;
				}
				item->item = (void *)domain;
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto domain_and_file_run_fail;
				}
				for (k = 0; k < apol_vector_get_size(domain_item->proof); k++) {
					sechk_proof_t *domain_proof;

					domain_proof = apol_vector_get_element(domain_item->proof, k);
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
					proof->type = SECHK_ITEM_TYPE;
					proof->text = strdup(domain_proof->text);
					if (!proof->text) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
				}
				for (k = 0; k < apol_vector_get_size(type_item->proof); k++) {
					sechk_proof_t *type_proof;

					type_proof = apol_vector_get_element(type_item->proof, k);
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
					proof->type = SECHK_ITEM_TYPE;
					proof->text = strdup(type_proof->text);
					if (!proof->text) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto domain_and_file_run_fail;
					}
				}
				if (apol_vector_append(res->items, (void *)item) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto domain_and_file_run_fail;
				}
			}
		}
	}

	mod->result = res;

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      domain_and_file_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

void domain_and_file_data_free(void *data)
{
	free(data);
}

int domain_and_file_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k = 0, l = 0, num_items;
	qpol_type_t *type;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	char *type_name;

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

	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0;	       /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			j %= 4;
			item = apol_vector_get_element(mod->result->items, i);
			type = (qpol_type_t *) item->item;
			qpol_type_get_name(q, type, &type_name);
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (k = 0; k < num_items; k++) {
			item = apol_vector_get_element(mod->result->items, k);
			if (item) {
				type = item->item;
				qpol_type_get_name(q, type, &type_name);
				printf("%s\n", (char *)type_name);
				for (l = 0; l < apol_vector_get_size(item->proof); l++) {
					proof = apol_vector_get_element(item->proof, l);
					if (proof)
						printf("\t%s\n", proof->text);
				}
			}
		}
		printf("\n");
	}

	return 0;
}
