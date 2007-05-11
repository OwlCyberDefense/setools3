/**
 *  @file
 *  Implementation of the incomplete mount permissions module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
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

#include "inc_mount.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "inc_mount";

/* The register function registers all of a module's functions
 * with the library.  */
int inc_mount_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "no library");
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
	mod->brief_description = "domains with partial mount permissions";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds domains that have incomplete mount permissions.\n"
		"In order for a mount operation to be allowed by the policy the following rules\n"
		"must be present: \n"
		"\n"
		"   1) allow somedomain_d sometype_t : filesystem  { mount };\n"
		"   2) allow somedomain_d sometype_t : dir { mounton };\n"
		"\n" "This module finds domains that have only one of the rules listed above.\n";
	mod->opt_description =
		"Module requirements:\n" "   none\n" "Module dependencies:\n" "   none\n" "Module options:\n" "   none\n";
	mod->severity = SECHK_SEV_MED;
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
	fn_struct->fn = inc_mount_init;
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
	fn_struct->fn = inc_mount_run;
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
	fn_struct->fn = inc_mount_print;
	if (apol_vector_append(mod->functions, (void *)fn_struct) < 0) {
		ERR(NULL, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_mount_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
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

int inc_mount_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i, j;
	bool both = false, add_proof = false;
	int error = 0;
	char *tmp = NULL;
	apol_vector_t *mount_vector;
	apol_vector_t *mounton_vector;
	apol_avrule_query_t *mount_avrule_query = NULL;
	apol_avrule_query_t *mounton_avrule_query = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);

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
		goto inc_mount_run_fail;
	}
	res->item_type = SECHK_ITEM_TYPE;
	if (!(res->items = apol_vector_create(sechk_item_free))) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto inc_mount_run_fail;
	}

	if (!(mount_avrule_query = apol_avrule_query_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto inc_mount_run_fail;
	}

	if (!(mounton_avrule_query = apol_avrule_query_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto inc_mount_run_fail;
	}

	/* Get avrules for filesystem mount */
	apol_avrule_query_set_rules(policy, mount_avrule_query, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, mount_avrule_query, "filesystem");
	apol_avrule_query_append_perm(policy, mount_avrule_query, "mount");
	apol_avrule_get_by_query(policy, mount_avrule_query, &mount_vector);

	/* Get avrules for dir mounton */
	apol_avrule_query_set_rules(policy, mounton_avrule_query, QPOL_RULE_ALLOW);
	apol_avrule_query_append_class(policy, mounton_avrule_query, "dir");
	apol_avrule_query_append_perm(policy, mounton_avrule_query, "mounton");
	apol_avrule_get_by_query(policy, mounton_avrule_query, &mounton_vector);

	for (i = 0; i < apol_vector_get_size(mount_vector); i++) {
		qpol_avrule_t *mount_rule;
		qpol_type_t *mount_source;
		qpol_type_t *mount_target;
		char *mount_source_name, *mount_target_name;

		both = false;
		add_proof = true;
		mount_rule = apol_vector_get_element(mount_vector, i);
		qpol_avrule_get_source_type(q, mount_rule, &mount_source);
		qpol_avrule_get_target_type(q, mount_rule, &mount_target);
		qpol_type_get_name(q, mount_source, &mount_source_name);
		qpol_type_get_name(q, mount_target, &mount_target_name);

		for (j = 0; j < apol_vector_get_size(mounton_vector); j++) {
			qpol_avrule_t *mounton_rule;
			qpol_type_t *mounton_source;
			qpol_type_t *mounton_target;
			char *mounton_source_name, *mounton_target_name;

			mounton_rule = apol_vector_get_element(mounton_vector, j);
			qpol_avrule_get_source_type(q, mounton_rule, &mounton_source);
			qpol_avrule_get_target_type(q, mounton_rule, &mounton_target);
			qpol_type_get_name(q, mounton_source, &mounton_source_name);
			qpol_type_get_name(q, mounton_target, &mounton_target_name);

			/* Check to see if they match */
			if (!strcmp(mount_source_name, mounton_source_name) && !strcmp(mount_target_name, mounton_target_name))
				both = true;
		}
		if (!both) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto inc_mount_run_fail;
			}
			proof->type = SECHK_ITEM_AVRULE;
			proof->elem = mount_rule;
			tmp = apol_avrule_render(policy, mount_rule);
			asprintf(&proof->text, "Have Rule:\n\t\t%s\n\tMissing:\n\t\tallow %s %s : dir mounton ;\n",
				 tmp, mount_source_name, mount_target_name);
			free(tmp);
			if (!proof->text) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto inc_mount_run_fail;
			}
			for (j = 0; j < apol_vector_get_size(res->items); j++) {
				sechk_item_t *res_item;
				qpol_type_t *res_type;
				char *res_type_name;

				res_item = apol_vector_get_element(res->items, j);
				res_type = res_item->item;
				qpol_type_get_name(q, res_type, &res_type_name);
				if (!strcmp(mount_source_name, res_type_name) || !strcmp(mount_target_name, res_type_name))
					add_proof = false;
			}
			if (add_proof) {
				if (!item) {
					item = sechk_item_new(NULL);
					if (!item) {
						error = errno;
						ERR(NULL, "%s", strerror(ENOMEM));
						goto inc_mount_run_fail;
					}
					item->item = (void *)mount_source;
				}
				if (!item->proof) {
					if (!(item->proof = apol_vector_create(sechk_proof_free))) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto inc_mount_run_fail;
					}
				}
				if (apol_vector_append(item->proof, (void *)proof) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_mount_run_fail;
				}
				if (apol_vector_append(res->items, (void *)item) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_mount_run_fail;
				}
				item = NULL;
				proof = NULL;
			}
			sechk_proof_free(proof);
			proof = NULL;
		}
	}

	for (i = 0; i < apol_vector_get_size(mounton_vector); i++) {
		qpol_avrule_t *mounton_rule;
		qpol_type_t *mounton_source;
		qpol_type_t *mounton_target;
		char *mounton_source_name, *mounton_target_name;

		both = false;
		add_proof = true;
		mounton_rule = apol_vector_get_element(mounton_vector, i);
		qpol_avrule_get_source_type(q, mounton_rule, &mounton_source);
		qpol_avrule_get_target_type(q, mounton_rule, &mounton_target);
		qpol_type_get_name(q, mounton_source, &mounton_source_name);
		qpol_type_get_name(q, mounton_target, &mounton_target_name);

		for (j = 0; j < apol_vector_get_size(mount_vector); j++) {
			qpol_avrule_t *mount_rule;
			qpol_type_t *mount_source;
			qpol_type_t *mount_target;
			char *mount_source_name, *mount_target_name;

			mount_rule = apol_vector_get_element(mount_vector, j);
			qpol_avrule_get_source_type(q, mount_rule, &mount_source);
			qpol_avrule_get_target_type(q, mount_rule, &mount_target);
			qpol_type_get_name(q, mount_source, &mount_source_name);
			qpol_type_get_name(q, mount_target, &mount_target_name);

			if (!strcmp(mount_source_name, mounton_source_name) && !strcmp(mount_target_name, mounton_target_name))
				both = true;
		}
		if (!both) {
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto inc_mount_run_fail;
			}
			proof->type = SECHK_ITEM_AVRULE;
			proof->elem = mounton_rule;
			tmp = apol_avrule_render(policy, mounton_rule);
			asprintf(&proof->text, "Have Rule:\n\t\t%s\n\tMissing:\n\t\tallow %s %s : filesystem mount ;\n",
				 tmp, mounton_source_name, mounton_target_name);
			free(tmp);
			for (j = 0; j < apol_vector_get_size(res->items); j++) {
				sechk_item_t *res_item;
				qpol_type_t *res_type;
				char *res_type_name;

				res_item = apol_vector_get_element(res->items, j);
				res_type = res_item->item;
				qpol_type_get_name(q, res_type, &res_type_name);
				if (!strcmp(mounton_source_name, res_type_name) || !strcmp(mounton_target_name, res_type_name))
					add_proof = false;
			}
			if (add_proof) {
				if (!item) {
					item = sechk_item_new(NULL);
					if (!item) {
						error = errno;
						ERR(NULL, "%s", strerror(ENOMEM));
						goto inc_mount_run_fail;
					}
					item->item = (void *)mounton_source;
				}
				if (!item->proof) {
					if (!(item->proof = apol_vector_create(sechk_proof_free))) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto inc_mount_run_fail;
					}
				}
				if (apol_vector_append(item->proof, (void *)proof) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_mount_run_fail;
				}
				if (apol_vector_append(res->items, (void *)item) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto inc_mount_run_fail;
				}
				item = NULL;
				proof = NULL;
			}
			sechk_proof_free(proof);
			proof = NULL;
		}
	}
	apol_vector_destroy(&mount_vector);
	apol_vector_destroy(&mounton_vector);

	mod->result = res;
	apol_avrule_query_destroy(&mount_avrule_query);
	apol_avrule_query_destroy(&mounton_avrule_query);

	if (apol_vector_get_size(res->items))
		return 1;
	return 0;

      inc_mount_run_fail:
	apol_vector_destroy(&mount_vector);
	apol_vector_destroy(&mounton_vector);
	apol_avrule_query_destroy(&mount_avrule_query);
	apol_avrule_query_destroy(&mounton_avrule_query);
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(tmp);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_mount_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k, l, num_items;
	qpol_type_t *type;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	char *type_name;

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
		printf("Found %zd types.\n", num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(q, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with the severity.
	 * Each proof element is then displayed in an indented list one per
	 * line below it. */
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
