/**
 *  @file spurious_audit.c
 *  Implementation of the spurious audit rule module. 
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Ryan Jordan rjordan@tresys.com
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

#include "sechecker.h"
#include "spurious_audit.h"
#include <apol/policy-query.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "spurious_audit";

/* The register function registers all of a module's functions
 * with the library.  */
int spurious_audit_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		ERR(NULL, "%s", "no library");	
		return -1;
	}

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		ERR(NULL, "%s%s%s", "module unknown, \"", mod_name, "\"");
		errno = ENOENT;
		return -1;
	}

	mod->parent_lib = lib;

	/* assign the descriptions */
	mod->brief_description = "audit rules with no effect";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds audit rules in the policy which do not affect the auditing of\n"
		"the policy.  This could happen in the following situations:\n"
		"\n"
		"   1) there is an allow rule with the same key and permissions for a dontaudit\n"
		"      rule\n"
		"   2) there is an auditallow rule without an allow rule with a key and\n"
		"      permission that does not appear in an allow rule.\n";
	mod->opt_description = 
		"  Module requirements:\n"
		"    none\n"
		"  Module dependencies:\n"
		"    none\n"
		"  Module options:\n"
		"    none\n";
	mod->severity = SECHK_SEV_LOW;

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(errno));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = spurious_audit_init;
	apol_vector_append(mod->functions, (void*)fn_struct);

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(errno));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = spurious_audit_run;
	apol_vector_append(mod->functions, (void*)fn_struct);

	mod->data_free = NULL;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		ERR(lib->policy, "%s", strerror(errno));
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		ERR(lib->policy, "%s", strerror(ENOMEM));
		return -1;
	}
	fn_struct->fn = spurious_audit_print;
	apol_vector_append(mod->functions, (void*)fn_struct);

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int spurious_audit_init(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "%s%s%s", "wrong module (", mod->name, ")");
		errno = EINVAL;
		return -1;
	}

	mod->data = NULL;

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int spurious_audit_run(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused)))
{
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int error, rule_found;
	apol_avrule_query_t *query = 0;
	apol_vector_t *allow_rules, *auditallow_rules, *dontaudit_rules,
					  *perm_vector1, *perm_vector2, *perm_intersection;
	size_t i, j, k, l, tmp_counter;
	qpol_avrule_t *rule1, *rule2;
	qpol_type_t *source, *target;
	qpol_class_t *object;
	qpol_iterator_t *perm_iter1, *perm_iter2;
	char *string1, *string2, *tmp, *src_name, *tgt_name, *obj_name, *perms;

	error = rule_found = 0;
	allow_rules = auditallow_rules = dontaudit_rules =
		perm_vector1 = perm_vector2 = perm_intersection = NULL;
	rule1 = rule2 = 0;
	source = target = NULL;
	perm_iter1 = perm_iter2 = NULL;
	string1 = string2 = tmp = src_name = tgt_name = obj_name = perms = NULL;


	if (!mod || !policy) {
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "%s%s%s","wrong module (", mod->name, ")");
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
		goto spurious_audit_run_fail;
	}
	res->item_type = SECHK_ITEM_AVRULE;

	query = apol_avrule_query_create();
	if (!query) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto spurious_audit_run_fail;
	}

	apol_avrule_query_set_rules(policy, query, QPOL_RULE_AUDITALLOW);
	if (apol_get_avrule_by_query(policy, query, &auditallow_rules)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto spurious_audit_run_fail;
	}

	apol_avrule_query_set_rules(policy, query, QPOL_RULE_DONTAUDIT);
	if (apol_get_avrule_by_query(policy, query, &dontaudit_rules)) {
		error = errno;
		ERR(policy, "%s", strerror(error));
		goto spurious_audit_run_fail;
	}

	/* First error case: Allow && Don't Audit */
	for (i = 0; i < apol_vector_get_size(dontaudit_rules); i++)
	{
		/* get first (DONT_AUDIT) rule */
		rule1 = (qpol_avrule_t *) apol_vector_get_element(dontaudit_rules, i);
		if (!rule1) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		/* get source, target, object for Don't Audit rule */
		if (qpol_avrule_get_source_type(policy->p, rule1, &source)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_avrule_get_target_type(policy->p, rule1, &target)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_avrule_get_object_class(policy->p, rule1, &object)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		/* extract name strings from source, target, object */
		if (qpol_type_get_name(policy->p, source, &src_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_type_get_name(policy->p, target, &tgt_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_class_get_name(policy->p, object, &obj_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		/* configure Allow rule query to match above Don't Audit rule */
		apol_avrule_query_set_rules(policy, query, QPOL_RULE_ALLOW);
		apol_avrule_query_set_source(policy, query, src_name, 1);
		apol_avrule_query_set_target(policy, query, tgt_name, 1);
		apol_avrule_query_append_class(policy, query, NULL);
		apol_avrule_query_append_class(policy, query, obj_name);

		/* get vector of matching ALLOW rules */
		if (apol_get_avrule_by_query(policy, query, &allow_rules)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}


		if (apol_vector_get_size(allow_rules) != 0) {
			/* Bad News: Allow && Don't Audit */
			for (j = 0; j < apol_vector_get_size(allow_rules); j++)
			{	
				/* get second (Allow) rule */
				rule2 = (qpol_avrule_t *) apol_vector_get_element(allow_rules, j);
				if (!rule2) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}

				/* get permission iterators for both rules, and make vectors from them */
				if (qpol_avrule_get_perm_iter(policy->p, rule1, &perm_iter1)) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
				perm_vector1 = apol_vector_create_from_iter(perm_iter1);
				if (!perm_vector1) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}

				if (qpol_avrule_get_perm_iter(policy->p, rule2, &perm_iter2)) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
				perm_vector2 = apol_vector_create_from_iter(perm_iter2);
				if (!perm_vector2) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}

				/* create intersection of permissions */
				perm_intersection = apol_vector_create_from_intersection(perm_vector1,
						perm_vector2, apol_str_strcmp, NULL);
				if (!perm_intersection) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}

				if (apol_vector_get_size(perm_intersection) != 0) {
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto spurious_audit_run_fail;
					}
					proof->elem = (void*)rule2; /* proof is the allow rule */
					proof->type = SECHK_ITEM_AVRULE;
					/* text will show the permissions that conflict */
					tmp_counter = 0;
					for (k = 0; k < apol_vector_get_size(perm_intersection); k++)
					{
						apol_str_append(&(proof->text), &tmp_counter,
								(char*) apol_vector_get_element(perm_intersection, k));
						if (k != (apol_vector_get_size(perm_intersection) - 1))
							apol_str_append(&(proof->text), &tmp_counter, ", ");
					}
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
							error = errno;
							ERR(policy, "%s", strerror(error));
							goto spurious_audit_run_fail;
						}
						item->item = rule1; /* item is the dontaudit rule */
					}
					if (!item->proof) {
						item->proof = apol_vector_create();
						if (!item->proof) {
							error = errno;
							ERR(policy, "%s", strerror(error));
							goto spurious_audit_run_fail;
						}
					}
					apol_vector_append(item->proof, (void*) proof);

				}
				else {
					/* these two rules don't overlap, no problem */
				}
				/* clean up */
				rule2 = NULL;
				apol_vector_destroy(&perm_vector1, free);
				apol_vector_destroy(&perm_vector2, free);
				apol_vector_destroy(&perm_intersection, NULL);
				qpol_iterator_destroy(&perm_iter1);
				qpol_iterator_destroy(&perm_iter2);
			}
			if (!res->items) {
				res->items = apol_vector_create();
				if (!res->items) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			apol_vector_append(res->items, (void*) item);

			item = NULL;
			apol_vector_destroy(&allow_rules, NULL);
		}
	}
	apol_vector_destroy(&dontaudit_rules, NULL);

	/* Second error case: AuditAllow w/out Allow */
	for (i = 0; i < apol_vector_get_size(auditallow_rules); i++)
	{
		/* get first (AuditAllow) rule */
		rule1 = (qpol_avrule_t *)apol_vector_get_element(auditallow_rules, i);
		if (!rule1) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		/* get first rule's source, target, object class */
		if (qpol_avrule_get_source_type(policy->p, rule1, &source)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_avrule_get_target_type(policy->p, rule1, &target)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_avrule_get_object_class(policy->p, rule1, &object)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		/* extract name strings from source, target, object */
		if (qpol_type_get_name(policy->p, source, &src_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_type_get_name(policy->p, target, &tgt_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		if (qpol_class_get_name(policy->p, object, &obj_name)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		/* configure ALLOW rule query to match above rule */
		apol_avrule_query_set_rules(policy, query, QPOL_RULE_ALLOW);
		apol_avrule_query_set_source(policy, query, src_name, 1);
		apol_avrule_query_set_target(policy, query, tgt_name, 1);
		apol_avrule_query_append_class(policy, query, obj_name);

		if (apol_get_avrule_by_query(policy, query, &allow_rules)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		if (!apol_vector_get_size(allow_rules)) {
			/* No ALLOW rule for given AUDIT_ALLOW rule */

			/* Make proof: missing allow rule */
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}
			proof->elem = NULL;
			proof->type = SECHK_ITEM_AVRULE;

			/* grab permisisons of auditallow rule, and make text */
			if (qpol_avrule_get_perm_iter(policy->p, rule1, &perm_iter1)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}
			perm_vector1 = apol_vector_create_from_iter(perm_iter1);
			if (!perm_vector1) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}

			tmp_counter = 0;
			for (j = 0; j < apol_vector_get_size(perm_vector1); j++)
			{
				if (apol_str_append(&(proof->text), &tmp_counter,
							(char*)apol_vector_get_element(perm_vector1, j)))
				{
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
				if (j != (apol_vector_get_size(perm_vector1) - 1)) {
					if (apol_str_append(&(proof->text), &tmp_counter, ", ")) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto spurious_audit_run_fail;
					}
				}
			}
			apol_vector_destroy(&perm_vector1, free);
			qpol_iterator_destroy(&perm_iter1);

			/* Make item: inconsistent auditallow rule */
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			item->item = rule1;
			if (!item->proof) {
				item->proof = apol_vector_create();
				if (!item->proof) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			apol_vector_append(item->proof, (void*) proof);

			/* Add item to test result */
			if (!res->items) {
				res->items = apol_vector_create();
				if (!res->items) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			apol_vector_append(res->items, (void*) item);
			item = NULL;
			continue;
		}

		/* Here we have AuditAllow rule and Allow rule(s) with same key */
		/* Checking to make sure they have the same permissions */

		/* Make vector of AuditAllow permissions */
		if (qpol_avrule_get_perm_iter(policy->p, rule1, &perm_iter1)) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}
		perm_vector1 = apol_vector_create_from_iter(perm_iter1);
		if (!perm_vector1) {
			error = errno;
			ERR(policy, "%s", strerror(error));
			goto spurious_audit_run_fail;
		}

		/* Get permissions vector for Allow rule(s) */
		for (j = 0; j < apol_vector_get_size(allow_rules); j++)
		{
			/* get Allow rule */
			rule2 = (qpol_avrule_t *)apol_vector_get_element(allow_rules, j);
			if (!rule2) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}

			if (qpol_avrule_get_perm_iter(policy->p, rule2, &perm_iter2)) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}

			if (!perm_vector2) {
				perm_vector2 = apol_vector_create();
				if (!perm_vector2) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}

			/* concatenate permissions from this rule, check for errors, all in one go */
			if (apol_vector_cat(perm_vector2, apol_vector_create_from_iter(perm_iter2))) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}
		}

		/* Find intersection of permission, put into a vector */
		perm_intersection = apol_vector_create_from_intersection(perm_vector1, perm_vector2,
				apol_str_strcmp, NULL);

		if (apol_vector_get_size(perm_intersection) != apol_vector_get_size(perm_vector1)) {
			/* Auditallow rule audits things that are not allowed */

			/* item for result is the AuditAllow rule */
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(error));;
					goto spurious_audit_run_fail;
				}
			}
			item->item = rule1;
			/* proof is the lack of Allow rule */
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(error));
				goto spurious_audit_run_fail;
			}
			proof->elem = NULL;
			proof->type = SECHK_ITEM_AVRULE;

			/* the next series of if statements prints the following:
missing: allow <src_name> <tgt_name> : <obj_name> { perms }; */
			tmp_counter = 0;
			for (j = 0; j < apol_vector_get_size(perm_vector1); j++)
			{
				string1 = (char*) apol_vector_get_element(perm_vector1, j);
				if (!apol_vector_get_index(perm_intersection, (void*)string1,
							apol_str_strcmp, NULL, &l))
				{
					if (apol_str_append(&(proof->text), &tmp_counter, string1)) {
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto spurious_audit_run_fail;
					}
					if (apol_str_append(&(proof->text), &tmp_counter, ", "))
					{
						error = errno;
						ERR(policy, "%s", strerror(error));
						goto spurious_audit_run_fail;
					}
				}
				string1 = NULL;
			}

			if (!item->proof) {
				item->proof = apol_vector_create();
				if (!item->proof) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			apol_vector_append(item->proof, (void*) proof);
			proof = NULL;
			if (!res->items) {
				res->items = apol_vector_create();
				if (!res->items) {
					error = errno;
					ERR(policy, "%s", strerror(error));
					goto spurious_audit_run_fail;
				}
			}
			apol_vector_append(res->items, (void*) item);
			item = NULL;
		}

		/* clean up */
		apol_vector_destroy(&perm_vector1, free);
		apol_vector_destroy(&perm_vector2, free);
		apol_vector_destroy(&perm_intersection, NULL);
		apol_vector_destroy(&allow_rules, NULL);
		qpol_iterator_destroy(&perm_iter1);
		qpol_iterator_destroy(&perm_iter2);
	}

	apol_vector_destroy(&auditallow_rules, NULL);
	apol_avrule_query_destroy(&query);

	mod->result = res;

	/* If module finds something that would be considered a fail 
	 * on the policy return 1 here */
	if (apol_vector_get_size(res->items) > 0)
		return 1;

	return 0;

spurious_audit_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	apol_vector_destroy(&allow_rules, NULL);
	apol_vector_destroy(&auditallow_rules, NULL);
	apol_vector_destroy(&dontaudit_rules, NULL);
	apol_vector_destroy(&perm_vector1, free);
	apol_vector_destroy(&perm_vector2, free);
	apol_vector_destroy(&perm_intersection, NULL);
	qpol_iterator_destroy(&perm_iter1);
	qpol_iterator_destroy(&perm_iter2);
	apol_avrule_query_destroy(&query);
	free(tmp);
	tmp = NULL;
	errno = error;
	return -1;
}

/* The print function generates the text and prints the
 * results to stdout. */
int spurious_audit_print(sechk_module_t *mod, apol_policy_t *policy, void *arg __attribute__((unused))) 
{
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0;
	uint32_t ruletype;

	if (!mod || !policy) {
		ERR(NULL, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "%s%s%s","wrong module (", mod->name, ")");
		errno = EINVAL;
		return -1;
	}

	outformat = mod->outputformat;

	if (!mod->result) {
		ERR(policy, "%s%s%s","module ", mod->name, "has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		i = apol_vector_get_size(mod->result->items);
		printf("Found %zd rule%s.\n", i, (i == 1) ? "" : "s" );
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			item = apol_vector_get_element(mod->result->items, i);
			printf("%s\n", apol_avrule_render(policy, (qpol_avrule_t*)item->item)); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			item = apol_vector_get_element(mod->result->items, i);
			printf("%s\n", apol_avrule_render(policy, (qpol_avrule_t*)item->item));

			qpol_avrule_get_rule_type(policy->p, (qpol_avrule_t*)item->item, &ruletype);
			if (ruletype == QPOL_RULE_DONTAUDIT) {
				for (j = 0; j < apol_vector_get_size(item->proof); j++) {
					proof = apol_vector_get_element(item->proof, j);
					printf("\tinconsistent: ");
					printf("%s\n", apol_avrule_render(policy, (qpol_avrule_t*)proof->elem));
					printf("\tinconsistent permissions:\n");
					printf("\t%s\n", proof->text);
				}
			}
			else if(ruletype == QPOL_RULE_AUDITALLOW) {
				printf("\tmissing: ");
				printf("%s\n", strstr(apol_avrule_render(policy, (qpol_avrule_t*)item->item), "allow"));
				printf("\tmissing permissions:\n");
				for (j = 0; j < apol_vector_get_size(item->proof); j++) {
					proof = apol_vector_get_element(item->proof, j);
					printf("\t%s\n", proof->text);
				}
			}
			printf("\n");
		}
		printf("\n");
	}

	return 0;
}

