/**
 *  @file find_domains.c
 *  Implementation of the find domains utility module. 
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

#include "find_domains.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

static const char *const mod_name = "find_domains";

int find_domains_register(sechk_lib_t * lib)
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
		ERR(NULL, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}
	mod->parent_lib = lib;

	/* assign descriptions */
	mod->brief_description = "utility module";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This is a utility module which finds types in a policy that are treated as a    \n"
		"domain.  A type is considered a domain if any of the following is true:\n"
		"\n"
		"   1) it has an attribute associated with domains\n"
		"   2) it is the source of a TE rule for object class other than filesystem\n"
		"   3) it is the default type in a type_transition rule for object class process \n"
		"   4) it is associated with a role other than object_r\n";
	mod->opt_description =
		"Module requirements:\n"
		"   policy source\n"
		"Module dependencies:\n" "   none\n" "Module options:\n" "   domain_attributes can be set in a profile\n";
	mod->severity = SECHK_SEV_NONE;
	/* assign requirements */
	apol_vector_append(mod->requirements, sechk_name_value_new("policy_type", "source"));

	/* assign options */
	apol_vector_append(mod->options, sechk_name_value_new("domain_attribute", "domain"));

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
	fn_struct->fn = find_domains_init;
	apol_vector_append(mod->functions, fn_struct);

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
	fn_struct->fn = find_domains_run;
	apol_vector_append(mod->functions, fn_struct);

	mod->data_free = find_domains_data_free;

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
	fn_struct->fn = find_domains_print;
	apol_vector_append(mod->functions, fn_struct);

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
	fn_struct->fn = find_domains_get_list;
	apol_vector_append(mod->functions, fn_struct);

	return 0;
}

int find_domains_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_name_value_t *opt = NULL;
	find_domains_data_t *datum = NULL;
	size_t i, j;
	qpol_type_t *attr = NULL;
	apol_vector_t *attr_vector = NULL;
	apol_attr_query_t *attr_query = apol_attr_query_create();

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

	datum = find_domains_data_new();
	if (!datum) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	if (!(datum->domain_attribs = apol_vector_create())) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	mod->data = datum;

	for (i = 0; i < apol_vector_get_size(mod->options); i++) {
		opt = apol_vector_get_element(mod->options, i);
		if (!strcmp(opt->name, "domain_attribute")) {
			apol_attr_query_set_attr(policy, attr_query, opt->value);
			apol_get_attr_by_query(policy, attr_query, &attr_vector);
			for (j = 0; j < apol_vector_get_size(attr_vector); j++) {
				char *domain_attrib;
				attr = apol_vector_get_element(attr_vector, j);
				qpol_type_get_name(policy->p, attr, &domain_attrib);
				if (apol_vector_append(datum->domain_attribs, (void *)domain_attrib) < 0) {
					apol_vector_destroy(&attr_vector, NULL);
					ERR(policy, "%s", strerror(ENOMEM));
					errno = ENOMEM;
					return -1;

				}
			}
			apol_vector_destroy(&attr_vector, NULL);
		}
	}
	apol_attr_query_destroy(&attr_query);
	return 0;
}

int find_domains_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	int i, j, error = 0;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	char *type_name = NULL;
	find_domains_data_t *datum = NULL;
	size_t num_items, proof_idx;
	apol_vector_t *domain_vector = NULL, *avrule_vector = NULL, *terule_vector = NULL, *role_vector = NULL;
	apol_terule_query_t *terule_query = NULL;
	apol_avrule_query_t *avrule_query = NULL;
	apol_role_query_t *role_query = NULL;
	qpol_iterator_t *domain_attr_iter = NULL;

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

	datum = (find_domains_data_t *) mod->data;
	res = sechk_result_new();
	if (!res) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		errno = error;
		return -1;
	}
	res->item_type = SECHK_ITEM_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto find_domains_run_fail;
	}

	if (!(res->items = apol_vector_create())) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto find_domains_run_fail;
	}

	if (apol_get_type_by_query(policy, NULL, &domain_vector) < 0) {
		goto find_domains_run_fail;
	}

	if ((num_items = apol_vector_get_size(domain_vector)) < 0) {
		goto find_domains_run_fail;
	}

	for (i = 0; i < apol_vector_get_size(domain_vector); i++) {
		qpol_type_t *type = apol_vector_get_element(domain_vector, i);
		qpol_type_get_name(policy->p, type, &type_name);

		if (qpol_type_get_attr_iter(policy->p, type, &domain_attr_iter) < 0) {
			error = errno;
			ERR(policy, "Can't get attributes for type %s", type_name);
			goto find_domains_run_fail;
		}

		for (; !qpol_iterator_end(domain_attr_iter); qpol_iterator_next(domain_attr_iter)) {
			char *attr_name;
			qpol_type_t *attr;
			int nfta;

			qpol_iterator_get_item(domain_attr_iter, (void **)&attr);
			qpol_type_get_name(policy->p, attr, &attr_name);
			for (nfta = 0; nfta < apol_vector_get_size(datum->domain_attribs); nfta++) {
				char *domain_attrib;

				domain_attrib = apol_vector_get_element(datum->domain_attribs, nfta);
				if (!strcmp(attr_name, domain_attrib)) {
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_domains_run_fail;
					}
					proof->type = SECHK_ITEM_ATTRIB;
					proof->elem = attr;
					asprintf(&proof->text, "%s has attribute %s", type_name, attr_name);
					if (!proof->text) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_domains_run_fail;
					}
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_domains_run_fail;
						}
						item->test_result = 1;
					}
					if (!item->proof) {
						if (!(item->proof = apol_vector_create())) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_domains_run_fail;
						}
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_domains_run_fail;
					}
				}
			}
		}
		qpol_iterator_destroy(&domain_attr_iter);

		/* rule src check !filesystem associate */
		if (!(avrule_query = apol_avrule_query_create())) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_domains_run_fail;
		}
		apol_avrule_query_set_source(policy, avrule_query, type_name, 0);
		if (apol_get_avrule_by_query(policy, avrule_query, &avrule_vector) < 0) {
			error = errno;
			ERR(policy, "%s", "Unable to retrieve AV rules");
			goto find_domains_run_fail;
		}
		for (j = 0; j < apol_vector_get_size(avrule_vector); j++) {
			qpol_avrule_t *avrule = NULL;
			qpol_class_t *class = NULL;
			char *class_name = NULL;

			avrule = apol_vector_get_element(avrule_vector, j);
			qpol_avrule_get_object_class(policy->p, avrule, &class);
			qpol_class_get_name(policy->p, class, &class_name);
			if (strcmp("filesystem", class_name)) {
				proof = sechk_proof_new(NULL);
				if (!proof) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;
				}
				proof->type = SECHK_ITEM_AVRULE;
				proof->text = apol_avrule_render(policy, avrule);
				if (!item) {
					item = sechk_item_new(NULL);
					if (!item) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_domains_run_fail;
					}
					item->test_result = 1;
				}
				if (!item->proof) {
					if (!(item->proof = apol_vector_create())) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_domains_run_fail;
					}
				}
				if (apol_vector_append(item->proof, (void *)proof) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;
				}
			}
		}
		apol_vector_destroy(&avrule_vector, NULL);
		apol_avrule_query_destroy(&avrule_query);

		/* type rule check file object */
		if (!(terule_query = apol_terule_query_create())) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_domains_run_fail;
		}
		apol_terule_query_set_default(policy, terule_query, type_name);
		apol_terule_query_append_class(policy, terule_query, "process");
		if (apol_get_terule_by_query(policy, terule_query, &terule_vector) < 0) {
			error = errno;
			ERR(policy, "%s", "Unable to retrieve TE rules");
			goto find_domains_run_fail;
		}
		for (j = 0; j < apol_vector_get_size(terule_vector); j++) {
			qpol_terule_t *terule = NULL;
			terule = apol_vector_get_element(terule_vector, j);

			if (apol_vector_get_index(item->proof, terule, sechk_proof_with_element_compare, NULL, &proof_idx) == 0)
				continue;

			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_domains_run_fail;
			}
			proof->type = SECHK_ITEM_TERULE;
			proof->elem = terule;
			proof->text = apol_terule_render(policy, terule);
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;
				}
				item->test_result = 1;
			}
			if (!item->proof) {
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;
				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_domains_run_fail;
			}
		}
		apol_vector_destroy(&terule_vector, NULL);
		apol_terule_query_destroy(&terule_query);

		/* Check Roles */
		if (!(role_query = apol_role_query_create())) {
			error = errno;
			ERR(policy, "%s", strerror(ENOMEM));
			goto find_domains_run_fail;
		}
		apol_role_query_set_type(policy, role_query, type_name);
		apol_get_role_by_query(policy, role_query, &role_vector);
		for (j = 0; j < apol_vector_get_size(role_vector); j++) {
			qpol_role_t *role;
			char *role_name;

			role = (qpol_role_t *) apol_vector_get_element(role_vector, j);
			qpol_role_get_name(policy->p, role, &role_name);
			if (!strcmp("object_r", role_name))
				continue;
			proof = sechk_proof_new(NULL);
			if (!proof) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_domains_run_fail;
			}
			proof->type = SECHK_ITEM_ROLE;
			proof->elem = role;
			asprintf(&proof->text, "role %s types %s;", role_name, type_name);
			if (!item) {
				item = sechk_item_new(NULL);
				if (!item) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;
				}
				item->test_result = 1;
			}
			if (!item->proof) {
				if (!(item->proof = apol_vector_create())) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_domains_run_fail;

				}
			}
			if (apol_vector_append(item->proof, (void *)proof) < 0) {
				error = errno;
				ERR(policy, "Error: %s\n", strerror(error));
				goto find_domains_run_fail;
			}
		}
		apol_vector_destroy(&role_vector, NULL);
		apol_role_query_destroy(&role_query);

		/* insert any results for this type */
		if (item) {
			item->item = type;
			if (apol_vector_append(res->items, (void *)item) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_domains_run_fail;
			}
		}
		item = NULL;
		type = NULL;
		type_name = NULL;
	}
	apol_vector_destroy(&domain_vector, NULL);

	/* results are valid at this point */
	mod->result = res;
	return 0;

      find_domains_run_fail:
	qpol_iterator_destroy(&domain_attr_iter);
	apol_vector_destroy(&domain_vector, NULL);
	apol_vector_destroy(&avrule_vector, NULL);
	apol_vector_destroy(&terule_vector, NULL);
	apol_vector_destroy(&role_vector, NULL);
	apol_avrule_query_destroy(&avrule_query);
	apol_terule_query_destroy(&terule_query);
	apol_role_query_destroy(&role_query);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

void find_domains_data_free(void *data)
{
	find_domains_data_t *datum = (find_domains_data_t *) data;

	if (datum) {
		apol_vector_destroy(&datum->domain_attribs, NULL);
	}
	free(data);
}

int find_domains_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	find_domains_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0, j = 0, k = 0, l = 0, num_items;
	sechk_proof_t *proof = NULL;
	qpol_type_t *type;
	char *type_name;

	if (!mod || !policy) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp("find_domains", mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}

	datum = (find_domains_data_t *) mod->data;
	outformat = mod->outputformat;
	num_items = apol_vector_get_size(mod->result->items);

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET)) {
		return 0;	       /* not an error - no output is requested */
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i domain types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are domains.\n");
	}

	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < num_items; i++) {
			j++;
			item = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(policy->p, type, &type_name);
			j %= 4;
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
				qpol_type_get_name(policy->p, type, &type_name);
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

int find_domains_get_list(sechk_module_t * mod, apol_policy_t * policy, void *arg)
{
	apol_vector_t **v = arg;

	if (!mod || !arg) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		ERR(policy, "Wrong module (%s)", mod->name);
		errno = EINVAL;
		return -1;
	}
	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	v = &mod->result->items;

	return 0;
}

find_domains_data_t *find_domains_data_new(void)
{
	find_domains_data_t *datum = NULL;

	datum = (find_domains_data_t *) calloc(1, sizeof(find_domains_data_t));

	return datum;
}
