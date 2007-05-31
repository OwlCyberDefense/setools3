/**
 *  @file
 *  Implementation of the find file types utility module.
 *
 *  @author Kevin Carr kcarr@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *  @author Randy Wicks rwicks@tresys.com
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

#include "find_file_types.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

static const char *const mod_name = "find_file_types";

int find_file_types_register(sechk_lib_t * lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;
	sechk_name_value_t *nv = NULL;

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

	/* assign the descriptions */

	mod->brief_description = "utility module";
	mod->detailed_description =
		"--------------------------------------------------------------------------------\n"
		"This module finds all types in the policy treated as a file type.  A type is    \n"
		"considered a file type if any of the following is true:\n"
		"\n"
		"   1) it has an attribute associated with file types\n"
		"   2) it is the source of a rule to allow filesystem associate permission\n"
		"   3) it is the default type of a type transition rule with an object class\n" "      other than process\n"
		"   4) it is specified in a context in the file_contexts file\n";
	mod->opt_description = "Module requirements:\n" "   attribute names\n"
		"   file_contexts\n"
		"Module dependencies:\n" "   none\n" "Module options:\n" "   file_type_attribute can be modified in a profile\n";
	mod->severity = SECHK_SEV_NONE;
	/* assign requirements */
	nv = sechk_name_value_new(SECHK_REQ_POLICY_CAP, SECHK_REQ_CAP_ATTRIB_NAMES);
	apol_vector_append(mod->requirements, (void *)nv);
	nv = sechk_name_value_new(SECHK_REQ_FILE_CONTEXTS, NULL);
	apol_vector_append(mod->requirements, (void *)nv);

	/* assign options */
	nv = sechk_name_value_new("file_type_attribute", "file_type");
	apol_vector_append(mod->options, (void *)nv);

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
	fn_struct->fn = find_file_types_init;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = find_file_types_run;
	apol_vector_append(mod->functions, (void *)fn_struct);

	mod->data_free = find_file_types_data_free;

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
	fn_struct->fn = find_file_types_print;
	apol_vector_append(mod->functions, (void *)fn_struct);

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
	fn_struct->fn = find_file_types_get_list;
	apol_vector_append(mod->functions, (void *)fn_struct);

	return 0;
}

int find_file_types_init(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	sechk_name_value_t *opt = NULL;
	find_file_types_data_t *datum = NULL;
	apol_vector_t *attr_vector = NULL;
	apol_attr_query_t *attr_query = apol_attr_query_create();
	qpol_type_t *attr = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i = 0, j = 0;

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

	datum = find_file_types_data_new();
	if (!datum) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	if (!(datum->file_type_attribs = apol_vector_create(NULL))) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}
	mod->data = datum;

	for (i = 0; i < apol_vector_get_size(mod->options); i++) {
		opt = apol_vector_get_element(mod->options, i);
		if (!strcmp(opt->name, "file_type_attribute")) {
			apol_attr_query_set_attr(policy, attr_query, opt->value);
			apol_attr_get_by_query(policy, attr_query, &attr_vector);
			for (j = 0; j < apol_vector_get_size(attr_vector); j++) {
				char *file_attrib;
				attr = apol_vector_get_element(attr_vector, j);
				qpol_type_get_name(q, attr, &file_attrib);
				if (apol_vector_append(datum->file_type_attribs, (void *)file_attrib) < 0) {
					ERR(policy, "%s", strerror(ENOMEM));
					errno = ENOMEM;
					return -1;
				}
			}
			apol_vector_destroy(&attr_vector);
		}
	}
	apol_attr_query_destroy(&attr_query);
	return 0;
}

int find_file_types_run(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	find_file_types_data_t *datum;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *res = NULL;
	char *type_name = NULL;
	apol_avrule_query_t *avrule_query = NULL;
	apol_terule_query_t *terule_query = NULL;
	apol_vector_t *avrule_vector = NULL;
	apol_vector_t *terule_vector = NULL;
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, j, x;
	char *buff = NULL;
	int buff_sz, error = 0;

	/* NEW */
	size_t num_fc_entries = 0;
	apol_vector_t *type_vector = NULL;
	apol_vector_t *fc_entry_vector = NULL;

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

	datum = (find_file_types_data_t *) mod->data;
	res->item_type = SECHK_ITEM_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto find_file_types_run_fail;
	}
	if (!(res->items = apol_vector_create(sechk_item_free))) {
		error = errno;
		ERR(policy, "%s", strerror(ENOMEM));
		goto find_file_types_run_fail;
	}
	if (mod->parent_lib->fc_entries) {
		if (mod->parent_lib->fc_path) {
			fc_entry_vector = mod->parent_lib->fc_entries;
			num_fc_entries = apol_vector_get_size(fc_entry_vector);
		} else {
			error = ENOENT;
			ERR(policy, "%s", "Unable to find file contexts file");
			goto find_file_types_run_fail;
		}
	}

	/* Get an iterator for the types */
	if (apol_type_get_by_query(policy, NULL, &type_vector) < 0) {
		error = errno;
		ERR(policy, "%s", "Unable to retrieve types");
		return -1;
	}

	for (i = 0; i < apol_vector_get_size(type_vector); i++) {
		qpol_iterator_t *file_attr_iter;

		qpol_type_t *type = apol_vector_get_element(type_vector, i);
		qpol_type_get_name(q, type, &type_name);

		if (qpol_type_get_attr_iter(q, type, &file_attr_iter) < 0) {
			error = errno;
			ERR(policy, "Could not get attributes for %s\n", type_name);
			goto find_file_types_run_fail;
		}

		for (; !qpol_iterator_end(file_attr_iter); qpol_iterator_next(file_attr_iter)) {
			char *attr_name;
			qpol_type_t *attr;
			size_t nfta;

			qpol_iterator_get_item(file_attr_iter, (void **)&attr);
			qpol_type_get_name(q, attr, &attr_name);
			for (nfta = 0; nfta < apol_vector_get_size(datum->file_type_attribs); nfta++) {
				char *file_type_attrib;

				file_type_attrib = apol_vector_get_element(datum->file_type_attribs, nfta);
				if (!strcmp(attr_name, file_type_attrib)) {
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
					proof->type = SECHK_ITEM_ATTRIB;
					proof->elem = attr;
					asprintf(&proof->text, "has attribute %s", attr_name);
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_file_types_run_fail;
						}
						item->test_result = 1;
					}
					if (!item->proof) {
						if (!(item->proof = apol_vector_create(sechk_proof_free))) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_file_types_run_fail;
						}
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
				}
			}
		}
		qpol_iterator_destroy(&file_attr_iter);

		/* rule src check filesystem associate */
		if (!(avrule_query = apol_avrule_query_create())) {
			error = errno;
			ERR(policy, "%s", "Could not retrieve AV rules");
			goto find_file_types_run_fail;
		}
		apol_avrule_query_set_source(policy, avrule_query, type_name, 0);
		apol_avrule_query_append_class(policy, avrule_query, "filesystem");
		apol_avrule_query_append_perm(policy, avrule_query, "associate");
		apol_avrule_get_by_query(policy, avrule_query, &avrule_vector);
		for (x = 0; x < apol_vector_get_size(avrule_vector); x++) {
			qpol_avrule_t *avrule;
			avrule = apol_vector_get_element(avrule_vector, x);
			if (avrule) {
				proof = sechk_proof_new(NULL);
				if (!proof) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_file_types_run_fail;
				}
				proof->type = SECHK_ITEM_AVRULE;
				proof->elem = avrule;
				proof->text = apol_avrule_render(policy, avrule);
				if (!item) {
					item = sechk_item_new(NULL);
					if (!item) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
					item->test_result = 1;
				}
				if (!item->proof) {
					if (!(item->proof = apol_vector_create(sechk_proof_free))) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
				}
				item->test_result = 1;
				if (apol_vector_append(item->proof, (void *)proof) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_file_types_run_fail;
				}
			}
		}
		apol_vector_destroy(&avrule_vector);
		apol_avrule_query_destroy(&avrule_query);

		/* type rule check file object */
		if (!(terule_query = apol_terule_query_create())) {
			error = errno;
			ERR(policy, "%s", "Could not retrieve TE rules");
			goto find_file_types_run_fail;
		}
		apol_terule_query_set_default(policy, terule_query, type_name);
		apol_terule_get_by_query(policy, terule_query, &terule_vector);
		for (x = 0; x < apol_vector_get_size(terule_vector); x++) {
			qpol_terule_t *terule;
			qpol_class_t *objclass;
			char *class_name;

			terule = apol_vector_get_element(terule_vector, x);
			qpol_terule_get_object_class(q, terule, &objclass);
			qpol_class_get_name(q, objclass, &class_name);
			if (strcmp(class_name, "process")) {
				proof = sechk_proof_new(NULL);
				if (!proof) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_file_types_run_fail;
				}
				proof->type = SECHK_ITEM_TERULE;
				proof->elem = terule;
				proof->text = apol_terule_render(policy, terule);
				if (!item) {
					item = sechk_item_new(NULL);
					if (!item) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
					item->test_result = 1;
				}
				if (!item->proof) {
					if (!(item->proof = apol_vector_create(sechk_proof_free))) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
				}
				item->test_result = 1;
				if (apol_vector_append(item->proof, (void *)proof) < 0) {
					error = errno;
					ERR(policy, "%s", strerror(ENOMEM));
					goto find_file_types_run_fail;
				}
			}
		}
		apol_vector_destroy(&terule_vector);
		apol_terule_query_destroy(&terule_query);

		/* assigned in fc check */
		if (fc_entry_vector) {
			buff = NULL;
			for (j = 0; j < num_fc_entries; j++) {
#if 0 /* FIX ME */
				sefs_fc_entry_t *fc_entry;
				char *fc_type_name = NULL;
				fc_entry = apol_vector_get_element(fc_entry_vector, j);
				if (!fc_entry->context)
					continue;
				if (fc_entry->context->type)
					fc_type_name = fc_entry->context->type;
				if (fc_entry->context && !strcmp(type_name, fc_type_name)) {
					buff_sz = 1;
					buff_sz += strlen(fc_entry->path);
					switch (fc_entry->filetype) {
					case SEFS_FILETYPE_DIR:	/* Directory */
					case SEFS_FILETYPE_CHR:	/* Character device */
					case SEFS_FILETYPE_BLK:	/* Block device */
					case SEFS_FILETYPE_REG:	/* Regular file */
					case SEFS_FILETYPE_FIFO:	/* FIFO */
					case SEFS_FILETYPE_LNK:	/* Symbolic link */
					case SEFS_FILETYPE_SOCK:	/* Socket */
						buff_sz += 4;
						break;
					case SEFS_FILETYPE_ANY:	/* any type */
						buff_sz += 2;
						break;
					case SEFS_FILETYPE_NONE:	/* none */
					default:
						ERR(policy, "%s", "Invalid file type");
						goto find_file_types_run_fail;
						break;
					}
					if (apol_vector_get_size(mod->parent_lib->fc_entries) > 0) {
						buff_sz += (strlen(fc_entry->context->user) + 1);
						buff_sz += (strlen(fc_entry->context->role) + 1);
						buff_sz += strlen(fc_entry->context->type);
					} else {
						buff_sz += strlen("<<none>>");
					}
					buff = (char *)calloc(buff_sz, sizeof(char));
					strcat(buff, fc_entry->path);
					switch (fc_entry->filetype) {
					case SEFS_FILETYPE_DIR:	/* Directory */
						strcat(buff, "\t-d\t");
						break;
					case SEFS_FILETYPE_CHR:	/* Character device */
						strcat(buff, "\t-c\t");
						break;
					case SEFS_FILETYPE_BLK:	/* Block device */
						strcat(buff, "\t-b\t");
						break;
					case SEFS_FILETYPE_REG:	/* Regular file */
						strcat(buff, "\t--\t");
						break;
					case SEFS_FILETYPE_FIFO:	/* FIFO */
						strcat(buff, "\t-p\t");
						break;
					case SEFS_FILETYPE_LNK:	/* Symbolic link */
						strcat(buff, "\t-l\t");
						break;
					case SEFS_FILETYPE_SOCK:	/* Socket */
						strcat(buff, "\t-s\t");
						break;
					case SEFS_FILETYPE_ANY:	/* any type */
						strcat(buff, "\t\t");
						break;
					case SEFS_FILETYPE_NONE:	/* none */
					default:
						ERR(policy, "%s", "Invalid file type");
						goto find_file_types_run_fail;
						break;
					}
					if (fc_entry->context) {
						strcat(buff, fc_entry->context->user);
						strcat(buff, ":");
						strcat(buff, fc_entry->context->role);
						strcat(buff, ":");
						strcat(buff, fc_entry->context->type);
					} else {
						strcat(buff, "<<none>>");
					}
					proof = sechk_proof_new(NULL);
					if (!proof) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
					proof->type = SECHK_ITEM_FCENT;
					proof->elem = fc_entry;
					proof->text = buff;
					buff = NULL;
					if (!item) {
						item = sechk_item_new(NULL);
						if (!item) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_file_types_run_fail;
						}
						item->test_result = 1;
					}
					if (!item->proof) {
						if (!(item->proof = apol_vector_create(sechk_proof_free))) {
							error = errno;
							ERR(policy, "%s", strerror(ENOMEM));
							goto find_file_types_run_fail;
						}
					}
					if (apol_vector_append(item->proof, (void *)proof) < 0) {
						error = errno;
						ERR(policy, "%s", strerror(ENOMEM));
						goto find_file_types_run_fail;
					}
				}
#endif
			}
		}
		/* insert any results for this type */
		if (item) {
			item->item = type;
			if (apol_vector_append(res->items, (void *)item) < 0) {
				error = errno;
				ERR(policy, "%s", strerror(ENOMEM));
				goto find_file_types_run_fail;
			}
		}
		item = NULL;
		type = NULL;
		type_name = NULL;
	}
	apol_vector_destroy(&type_vector);

	/* results are valid at this point */
	mod->result = res;

	return 0;

      find_file_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	free(buff);
	apol_vector_destroy(&type_vector);
	sechk_result_destroy(&res);
	errno = error;
	return -1;
}

void find_file_types_data_free(void *data)
{
	find_file_types_data_t *datum = (find_file_types_data_t *) data;

	if (datum) {
		apol_vector_destroy(&datum->file_type_attribs);
	}
	free(data);
}

int find_file_types_print(sechk_module_t * mod, apol_policy_t * policy, void *arg __attribute__ ((unused)))
{
	find_file_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	size_t i = 0, j = 0, k = 0, l = 0, num_items = 0;
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

	datum = (find_file_types_data_t *) mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		ERR(policy, "%s", "Module has not been run");
		errno = EINVAL;
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0;	       /* not an error - no output is requested */
	if (outformat & SECHK_OUT_STATS) {
		num_items = apol_vector_get_size(mod->result->items);
		printf("Found %zd file types.\n", num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are file types.\n\n");
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (i = 0; i < apol_vector_get_size(mod->result->items); i++) {
			j++;
			item = apol_vector_get_element(mod->result->items, i);
			type = item->item;
			qpol_type_get_name(q, type, &type_name);
			j %= 4;
			printf("%s%s", type_name, (char *)((j && i != num_items - 1) ? ", " : "\n"));
		}
		printf("\n");
	}

	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (k = 0; k < apol_vector_get_size(mod->result->items); k++) {
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

int find_file_types_get_list(sechk_module_t * mod, apol_policy_t * policy __attribute__ ((unused)), void *arg
			     __attribute__ ((unused)))
{
	apol_vector_t **v = arg;

	if (!mod || !arg) {
		ERR(NULL, "%s", strerror(EINVAL));
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

find_file_types_data_t *find_file_types_data_new(void)
{
	find_file_types_data_t *datum = NULL;

	datum = (find_file_types_data_t *) calloc(1, sizeof(find_file_types_data_t));

	return datum;
}
