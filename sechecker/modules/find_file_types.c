/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_file_types.h"
#include "render.h"
#ifdef LIBSEFS
#include "../libsefs/file_contexts.h"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <semantic/avsemantics.h>

static sechk_lib_t *library;
static const char *const mod_name = "find_file_types";

int find_file_types_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}

	/* assign the descriptions */
	mod->brief_description = "utility module";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds all types in the policy treated as a file type.  A type is    \n"
"considered a file type if any of the following is true:\n"
"\n"
"   1) it has an attribute associated with file types\n"
"   2) it is the source of a rule to allow filesystem associate permission\n"
"   3) it is the default type of a type transition rule with an object class\n"
"      other than process\n"
"   4) it is specified in a context in the file_contexts file\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   file_type_attribute can be modified in a profile\n";
	mod->severity = SECHK_SEV_NONE;
	/* assign requirements */
	mod->requirements = sechk_name_value_new("policy_type","source");

	/* assign options */
	mod->options = sechk_name_value_new("file_type_attribute", "file_type");

	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_INIT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_RUN);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_FREE);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_data_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_PRINT);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_print_output;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup(SECHK_MOD_FN_GET_RES);
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_list");
	if (!fn_struct->name) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	fn_struct->fn = &find_file_types_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;


	return 0;
}

int find_file_types_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_name_value_t *opt = NULL;
	find_file_types_data_t *datum = NULL;
	int attr = -1, retv;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_file_types_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "file_type_attribute")) {
			attr = get_attrib_idx(opt->value, policy);
			if (attr != -1) {
				retv = add_i_to_a(attr, &(datum->num_file_type_attribs), &(datum->file_type_attribs));
				if (retv) {
					fprintf(stderr, "Error: out of memory\n");
					return -1;
				}
			} else {
				fprintf(stderr, "Warning: attribute %s not defined, ignoring\n", opt->value);
			}
		}
		opt = opt->next;
	}

	return 0;
}

int find_file_types_run(sechk_module_t *mod, policy_t *policy) 
{
/* FIX ME: need to convert this to use new libapol */
#if 0
	find_file_types_data_t *datum;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_result_t *res = NULL;
	int i, j, retv;
	int filesystem_obj_class_idx = -1;
	int process_obj_class_idx = -1;
	int associate_perm_idx = -1;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	avh_rule_t *hash_rule = NULL;
	char *buff = NULL;
	int buff_sz;
	int *attribs = NULL, num_attribs = 0;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	filesystem_obj_class_idx = get_obj_class_idx("filesystem", policy);
	process_obj_class_idx = get_obj_class_idx("process", policy);
	associate_perm_idx = get_perm_idx("associate", policy);

	datum = (find_file_types_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->item_type = POL_LIST_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto find_file_types_run_fail;
	}

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto find_file_types_run_fail;
		}
	}

#ifdef LIBSEFS
	if (!library->fc_entries) {
		if (library->fc_path) {
			retv = parse_file_contexts_file(library->fc_path, &(library->fc_entries), &(library->num_fc_entries), policy);
			if (retv) {
				fprintf(stderr, "Warning: unable to process file_contexts file\n");
			}
		} else {
			fprintf(stderr, "Warning: unable to find file_contexts file\n");
		}
	}
#endif


	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		/* test attributes */
		if (!(is_binary_policy(policy))) {
			retv = get_type_attribs(i, &num_attribs, &attribs, policy);
			if (retv) {
				fprintf(stderr, "Error: could not get attributes for %s\n", policy->types[i].name);
				goto find_file_types_run_fail;
			}
			for (j = 0; j < datum->num_file_type_attribs; j++) {
				buff = NULL;
				if (find_int_in_array(datum->file_type_attribs[j], attribs, num_attribs) != -1) {
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_file_types_run_fail;
					}
					proof->idx = datum->file_type_attribs[j];
					proof->type = POL_LIST_ATTRIB;
					buff_sz = 1+strlen(policy->types[i].name)+strlen(policy->attribs[datum->file_type_attribs[j]].name)+strlen("type  has attribute ");
					buff = (char*)calloc(buff_sz, sizeof(char));
					if (!buff) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_file_types_run_fail;
					}
					proof->text = buff;
					if (!proof->text) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_file_types_run_fail;
					}
					snprintf(proof->text, buff_sz, "has attribute %s", policy->attribs[datum->file_type_attribs[j]].name);
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_file_types_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;
				}
			}
		}

		/* rule src check filesystem associate */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
			if (hash_idx->nodes[j]->key.cls == filesystem_obj_class_idx && hash_idx->nodes[j]->key.rule_type == RULE_TE_ALLOW) {
				for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
					if (sechk_item_has_proof(hash_rule->rule, POL_LIST_AV_ACC, item))
						continue;
					buff = NULL;
					if (does_av_rule_use_perms(hash_rule->rule, 1, &associate_perm_idx, 1, policy)) {
						buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 0, policy);
						proof = sechk_proof_new();
						if (!proof) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_file_types_run_fail;
						}
						proof->idx = hash_rule->rule;
						proof->type = POL_LIST_AV_ACC;
						proof->text = buff;
						if (!item) {
							item = sechk_item_new();
							if (!item) {
								fprintf(stderr, "Error: out of memory\n");
								goto find_file_types_run_fail;
							}
							item->item_id = i;
							item->test_result = 1;
						}
						proof->next = item->proof;
						item->proof = proof;
					}
				}
			}
		}

		/* type rule check file object */
		for (j = 0; j < policy->num_te_trans; j++) {
			if (policy->te_trans[j].dflt_type.idx == i && !does_tt_rule_use_classes(j, &process_obj_class_idx, 1, policy)) {
				buff = re_render_tt_rule(!is_binary_policy(policy), j, policy);
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_file_types_run_fail;
				}
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_file_types_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_file_types_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;

			
		}

#ifdef LIBSEFS
		/* assigned in fc check */
		if (library->fc_entries) {
			for (j=0; j < library->num_fc_entries; j++) {
				if (library->fc_entries[j].context && library->fc_entries[j].context->type == i) {
					buff_sz = 1;
					buff_sz += strlen(library->fc_entries[j].path);
					switch (library->fc_entries[j].filetype) {
					case FILETYPE_DIR: /* Directory */
					case FILETYPE_CHR: /* Character device */
					case FILETYPE_BLK: /* Block device */
					case FILETYPE_REG: /* Regular file */
					case FILETYPE_FIFO: /* FIFO */
					case FILETYPE_LNK: /* Symbolic link */
					case FILETYPE_SOCK: /* Socket */
						buff_sz += 4;
						break;
					case FILETYPE_ANY: /* any type */
						buff_sz += 2;
						break;
					case FILETYPE_NONE: /* none */
					default:
						fprintf(stderr, "Error: error processing file context entries\n");
						goto find_file_types_run_fail;
						break;
					}
					if (library->fc_entries[j].context) {
						buff_sz += (strlen(policy->users[library->fc_entries[j].context->user].name) + 1);
						buff_sz += (strlen(policy->roles[library->fc_entries[j].context->role].name) + 1);
						buff_sz += strlen(policy->types[library->fc_entries[j].context->type].name);
					} else {
						buff_sz += strlen("<<none>>");
					}
					buff = (char*)calloc(buff_sz, sizeof(char));
					strcat(buff, library->fc_entries[j].path);
					switch (library->fc_entries[j].filetype) {
					case FILETYPE_DIR: /* Directory */
						strcat(buff, "\t-d\t");
						break;
					case FILETYPE_CHR: /* Character device */
						strcat(buff, "\t-c\t");
						break;
					case FILETYPE_BLK: /* Block device */
						strcat(buff, "\t-b\t");
						break;
					case FILETYPE_REG: /* Regular file */
						strcat(buff, "\t--\t");
						break;
					case FILETYPE_FIFO: /* FIFO */
						strcat(buff, "\t-p\t");
						break;
					case FILETYPE_LNK: /* Symbolic link */
						strcat(buff, "\t-l\t");
						break;
					case FILETYPE_SOCK: /* Socket */
						strcat(buff, "\t-s\t");
						break;
					case FILETYPE_ANY: /* any type */
						strcat(buff, "\t\t");
						break;
					case FILETYPE_NONE: /* none */
					default:
						fprintf(stderr, "Error: error processing file context entries\n");
						goto find_file_types_run_fail;
						break;
					}
					if (library->fc_entries[j].context) {
						strcat(buff, policy->users[library->fc_entries[j].context->user].name);
						strcat(buff, ":");
						strcat(buff, policy->roles[library->fc_entries[j].context->role].name);
						strcat(buff, ":");
						strcat(buff, policy->types[library->fc_entries[j].context->type].name);
					} else {
						strcat(buff, "<<none>>");
					}
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_file_types_run_fail;
					}
					proof->idx = j;
					proof->type = SECHK_TYPE_FCENT;
					proof->text = buff;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_file_types_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;
				}
			}
		}
#endif

		/* insert any resutls for this type */
		if (item) {
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
		}
		item = NULL;
	}

	/* results are valid at this point */
	mod->result = res;

	return 0;

find_file_types_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	free(buff);
#endif
	return -1;
}

void find_file_types_data_free(sechk_module_t *mod) 
{
	find_file_types_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (find_file_types_data_t*)mod->data;
	if (datum) {
		free(datum->file_type_attribs);
	}
	free(mod->data);
	mod->data = NULL;
}

int find_file_types_print_output(sechk_module_t *mod, policy_t *policy) 
{
	find_file_types_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	int i = 0;


        if (!mod || !policy){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (find_file_types_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i file types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\nThe following types are file types.\n\n");
	}
	if (outformat & (SECHK_OUT_LIST|SECHK_OUT_PROOF)) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			printf("%s%s", policy->types[item->item_id].name, (i&&item->next) ? ", " : "\n");
		}
		printf("\n");
	}

	return 0;
}

sechk_result_t *find_file_types_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return NULL;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

find_file_types_data_t *find_file_types_data_new(void) 
{
	find_file_types_data_t *datum = NULL;

	datum = (find_file_types_data_t*)calloc(1,sizeof(find_file_types_data_t));

	return datum;
}

int find_file_types_get_list(sechk_module_t *mod, int **array, int *size) 
{
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

	return 0;

}
