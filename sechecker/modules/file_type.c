/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "file_type.h"
#include "render.h"
#include "file_contexts.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <semantic/avsemantics.h>

static sechk_lib_t *library;

int file_type_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "file_type_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = sechk_lib_get_module("file_type", lib);
	if (!mod) {
		fprintf(stderr, "file_type_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("print_output");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_print_output;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = sechk_fn_new();
	if (!fn_struct) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_file_type_list");
	if (!fn_struct->name) {
		fprintf(stderr, "file_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &file_type_get_file_type_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;


	return 0;
}

int file_type_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_name_value_t *opt = NULL;
	file_type_data_t *datum = NULL;
	bool_t header = TRUE;
	int attr = -1, retv;
	int pol_ver = POL_VER_UNKNOWN;

	if (!mod || !policy) {
		fprintf(stderr, "file_type_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("file_type", mod->name)) {
		fprintf(stderr, "file_type_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = file_type_data_new();
	if (!datum) {
		fprintf(stderr, "file_type_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("Finds all types in the policy treated as a file type\nA type is considered a file type if any of the following is true:\n   It has an attribute associated with file types\n   It is the source of a rule to allow filesystem associate\n   It is the default type of a type transition rule for an object class other than process\n   It is specified in a context in the file_contexts file\n\n");

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "file_type_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "file_type_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "file_type_init failed: invalid policy type specification %s\n", opt->value);
				return -1;
			}
		} else if (!strcmp(opt->name, "pol_ver")) {
			pol_ver = atoi(opt->value);
			if (pol_ver < 11)
				pol_ver = POL_VER_PRE_11;
			else if (pol_ver < 15)
				pol_ver = POL_VER_12;
			else if (pol_ver < 16)
				pol_ver = POL_VER_15;
			else if (pol_ver == 16)
				pol_ver = POL_VER_16;
			else if (pol_ver == 17)
				pol_ver = POL_VER_17;
			else if (pol_ver == 18)
				pol_ver = POL_VER_18;
			else if (pol_ver > 18)
				pol_ver = POL_VER_19;
			else
				pol_ver = POL_VER_UNKNOWN;
			if (policy->version < pol_ver) {
				fprintf(stderr, "file_type_init failed: module requires newer policy version\n");
				return -1;
			}
		} else if (!strcmp(opt->name, "output_type")) {
			if (!strcmp(opt->value, "full")) {
				datum->outformat = (SECHK_OUT_LONG|SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "long")) {
				datum->outformat = (SECHK_OUT_LONG|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "short")) {
				datum->outformat = (SECHK_OUT_LIST|SECHK_OUT_STATS|SECHK_OUT_HEADER);
			} else if (!strcmp(opt->value, "stats")) {
				datum->outformat = (SECHK_OUT_STATS|SECHK_OUT_HEADER);
			}
		} else if (!strcmp(opt->name, "output_header")) {
			if (!strcmp(opt->value, "no")) {
				header = FALSE;
			}
		} else if (!strcmp(opt->name, "file_type_attribute")) {
			attr = get_attrib_idx(opt->value, policy);
			if (attr != -1) {
				retv = add_i_to_a(attr, &(datum->num_file_type_attribs), &(datum->file_type_attribs));
				if (retv) {
					fprintf(stderr, "file_type_init failed: out of memory\n");
					return -1;
				}
			} else {
				fprintf(stderr, "file_type_init Warning: attribute %s not defined, ignoring\n", opt->value);
			}
		}
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int file_type_run(sechk_module_t *mod, policy_t *policy) 
{
	file_type_data_t *datum;
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
		fprintf(stderr, "file_type_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("file_type", mod->name)) {
		fprintf(stderr, "file_type_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	filesystem_obj_class_idx = get_obj_class_idx("filesystem", policy);
	process_obj_class_idx = get_obj_class_idx("process", policy);
	associate_perm_idx = get_perm_idx("associate", policy);

	datum = (file_type_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "file_type_run failed: out of memory\n");
		return -1;
	}
	res->item_type = POL_LIST_TYPE;
	res->test_name = strdup("file_type");
	if (!res->test_name) {
		fprintf(stderr, "file_type_run failed: out of memory\n");
		goto file_type_run_fail;
	}

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "file_type_run failed: could not build hash table\n");
			goto file_type_run_fail;
		}
	}

	if (!library->fc_entries) {
		if (library->fc_path) {
			retv = parse_file_contexts_file(library->fc_path, &(library->fc_entries), &(library->num_fc_entries), policy);
			if (retv) {
				fprintf(stderr, "file_type_run Warning: unable to process file_contexts file\n");
			}
		} else {
			fprintf(stderr, "file_type_run Warning: unable to find file_contexts file\n");
		}
	}


	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		/* test attributes */
		if (!(is_binary_policy(policy))) {
			retv = get_type_attribs(i, &num_attribs, &attribs, policy);
			if (retv) {
				fprintf(stderr, "file_type_run failed: could not get attributes for %s\n", policy->types[i].name);
				goto file_type_run_fail;
			}
			for (j = 0; j < datum->num_file_type_attribs; j++) {
				buff = NULL;
				if (find_int_in_array(datum->file_type_attribs[j], attribs, num_attribs) != -1) {
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "file_type_run failed: out of memory\n");
						goto file_type_run_fail;
					}
					proof->idx = datum->file_type_attribs[j];
					proof->type = POL_LIST_ATTRIB;
					proof->severity = SECHK_SEV_MIN;
					buff_sz = 1+strlen(policy->types[i].name)+strlen(policy->attribs[datum->file_type_attribs[j]].name)+strlen("type  has attribute ");
					buff = (char*)calloc(buff_sz, sizeof(char));
					if (!buff) {
						fprintf(stderr, "file_type_run failed: out of memory\n");
						goto file_type_run_fail;
					}
					proof->text = buff;
					if (!proof->text) {
						fprintf(stderr, "file_type_run failed: out of memory\n");
						goto file_type_run_fail;
					}
					snprintf(proof->text, buff_sz, "type %s has attribute %s", policy->types[i].name, policy->attribs[datum->file_type_attribs[j]].name);
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "file_type_run failed: out of memory\n");
							goto file_type_run_fail;
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
					if (is_sechk_proof_in_item(hash_rule->rule, POL_LIST_AV_ACC, item))
						continue;
					buff = NULL;
					if (does_av_rule_use_perms(hash_rule->rule, 1, &associate_perm_idx, 1, policy)) {
						buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 0, policy);
						proof = sechk_proof_new();
						if (!proof) {
							fprintf(stderr, "file_type_run failed: out of memory\n");
							goto file_type_run_fail;
						}
						proof->idx = hash_rule->rule;
						proof->type = POL_LIST_AV_ACC;
						proof->text = buff;
						proof->severity = SECHK_SEV_LOW;
						if (!item) {
							item = sechk_item_new();
							if (!item) {
								fprintf(stderr, "file_type_run failed: out of memory\n");
								goto file_type_run_fail;
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
					fprintf(stderr, "file_type_run failed: out of memory\n");
					goto file_type_run_fail;
				}
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "file_type_run failed: out of memory\n");
					goto file_type_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "file_type_run failed: out of memory\n");
						goto file_type_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;

			
		}

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
						fprintf(stderr, "file_type_run failed: error processing file context entries\n");
						goto file_type_run_fail;
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
						fprintf(stderr, "file_type_run failed: error processing file context entries\n");
						goto file_type_run_fail;
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
						fprintf(stderr, "file_type_run failed: out of memory\n");
						goto file_type_run_fail;
					}
					proof->idx = j;
					proof->type = POL_LIST_FCENT;
					proof->text = buff;
					proof->severity = SECHK_SEV_MOD;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "file_type_run failed: out of memory\n");
							goto file_type_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;

				}
			}
		}

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

file_type_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	free(buff);
	return -1;
}

void file_type_free(sechk_module_t *mod) 
{
	file_type_data_free((file_type_data_t*)(mod->data));
	free(mod->data);
}

int file_type_print_output(sechk_module_t *mod, policy_t *policy) 
{
	file_type_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;


	if (!mod || !policy) {
		fprintf(stderr, "file_type_print_output failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("file_type", mod->name)) {
		fprintf(stderr, "file_type_print_output failed: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "file_type_print_output failed: module has not been run\n");
		return -1;
	}

	datum = (file_type_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return 0; /* not an error - no output is requested */

	printf("Module: File Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		printf("%s", datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i file types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			printf("%s %c", policy->types[item->item_id].name, i?' ':'\n');
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		printf("\n\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", policy->types[item->item_id].name);
			printf(" - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
	}

	return 0;
}

sechk_result_t *file_type_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "file_type_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("file_type", mod->name)) {
		fprintf(stderr, "file_type_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

file_type_data_t *file_type_data_new(void) 
{
	file_type_data_t *datum = NULL;

	datum = (file_type_data_t*)calloc(1,sizeof(file_type_data_t));

	return datum;
}

void file_type_data_free(file_type_data_t *datum) 
{
	if (!datum)
		return;

	free(datum->file_type_attribs);

	free(datum->mod_header);
}

int file_type_get_file_type_list(sechk_module_t *mod, int **array, int *size) 
{
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "file_type_get_file_type_list failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("file_type", mod->name)) {
		fprintf(stderr, "file_type_get_file_type_list failed: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "file_type_get_file_type_list failed: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "file_type_get_file_type_list failed: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

	return 0;

}
