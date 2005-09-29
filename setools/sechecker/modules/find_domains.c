/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "find_domains.h"
#include "render.h"

#include <stdio.h>
#include <string.h>
#include <semantic/avsemantics.h>

static sechk_lib_t *library;
static const char *const mod_name = "find_domains";

int find_domains_register(sechk_lib_t *lib) 
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

	/* assign descriptions */
	mod->brief_description = "Finds all types in policy treated as a domain. ";
	mod->detailed_description = "Finds all types in policy treated as a domain. "
"\n  A type is considered a domain if any of the following is true: "
"\n    It has an attribute associated with domains "
"\n    It is the source of a te rule for object class other than filesystem "
"\n    It is the default type in a type_transition rule for object class process "
"\n    It is associated with a role other than object_r"
"\n  Requirements:"
"\n    policy_type=source"
"\n  Dependencies:"
"\n    none"
"\n  Options:"
"\n    domain_attribute";

	/* assign requirements */
	mod->requirements = sechk_name_value_prepend(NULL,"policy_type","source");
	
	/* assign options */
	mod->options = sechk_name_value_prepend(NULL,"domain_attribute","domain");

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
	fn_struct->fn = &find_domains_init;
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
	fn_struct->fn = &find_domains_run;
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
	fn_struct->fn = &find_domains_data_free;
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
	fn_struct->fn = &find_domains_print_output;
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
	fn_struct->fn = &find_domains_get_result;
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
	fn_struct->fn = &find_domains_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int find_domains_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_name_value_t *opt = NULL;
	find_domains_data_t *datum = NULL;
	int attr = -1, retv;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = find_domains_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "domain_attribute")) {
			attr = get_attrib_idx(opt->value, policy);
			if (attr != -1) {
				retv = add_i_to_a(attr, &(datum->num_domain_attribs), &(datum->domain_attribs));
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

int find_domains_run(sechk_module_t *mod, policy_t *policy) 
{
	int i, j, retv, idx;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	find_domains_data_t *datum = NULL;
	int *attribs = NULL, num_attribs = 0;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	int process_idx = -1;
	int file_idx = -1;
	avh_rule_t *hash_rule = NULL;
	char *buff = NULL;
	int buff_sz;
	unsigned char type;
	
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

	process_idx = get_obj_class_idx("process", policy);
	file_idx = get_obj_class_idx("filesystem",policy);

	datum = (find_domains_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->item_type = POL_LIST_TYPE;
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto find_domains_run_fail;
	}

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto find_domains_run_fail;
		}
	}

	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		/* test attributes */
		if (!(is_binary_policy(policy))) {
			retv = get_type_attribs(i, &num_attribs, &attribs, policy);
			if (retv) {
				fprintf(stderr, "Error: could not get attributes for %s\n", policy->types[i].name);
				goto find_domains_run_fail;
			}
			for (j = 0; j < datum->num_domain_attribs; j++) {
				buff = NULL;
				if (find_int_in_array(datum->domain_attribs[j], attribs, num_attribs) != -1) {
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					proof->idx = datum->domain_attribs[j];
					proof->type = POL_LIST_ATTRIB;
					proof->severity = SECHK_SEV_LOW;
					buff_sz = 1+strlen(policy->types[i].name)+strlen(policy->attribs[datum->domain_attribs[j]].name)+strlen("type  has attribute ");
					buff = (char*)calloc(buff_sz, sizeof(char));
					if (!buff) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					proof->text = buff;
					if (!proof->text) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					snprintf(proof->text, buff_sz, "type %s has attribute %s", policy->types[i].name, policy->attribs[datum->domain_attribs[j]].name);
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_domains_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;
				}
			}
		}

		/* test for rule src */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;

		proof = NULL;
		buff = NULL;
		for (j = 0; j < num_nodes; j++) {
			/* if key.cls != file system */
			if(hash_idx->nodes[j]->key.cls != file_idx) {
				for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
					if (hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS)
						type = POL_LIST_TE_TRANS;
					else if (hash_idx->nodes[j]->key.rule_type > RULE_TE_ALLOW)
						type = POL_LIST_AV_AU;
					else
						type = POL_LIST_AV_ACC;
					idx = hash_rule->rule;
					if (sechk_item_has_proof(idx, type, item))
						continue;
					buff = NULL;
					if (hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS)
						buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					else if (hash_idx->nodes[j]->key.rule_type <= RULE_MAX_TE)
						buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, (hash_idx->nodes[j]->key.rule_type > RULE_TE_ALLOW ? 1 : 0), policy);
					if (!buff) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					proof->idx = idx;
					proof->type = type;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto find_domains_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;
				}
			}
		}

		proof = NULL;
		buff = NULL;
		/* test type rules */
		for (j = 0; j < policy->num_te_trans; j++) {
			if (i == policy->te_trans[j].dflt_type.idx && does_tt_rule_use_classes(j, &process_idx, 1, policy)) {
				buff = re_render_tt_rule(!is_binary_policy(policy), j, policy);
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_domains_run_fail;
				}
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_domains_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
		}

		/* test roles */
		proof = NULL;
		buff = NULL;
		for (j = 0; j < policy->num_roles; j++) {
			if (!strcmp("object_r", policy->roles[j].name))
				continue;
			if (does_role_use_type(j, i, policy)) {
				buff_sz = 1 + strlen("role  types ;") + strlen(policy->roles[j].name) + strlen(policy->types[i].name);
				buff = (char*)calloc(buff_sz, sizeof(char));
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_domains_run_fail;
				}
				snprintf(buff, buff_sz, "role %s types %s;", policy->roles[j].name, policy->types[i].name);
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto find_domains_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_ROLES;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto find_domains_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
		}

		/* insert any results for this type */
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

find_domains_run_fail:
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	free(buff);
	return -1;
}

void find_domains_data_free(sechk_module_t *mod) 
{
	find_domains_data_t *datum = NULL;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}
	datum = (find_domains_data_t*)mod->data;
	if (datum) {
		free(datum->domain_attribs);
	}
	free(mod->data);
	mod->data = NULL;
}

int find_domains_print_output(sechk_module_t *mod, policy_t *policy) 
{
	find_domains_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || (!policy && (mod->outputformat & ~(SECHK_OUT_BRF_DESCP)))) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp("find_domains", mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (find_domains_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result && (outformat & ~(SECHK_OUT_BRF_DESCP)) && (outformat & ~(SECHK_OUT_DET_DESCP))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat) {
		return 0; /* not an error - no output is requested */
	}
	printf("\nModule: %s\n", mod_name);
	/* print the brief description */
	if (outformat & SECHK_OUT_BRF_DESCP) {
		printf("%s\n\n", mod->brief_description);
	}
	/* print the detailed description */
	if (outformat & SECHK_OUT_DET_DESCP) {
		printf("%s\n\n", mod->detailed_description);
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i domain types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			printf("%s%s", policy->types[item->item_id].name, i ?", " : "\n");
		}
		printf("\n");
	}
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", policy->types[item->item_id].name);
			printf(" - severity: %s\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("\t%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

sechk_result_t *find_domains_get_result(sechk_module_t *mod) 
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

int find_domains_get_list(sechk_module_t *mod, int **array, int *size) 
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

find_domains_data_t *find_domains_data_new(void) 
{
	find_domains_data_t *datum = NULL;

	datum = (find_domains_data_t*)calloc(1,sizeof(find_domains_data_t));

	return datum;
}


