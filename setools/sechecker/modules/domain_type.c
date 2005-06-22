/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "domain_type.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int domain_type_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "domain_type_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = get_module("domain_type", lib);
	if (!mod) {
		fprintf(stderr, "domain_type_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_domain_list");
	if (!fn_struct->name) {
		fprintf(stderr, "domain_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &domain_type_get_domain_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int domain_type_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	domain_type_data_t *datum = NULL;
	int attr = -1, retv;
	bool_t header = TRUE;

	if (!mod || !policy) {
		fprintf(stderr, "domain_type_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_domain_type_data();
	if (!datum) {
		fprintf(stderr, "domain_type_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->conf->outformat;
	datum->mod_header = strdup("Finds all types in policy treated as a domain.\nA type is considered a domain if any of the following is true:\n   It has an attribute associated with domains\n   It is the source of a te rule for object class process\n   It is the default type in a type_transition rule for object class process\n   It is associated with a role other than object_r\n\n");

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "domain_attribute")) {
			attr = get_attrib_idx(opt->value, policy);
			if (attr != -1) {
				retv = add_i_to_a(attr, &(datum->num_domain_attribs), &(datum->domain_attribs));
				if (retv) {
					fprintf(stderr, "domain_type_init failed: out of memory\n");
					return -1;
				}
			} else {
				fprintf(stderr, "domain_type_init Warning: attribute %s not defined, ignoring\n", opt->value);
			}
		} else if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "domain_type_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "domain_type_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "domain_type_init failed: invalid policy type specification %s\n", opt->value);
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
		}
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int domain_type_run(sechk_module_t *mod, policy_t *policy) 
{
	int i, j, retv, idx;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	domain_type_data_t *datum = NULL;
	int *attribs = NULL, num_attribs = 0;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	int process_idx = -1;
	avh_rule_t *hash_rule = NULL;
	char *buff = NULL;
	int buff_sz;
	unsigned char type;
	
	if (!mod || !policy) {
		fprintf(stderr, "domain_type_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	process_idx = get_obj_class_idx("process", policy);

	datum = (domain_type_data_t*)mod->data;
	res = new_sechk_result();
	if (!res) {
		fprintf(stderr, "domain_type_run failed: out of memory\n");
		return -1;
	}
	res->item_type = POL_LIST_TYPE;
	res->test_name = strdup("doamin_type");
	if (!res->test_name) {
		fprintf(stderr, "domain_type_run failed: out of memory\n");
		goto domain_type_run_fail;
	}

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "domain_type_run failed: could not build hash table\n");
			goto domain_type_run_fail;
		}
	}

	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		/* test attributes */
		if (!(is_binary_policy(policy))) {
			retv = get_type_attribs(i, &num_attribs, &attribs, policy);
			if (retv) {
				fprintf(stderr, "domain_type_run failed: could not get attributes for %s\n", policy->types[i].name);
				goto domain_type_run_fail;
			}
			for (j = 0; j < datum->num_domain_attribs; j++) {
				buff = NULL;
				if (find_int_in_array(datum->domain_attribs[j], attribs, num_attribs) != -1) {
					proof = new_sechk_proof();
					if (!proof) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					proof->idx = datum->domain_attribs[j];
					proof->type = POL_LIST_ATTRIB;
					proof->severity = SECHK_SEV_MIN;
					buff_sz = 1+strlen(policy->types[i].name)+strlen(policy->attribs[datum->domain_attribs[j]].name)+strlen("type  has attribute ");
					buff = (char*)calloc(buff_sz, sizeof(char));
					if (!buff) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					proof->text = buff;
					if (!proof->text) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					snprintf(proof->text, buff_sz, "type %s has attribute %s", policy->types[i].name, policy->attribs[datum->domain_attribs[j]].name);
					if (!item) {
						item = new_sechk_item();
						if (!item) {
							fprintf(stderr, "domain_type_run failed: out of memory\n");
							goto domain_type_run_fail;
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

		for (j = 0; j < num_nodes; j++) {
			if(hash_idx->nodes[j]->key.cls == process_idx || hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS) {
				for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
					if (hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS)
						type = POL_LIST_TE_TRANS;
					else if (hash_idx->nodes[j]->key.rule_type > RULE_TE_ALLOW)
						type = POL_LIST_AV_AU;
					else
						type = POL_LIST_AV_ACC;
					idx = hash_rule->rule;
					if (is_sechk_proof_in_item(idx, type, item))
						continue;
					buff = NULL;
					if (hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS)
						buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					else if (hash_idx->nodes[j]->key.rule_type <= RULE_MAX_AV)
						buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, (hash_idx->nodes[j]->key.rule_type > RULE_TE_ALLOW ? 1 : 0), policy);
					if (!buff) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					proof = new_sechk_proof();
					if (!proof) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					proof->idx = idx;
					proof->type = type;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = new_sechk_item();
						if (!item) {
							fprintf(stderr, "domain_type_run failed: out of memory\n");
							goto domain_type_run_fail;
						}
						item->item_id = i;
						item->test_result = 1;
					}
					proof->next = item->proof;
					item->proof = proof;
				}
			}
		}

		/* test type rules */
		for (j = 0; j < policy->num_te_trans; j++) {
			if (i == policy->te_trans[j].dflt_type.idx && does_tt_rule_use_classes(j, &process_idx, 1, policy)) {
				buff = re_render_tt_rule(!is_binary_policy(policy), j, policy);
				if (!buff) {
					fprintf(stderr, "domain_type_run failed: out of memory\n");
					goto domain_type_run_fail;
				}
				proof = new_sechk_proof();
				if (!proof) {
					fprintf(stderr, "domain_type_run failed: out of memory\n");
					goto domain_type_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = new_sechk_item();
					if (!item) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
		}

		/* test roles 0 is object_r skip it */
		for (j = 1; j < policy->num_roles; j++) {
			if (does_role_use_type(j, i, policy)) {
				buff_sz = 1 + strlen("role  types ;") + strlen(policy->roles[j].name) + strlen(policy->types[i].name);
				buff = (char*)calloc(buff_sz, sizeof(char));
				if (!buff) {
					fprintf(stderr, "domain_type_run failed: out of memory\n");
					goto domain_type_run_fail;
				}
				snprintf(buff, buff_sz, "role %s types %s;", policy->roles[j].name, policy->types[i].name);
				proof = new_sechk_proof();
				if (!proof) {
					fprintf(stderr, "domain_type_run failed: out of memory\n");
					goto domain_type_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_ROLES;
				proof->text = buff;
				proof->severity = SECHK_SEV_MIN;
				if (!item) {
					item = new_sechk_item();
					if (!item) {
						fprintf(stderr, "domain_type_run failed: out of memory\n");
						goto domain_type_run_fail;
					}
					item->item_id = i;
					item->test_result = 1;
				}
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
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

domain_type_run_fail:
	free_sechk_proof(&proof);
	free_sechk_item(&item);
	free_sechk_result(&res);
	free(buff);
	return -1;
}

void domain_type_free(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "domain_type_free failed: invalid parameters\n");
		return;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_free failed: wrong module (%s)\n", mod->name);
		return;
	}
	
	free(mod->name);
	mod->name = NULL;
	free_sechk_result(&(mod->result));
	free_sechk_opt(&(mod->options));
	free_sechk_fn(&(mod->functions));
	free_domain_type_data((domain_type_data_t**)&(mod->data));
}

char *domain_type_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	domain_type_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "domain_type_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "domain_type_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (domain_type_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	buff_sz += strlen("Module: Domain Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  domain types.\n") + intlen(mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		buff_sz++; /* '\n' */
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += 2 + strlen(policy->types[item->item_id].name);
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		buff_sz += 2;
		for (item = mod->result->items; item; item = item->next) {
			buff_sz += strlen(policy->types[item->item_id].name);
			buff_sz += strlen(" - severity: x\n");
			for (proof = item->proof; proof; proof = proof->next) {
				buff_sz += 2 + strlen(proof->text);
			}
		}
	}
	buff_sz++; /* '\0' */

	buff = (char*)calloc(buff_sz, sizeof(char));
	if (!buff) {
		fprintf(stderr, "domain_type_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: Domain Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i domain types.\n", mod->result->num_items);
	}
	if (outformat & SECHK_OUT_LIST) {
		tmp += sprintf(tmp, "\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4; /* 4 items per line */
			tmp += sprintf(tmp, "%s %c", policy->types[item->item_id].name, i?' ':'\n');
		}
	}
	if (outformat & SECHK_OUT_LONG) {
		tmp += sprintf(tmp, "\n\n");
		for (item = mod->result->items; item; item = item->next) {
			tmp += sprintf(tmp,"%s", policy->types[item->item_id].name);
			tmp += sprintf(tmp, " - severity: %i\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				tmp += sprintf(tmp,"\t%s\n", proof->text);
			}
		}
	}

	return buff;
}

sechk_result_t *domain_type_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "domain_type_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

int domain_type_get_domain_list(sechk_module_t *mod, int **array, int *size) 
{
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "domain_type_get_domain_list failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("domain_type", mod->name)) {
		fprintf(stderr, "domain_type_get_domain_list failed: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "domain_type_get_domain_list failed: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "domain_type_get_domain_list failed: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

	return 0;
}

domain_type_data_t *new_domain_type_data(void) 
{
	domain_type_data_t *datum = NULL;

	datum = (domain_type_data_t*)calloc(1,sizeof(domain_type_data_t));

	return datum;
}

void free_domain_type_data(domain_type_data_t **datum) 
{
	if (!datum || !(*datum))
		return;

	free((*datum)->domain_attribs);

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

 
