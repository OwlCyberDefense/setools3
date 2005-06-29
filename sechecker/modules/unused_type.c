/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "unused_type.h"
#include "semantic/avsemantics.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

static sechk_lib_t *library;

int unused_type_register(sechk_lib_t *lib) 
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "unused_type_register failed: no library\n");
		return -1;
	}

	library = lib;

	mod = get_module("unused_type", lib);
	if (!mod) {
		fprintf(stderr, "unused_type_register failed: module unknown\n");
		return -1;
	}
	
	/* register functions */
	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("init");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_init;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("run");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_run;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("free");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_free;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_output_str");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_get_output_str;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_result");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	fn_struct = new_sechk_fn();
	if (!fn_struct) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->name = strdup("get_unused_types_list");
	if (!fn_struct->name) {
		fprintf(stderr, "unused_type_register failed: out of memory\n");
		return -1;
	}
	fn_struct->fn = &unused_type_get_unused_types_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

int unused_type_init(sechk_module_t *mod, policy_t *policy) 
{
	sechk_opt_t *opt = NULL;
	unused_type_data_t *datum = NULL;
	bool_t header = TRUE;
	int pol_ver = POL_VER_UNKNOWN;

	if (!mod || !policy) {
		fprintf(stderr, "unused_type_init failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_init failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = new_unused_type_data();
	if (!datum) {
		fprintf(stderr, "unused_type_init failed: out of memory\n");
		return -1;
	}
	mod->data = datum;

	datum->outformat = library->outformat;
	datum->mod_header = strdup("Finds types declared but not used in allow rules of a poicy.\nThis module reports other uses if found.\n\n");/* TODO: add header text */

	opt = mod->options;
	while (opt) {
		if (!strcmp(opt->name, "pol_type")) {
			if (!strcmp(opt->value, "source")) {
				if (is_binary_policy(policy))
					fprintf(stderr, "unused_type_init Warning: module required source policy but was given binary, results may not be complete\n");
			} else if (!strcmp(opt->value, "binary")) {
				if (!is_binary_policy(policy))
					fprintf(stderr, "unused_type_init Warning: module required binary policy but was given source, results may not be complete\n");
			} else {
				fprintf(stderr, "unused_type_init failed: invalid policy type specification %s\n", opt->value);
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
				fprintf(stderr, "unused_type_init failed: module requires newer policy version\n");
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
		}
		opt = opt->next;
	}
	if (!header)
		datum->outformat &= ~(SECHK_OUT_HEADER);

	return 0;
}

int unused_type_run(sechk_module_t *mod, policy_t *policy) 
{
	unused_type_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, j, retv;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	avh_rule_t *hash_rule = NULL;
	char *buff = NULL;
	int buff_sz;
	bool_t used = FALSE;
	ta_item_t *ta = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "unused_type_run failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_run failed: wrong module (%s)\n", mod->name);
		return -1;
	}

	/* if already run return */
	if (mod->result)
		return 0;

	datum = (unused_type_data_t*)mod->data;
	res = new_sechk_result();
	if (!res) {
		fprintf(stderr, "unused_type_run failed: out of memory\n");
		return -1;
	}
	res->test_name = strdup("unused_type");
	if (!res->test_name) {
		fprintf(stderr, "unused_type_run failed: out of memory\n");
		goto unused_type_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "unused_type_run failed: could not build hash table\n");
			goto unused_type_run_fail;
		}
	}

	/* head insert for item LL so walk backward to preserve order */
	for (i = policy->num_types - 1; i; i--) {
		used = FALSE;
		/* check for source */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
			used = FALSE;
			for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
				switch (hash_idx->nodes[j]->key.rule_type) {
				case RULE_TE_ALLOW:
					used = TRUE;
					break;
				case RULE_AUDITALLOW:
				case RULE_AUDITDENY:
				case RULE_DONTAUDIT:
					buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 1, policy);
					if (!buff) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					if (!buff) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (buff) {
					proof = new_sechk_proof();
					if (!proof) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					proof->idx = hash_rule->rule;
					proof->type = retv;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = new_sechk_item();
						if (!item) {
							fprintf(stderr, "unused_type_run failed: out of memory\n");
							goto unused_type_run_fail;
						}
						item->item_id = i;
					}
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
				buff = NULL;
			}
			if (used) 
				break;
		}
		if (used) {
			free_sechk_proof(&proof);
			free_sechk_item(&item);
			continue;
		}

		/* check for target */
		hash_idx = avh_tgt_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
			used = FALSE;
			for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
				switch (hash_idx->nodes[j]->key.rule_type) {
				case RULE_TE_ALLOW:
					used = TRUE;
					break;
				case RULE_AUDITALLOW:
				case RULE_AUDITDENY:
				case RULE_DONTAUDIT:
					buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 1, policy);
					if (!buff) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					if (!buff) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (buff) {
					proof = new_sechk_proof();
					if (!proof) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					proof->idx = hash_rule->rule;
					proof->type = retv;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = new_sechk_item();
						if (!item) {
							fprintf(stderr, "unused_type_run failed: out of memory\n");
							goto unused_type_run_fail;
						}
						item->item_id = i;
					}
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
				buff = NULL;
			}
			if (used) 
				break;
		}
		if (used) {
			free_sechk_proof(&proof);
			free_sechk_item(&item);
			continue;
		}

		/* role_trans not hashed check for tgt */
		for (j = 0; j < policy->num_role_trans; j++) {
			if (does_role_trans_use_ta(i, IDX_TYPE, 1, &(policy->role_trans[j]), &retv, policy)) {
				buff_sz += strlen("role_transition {} {} ; ");
				if (!is_binary_policy(policy))
					buff_sz += (intlen(policy->role_trans[j].lineno) + 3);
				for (ta = policy->role_trans[j].src_roles; ta; ta = ta->next) {
					buff_sz += (1 + strlen(policy->roles[ta->idx].name));
				}
				for (ta = policy->role_trans[j].tgt_types; ta; ta = ta->next) {
					if (ta->type == IDX_TYPE)
						buff_sz += (1 + strlen(policy->types[ta->idx].name));
					else
						buff_sz += (1 + strlen(policy->attribs[ta->idx].name));
				}
				buff_sz += strlen(policy->roles[policy->role_trans[j].trans_role.idx].name);
				buff = (char*)calloc(buff_sz, sizeof(char));
				if (!buff) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
 				if (!is_binary_policy(policy))
					sprintf(buff, "[%lu] ", policy->role_trans[j].lineno);
				strcat(buff, "role_transition {");
				for (ta = policy->role_trans[j].src_roles; ta; ta = ta->next) {
					strcat(buff, policy->roles[ta->idx].name);
					strcat(buff, " ");
				}
				strcat(buff, "} {");
				for (ta = policy->role_trans[j].tgt_types; ta; ta = ta->next) {
					if (ta->type == IDX_TYPE) {
						strcat(buff, policy->types[ta->idx].name);
						strcat(buff, " ");
					} else {
						strcat(buff, policy->attribs[ta->idx].name);
						strcat(buff, " ");
					}
				}
				strcat(buff, "} ");
				strcat(buff, policy->roles[policy->role_trans[j].trans_role.idx].name);
				strcat(buff, ";");

				proof = new_sechk_proof();
				if (!proof) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_ROLE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = new_sechk_item();
					if (!item) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					item->item_id = i;
				}
				item->test_result++;
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
			buff_sz = 0;
		}
		
		/* check for default*/
		for (j = 0; j < policy->num_te_trans; j++) {
			if (policy->te_trans[j].dflt_type.idx == i) {
				buff = re_render_tt_rule(!is_binary_policy(policy), j, policy);
				if (!buff) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				proof = new_sechk_proof();
				if (!proof) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = new_sechk_item();
					if (!item) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					item->item_id = i;
				}
				item->test_result++;
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
		}

		/* check neverallows */
		for (j = 0; j < policy->num_av_access; j++) {
			if (policy->av_access[j].type != RULE_NEVERALLOW)
				continue;
			if (does_av_rule_idx_use_type(j, 0, i, IDX_TYPE, BOTH_LISTS, 1, policy)) {
				buff = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 0, policy);
				if (!buff) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				retv = POL_LIST_AV_ACC;
				proof = new_sechk_proof();
				if (!proof) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				proof->idx = hash_rule->rule;
				proof->type = retv;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = new_sechk_item();
					if (!item) {
						fprintf(stderr, "unused_type_run failed: out of memory\n");
						goto unused_type_run_fail;
					}
					item->item_id = i;
				}
				item->test_result++;
				proof->next = item->proof;
				item->proof = proof;
			}
			buff = NULL;
		}

		/* not used anywhere*/
		if (!item) {
			proof = new_sechk_proof();
			if (!proof) {
				fprintf(stderr, "unused_type_run failed: out of memory\n");
				goto unused_type_run_fail;
			}
			proof->idx = -1;
			proof->type = -1;
			proof->text = strdup("This type does not appear in any rules.");
			proof->severity = SECHK_SEV_MIN;
			if (!item) {
				item = new_sechk_item();
				if (!item) {
					fprintf(stderr, "unused_type_run failed: out of memory\n");
					goto unused_type_run_fail;
				}
				item->item_id = i;
				item->test_result++;
			}
			proof->next = item->proof;
			item->proof = proof;
		}
	}

	mod->result = res;

	free(buff);
	return 0;

unused_type_run_fail:
	free(buff);
	free_sechk_proof(&proof);
	free_sechk_item(&item);
	free_sechk_result(&res);
	return -1;
}

void unused_type_free(sechk_module_t *mod) 
{
	if (!mod) {
		fprintf(stderr, "unused_type_free failed: invalid parameters\n");
		return;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_free failed: wrong module (%s)\n", mod->name);
		return;
	}
	
	free(mod->name);
	mod->name = NULL;
	free_sechk_result(&(mod->result));
	free_sechk_opt(&(mod->options));
	free_sechk_fn(&(mod->functions));
	free_unused_type_data((unused_type_data_t**)&(mod->data));
}

char *unused_type_get_output_str(sechk_module_t *mod, policy_t *policy) 
{
	char *buff = NULL, *tmp = NULL;
	unsigned long buff_sz = 0L;
	unused_type_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

	if (!mod || !policy) {
		fprintf(stderr, "unused_type_get_output_str failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_get_output_str failed: wrong module (%s)\n", mod->name);
		return NULL;
	}
	if (!mod->result) {
		fprintf(stderr, "unused_type_get_output_str failed: module has not been run\n");
		return NULL;
	}

	datum = (unused_type_data_t*)mod->data;
	outformat = datum->outformat;
	if (!outformat)
		return NULL; /* not an error - no output is requested */

	buff_sz += strlen("Module: Unused Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		buff_sz += strlen(datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		buff_sz += strlen("Found  types.\n") + intlen(mod->result->num_items);
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
		fprintf(stderr, "unused_type_get_output_str failed: out of memory\n");
		return NULL;
	}
	tmp = buff;

	tmp += sprintf(buff, "Module: Unused Type\n");
	if (outformat & SECHK_OUT_HEADER) {
		tmp += sprintf(tmp, datum->mod_header);
	}
	if (outformat & SECHK_OUT_STATS) {
		tmp += sprintf(tmp, "Found %i types.\n", mod->result->num_items);
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

sechk_result_t *unused_type_get_result(sechk_module_t *mod) 
{

	if (!mod) {
		fprintf(stderr, "unused_type_get_result failed: invalid parameters\n");
		return NULL;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_get_result failed: wrong module (%s)\n", mod->name);
		return NULL;
	}

	return mod->result;
}

unused_type_data_t *new_unused_type_data(void) 
{
	unused_type_data_t *datum = NULL;

	datum = (unused_type_data_t*)calloc(1,sizeof(unused_type_data_t));

	return datum;
}

void free_unused_type_data(unused_type_data_t **datum) 
{
	if (!datum || !(*datum))
		return;

	free((*datum)->mod_header);
	free(*datum);
	*datum = NULL;
}

int unused_type_get_unused_types_list(sechk_module_t *mod, int **array, int*size)
{
	int i;
	sechk_item_t *item = NULL;

	if (!mod || !array || !size) {
		fprintf(stderr, "unused_type_get_unused_types_list failed: invalid parameters\n");
		return -1;
	}
	if (strcmp("unused_type", mod->name)) {
		fprintf(stderr, "unused_type_get_unused_types_list failed: wrong module (%s)\n", mod->name);
		return -1;
	}
	if (!mod->result) {
		fprintf(stderr, "unused_type_get_unused_types_list failed: module has not been run\n");
		return -1;
	}

	*size = mod->result->num_items;

	*array = (int*)malloc(mod->result->num_items * sizeof(int));
	if (!(*array)) {
		fprintf(stderr, "unused_type_get_unused_types_list failed: out of memory\n");
		return -1;
	}

	for (i = 0, item = mod->result->items; item && i < *size; i++, item = item->next) {
		(*array)[i] = item->item_id;
	}

	return 0;
}
 
