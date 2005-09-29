/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "types_not_in_allow.h"
#include "semantic/avsemantics.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "types_not_in_allow";

/* The register function registers all of a module's functions
 * with the library. */
int types_not_in_allow_register(sechk_lib_t *lib)
{
	sechk_module_t *mod = NULL;
	sechk_fn_t *fn_struct = NULL;

	if (!lib) {
		fprintf(stderr, "Error: no library\n");
		return -1;
	}

	library = lib;

	/* Modules are declared by the config file and their name and options
	 * are stored in the module array.  The name is looked up to determine
	 * where to store the function structures */
	mod = sechk_lib_get_module(mod_name, lib);
	if (!mod) {
		fprintf(stderr, "Error: module unknown\n");
		return -1;
	}

	/* assign the descriptions */
	mod->brief_description = "Finds types declared but not used in allow rules of a policy.\n";
	mod->detailed_description = "Finds types declared but not used in allow rules of a policy."
"\nIf a type does not appear in an allow rule, all attemped access to that"
"\ntype will be denied (including relabeling to a usable type)."
		"\nThis module reports other uses if found."
		"\n  Requirements:"
		"\n    none"
		"\n  Dependencies:"
		"\n    none"
		"\n  Options:"
		"\n    none";
	
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
	fn_struct->fn = &types_not_in_allow_init;
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
	fn_struct->fn = &types_not_in_allow_run;
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
	fn_struct->fn = &types_not_in_allow_free;
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
	fn_struct->fn = &types_not_in_allow_print_output;
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
	fn_struct->fn = &types_not_in_allow_get_result;
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
	fn_struct->fn = &types_not_in_allow_get_list;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int types_not_in_allow_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	types_not_in_allow_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = types_not_in_allow_data_new();
	if (!datum) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	mod->data = datum;

	opt = mod->options;
	while (opt) {
		opt = opt->next;
	}

	return 0;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. This function allocates the result
 * structure and fills in all relavant item and proof data. */
int types_not_in_allow_run(sechk_module_t *mod, policy_t *policy)
{
	types_not_in_allow_data_t *datum;
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

	datum = (types_not_in_allow_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto types_not_in_allow_run_fail;
	}
	res->item_type  = POL_LIST_TYPE;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto types_not_in_allow_run_fail;
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
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					if (!buff) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (used)
					break;
				if (buff) {
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					proof->idx = hash_rule->rule;
					proof->type = retv;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto types_not_in_allow_run_fail;
						}
						item->item_id = i;
					}
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
				buff = NULL;
				proof = NULL;
			}
			if (used) 
				break;
		}
		if (used) {
			sechk_item_free(item);
			item = NULL;
			continue;
		}

		/* check for target */
		hash_idx = avh_tgt_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
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
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					retv = POL_LIST_AV_AU;
					break;
				case RULE_TE_TRANS:
				case RULE_TE_MEMBER:
				case RULE_TE_CHANGE:
					buff = re_render_tt_rule(!is_binary_policy(policy), hash_rule->rule, policy);
					if (!buff) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					retv = POL_LIST_TE_TRANS;
					break;
				default:
					break;
				}
				if (used)
					break;
				if (buff) {
					proof = sechk_proof_new();
					if (!proof) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
					}
					proof->idx = hash_rule->rule;
					proof->type = retv;
					proof->text = buff;
					proof->severity = SECHK_SEV_LOW;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "Error: out of memory\n");
							goto types_not_in_allow_run_fail;
						}
						item->item_id = i;
					}
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
				buff = NULL;
				proof = NULL;
			}
			if (used) 
				break;
		}
		if (used) {
			sechk_item_free(item);
			item = NULL;
			continue;
		}

		/* role_trans not hashed check for tgt */
		for (j = 0; j < policy->num_role_trans; j++) {
			if (does_role_trans_use_ta(i, IDX_TYPE, 1, &(policy->role_trans[j]), &retv, policy)) {
				buff_sz += strlen("role_transition {} {} ; ");
				if (!is_binary_policy(policy))
					buff_sz += ((policy->role_trans[j].lineno)/10 + 5);
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
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
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

				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_ROLE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
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
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				proof->idx = j;
				proof->type = POL_LIST_TE_TRANS;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
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
				buff = re_render_av_rule(!is_binary_policy(policy), j, 0, policy);
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				retv = POL_LIST_AV_ACC;
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				proof->idx = j;
				proof->type = retv;
				proof->text = buff;
				proof->severity = SECHK_SEV_LOW;
				if (!item) {
					item = sechk_item_new();
					if (!item) {
						fprintf(stderr, "Error: out of memory\n");
						goto types_not_in_allow_run_fail;
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
			proof = sechk_proof_new();
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto types_not_in_allow_run_fail;
			}
			proof->idx = -1;
			proof->type = -1;
			proof->text = strdup("This type does not appear in any rules.");
			proof->severity = SECHK_SEV_LOW;
			if (!item) {
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					goto types_not_in_allow_run_fail;
				}
				item->item_id = i;
				item->test_result++;
			}
			proof->next = item->proof;
			item->proof = proof;
		}

		if (item) {
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
		}
		item = NULL;
	}

	mod->result = res;

	return 0;

types_not_in_allow_run_fail:
	free(buff);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void types_not_in_allow_free(sechk_module_t *mod)
{
	types_not_in_allow_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (types_not_in_allow_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int types_not_in_allow_print_output(sechk_module_t *mod, policy_t *policy) 
{
	types_not_in_allow_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i = 0;

        if (!mod || (!policy && (mod->outputformat & ~(SECHK_OUT_BRF_DESCP) &&
                                 (mod->outputformat & ~(SECHK_OUT_DET_DESCP))))){
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (types_not_in_allow_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result && (outformat & ~(SECHK_OUT_BRF_DESCP)) && (outformat & ~(SECHK_OUT_DET_DESCP))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	printf("\nModule: %s\n", mod_name);
	/* print the brief description */
	if (outformat & SECHK_OUT_BRF_DESCP) {
		printf("%s\n\n", mod->brief_description);
	}
	/* print the detailed description */
	if (outformat & SECHK_OUT_DET_DESCP) {
		printf("%s\n\n", mod->detailed_description);
	}
	/* display the statistics of the results */
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			i++;
			i %= 4;
			printf("%s%s", policy->types[item->item_id].name, (i ? ", " : "\n")); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
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

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *types_not_in_allow_get_result(sechk_module_t *mod) 
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

/* The types_not_in_allow_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
types_not_in_allow_data_t *types_not_in_allow_data_new(void)
{
	types_not_in_allow_data_t *datum = NULL;

	datum = (types_not_in_allow_data_t*)calloc(1,sizeof(types_not_in_allow_data_t));

	return datum;
}

int types_not_in_allow_get_list(sechk_module_t *mod, int **array, int*size)
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
 
