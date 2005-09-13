/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "spurious_audit.h"
#include "render.h"
#include "semantic/avsemantics.h"
#include "semantic/avhash.h"

#include <stdio.h>
#include <string.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "spurious_audit";

/* The register function registers all of a module's functions
 * with the library. */
int spurious_audit_register(sechk_lib_t *lib)
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
	mod->brief_description = "Finds audit rules which do not affect the auditing of the policy.";
	mod->detailed_description = "Finds audit rules which do not affect the auditing of the policy."
"\nThis module finds two types of spurious audit rules:"
"\n  dontaudit rules for allowed permission sets"
"\n  auditallow rules without an allow rule";

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
	fn_struct->fn = &spurious_audit_init;
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
	fn_struct->fn = &spurious_audit_run;
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
	fn_struct->fn = &spurious_audit_free;
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
	fn_struct->fn = &spurious_audit_print_output;
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
	fn_struct->fn = &spurious_audit_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int spurious_audit_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	spurious_audit_data_t *datum = NULL;


	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = spurious_audit_data_new();
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
int spurious_audit_run(sechk_module_t *mod, policy_t *policy)
{
	spurious_audit_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, src, tgt, obj, perm, retv;
	avh_node_t *node;
	int *src_types = NULL, num_src_types = 0;
	int *tgt_types = NULL, num_tgt_types = 0;
	int *obj_classes = NULL, num_obj_classes = 0;
	int *perms = NULL, num_perms = 0;
	bool_t *used_perms = NULL;
	avh_key_t *key = NULL;
	avh_rule_t *hash_rule = NULL;
	char *tmp = NULL;

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

	datum = (spurious_audit_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto spurious_audit_run_fail;
	}
	res->item_type = POL_LIST_AV_AU;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto spurious_audit_run_fail;
		}
	}

	for (i = 0; i < policy->num_av_audit; i++) {
		retv = extract_types_from_te_rule(i, 1, SRC_LIST, &src_types, &num_src_types, policy);
		if (retv) {
			fprintf(stderr, "Error: out of memory\n");
			goto spurious_audit_run_fail;
		}
		extract_types_from_te_rule(i, 1, TGT_LIST, &tgt_types, &num_tgt_types, policy);
		if (retv) {
			fprintf(stderr, "Error: out of memory\n");
			goto spurious_audit_run_fail;
		}
		retv = extract_obj_classes_from_te_rule(i, 1, &obj_classes, &num_obj_classes, policy);
		if (retv) {
			fprintf(stderr, "Error: out of memory\n");
			goto spurious_audit_run_fail;
		}
		retv = extract_perms_from_te_rule(i, 1, &perms, &num_perms, policy);
		if (retv) {
			fprintf(stderr, "Error: out of memory\n");
			goto spurious_audit_run_fail;
		}
		if (num_perms) {
			used_perms = (bool_t*)calloc(num_perms, sizeof(bool_t));
			if (!used_perms) {
				fprintf(stderr, "Error: out of memory\n");
				goto spurious_audit_run_fail;
			}
		}
		for (src = 0; src < num_src_types; src++) {
			for (tgt = 0; tgt < num_tgt_types; tgt++) {
				for (obj = 0; obj < num_obj_classes; obj++) {
					proof = NULL;
					key = (avh_key_t*)calloc(1, sizeof(avh_key_t));
					if (!key) {
						fprintf(stderr, "Error: out of memory\n");
						goto spurious_audit_run_fail;
					}
					key->src = src_types[src];
					key->tgt = tgt_types[tgt];
					key->cls = obj_classes[obj];
					key->rule_type = RULE_TE_ALLOW;
					node = avh_find_first_node(&(policy->avh), key);
					if (policy->av_audit[i].type == RULE_AUDITALLOW) {
						if (!node) {
							proof = sechk_proof_new();
							if (!proof) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							proof->idx = -1;
							proof->type = POL_LIST_AV_ACC;
							proof->severity = SECHK_SEV_MOD;
							tmp = re_render_av_rule(!is_binary_policy(policy), i, 1, policy);
							if (!tmp) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							proof->text = (char*)calloc(9 + strlen(tmp), sizeof(char));
							if (!proof->text) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							snprintf(proof->text, 9+strlen(tmp), "missing: %s", strstr(tmp, "allow"));
							if (!item) {
								item = sechk_item_new();
								if (!item) {
									fprintf(stderr, "Error: out of memory\n");
									goto spurious_audit_run_fail;
								}
								item->item_id = i;
								item->test_result = SECHK_SPUR_AU_AA_MISS;
							} else {
								item->test_result |= SECHK_SPUR_AU_AA_MISS;
							}
							proof->next = item->proof;
							item->proof = proof;
						} else {
							retv = 0;
							for (perm = 0; perm < num_perms; perm++) {
								if (find_int_in_array(perms[perm], node->data, node->num_data) != -1) {
									used_perms[perm] = TRUE;
									retv ++;
								}
							}
							if (retv == num_perms)
								continue;
							proof = sechk_proof_new();
							proof->idx = -1;
							proof->type = POL_LIST_AV_ACC;
							proof->severity = SECHK_SEV_LOW;
							retv = 0;
							tmp = (char*)calloc(3*LIST_SZ, sizeof(char));
							if (!tmp) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							retv = snprintf(tmp, 3*LIST_SZ, "missing: allow %s %s : %s { ", policy->types[src_types[src]].name, policy->types[tgt_types[tgt]].name, policy->obj_classes[obj_classes[obj]].name);
							for (perm = 0; perm < num_perms; perm++) {
								if (!used_perms[perm])
									retv += snprintf(tmp+retv, 3*LIST_SZ-retv, "%s ", policy->perms[perms[perm]]);
							}
							snprintf(tmp+retv, 3*LIST_SZ-retv, "};");
							proof->text = strdup(tmp);
							if (!proof->text) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							if (!item) {
								item = sechk_item_new();
								if (!item) {
									fprintf(stderr, "Error: out of memory\n");
									goto spurious_audit_run_fail;
								}
								item->item_id = i;
								item->test_result = SECHK_SPUR_AU_AA_PART;
							} else {
								item->test_result |= SECHK_SPUR_AU_AA_PART;
							}
							proof->next = item->proof;
							item->proof = proof;
						}
					} else if (policy->av_audit[i].type == RULE_DONTAUDIT) {
						if (!node) {
							continue;
						}
						retv = 0;
						for (perm = 0; perm < num_perms; perm++) {
							if (find_int_in_array(perms[perm], node->data, node->num_data) != -1) {
								used_perms[perm] = TRUE;
								retv ++;
							}
						}
						if (!retv)
							continue;
						if (!item) {
							item = sechk_item_new();
							if (!item) {
								fprintf(stderr, "Error: out of memory\n");
								goto spurious_audit_run_fail;
							}
							item->item_id = i;
							if (retv == num_perms) 
								item->test_result = SECHK_SPUR_AU_DA_FULL;
							else
								item->test_result = SECHK_SPUR_AU_DA_PART;
						} else {
							if (retv == num_perms)
								item->test_result |= SECHK_SPUR_AU_DA_FULL;
							else
								item->test_result |= SECHK_SPUR_AU_DA_PART;
						}
						for (hash_rule = node->rules; hash_rule; hash_rule = hash_rule->next) {
							proof = NULL;
							tmp = NULL;
							if (does_av_rule_use_perms(hash_rule->rule, 1, perms, num_perms, policy)) {
								if (sechk_item_has_proof(hash_rule->rule, POL_LIST_AV_ACC, item))
									continue;
								proof = sechk_proof_new();
								if (!proof) {
									fprintf(stderr, "Error: out of memory\n");
									goto spurious_audit_run_fail;
								}
								proof->idx = hash_rule->rule;
								proof->type = POL_LIST_AV_ACC;
								if (retv == num_perms)
									proof->severity = SECHK_SEV_MOD;
								else
									proof->severity = SECHK_SEV_LOW;
								tmp = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 0, policy);
								proof->text = (char*)calloc(15+strlen(tmp), sizeof(char));
								if (!proof->text) {
									fprintf(stderr, "Error: out of memory\n");
									goto spurious_audit_run_fail;
								}
								strcat(proof->text, "conflicting: ");
								strcat(proof->text, tmp);
								free(tmp);
								proof->next = item->proof;
								item->proof = proof;
							}
						}
					}
				}
			}
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

spurious_audit_run_fail:
	free(tmp);
	free(key);
	free(used_perms);
	free(src_types);
	free(tgt_types);
	free(obj_classes);
	free(perms);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void spurious_audit_free(sechk_module_t *mod)
{
	spurious_audit_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (spurious_audit_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int spurious_audit_print_output(sechk_module_t *mod, policy_t *policy) 
{
	spurious_audit_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (spurious_audit_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result && (outformat & ~(SECHK_OUT_BRF_DESCP)) && (outformat & ~(SECHK_OUT_DET_DESCP))) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat)
		return 0; /* not an error - no output is requested */

	printf("\nModule: %s\n", mod_name);
	/* print the header */
	/* print the brief description */
	if (outformat & SECHK_OUT_BRF_DESCP) {
		printf("%s\n\n", mod->brief_description);
	}
	/* print the detailed description */
	if (outformat & SECHK_OUT_DET_DESCP) {
		printf("%s\n\n", mod->detailed_description);
	}
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i rules.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 1, policy)); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * items are printed on a line followed by the severity.
	 * Each proof element is then displayed in an indented list
	 * one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 1, policy));/* TODO: item name */
			printf(" - severity: %i\n", sechk_item_sev(item));
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
sechk_result_t *spurious_audit_get_result(sechk_module_t *mod) 
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

/* The spurious_audit_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
spurious_audit_data_t *spurious_audit_data_new(void)
{
	spurious_audit_data_t *datum = NULL;

	datum = (spurious_audit_data_t*)calloc(1,sizeof(spurious_audit_data_t));

	return datum;
}

 
