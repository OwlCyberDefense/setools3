/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "inc_mount.h"
#include "semantic/avhash.h"
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
static const char *const mod_name = "inc_mount";

/* The register function registers all of a module's functions
 * with the library.  */
int inc_mount_register(sechk_lib_t *lib)
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
	mod->brief_description = "domains with partial mount permissions";
	mod->detailed_description = "finds domains that have only one of mount for filesystem" 
"\nand mounton for dir. Both are needed for a successful mount operation."
"\nThis module lists all rules found containing one of these"
"\npermissions for each domain found."
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
	fn_struct->fn = &inc_mount_init;
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
	fn_struct->fn = &inc_mount_run;
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
	fn_struct->fn = &inc_mount_free;
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
	fn_struct->fn = &inc_mount_print_output;
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
	fn_struct->fn = &inc_mount_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_mount_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	inc_mount_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = inc_mount_data_new();
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
 
int inc_mount_run(sechk_module_t *mod, policy_t *policy)
{
	inc_mount_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	int i, j, k, retv, tmp_sz = 0, *tmp = NULL;
	avh_idx_t *hash_idx = NULL;
	int num_nodes = 0;
	avh_rule_t *hash_rule = NULL;
	char *buff = NULL;
	int mount_perm_idx = -1, mounton_perm_idx = -1;
	int dir_obj_class_idx = -1, filesystem_obj_class_idx = -1;
	bool_t can_mount = FALSE, can_mounton = FALSE;
	int *mount_rules = NULL, *mounton_rules = NULL;
	int num_mount_rules = 0, num_mounton_rules = 0;

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

	datum = (inc_mount_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto inc_mount_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto inc_mount_run_fail;
		}
	}

	mount_perm_idx = get_perm_idx("mount", policy);
	mounton_perm_idx = get_perm_idx("mounton", policy);
	dir_obj_class_idx = get_obj_class_idx("dir", policy);
	filesystem_obj_class_idx = get_obj_class_idx("filesystem", policy);

	/* skip self (type 0) */
	for(i = policy->num_types - 1; i; i--) {
		item = NULL;
		free(mount_rules);
		mount_rules = NULL;
		free(mounton_rules);
		mounton_rules = NULL;
		num_mount_rules = num_mounton_rules = 0;

		/* look for mount and mount on perms */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;

		can_mount = can_mounton = FALSE;
		for (j = 0; j < num_nodes; j++) {
			proof = NULL;
			if (hash_idx->nodes[j]->key.rule_type != RULE_TE_ALLOW)
				continue;
			if (hash_idx->nodes[j]->key.cls == filesystem_obj_class_idx && find_int_in_array(mount_perm_idx, hash_idx->nodes[j]->data, hash_idx->nodes[j]->num_data) != -1) {
				can_mount = TRUE;
				for(hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
					if (does_av_rule_use_perms(hash_rule->rule, 1, &mount_perm_idx, 1, policy)) {
						if (find_int_in_array(hash_rule->rule, mount_rules, num_mount_rules) == -1) {
							retv = add_i_to_a(hash_rule->rule, &num_mount_rules, &mount_rules);
							if (retv) {
								fprintf(stderr, "Error: out of memory\n");
								goto inc_mount_run_fail;
							}
						}
					}
				}
			}
			if (find_int_in_array(mounton_perm_idx, hash_idx->nodes[j]->data, hash_idx->nodes[j]->num_data) != -1) {
				can_mounton = TRUE;
				if (hash_idx->nodes[j]->key.cls == dir_obj_class_idx) {
					for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
						if (does_av_rule_use_classes(hash_rule->rule, 1, &dir_obj_class_idx, 1, policy) && does_av_rule_use_perms(hash_rule->rule, 1, &mounton_perm_idx, 1, policy)) {
							if (find_int_in_array(hash_rule->rule, mounton_rules, num_mounton_rules) == -1) {
								retv = add_i_to_a(hash_rule->rule, &num_mounton_rules, &mounton_rules);
								if (retv) {
									fprintf(stderr, "Error: out of memory\n");
									goto inc_mount_run_fail;
								}
							}
						}
					}
				} else {
					for (hash_rule = hash_idx->nodes[j]->rules; hash_rule; hash_rule = hash_rule->next) {
						if (does_av_rule_use_classes(hash_rule->rule, 1, &dir_obj_class_idx, 1, policy) || !does_av_rule_use_perms(hash_rule->rule, 1, &mounton_perm_idx, 1, policy))
							continue;
						if (!item) {
							item = sechk_item_new();
							if (!item) {
								fprintf(stderr, "Error: out of memory\n");
								goto inc_mount_run_fail;
							}
							item->item_id = i;
						}
						item->test_result |= SECHK_MOUNT_INV_MOUNTON;
						if (!sechk_item_has_proof(hash_rule->rule, POL_LIST_AV_ACC, item)) {
							proof = sechk_proof_new();
							if (!proof) {
								fprintf(stderr, "Error: out of memory\n");
								goto inc_mount_run_fail;
							}
							proof->idx = hash_rule->rule;
							proof->type = POL_LIST_AV_ACC;
							proof->text = re_render_av_rule(!is_binary_policy(policy), hash_rule->rule, 0, policy);
							if (!proof->text) {
								fprintf(stderr, "Error: out of memory\n");
								goto inc_mount_run_fail;
							}
							proof->severity = SECHK_SEV_LOW;
							proof->next = item->proof;
							item->proof = proof;
						}
					}
				}
			}
		}
		if (can_mount != can_mounton) {
			if (!item) {
				item = sechk_item_new();
				if (!item) {
					fprintf(stderr, "Error: out of memory\n");
					goto inc_mount_run_fail;
				}
				item->item_id = i;
			}
			if (can_mount) {
				item->test_result |= SECHK_MOUNT_ONLY_MOUNT;
				buff = strdup("This type has mount permission but cannot mounton any directory");
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto inc_mount_run_fail;
				}
				tmp = mount_rules;
				tmp_sz = num_mount_rules;
			} else if (can_mounton) {
				item->test_result |= SECHK_MOUNT_ONLY_MOUNTON;
				buff = strdup("This type has mounton permission but cannot mount any filesystem");
				if (!buff) {
					fprintf(stderr, "Error: out of memory\n");
					goto inc_mount_run_fail;
				}
				tmp = mounton_rules;
				tmp_sz = num_mounton_rules;
			}
			for (k = 0; k < tmp_sz; k++) {
				proof = sechk_proof_new();
				if (!proof) {
					fprintf(stderr, "Error: out of memory\n");
					goto inc_mount_run_fail;
				}
				proof->idx = tmp[k];
				proof->type = POL_LIST_AV_ACC;
				proof->text = re_render_av_rule(!is_binary_policy(policy),tmp[k], 0, policy);
				if (!proof->text) {
					fprintf(stderr, "Error: out of memory\n");
					goto inc_mount_run_fail;
				}
				proof->severity = SECHK_SEV_LOW;
				proof->next = item->proof;
				item->proof = proof;
			}
			proof = sechk_proof_new();
			if (!proof) {
				fprintf(stderr, "Error: out of memory\n");
				goto inc_mount_run_fail;
			}
			proof->idx = -1;
			proof->type = -1;
			proof->text = buff;
			proof->next = item->proof;
			item->proof = proof;
			
		}
		if (item) {
			if (item->test_result == SECHK_MOUNT_INV_MOUNTON) {
				sechk_item_free(item);
				item = NULL;
				continue;
			}
			item->next = res->items;
			res->items = item;
			(res->num_items)++;
			item = NULL;
		}
	}
	mod->result = res;

	if (res->num_items > 0)
		return 1;

	return 0;

inc_mount_run_fail:
	free(buff);
	free(mount_rules);
	free(mounton_rules);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void inc_mount_free(sechk_module_t *mod)
{
	inc_mount_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (inc_mount_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_mount_print_output(sechk_module_t *mod, policy_t *policy) 
{
	inc_mount_data_t *datum = NULL;
	unsigned char outformat = 0x00;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;

	if (!mod || (!policy && (mod->outputformat & ~(SECHK_OUT_BRF_DESCP) &&
				 (mod->outputformat & ~(SECHK_OUT_DET_DESCP))))) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = (inc_mount_data_t*)mod->data;
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
	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i types.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s - ", policy->types[item->item_id].name);
			if (item->test_result & SECHK_MOUNT_ONLY_MOUNT)
				printf("has mount but not mounton");
			else if (item->test_result & SECHK_MOUNT_ONLY_MOUNTON)
				printf("has mounton but not mount");
			else
				printf("ERROR");
			if (item->test_result & SECHK_MOUNT_INV_MOUNTON)
				printf(" and invalid mounton rules\n");
			else
				printf("\n");
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with the severity. 
	 * Each proof element is then displayed in an indented list one per 
	 * line below it. */
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
sechk_result_t *inc_mount_get_result(sechk_module_t *mod) 
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

/* The inc_mount_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
inc_mount_data_t *inc_mount_data_new(void)
{
	inc_mount_data_t *datum = NULL;

	datum = (inc_mount_data_t*)calloc(1,sizeof(inc_mount_data_t));

	return datum;
}

 
