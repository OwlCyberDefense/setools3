/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "inc_dom_trans.h"
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
static const char *const mod_name = "inc_dom_trans";

/* The register function registers all of a module's functions
 * with the library. */
int inc_dom_trans_register(sechk_lib_t *lib)
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
	mod->brief_description = "domains with partial transition permissions";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds potential domain transitions missing key permissions.  A valid\n"
"domain transition requires the following.\n"
"\n"
"   1) the starting domain can transition to the end domain for class process\n"
"   2) the end domain has some type as an entrypoint\n"
"   3) the starting domain can execute that extrypoint type\n"
"   4) (optional) a type transition rules specifying these three types\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";

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
	fn_struct->fn = &inc_dom_trans_init;
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
	fn_struct->fn = &inc_dom_trans_run;
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
	fn_struct->fn = &inc_dom_trans_free;
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
	fn_struct->fn = &inc_dom_trans_print_output;
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
	fn_struct->fn = &inc_dom_trans_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int inc_dom_trans_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	inc_dom_trans_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = inc_dom_trans_data_new();
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

typedef struct trans_pair {
	int ep; /* entrypoint type */
	int tt; /* transition type */
} trans_pair_t;

static int add_trans_pair_to_a(trans_pair_t tp, int *sz, trans_pair_t **a)
{
	if (!sz || !a)
		return -1;

	*a = (trans_pair_t*)realloc(*a, sizeof(trans_pair_t) * (*sz + 1));
	if (!(*a))
		return -1;

	(*a)[*sz] = tp;
	(*sz)++;

	return 0;	
};

static sechk_proof_t *inc_dom_trans_generate_proof(int src, int exec, int trx, unsigned char flags, policy_t *policy)
{
	sechk_proof_t *proof = NULL;
	char buff[BUF_SZ];
	char *text = NULL;
	int text_len = 0;

	/* check for input error conditions and report from here */
	if (!policy) {
		fprintf(stderr, "invalid policy\n");
		return NULL;
	}
	if (flags & ~(SECHK_INC_DOM_TRANS_COMPLETE|SECHK_INC_DOM_TRANS_HAS_TT)) {
		fprintf(stderr, "invalid flag combination %x\n", flags);
		return NULL;
	}
	if (src < 1 || src > policy->num_types) {
		fprintf(stderr, "invalid source type %d\n", src);
		return NULL;
	}
	if (trx > policy->num_types) {
		fprintf(stderr, "invalid transition type %d\n", trx);
		return NULL;
	}
	if (exec > policy->num_types) {
		fprintf(stderr, "invalid executable type %d\n", exec);
		return NULL;
	}
	if (exec < 1 && (flags & SECHK_INC_DOM_TRANS_CAN_EXEC)) {
		fprintf(stderr, "missing or invalid executable type %d\n", exec);
		return NULL;
	}
	if (trx < 1 && (flags & (SECHK_INC_DOM_TRANS_CAN_TRANS|SECHK_INC_DOM_TRANS_IS_EP))) {
		fprintf(stderr, "missing or invalid transition type %d\n", trx);
		return NULL;
	}
	/* end input error checking */

	proof = sechk_proof_new();
	if (!proof) {
		fprintf(stderr, "out of memory\n");
		return NULL;
	}

	proof->idx = (int) flags;
	proof->type = 0xFF;
	proof->severity = SECHK_SEV_MOD;

	if (flags & SECHK_INC_DOM_TRANS_HAS_TT) {
		snprintf(buff, sizeof(buff)-1, "%s", policy->types[src].name);
		append_str(&text, &text_len, buff);
		append_str(&text, &text_len, " has a type_transition rule\n");
		snprintf(buff, sizeof(buff)-1, "type_transition %s %s : process %s;\n", 
			policy->types[src].name, policy->types[exec].name, policy->types[trx].name);
		append_str(&text, &text_len, buff);
	}
	if (flags & SECHK_INC_DOM_TRANS_CAN_TRANS) {
		snprintf(buff, sizeof(buff)-1, "%s is permitted to transition to %s\n",
			policy->types[src].name, policy->types[trx].name);
		append_str(&text, &text_len, buff);
	}
	if (flags & SECHK_INC_DOM_TRANS_CAN_EXEC) {
		snprintf(buff, sizeof(buff)-1, "%s is permitted to execute %s\n",
			policy->types[src].name, policy->types[exec].name);
		append_str(&text, &text_len, buff);
	}
	if (!(flags & SECHK_INC_DOM_TRANS_IS_EP)) {
		if (exec != -1 && trx != -1) {
			snprintf(buff, sizeof(buff)-1, "%s is not an entrypoint for %s\n", 
				policy->types[exec].name, policy->types[trx].name);
			append_str(&text, &text_len, buff);
		} else if (exec == -1) {
			snprintf(buff, sizeof(buff)-1, "there is no entrypoint for %s\n", 
				policy->types[trx].name);
			append_str(&text, &text_len, buff);
		} else if (trx == -1) {
			snprintf(buff, sizeof(buff)-1, "%s is not an entrypoint type\n", 
				policy->types[exec].name);
			append_str(&text, &text_len, buff);
		}
	}
	if ((flags & SECHK_INC_DOM_TRANS_CAN_TRANS) && (flags & SECHK_INC_DOM_TRANS_IS_EP)) {
		snprintf(buff, sizeof(buff)-1, "%s is not permitted to execute any entrypoint for %s\n",
			policy->types[src].name, policy->types[trx].name);
		append_str(&text, &text_len, buff);
	}
	if (exec != -1 && !(flags & SECHK_INC_DOM_TRANS_CAN_EXEC)) {
		snprintf(buff, sizeof(buff)-1, "%s is not permitted to execute %s\n",
			policy->types[src].name, policy->types[exec].name);
		append_str(&text, &text_len, buff);
	}
	if (trx != -1 && !(flags & SECHK_INC_DOM_TRANS_CAN_TRANS)) {
		snprintf(buff, sizeof(buff)-1, "%s is not permitted to transition to %s\n",
			policy->types[src].name, policy->types[trx].name);
		append_str(&text, &text_len, buff);
	}

	proof->text = text;

	return proof;
};

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int inc_dom_trans_run(sechk_module_t *mod, policy_t *policy)
{
	inc_dom_trans_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	avh_idx_t *hash_idx = NULL, *hash_idx2 = NULL;
	avh_node_t *hash_node = NULL;
	int i, j, k, l, idx, retv;
	int process_obj_class_idx = -1;
	int file_obj_class_idx = -1;
	int execute_perm_idx = -1;
	int execute_no_trans_perm_idx = -1;
	int entrypoint_perm_idx = -1;
	int transition_perm_idx = -1;
	int num_nodes;
	int *execnotrans_list = NULL, execnotrans_list_sz = 0;
	int *execwtrans_list = NULL, execwtrans_list_sz = 0;
	int *proctrans_list = NULL, proctrans_list_sz = 0;
	trans_pair_t *transpair_list = NULL, tmp = {-1,-1};
	int transpair_list_sz = 0;
	avh_key_t key = {-1, -1, -1, RULE_INVALID};
	bool_t found_ep = FALSE, used = FALSE;
	unsigned char report_flag = 0x00;

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

	datum = (inc_dom_trans_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto inc_dom_trans_run_fail;
	}
	res->item_type = POL_LIST_TYPE;

	if (!avh_hash_table_present(policy->avh)) {
		retv = avh_build_hashtab(policy);
		if (retv) {
			fprintf(stderr, "Error: could not build hash table\n");
			goto inc_dom_trans_run_fail;
		}
	}

	process_obj_class_idx = get_obj_class_idx("process", policy);
	if (process_obj_class_idx == -1) 
		goto inc_dom_trans_run_fail;
	execute_perm_idx = get_perm_idx("execute", policy);
	if (execute_perm_idx == -1) 
		goto inc_dom_trans_run_fail;
	execute_no_trans_perm_idx = get_perm_idx("execute_no_trans", policy);
	if (execute_no_trans_perm_idx == -1) 
		goto inc_dom_trans_run_fail;
	entrypoint_perm_idx = get_perm_idx("entrypoint", policy);
	if (entrypoint_perm_idx == -1) 
		goto inc_dom_trans_run_fail;
	transition_perm_idx = get_perm_idx("transition", policy);
	if (transition_perm_idx == -1) 
		goto inc_dom_trans_run_fail;
	file_obj_class_idx = get_obj_class_idx("file", policy);
	if (file_obj_class_idx == -1)	
		goto inc_dom_trans_run_fail;

	/* skip self (type 0) */
	for (i = policy->num_types - 1; i; i--) {
		/* free lists */
		free(proctrans_list);
		proctrans_list = NULL;
		proctrans_list_sz = 0;
		free(execnotrans_list);
		execnotrans_list = NULL;
		execnotrans_list_sz = 0;
		free(execwtrans_list);
		execwtrans_list = NULL;
		execwtrans_list_sz = 0;
		free(transpair_list);
		transpair_list = NULL;
		transpair_list_sz = 0;

		report_flag = 0x00;

		/* get hash index */
		hash_idx = avh_src_type_idx_find(&(policy->avh), i);
		if (!hash_idx)
			num_nodes = 0;
		else 
			num_nodes = hash_idx->num_nodes;
		for (j = 0; j < num_nodes; j++) {
		
			/* find permitted transitions */
			if (hash_idx->nodes[j]->key.cls == process_obj_class_idx && 
				hash_idx->nodes[j]->key.rule_type == RULE_TE_ALLOW &&
				find_int_in_array(transition_perm_idx, hash_idx->nodes[j]->data, hash_idx->nodes[j]->num_data) != -1) {
				if (find_int_in_array(hash_idx->nodes[j]->key.tgt, proctrans_list, proctrans_list_sz) == -1) {
					retv = add_i_to_a(hash_idx->nodes[j]->key.tgt, &proctrans_list_sz, &proctrans_list);
					if (retv) {
						fprintf(stderr, "out of memory\n");
						goto inc_dom_trans_run_fail;
					}
				}
			} /* end collect transition end points */

			/* find types permitted to execute */
			if (hash_idx->nodes[j]->key.cls == file_obj_class_idx &&
				hash_idx->nodes[j]->key.rule_type == RULE_TE_ALLOW &&
				find_int_in_array(execute_perm_idx, hash_idx->nodes[j]->data, hash_idx->nodes[j]->num_data) != -1) {
				if (find_int_in_array(execute_no_trans_perm_idx, hash_idx->nodes[j]->data, hash_idx->nodes[j]->num_data) != -1) {
					if (find_int_in_array(hash_idx->nodes[j]->key.tgt, execnotrans_list, execnotrans_list_sz) == -1) {
						retv = add_i_to_a(hash_idx->nodes[j]->key.tgt, &execnotrans_list_sz, &execnotrans_list);
						if (retv) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
					}
				} else {
					if (find_int_in_array(hash_idx->nodes[j]->key.tgt, execwtrans_list, execwtrans_list_sz) == -1) {
						retv = add_i_to_a(hash_idx->nodes[j]->key.tgt, &execwtrans_list_sz, &execwtrans_list);
						if (retv) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
					}
				}
			} /* end collect executable types */

			/* find any type_transition rules */
			if (hash_idx->nodes[j]->key.cls == process_obj_class_idx && 
				hash_idx->nodes[j]->key.rule_type == RULE_TE_TRANS) {
					tmp.ep = hash_idx->nodes[j]->key.tgt;
					tmp.tt = hash_idx->nodes[j]->data[0];
					retv = add_trans_pair_to_a(tmp, &transpair_list_sz, &transpair_list);
					if (retv) {
						fprintf(stderr, "out of memory\n");
						goto inc_dom_trans_run_fail;
					}
			} /* end collect type_transitions */

			/* confirm type_transitions */
			for (k = 0; k > transpair_list_sz; k++) {
				report_flag = SECHK_INC_DOM_TRANS_HAS_TT;
				/* for pair {A,B} */
				/* find allow B A : file entrypoint */
				key.src = transpair_list[k].tt;
				key.tgt = transpair_list[k].ep;
				key.cls = file_obj_class_idx;
				key.rule_type = RULE_TE_ALLOW;
				hash_node = avh_find_first_node(&(policy->avh), &key);
				if (hash_node && find_int_in_array(entrypoint_perm_idx, hash_node->data, hash_node->num_data) != -1) {
					report_flag |= SECHK_INC_DOM_TRANS_IS_EP;
				}

				/* confirm process transition to B*/
				idx = find_int_in_array(transpair_list[k].tt, proctrans_list, proctrans_list_sz);
				if (idx != -1) {
					/* mark used */
					proctrans_list[idx] = -1;
					report_flag |= SECHK_INC_DOM_TRANS_CAN_TRANS;
				} 

				/* confirm execute permission for A */
				idx = find_int_in_array(transpair_list[k].ep, execnotrans_list, execnotrans_list_sz);
				if (idx != 1) {
					/* mark used */
					execnotrans_list[idx] = -1;
					report_flag |= SECHK_INC_DOM_TRANS_CAN_EXEC;
				} else {
					idx = find_int_in_array(transpair_list[k].ep, execwtrans_list, execwtrans_list_sz);
					if (idx != -1) {
						/* mark used */
						execwtrans_list[idx] = -1;
						report_flag |= SECHK_INC_DOM_TRANS_CAN_EXEC;
					}
				}

				if (report_flag != (SECHK_INC_DOM_TRANS_COMPLETE|SECHK_INC_DOM_TRANS_HAS_TT)) {
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, transpair_list[k].ep, transpair_list[k].tt, report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
			} /* end confirm type_transitions */
			report_flag = 0x00;

			/* confirm permitted transition end points */
			for (k = 0; k < proctrans_list_sz; k++) {
				if (proctrans_list[k] == -1)
					continue; /* already used */
				used = found_ep = FALSE;
				report_flag = SECHK_INC_DOM_TRANS_CAN_TRANS;
				hash_idx2 = avh_src_type_idx_find(&(policy->avh), proctrans_list[k]);
				if (!hash_idx2) {
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, -1, proctrans_list[k], report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
					continue;
				}
				for (l = 0; l < hash_idx2->num_nodes; l++) {
					if (hash_idx2->nodes[l]->key.rule_type != RULE_TE_ALLOW ||
						hash_idx2->nodes[l]->key.cls != file_obj_class_idx ||
						find_int_in_array(entrypoint_perm_idx, hash_idx2->nodes[l]->data, hash_idx2->nodes[l]->num_data) == -1)
						continue;
					found_ep = TRUE;
					idx = find_int_in_array(hash_idx2->nodes[l]->key.tgt, execnotrans_list, execnotrans_list_sz);
					if (idx != -1) {
						/* mark used */
						execnotrans_list[idx] = -1;
						used = TRUE;
					} else {
						idx = find_int_in_array(hash_idx2->nodes[l]->key.tgt, execwtrans_list, execwtrans_list_sz);
						if (idx != -1) {
							/* mark used */
							execwtrans_list[idx] = -1;
							used = TRUE;
						} 
					}
				}

				if (!found_ep) {
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, -1, proctrans_list[k], report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				} else if (!used) {
					report_flag |= SECHK_INC_DOM_TRANS_IS_EP;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, -1, proctrans_list[k], report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
			} /* end confirm transition end points */
			report_flag = 0x00;

			/* check remaining executable types */
			for (k = 0; k < execwtrans_list_sz; k++) {
				found_ep = FALSE;
				report_flag = SECHK_INC_DOM_TRANS_CAN_EXEC;
				if (execwtrans_list[k] == -1)
					continue; /* already used */
				hash_idx2 = avh_tgt_type_idx_find(&(policy->avh), execwtrans_list[k]);
				if (!hash_idx2) {
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, execwtrans_list[k], -1, report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
					continue;
				}
				for (l = 0; l < hash_idx2->num_nodes; l++) {
					if (hash_idx2->nodes[l]->key.rule_type != RULE_TE_ALLOW ||
						hash_idx2->nodes[l]->key.cls != file_obj_class_idx ||
						find_int_in_array(entrypoint_perm_idx, hash_idx2->nodes[l]->data, hash_idx2->nodes[l]->num_data) == -1)
						continue;
					found_ep = TRUE;
					report_flag = SECHK_INC_DOM_TRANS_IS_EP;
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, execwtrans_list[k], hash_idx2->nodes[l]->key.src, report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
				if (!found_ep) {
					if (!item) {
						item = sechk_item_new();
						if (!item) {
							fprintf(stderr, "out of memory\n");
							goto inc_dom_trans_run_fail;
						}
						item->item_id = i;
					}
					proof = inc_dom_trans_generate_proof(i, execwtrans_list[k], -1, report_flag, policy);
					if (!proof)
						goto inc_dom_trans_run_fail;
					item->test_result++;
					proof->next = item->proof;
					item->proof = proof;
				}
			} /* end remaining executable types */

		} /* end for nodes with type i as source */

		if (item) {
			item->next = res->items;
			res->items = item;
			res->num_items++;
			item = NULL;
		}
	}/* end foreach type */

	mod->result = res;

	free(transpair_list);
	free(proctrans_list);
	free(execnotrans_list);
	free(execwtrans_list);

	/* If module finds something that would be considered a fail
	 * on the policy return 1 here */
	if (res->num_items > 0)
		return 1;

	return 0;

inc_dom_trans_run_fail:
	free(transpair_list);
	free(proctrans_list);
	free(execnotrans_list);
	free(execwtrans_list);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void inc_dom_trans_free(sechk_module_t *mod)
{
	inc_dom_trans_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (inc_dom_trans_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int inc_dom_trans_print_output(sechk_module_t *mod, policy_t *policy) 
{
	inc_dom_trans_data_t *datum = NULL;
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

	datum = (inc_dom_trans_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i start types.\n", mod->result->num_items);
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s\t-\t%d incomplete transitions\n", policy->types[item->item_id].name, item->test_result); 
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation) */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			printf("%s", policy->types[item->item_id].name);
			printf(" - severity: %s\n", sechk_item_sev(item));
			for (proof = item->proof; proof; proof = proof->next) {
				printf("%s\n", proof->text);
			}
		}
		printf("\n");
	}

	return 0;
}

/* The get_result function returns a pointer to the results
 * structure for this check to be used in another check. */
sechk_result_t *inc_dom_trans_get_result(sechk_module_t *mod) 
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

/* The inc_dom_trans_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module.  */
inc_dom_trans_data_t *inc_dom_trans_data_new(void)
{
	inc_dom_trans_data_t *datum = NULL;

	datum = (inc_dom_trans_data_t*)calloc(1,sizeof(inc_dom_trans_data_t));

	return datum;
}

