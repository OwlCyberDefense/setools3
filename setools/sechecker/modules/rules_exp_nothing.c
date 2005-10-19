/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "rules_exp_nothing.h"
#include "render.h"

#include <stdio.h>
#include <string.h>

/* This is the pointer to the library which contains the module;
 * it is used to access needed parts of the library policy, fc entries, etc.*/
static sechk_lib_t *library;

/* This string is the name of the module and should match the stem
 * of the file name; it should also match the prefix of all functions
 * defined in this module and the private data storage structure */
static const char *const mod_name = "rules_exp_nothing";

/* The register function registers all of a module's functions
 * with the library. */
int rules_exp_nothing_register(sechk_lib_t *lib)
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
	mod->brief_description = "rules that disappear during expansion";
	mod->detailed_description = 
"--------------------------------------------------------------------------------\n"
"This module finds rules that disappear during expansion.  This can occur if a   \n"
"rule uses an attribute with no types, or if all types are subtracted from a set.\n";
	mod->opt_description = 
"Module requirements:\n"
"   none\n"
"Module dependencies:\n"
"   none\n"
"Module options:\n"
"   none\n";
	mod->severity = SECHK_SEV_MED;
	/* assign requirements */
	mod->requirements = sechk_name_value_new("policy_type", "source");

	/* assign dependencies */
	mod->dependencies = sechk_name_value_new("module", "attribs_wo_types");

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
	fn_struct->fn = &rules_exp_nothing_init;
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
	fn_struct->fn = &rules_exp_nothing_run;
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
	fn_struct->fn = &rules_exp_nothing_free;
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
	fn_struct->fn = &rules_exp_nothing_print_output;
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
	fn_struct->fn = &rules_exp_nothing_get_result;
	fn_struct->next = mod->functions;
	mod->functions = fn_struct;

	return 0;
}

/* The init function creates the module's private data storage object
 * and initializes its values based on the options parsed in the config
 * file. */
int rules_exp_nothing_init(sechk_module_t *mod, policy_t *policy)
{
	sechk_name_value_t *opt = NULL;
	rules_exp_nothing_data_t *datum = NULL;

	if (!mod || !policy) {
		fprintf(stderr, "Error: invalid parameters\n");
		return -1;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return -1;
	}

	datum = rules_exp_nothing_data_new();
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

/* function for finding attributes in type lists containing only attribs 
 * returns false for * ~ or if any single type is specified otherwise
 * fills the array with the indices of the attributes */
static bool_t rules_exp_nothing_process_list_attribs(ta_item_t *list, unsigned char flags, bool_t is_src, int **array, int *size)
{
	ta_item_t *item = NULL;
	int retv;

	if ((is_src && (flags & (AVFLAG_SRC_TILDA | AVFLAG_SRC_STAR))) || (!is_src && (flags & (AVFLAG_TGT_TILDA | AVFLAG_TGT_STAR))))
		return FALSE; 

	*array = NULL;
	*size = 0;

	for (item = list; item; item = item->next) {
		if (item->type == IDX_ATTRIB) {
			retv = add_i_to_a(item->idx, size, array);
			if (retv)
				return FALSE;
		} else {
			return FALSE;
		}
	}

	return TRUE;
}

/* tests if array subset of size ssz is a subset of master of size msz */
static bool_t is_subset(int *master, int msz, int *subset, int ssz)
{
	int i;

	if (!master || !msz || !subset || !ssz)
		return FALSE;

	if (ssz > msz)
		return FALSE;

	for (i = 0; i < ssz; i++) {
		if (find_int_in_array(subset[i], master, msz) == -1)
			return FALSE;
	}

	return TRUE;
}

/* The run function performs the check. This function runs only once
 * even if called multiple times. */
int rules_exp_nothing_run(sechk_module_t *mod, policy_t *policy)
{
	rules_exp_nothing_data_t *datum;
	sechk_result_t *res = NULL;
	sechk_item_t *item = NULL;
	sechk_proof_t *proof = NULL;
	sechk_run_fn_t run_fn = NULL;
	int (*get_list_fn)(sechk_module_t *mod, int **array, int *size);
	int *attrib_list = NULL, attrib_list_sz = 0, retv;
	int *src_list_attribs = NULL, src_list_attribs_sz = 0; 
	int *tgt_list_attribs = NULL, tgt_list_attribs_sz = 0; 
	sechk_module_t *mod_ptr = NULL;
	int i, j;
	char buff[BUF_SZ];  

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

	datum = (rules_exp_nothing_data_t*)mod->data;
	res = sechk_result_new();
	if (!res) {
		fprintf(stderr, "Error: out of memory\n");
		return -1;
	}
	res->test_name = strdup(mod_name);
	if (!res->test_name) {
		fprintf(stderr, "Error: out of memory\n");
		goto rules_exp_nothing_run_fail;
	}
	res->item_type = SECHK_TYPE_NONE; /* can be multiple types, ignored */

	run_fn = sechk_lib_get_module_function("attribs_wo_types", SECHK_MOD_FN_RUN, library);
	if (!run_fn)
		goto rules_exp_nothing_run_fail;
	get_list_fn = sechk_lib_get_module_function("attribs_wo_types", "get_list", library);
	if (!get_list_fn)
		goto rules_exp_nothing_run_fail;	

	retv = run_fn((mod_ptr = sechk_lib_get_module("attribs_wo_types", library)), policy);
	if (retv < 0) {
		fprintf(stderr, "Error: depenency failed\n");
		goto rules_exp_nothing_run_fail;
	}
	retv = get_list_fn(mod_ptr, &attrib_list, &attrib_list_sz);
	if (retv) {
		fprintf(stderr, "Error: unable to get list\n");
		goto rules_exp_nothing_run_fail;
	}

	/* access rules */
	for (j = 0; j < policy->num_av_access; j++) {
		/* source type field */
		if (rules_exp_nothing_process_list_attribs(policy->av_access[j].src_types, policy->av_access[j].flags, 1, &src_list_attribs, &src_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, src_list_attribs, src_list_attribs_sz)) {
				item = sechk_item_new();
				if (!item)
					goto rules_exp_nothing_run_fail;
				item->item_id = j;
				item->test_result = POL_LIST_AV_ACC;
				for (i = 0; i < src_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = src_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in source", policy->attribs[src_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(src_list_attribs);
			src_list_attribs = NULL;
			src_list_attribs_sz = 0;
		}

		/* target type field */
		if (rules_exp_nothing_process_list_attribs(policy->av_access[j].tgt_types, policy->av_access[j].flags, 0, &tgt_list_attribs, &tgt_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, tgt_list_attribs, tgt_list_attribs_sz)) {
				if (!item) {
					item = sechk_item_new();
					if (!item)
						goto rules_exp_nothing_run_fail;
					item->item_id = j;
					item->test_result = POL_LIST_AV_ACC;
				}
				for (i = 0; i < tgt_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = tgt_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in target", policy->attribs[tgt_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(tgt_list_attribs);
			tgt_list_attribs = NULL;
			tgt_list_attribs_sz = 0;
		}

		if (item) {
			proof = sechk_proof_new();
			if (!proof)
				goto rules_exp_nothing_run_fail;
			proof->idx = -1;
			proof->type = SECHK_TYPE_NONE;
			snprintf(buff, sizeof(buff)-1, "rule uses %d attribute%swhich expand%sto no types", 
				src_list_attribs_sz + tgt_list_attribs_sz, 
				/* handle English plurality */
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?"s ":" "), 
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?" ":"s "));
			proof->text = strdup(buff);
			if (!proof->text)
				goto rules_exp_nothing_run_fail;
			proof->next = item->proof;
			item->proof = proof;
			proof = NULL;
			item->next = res->items;
			res->items = item;
			res->num_items++;
			if (policy->av_access[j].type == RULE_TE_ALLOW)
				datum->num_allow++;
			else
				datum->num_neverallow++;
			item = NULL;
		}

		/* free lists now */
		free(src_list_attribs);
		src_list_attribs = NULL;
		src_list_attribs_sz = 0;
		free(tgt_list_attribs);
		tgt_list_attribs = NULL;
		tgt_list_attribs_sz = 0;
	}

	/* audit rules */
	for (j = 0; j < policy->num_av_audit; j++) {
		/* source type field */
		if (rules_exp_nothing_process_list_attribs(policy->av_audit[j].src_types, policy->av_access[j].flags, 1, &src_list_attribs, &src_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, src_list_attribs, src_list_attribs_sz)) {
				item = sechk_item_new();
				if (!item)
					goto rules_exp_nothing_run_fail;
				item->item_id = j;
				item->test_result = POL_LIST_AV_AU;
				for (i = 0; i < src_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = src_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in source", policy->attribs[src_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(src_list_attribs);
			src_list_attribs = NULL;
			src_list_attribs_sz = 0;
		}

		/* target type field */
		if (rules_exp_nothing_process_list_attribs(policy->av_audit[j].tgt_types, policy->av_access[j].flags, 0, &tgt_list_attribs, &tgt_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, tgt_list_attribs, tgt_list_attribs_sz)) {
				if (!item) {
					item = sechk_item_new();
					if (!item)
						goto rules_exp_nothing_run_fail;
					item->item_id = j;
					item->test_result = POL_LIST_AV_AU;
				}
				for (i = 0; i < tgt_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = tgt_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in target", policy->attribs[tgt_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(tgt_list_attribs);
			tgt_list_attribs = NULL;
			tgt_list_attribs_sz = 0;
		}

		if (item) {
			proof = sechk_proof_new();
			if (!proof)
				goto rules_exp_nothing_run_fail;
			proof->idx = -1;
			proof->type = SECHK_TYPE_NONE;
			snprintf(buff, sizeof(buff)-1, "rule uses attribute %d attribute%swhich expand%sto no types", 
				src_list_attribs_sz + tgt_list_attribs_sz, 
				/* handle English plurality */
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?"s ":" "), 
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?" ":"s "));
			proof->text = strdup(buff);
			if (!proof->text)
				goto rules_exp_nothing_run_fail;
			proof->next = item->proof;
			item->proof = proof;
			proof = NULL;
			item->next = res->items;
			res->items = item;
			res->num_items++;
			if (policy->av_audit[j].type == RULE_AUDITALLOW)
				datum->num_auditallow++;
			else
				datum->num_dontaudit++;
			item = NULL;
		}

		/* free lists now */
		free(src_list_attribs);
		src_list_attribs = NULL;
		src_list_attribs_sz = 0;
		free(tgt_list_attribs);
		tgt_list_attribs = NULL;
		tgt_list_attribs_sz = 0;
	}
	
	for (j = 0; j < policy->num_te_trans; j++) {
		/* source type field */
		if (rules_exp_nothing_process_list_attribs(policy->te_trans[j].src_types, policy->av_access[j].flags, 1, &src_list_attribs, &src_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, src_list_attribs, src_list_attribs_sz)) {
				item = sechk_item_new();
				if (!item)
					goto rules_exp_nothing_run_fail;
				item->item_id = j;
				item->test_result = POL_LIST_TE_TRANS;
				for (i = 0; i < src_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = src_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in source", policy->attribs[src_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(src_list_attribs);
			src_list_attribs = NULL;
			src_list_attribs_sz = 0;
		}

		/* target type field */
		if (rules_exp_nothing_process_list_attribs(policy->te_trans[j].tgt_types, policy->av_access[j].flags, 0, &tgt_list_attribs, &tgt_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, tgt_list_attribs, tgt_list_attribs_sz)) {
				if (!item) {
					item = sechk_item_new();
					if (!item)
						goto rules_exp_nothing_run_fail;
					item->item_id = j;
					item->test_result = POL_LIST_TE_TRANS;
				}
				for (i = 0; i < tgt_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = tgt_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in target", policy->attribs[tgt_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(tgt_list_attribs);
			tgt_list_attribs = NULL;
			tgt_list_attribs_sz = 0;
		}

		if (item) {
			proof = sechk_proof_new();
			if (!proof)
				goto rules_exp_nothing_run_fail;
			proof->idx = -1;
			proof->type = SECHK_TYPE_NONE;
			snprintf(buff, sizeof(buff)-1, "rule uses attribute %d attribute%swhich expand%sto no types", 
				src_list_attribs_sz + tgt_list_attribs_sz, 
				/* handle English plurality */
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?"s ":" "), 
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?" ":"s "));
			proof->text = strdup(buff);
			if (!proof->text)
				goto rules_exp_nothing_run_fail;
			proof->next = item->proof;
			item->proof = proof;
			proof = NULL;
			item->next = res->items;
			res->items = item;
			res->num_items++;
			if (policy->te_trans[j].type == RULE_TE_TRANS)
				datum->num_typetrans++;
			else if (policy->te_trans[j].type == RULE_TE_CHANGE)
				datum->num_typechange++;
			else
				datum->num_typemember++;
			item = NULL;
		}

		/* free lists now */
		free(src_list_attribs);
		src_list_attribs = NULL;
		src_list_attribs_sz = 0;
		free(tgt_list_attribs);
		tgt_list_attribs = NULL;
		tgt_list_attribs_sz = 0;
	}

	/* role transitions (rules only have types in target) */
	src_list_attribs = NULL;
	src_list_attribs_sz = 0;		
	for (j = 0; j < policy->num_role_trans; j++) {
		/* target type field */
		if (rules_exp_nothing_process_list_attribs(policy->role_trans[j].tgt_types, policy->av_access[j].flags, 0, &tgt_list_attribs, &tgt_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, tgt_list_attribs, tgt_list_attribs_sz)) {
				item = sechk_item_new();
				if (!item)
					goto rules_exp_nothing_run_fail;
				item->item_id = j;
				item->test_result = POL_LIST_ROLE_TRANS;
				for (i = 0; i < tgt_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = tgt_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in target", policy->attribs[tgt_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(tgt_list_attribs);
			tgt_list_attribs = NULL;
			tgt_list_attribs_sz = 0;
		}

		if (item) {
			proof = sechk_proof_new();
			if (!proof)
				goto rules_exp_nothing_run_fail;
			proof->idx = -1;
			proof->type = SECHK_TYPE_NONE;
			snprintf(buff, sizeof(buff)-1, "rule uses attribute %d attribute%swhich expand%sto no types", 
				src_list_attribs_sz + tgt_list_attribs_sz, 
				/* handle English plurality */
				(tgt_list_attribs_sz > 1?"s ":" "), 
				(tgt_list_attribs_sz > 1?" ":"s "));
			proof->text = strdup(buff);
			if (!proof->text)
				goto rules_exp_nothing_run_fail;
			proof->next = item->proof;
			item->proof = proof;
			proof = NULL;
			item->next = res->items;
			res->items = item;
			res->num_items++;
			datum->num_roletrans++;
			item = NULL;
		}

		/* free lists now */
		free(tgt_list_attribs);
		tgt_list_attribs = NULL;
		tgt_list_attribs_sz = 0;
	}

	/* range transition rules (MLS) */
	for (j = 0; j < policy->num_rangetrans; j++) {
		/* source type field */
		if (rules_exp_nothing_process_list_attribs(policy->rangetrans[j].src_types, policy->av_access[j].flags, 1, &src_list_attribs, &src_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, src_list_attribs, src_list_attribs_sz)) {
				item = sechk_item_new();
				if (!item)
					goto rules_exp_nothing_run_fail;
				item->item_id = j;
				item->test_result = POL_LIST_RANGETRANS;
				for (i = 0; i < src_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = src_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in source", policy->attribs[src_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(src_list_attribs);
			src_list_attribs = NULL;
			src_list_attribs_sz = 0;
		}

		/* target type field */
		if (rules_exp_nothing_process_list_attribs(policy->rangetrans[j].tgt_types, policy->av_access[j].flags, 0, &tgt_list_attribs, &tgt_list_attribs_sz)) {
			if (is_subset(attrib_list, attrib_list_sz, tgt_list_attribs, tgt_list_attribs_sz)) {
				if (!item) {
					item = sechk_item_new();
					if (!item)
						goto rules_exp_nothing_run_fail;
					item->item_id = j;
					item->test_result = POL_LIST_RANGETRANS;
				}
				for (i = 0; i < tgt_list_attribs_sz; i++) {
					proof = sechk_proof_new();
					if (!proof)
						goto rules_exp_nothing_run_fail;
					proof->idx = tgt_list_attribs[i];
					proof->type = POL_LIST_ATTRIB;
					snprintf(buff, sizeof(buff)-1, "rule uses attribute %s in target", policy->attribs[tgt_list_attribs[i]].name);
					proof->text = strdup(buff);
					if (!proof->text)
						goto rules_exp_nothing_run_fail;
					proof->next = item->proof;
					item->proof = proof;
					proof = NULL;
				}
			}
		} else {
			free(tgt_list_attribs);
			tgt_list_attribs = NULL;
			tgt_list_attribs_sz = 0;
		}

		if (item) {
			proof = sechk_proof_new();
			if (!proof)
				goto rules_exp_nothing_run_fail;
			proof->idx = -1;
			proof->type = SECHK_TYPE_NONE;
			snprintf(buff, sizeof(buff)-1, "rule uses attribute %d attribute%swhich expand%sto no types", 
				src_list_attribs_sz + tgt_list_attribs_sz, 
				/* handle English plurality */
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?"s ":" "), 
				((src_list_attribs_sz + tgt_list_attribs_sz) > 1?" ":"s "));
			proof->text = strdup(buff);
			if (!proof->text)
				goto rules_exp_nothing_run_fail;
			proof->next = item->proof;
			item->proof = proof;
			proof = NULL;
			item->next = res->items;
			res->items = item;
			res->num_items++;
			datum->num_rangetrans++;
			item = NULL;
		}

		/* free lists now */
		free(src_list_attribs);
		src_list_attribs = NULL;
		src_list_attribs_sz = 0;
		free(tgt_list_attribs);
		tgt_list_attribs = NULL;
		tgt_list_attribs_sz = 0;
	}

	mod->result = res;

	if (res->num_items > 0)
		return 1;

	return 0;

rules_exp_nothing_run_fail:
	free(attrib_list);
	free(src_list_attribs);
	free(tgt_list_attribs);
	sechk_proof_free(proof);
	sechk_item_free(item);
	sechk_result_free(res);
	return -1;
}

/* The free function frees the private data of a module */
void rules_exp_nothing_free(sechk_module_t *mod)
{
	rules_exp_nothing_data_t *datum;

	if (!mod) {
		fprintf(stderr, "Error: invalid parameters\n");
		return;
	}
	if (strcmp(mod_name, mod->name)) {
		fprintf(stderr, "Error: wrong module (%s)\n", mod->name);
		return;
	}

	datum = (rules_exp_nothing_data_t*)mod->data;

	free(mod->data);
	mod->data = NULL;
}

/* The print output function generates the text printed in the
 * report and prints it to stdout. */
int rules_exp_nothing_print_output(sechk_module_t *mod, policy_t *policy) 
{
	rules_exp_nothing_data_t *datum = NULL;
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

	datum = (rules_exp_nothing_data_t*)mod->data;
	outformat = mod->outputformat;

	if (!mod->result) {
		fprintf(stderr, "Error: module has not been run\n");
		return -1;
	}

	if (!outformat || (outformat & SECHK_OUT_QUIET))
		return 0; /* not an error - no output is requested */

	if (outformat & SECHK_OUT_STATS) {
		printf("Found %i rules.\n", mod->result->num_items);
		if (mod->result->num_items > 0) {
			printf("\nRules by type:\n");
			printf("\n");
			printf("\tallow:\t\t%7d\t\ttype_transition:%7d\n", datum->num_allow, datum->num_typetrans);
			printf("\tneverallow:\t%7d\t\ttype_change:\t%7d\n", datum->num_neverallow, datum->num_typechange); 
			printf("\tauditallow:\t%7d\t\ttype_member:\t%7d\n", datum->num_auditallow, datum->num_typemember);
			printf("\tdontaudit:\t%7d\t\trole_transition:%7d\n", datum->num_dontaudit, datum->num_roletrans);
			printf("\trange_transition:%6d\n", datum->num_rangetrans);
		}
	}
	/* The list report component is a display of all items
	 * found without any supporting proof. */
	if (outformat & SECHK_OUT_LIST) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			switch (item->test_result) {
			case POL_LIST_AV_ACC:
				printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 0, policy)); 
				break;
			case POL_LIST_AV_AU:
				printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 1, policy)); 
				break;
			case POL_LIST_TE_TRANS:
				printf("%s\n", re_render_tt_rule(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			case POL_LIST_ROLE_TRANS:
				printf("%s\n", re_render_role_trans(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			case POL_LIST_RANGETRANS:
				printf("%s\n", re_render_rangetrans(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			default:
				fprintf(stderr, "Error: invalid rule\n");
				return -1;
			}
		}
		printf("\n");
	}
	/* The proof report component is a display of a list of items
	 * with an indented list of proof statements supporting the result
	 * of the check for that item (e.g. rules with a given type)
	 * this field also lists the computed severity of each item
	 * (see sechk_item_sev in sechecker.c for details on calculation)
	 * items are printed on a line either with (or, if long, such as a
	 * rule, followed by) the severity. Each proof element is then
	 * displayed in an indented list one per line below it. */
	if (outformat & SECHK_OUT_PROOF) {
		printf("\n");
		for (item = mod->result->items; item; item = item->next) {
			switch (item->test_result) {
			case POL_LIST_AV_ACC:
				printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 0, policy)); 
				break;
			case POL_LIST_AV_AU:
				printf("%s\n", re_render_av_rule(!is_binary_policy(policy), item->item_id, 1, policy)); 
				break;
			case POL_LIST_TE_TRANS:
				printf("%s\n", re_render_tt_rule(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			case POL_LIST_ROLE_TRANS:
				printf("%s\n", re_render_role_trans(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			case POL_LIST_RANGETRANS:
				printf("%s\n", re_render_rangetrans(!is_binary_policy(policy), item->item_id, policy)); 
				break;
			default:
				fprintf(stderr, "Error: invalid rule\n");
				return -1;
			}
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
sechk_result_t *rules_exp_nothing_get_result(sechk_module_t *mod) 
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

/* The rules_exp_nothing_data_new function allocates and returns an
 * initialized private data storage structure for this
 * module. */
rules_exp_nothing_data_t *rules_exp_nothing_data_new(void)
{
	rules_exp_nothing_data_t *datum = NULL;

	/* zero initialize all counters */
	datum = (rules_exp_nothing_data_t*)calloc(1,sizeof(rules_exp_nothing_data_t));

	return datum;
}

 
