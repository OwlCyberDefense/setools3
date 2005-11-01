/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "test.h"
#include "policy.h"
#include "policy-io.h"
#include "dta.h"
#include "semantic/avsemantics.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>

policy_t *policy;

int main(int argc, char **argv)
{
	dta_table_t *table = NULL;
	int retv;
	time_t time_last, time_now;
	dta_trans_t *transitions = NULL;

	init_tests(argc, argv);

	time_last = time(NULL);
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);
	time_now = time(NULL);
	fprintf(stderr, "time: %lds\n", time_now - time_last);

	time_last = time(NULL);
	TEST("building hash table", !avh_build_hashtab(policy));
	time_now = time(NULL);
	fprintf(stderr, "time: %lds\n", time_now - time_last);

	time_last = time(NULL);
	table = dta_table_new(policy);
	if (!table)
		perror("error creating table");
	retv = dta_table_build(table, policy);
	time_now = time(NULL);
	if (retv)
		perror("error building table");
	TEST("building dta table", !retv);
	fprintf(stderr, "time: %lds\n", time_now - time_last);

	int i, j, k, size = 0;
	for (i = 0; i < table->size; i++) {
		for (j = 0; j < table->dom_list[i].num_proc_trans_rules; j++) {
			for (k = 0; k < table->dom_list[i].proc_trans_rules[j].num_rules; k++) {
				size += sizeof(int);
			}
			size += sizeof(dta_rule_t);
		}
		for (j = 0; j < table->dom_list[i].num_ep_rules; j++) {
			for (k = 0; k < table->dom_list[i].ep_rules[j].num_rules; k++) {
				size += sizeof(int);
			}
			size += sizeof(dta_rule_t);
		}
		for (j = 0; j < table->dom_list[i].num_type_trans_rules; j++) {
			for (k = 0; k < table->dom_list[i].type_trans_rules[j].num_rules; k++) {
				size += sizeof(int);
			}
			size += sizeof(dta_rule_t);
		}
		for (j = 0; j < table->exec_list[i].num_ep_rules; j++) {
			for (k = 0; k < table->exec_list[i].ep_rules[j].num_rules; k++) {
				size += sizeof(int);
			}
			size += sizeof(dta_rule_t);
		}
		for (j = 0; j < table->exec_list[i].num_exec_rules; j++) {
			for (k = 0; k < table->exec_list[i].exec_rules[j].num_rules; k++) {
				size += sizeof(int);
			}
			size += sizeof(dta_rule_t);
		}
		size += sizeof(dta_dom_node_t);
		size += sizeof(dta_exec_node_t);
	}
	fprintf(stderr, "size = %dB\n", size);

	time_last = time(NULL);
	int idx = get_type_idx("init_t", policy);
	TEST("runing lookup function", !dta_table_get_all_trans(table, &transitions, idx));
	TEST("filtering valid transitions", !dta_trans_filter_valid(&transitions, 1));
	int sysadm_idx = get_type_idx("sysadm_t", policy);
	int proc_idx = get_type_idx("proc_t", policy);
	TEST("filtering for end type sysadm_t", !dta_trans_filter_end_types(&transitions, &sysadm_idx, 1));
	obj_perm_set_t set;
	set.obj_class = get_obj_class_idx("file", policy);
	set.perms = NULL;
	set.num_perms = 0;
	add_i_to_a(get_perm_idx("read", policy), &(set.num_perms), &(set.perms));
	TEST("filtering for end types w/ proc_t : file read access", !dta_trans_filter_access_types(&transitions, &proc_idx, 1, &set, 1, policy));
	domain_trans_analysis_t *dta = NULL;
	dta = dta_trans_convert(transitions, 0);
	TEST("conversion function", dta != NULL);
	time_now = time(NULL);
	fprintf(stderr, "time: %lds\n", time_now - time_last);


	time_last = time(NULL);
	fprintf(stderr, "freeing stuff ...");
	free_policy(&policy);
	free_domain_trans_analysis(dta);
	dta_table_free(table);
	free(table);
	dta_trans_destroy(&transitions);
	time_now = time(NULL);
	fprintf(stderr, " done\ntime: %lds\n", time_now - time_last);

	return 0;
}
