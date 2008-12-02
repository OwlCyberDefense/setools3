/* Copyright (C) 2004-2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* This file runs a regression test for the relabel analysis
 * module for Apol. All tests are run with the test file
 * <setools top dir>/test/policy/relabel-corner.conf
 * test file last updated as of 2005.04.08
 * Order of the tests here is important only for use of 
 * variables internal to this test the results and queries
 * are destroyed and reinitialized by each test. */

#include "policy.h"
#include "policy-io.h"
#include "./test.h"
#include "relabel_analysis.h"
#include "render.h"

#include <string.h>

int main(int argc, char **argv)
{
	int type1_idx = -1, type2_idx = -1, retv = 0, type3_idx = -1, obj1_idx = -1;
	int *obj_filter = NULL, *subj_filter = NULL;
	int obj_filter_sz = 0, subj_filter_sz = 0;
	unsigned char mode = 0, direction = 0;
	policy_t *policy = NULL;
	ap_relabel_result_t *res = NULL;
	int i, j, k, x, tmp1, tmp2;

	tmp1 = tmp2 = 0;
	/* check test args */
	init_tests(argc, argv);

	/* load policy*/
	TEST("load policy", open_policy("policy/relabel-corner.conf", &policy) == 0);

	/* get type indices */
	type1_idx = get_type_idx("typC", policy);
	type2_idx = get_type_idx("domC", policy);
	
	/* create result structure */
	TEST("allocating result holder",(res = (ap_relabel_result_t*)malloc(1 * sizeof(ap_relabel_result_t))));
	
	/* set mode for query */
	mode = AP_RELABEL_MODE_OBJ;
	direction = AP_RELABEL_DIR_TO;
	
	printf("\nRunning Queries\n\n");

	/* The first two tests are checking for the false positive for start and end types
	 * of different object classes. The type domC cannot really relabel anything because
	 * it has only relabelfrom permission for dir and only relabelto for file.  */

	TEST("querying typC mode=obj dir=to", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		for (j = 0; j < res->targets[i].num_objects; j++) {
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				if (res->targets[i].objects[j].subjects[k].source_type == type2_idx)
					retv = 1;
			}
		}
	}
	TEST("whether domC was incorrectly found", !retv);

	ap_relabel_result_destroy(res);
	direction = AP_RELABEL_DIR_FROM;
	type1_idx = get_type_idx("typD", policy);
	TEST("querying typD mode=obj dir=from", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		for (j = 0; j < res->targets[i].num_objects; j++) {
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				if (res->targets[i].objects[j].subjects[k].source_type == type2_idx)
					retv = 1;
			}
		}
	}
	TEST("whether domC was incorrectly found", !retv);

	/* Relabel analysis finds all rules that contribute to the relabeling optration
	 * even if they are redundant rules that would be combined in binary policies
	 * This test checks that these are found. */

	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_SUBJ;
	type3_idx = get_type_idx("domF", policy);
	obj1_idx = get_obj_class_idx("file", policy);
	TEST("querying domF mode=subj", !ap_relabel_query(type3_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		for (j = 0; j < res->targets[i].num_objects; j++) {
			if (res->targets[i].objects[j].object_class != obj1_idx)
				continue;
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				if (res->targets[i].objects[j].subjects[k].num_rules != 2)
					retv = 1;
			}
		}
	}
	TEST("whether the correct number of rules (2) were found for file", !retv);

	/* This test checks the case of a type being relabeled to itself */

	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_OBJ;
	direction = AP_RELABEL_DIR_BOTH;
	type2_idx = get_type_idx("domD", policy);
	TEST("querying typD mode=obj dir=both", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		if (res->targets[i].target_type != type1_idx)
			continue;
		for (j = 0; j < res->targets[i].num_objects; j++) {
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				if (res->targets[i].objects[j].subjects[k].source_type == type2_idx)
					retv = 1;
			}
		}
	}
	TEST("whether subject domD was found for target typD", retv);

	/* This test checks that rules with '*' as the target are expanded properly */

	ap_relabel_result_destroy(res);
	direction = AP_RELABEL_DIR_TO;
	type3_idx = get_type_idx("typF", policy);
	TEST("querying typF mode=obj dir=to", !ap_relabel_query(type3_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		for (j = 0; j < res->targets[i].num_objects; j++) {
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				for (x = 0; x < res->targets[i].objects[j].subjects[k].num_rules; x++) {
					if (!(AP_RELABEL_DIR_START & res->targets[i].objects[j].subjects[k].rules[x].direction))
						continue;
					if (!(AVFLAG_TGT_STAR & policy->av_access[res->targets[i].objects[j].subjects[k].rules[x].rule_index].flags))
						retv = 1;
				}
			}
		}
	}
	TEST("whether non-star rules were incorrectly found", !retv);

	/* This test checks that types w/o permission to relabel as subjects
	 * do not casuse problems and properly return an empty result set */
	
	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_SUBJ;
	TEST("querying typD mode=subj", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	TEST("whether results are empty", res->num_targets == 0);

	/* This test checks the expansion of attributes in the source of a rule
 	 * to be sure that all sources are treated as subjects */

	ap_relabel_result_destroy(res);
	type1_idx = get_type_idx("typA", policy);
	TEST("querying typA mode=subj", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	TEST("whether results are non-empty", res->num_targets > 0);

	/* This test checks that subjects with permission 
	 * to relabel '*' are listed in all targets */

	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_OBJ;
	direction = AP_RELABEL_DIR_BOTH;
	type2_idx = get_type_idx("domF", policy);
	TEST("querying typA mode=obj dir=both", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		for (j = 0; j < res->targets[i].num_objects; j++) {
			if (res->targets[i].objects[j].object_class != obj1_idx)
				continue;
			for (k = 0; k < res->targets[i].objects[j].num_subjects; k++) {
				if (res->targets[i].objects[j].subjects[k].source_type == type2_idx)
					retv++;
			}
		}
	}
	TEST("whether domF is in all file results", retv == 12);

	/* This test check that filtering to include only one object class
	 * produces results with one object class per target */

	ap_relabel_result_destroy(res);
	direction = AP_RELABEL_DIR_TO;
	obj1_idx = get_obj_class_idx("dir", policy);
	add_i_to_a(obj1_idx, &obj_filter_sz, &obj_filter);
	TEST("querying typA mode=obj dir=to filter=dir", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, obj_filter, obj_filter_sz, res, policy));
	retv = 0;
	for (i = 0; i < res->num_targets; i++) {
		if (res->targets[i].num_objects != 1)
			retv = 1;
	}
	TEST("whether one object was found for each target",retv != 1);

	/* Test checks for the ability to find a specific operation correctly */

	ap_relabel_result_destroy(res);
	type2_idx = get_type_idx("domB", policy);
	add_i_to_a(type2_idx, &subj_filter_sz, &subj_filter);
	type2_idx = get_type_idx("domA", policy);
	type3_idx = get_type_idx("typB", policy);
	TEST("querying typA mode=obj dir=to filter=dir,domB", !ap_relabel_query(type1_idx, mode, direction, subj_filter, subj_filter_sz, obj_filter, obj_filter_sz, res, policy));
	TEST("whether correct result was found", res->num_targets == 1 && res->targets[0].target_type == type3_idx && res->targets[0].num_objects == 1 && res->targets[0].objects[0].object_class == obj1_idx && res->targets[0].objects[0].num_subjects == 1 && res->targets[0].objects[0].subjects[0].source_type == type2_idx);

	/* As an extension of empty result handling checking, this test
	 * checks for proper handling when a filter excludes all results
	 * but is still a valid filter */

	ap_relabel_result_destroy(res);
	type1_idx = get_type_idx("domE", policy);
	mode = AP_RELABEL_MODE_SUBJ;
	TEST("querying domE mode=subj filter=dir", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, obj_filter, obj_filter_sz, res, policy));
	TEST("whether results are empty", res->num_targets == 0); 

	/* This test checks that multiple subjects performing the same 
	 * operation are reported correctly */

	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_OBJ;
	type1_idx = get_type_idx("typC", policy);
	type3_idx = get_type_idx("domF", policy);
	add_i_to_a(type2_idx, &subj_filter_sz, &subj_filter);
	add_i_to_a(type3_idx, &subj_filter_sz, &subj_filter);
	TEST("querying typC mode=obj dir=to filter=domB,domF,domA", !ap_relabel_query(type1_idx, mode, direction, subj_filter, subj_filter_sz, NULL, 0, res, policy));
	type1_idx = get_type_idx("typF", policy);
	type2_idx = get_type_idx("typA", policy);
	type3_idx = get_type_idx("typE", policy);
	obj1_idx = get_obj_class_idx("file", policy);
	TEST("whether the correct two subjects are found", \
		res->num_targets == 1 && res->targets[0].target_type == type1_idx && \
		res->targets[0].num_objects == 1 && res->targets[0].objects[0].object_class == obj1_idx  && \
		res->targets[0].objects[0].num_subjects == 2 && \
		(res->targets[0].objects[0].subjects[0].source_type == type2_idx || \
		res->targets[0].objects[0].subjects[1].source_type == type2_idx) && \
		(res->targets[0].objects[0].subjects[0].source_type == type3_idx || \
		res->targets[0].objects[0].subjects[1].source_type == type3_idx) && \
		res->targets[0].objects[0].subjects[0].source_type != res->targets[0].objects[0].subjects[1].source_type);


	/* This test checks that no targets are removed by a filter 
	 * that is not relevant to the query */

	ap_relabel_result_destroy(res);
	free(subj_filter);
	subj_filter = NULL; 
	subj_filter_sz = 0;
	add_i_to_a(obj1_idx, &obj_filter_sz, &obj_filter);
	type1_idx = get_type_idx("typA", policy);
	type2_idx = get_type_idx("domC", policy);
	direction = AP_RELABEL_DIR_FROM;
	TEST("querying typA mode=obj dir=from filter=file,dir,domC", !ap_relabel_query(type1_idx, mode, direction, subj_filter, subj_filter_sz, obj_filter, obj_filter_sz, res, policy));
	TEST("whether correct number of targets were found (12)", res->num_targets == 12);

	/* This test checks the correct function of filtering in subject mode */

	ap_relabel_result_destroy(res);
	free(obj_filter);
	obj_filter = NULL;
	obj_filter_sz = 0;
	mode = AP_RELABEL_MODE_SUBJ;
	type1_idx = get_type_idx("domD", policy);
	add_i_to_a(get_obj_class_idx("dir", policy), &obj_filter_sz, &obj_filter);
	TEST("querying domD mode=subj filter=dir", !ap_relabel_query(type1_idx, mode, direction, subj_filter, subj_filter_sz, obj_filter, obj_filter_sz, res, policy));
	TEST("whether correct number of targets were found (4)", res->num_targets == 4);

	/* This test checks that when a rule permits therelabeling of multiple 
	 * targets that the same rules are found for each target */

	ap_relabel_result_destroy(res);
	obj_filter[0] = get_obj_class_idx("file", policy);
	type1_idx = get_type_idx("typE", policy);
	type2_idx = get_type_idx("domB", policy);
	mode = AP_RELABEL_MODE_OBJ;
	direction = AP_RELABEL_DIR_FROM;
	free(subj_filter);
	subj_filter = NULL;
	subj_filter_sz = 0;
	for (i = 1; i < 13; i++) {
		if (type2_idx != i)
			add_i_to_a(i, &subj_filter_sz, &subj_filter);
	}
	TEST("querying typE mode=obj dir=from filter=file,~domB", !ap_relabel_query(type1_idx, mode, direction, subj_filter, subj_filter_sz, obj_filter, obj_filter_sz, res, policy));
	retv = 0;
	if (res->num_targets != 12)
		retv = 1;
	for (i = 0; i < res->num_targets; i++) {
		if (retv) break;
		if (!i) {
			tmp1 = res->targets[0].objects[0].subjects[0].rules[0].rule_index;
			tmp2 = res->targets[0].objects[0].subjects[0].rules[1].rule_index;
		} else {
			if ((res->targets[i].objects[0].subjects[0].rules[0].rule_index != tmp1 &&
				res->targets[i].objects[0].subjects[0].rules[0].rule_index != tmp2) ||
				(res->targets[i].objects[0].subjects[0].rules[1].rule_index != tmp1 &&
				res->targets[i].objects[0].subjects[0].rules[1].rule_index != tmp2) ||
				res->targets[i].objects[0].subjects[0].rules[1].rule_index == res->targets[i].objects[0].subjects[0].rules[0].rule_index)
				retv = 1;
		}
	}
	TEST("whether the same two rules are found for all targets", !retv);

	ap_relabel_result_destroy(res);
	free(res);
	free(obj_filter);
	free(subj_filter);
	avh_free(&(policy->avh));
	free_policy(&policy);
	TEST("end of tests",1);
	return retv;
}
