/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "policy.h"
#include "policy-io.h"
#include "./test.h"
#include "relabel_analysis.h"
#include "render.h"

#include <string.h>

int main(int argc, char **argv)
{
	int type1_idx = -1, type2_idx = -1, retv = 0, type3_idx = -1, obj1_idx = -1;
	unsigned char mode = 0, direction = 0;
	policy_t *policy = NULL;
	ap_relabel_result_t *res = NULL;
	int i, j, k, x;

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

	/* run the query */
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
	
	ap_relabel_result_destroy(res);
	mode = AP_RELABEL_MODE_SUBJ;
	TEST("querying typD mode=subj", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	TEST("whether results are empty", res->num_targets == 0);

	ap_relabel_result_destroy(res);
	type1_idx = get_type_idx("typA", policy);
	TEST("querying typA mode=subj", !ap_relabel_query(type1_idx, mode, direction, NULL, 0, NULL, 0, res, policy));
	TEST("whether results are non-empty", res->num_targets > 0);

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

	ap_relabel_result_destroy(res);
	free(res);
	return retv;
}
