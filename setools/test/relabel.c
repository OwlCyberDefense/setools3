/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "policy.h"
#include "policy-io.h"
#include "./test.h"
#include "relabel_analysis.h"

#include <string.h>

int main(int argc, char **argv)
{
	int sysadm_home_t_idx = -1, sysadm_t_idx = -1, retv = 0, user_home_t_idx = -1;
	unsigned char mode = 0, direction = 0;
	policy_t *policy = NULL;
	char *str = NULL;
	ap_relabel_result_t *res = NULL;
	int i, j;

	/* check test args */
	init_tests(argc, argv);

	/* load policy*/
	TEST("load policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);

	/* get type indices */
	TEST("getting sysadm_home_t index", (sysadm_home_t_idx = get_type_idx("sysadm_home_t", policy)) != -1);
	get_type_name(sysadm_home_t_idx, &str, policy);
	TEST("consistancy", !strncmp("sysadm_home_t", str, 13));
	free(str);
	str = NULL;
	
	TEST("getting sysadm_t index", (sysadm_t_idx = get_type_idx("sysadm_t", policy)) != -1);
	get_type_name(sysadm_t_idx, &str, policy);
	TEST("consistancy", !strncmp("sysadm_t", str, 8));
	free(str);
	str = NULL;

	/* create result structure */
	TEST("allocating result holder",(res = (ap_relabel_result_t*)malloc(1 * sizeof(ap_relabel_result_t))));
	
	/* set mode for query */
	mode = AP_RELABEL_MODE_OBJ;
	direction = AP_RELABEL_DIR_TO;
	
	printf("\nRunning Queries\n\n");

	/* run the query */
	TEST("querying sysadm_home_t mode=obj dir=to", !ap_relabel_query(sysadm_home_t_idx, mode, direction, res, policy));
	printf("\nnum found %i\n", res->num_targets);
	TEST("whether the correct number of types (170) were found", res->num_targets == 170);

	direction = AP_RELABEL_DIR_FROM;
	TEST("querying sysadm_home_t mode=obj dir=from", !ap_relabel_query(sysadm_home_t_idx, mode, direction, res, policy));
	printf("\nnum found %i\n", res->num_targets);
	TEST("whether the correct number of types (170) were found", res->num_targets == 170);

	direction = AP_RELABEL_DIR_BOTH;
	TEST("querying sysadm_home_t mode=both", !ap_relabel_query(sysadm_home_t_idx, mode, direction, res, policy));
	printf("\nnum found %i\n", res->num_targets);
	TEST("whether the correct number of types (170) were found", res->num_targets == 170);

	mode = AP_RELABEL_MODE_SUBJ;
	TEST("querying sysadm_t mode=subject", !ap_relabel_query(sysadm_t_idx, mode, direction, res, policy));
	printf("\nnum found %i\n", res->num_targets);
	for (i =0; i < res->num_targets; i++) {
		for(j = i; j < res->num_targets; j++) {
			if (i != j && res->targets[i].target_type == res->targets[j].target_type) {
				get_type_name(res->targets[i].target_type, &str, policy);
				fprintf(stderr, " dup :%s\n", str);
				free(str);
				str = NULL;
			}
		}
	}
	TEST("whether the correct number of types (172) were found", res->num_targets == 172);

	user_home_t_idx = get_type_idx("user_home_t", policy);

	mode = AP_RELABEL_MODE_SUBJ;
	TEST("querying user_home_t mode=subject", !ap_relabel_query(user_home_t_idx, mode, direction, res, policy));
	printf("\nnum found %i\n", res->num_targets);
	TEST("whether the correct number of types (none) were found", res->num_targets == 0);
	
	ap_relabel_result_destroy(res);
	free(res);
	return retv;
}
