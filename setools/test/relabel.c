/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include <policy.h>
#include <policy-io.h>
#include "./test.h"
#include <relabel_analysis.h>

#include <string.h>

int main(int argc, char **argv)
{
	int i, sysadm_home_t_idx, sysadm_t_idx, retv = 0, user_home_t_idx;
	policy_t *policy;
	char *str;
	relabel_mode_t *mode = NULL;
	relabel_filter_t *filter = NULL;
	relabel_result_t *res = NULL;
	relabel_set_t *sets = NULL;

	/* check test args */
	init_tests(argc, argv);

	/* load policy*/
	TEST("load policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);

	/* get type indices */
	TEST("getting sysadm_home_t index", (sysadm_home_t_idx = get_type_idx("sysadm_home_t", policy)) != -1);
	get_type_name(sysadm_home_t_idx, &str, policy);
	TEST("consistancy", !strncmp("sysadm_home_t", str, 13));
	
	TEST("getting sysadm_t index", (sysadm_t_idx = get_type_idx("sysadm_t", policy)) != -1);
	get_type_name(sysadm_t_idx, &str, policy);
	TEST("consistancy", !strncmp("sysadm_t", str, 8));

	/* create relabel mode structure*/
	TEST("allocating mode", (mode = (relabel_mode_t*)malloc(1 * sizeof(relabel_mode_t))));
	TEST("init mode", !apol_relabel_mode_init(mode));
	
	/* create filter */
	TEST("allocating filter",(filter = (relabel_filter_t*)malloc(1 * sizeof(relabel_filter_t))));
	TEST("init filter", !apol_relabel_filter_init(filter));

	/* create result structure */
	TEST("allocating result holder",(res = (relabel_result_t*)malloc(1 * sizeof(relabel_result_t))));
	TEST("init result holder", !apol_relabel_result_init(res));
	
	/* do analysis */
	TEST("running analysis", !apol_do_relabel_analysis(&sets, policy));

	/* set mode for query */
	mode->mode = MODE_TO;
	mode->filter = 0;
	mode->transitive = 0;
	
	printf("\nRunning Queries\n\n");

	/* run the query */
	TEST("querying sysadm_home_t mode=to", !apol_query_relabel_analysis(sets, sysadm_home_t_idx, res, policy, mode, NULL));
	TEST("whether the correct number of types (170) were found", res->num_types == 170);

	mode->mode = MODE_FROM;
	TEST("querying sysadm_home_t mode=from", !apol_query_relabel_analysis(sets, sysadm_home_t_idx, res, policy, mode, NULL));
	TEST("whether the correct number of types (170) were found", res->num_types == 170);

	mode->mode = MODE_BOTH;
	TEST("querying sysadm_home_t mode=both", !apol_query_relabel_analysis(sets, sysadm_home_t_idx, res, policy, mode, NULL));
	TEST("whether the correct number of types (170) were found", res->num_types == 170);

	mode->mode = MODE_DOM;
	TEST("querying sysadm_t mode=subject", !apol_query_relabel_analysis(sets, sysadm_t_idx, res, policy, mode, NULL));
	TEST("whether the correct number of types (170) were found", res->set->num_types == 170);

	/* build filter */
	filter->perm_sets = (obj_perm_set_t*)calloc(1, sizeof(obj_perm_set_t));
	if (!filter->perm_sets) {
		fprintf(stderr, "O.o.M.\n");
		retv = -1;
		goto endoftest;
	}
	filter->perm_sets[0].obj_class = get_obj_class_idx("file", policy);
	filter->num_perm_sets = 1;
	filter->perm_sets[0].perms = (int*)calloc(1, sizeof(int));
	if (!filter->perm_sets[0].perms) {
		fprintf(stderr, "O.o.M.\n");
		retv = -1;
		goto endoftest;
	}
	filter->perm_sets[0].perms[0] = get_perm_idx("write", policy);
	filter->perm_sets[0].num_perms = 1;

	user_home_t_idx = get_type_idx("user_home_t", policy);

	mode->mode = MODE_TO;
	mode->filter = 1;
	TEST("querying user_home_t mode=to filter=file:write", !apol_query_relabel_analysis(sets, user_home_t_idx, res, policy, mode, filter));
	TEST("whether the correct number of types (144) were found", res->num_types == 144);

	mode->mode = MODE_DOM;
	mode->filter = 0;
	TEST("querying user_home_t mode=subject", !apol_query_relabel_analysis(sets, user_home_t_idx, res, policy, mode, NULL));
	TEST("whether the correct number of types (none) were found", res->set->num_types == 0);
	

endoftest:
	apol_free_relabel_result_data(res);
	free(res);
	for (i = 0; i < policy->num_types; i++) {
		apol_free_relabel_set_data(&(sets[i]));
	}
	free(sets);
	apol_free_relabel_filter_data(filter);
	free(filter);
	free(mode);
	return retv;
}
