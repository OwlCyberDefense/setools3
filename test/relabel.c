/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include <policy.h>
#include <policy-io.h>
#include "./test.h"
#include <relabel_analysis.h>

#include <string.h>

int main(int argc, char **argv)
{
	int retv, sysadm_home_t_idx, sysadm_t_idx, pol_num_types;
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
	
	/* run the query */
	TEST("querying sysadm_home_t relabelto", !apol_query_relabel_analysis(sets, sysadm_home_t_idx, res, policy, mode, NULL));
	printf("found %i\n", res->num_types);
	TEST(" whether the correct number of types were found", res->num_types == 170);

	return 0;
}
