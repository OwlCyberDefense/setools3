#include "policy.h"
#include "policy-io.h"
#include "test.h"
#include "analysis.h"

policy_t *policy;

int main(int argc, char **argv)
{	
	iflow_query_t *q;
	iflow_transitive_t *a;
	int j, i = 100;
	int num;

	init_tests(argc, argv);

	while (i--) {
		a = NULL;
		TEST("load", open_policy("policy/transitive_flow_small.conf", &policy) == 0);
		TEST("perm map load", (load_policy_perm_mappings(policy,
								 fopen("policy/transitive_flow_small.map", "r"))
		     & PERMMAP_RET_ERROR) == 0);

		q = iflow_query_create();
		TEST("query alloc", q != NULL);

		q->start_type = get_rand_int(1, (policy->num_types - 1));
		q->direction = get_rand_int(IFLOW_IN, IFLOW_OUT);
		num = get_rand_int(0, policy->num_types - 2);
		if (num) {
			for (j = 0; j < num; j++) {
				iflow_query_add_end_type(q, get_rand_int(1, (policy->num_types - 1)));
				iflow_query_add_type(q, get_rand_int(1, (policy->num_types - 1)));
			}
		}

		num = get_rand_int(0, policy->num_obj_classes - 1);
		if (num) {
			for (j = 0; j < num; j++) {
				iflow_query_add_obj_class(q, get_rand_int(0, (policy->num_obj_classes - 1)));
			}
		}

		if (!iflow_query_is_valid(q, policy)) {
			i++;
			goto out;
		}
		
		a = iflow_transitive_flows(policy, q);
		TEST("transitive flows", a);

	out:
		if (a)
			iflow_transitive_destroy(a);
		iflow_query_destroy(q);
		free_policy(&policy);
	}
	return 0;
}
