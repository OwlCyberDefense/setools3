#include "policy.h"
#include "policy-io.h"
#include "test.h"
#include "infoflow.h"

policy_t *policy;

int main(int argc, char **argv)
{	
	iflow_query_t *q;
	iflow_transitive_t *a;
	int j, i = 10;
	int num;

	init_tests(argc, argv);
	
	TEST("load", open_policy("policy/transitive_flow_small.conf", &policy) == 0);
	TEST("perm map load", (load_policy_perm_mappings(policy,
							 fopen("policy/transitive_flow_small.map", "r"))
			       & PERMMAP_RET_ERROR) == 0);	

	while (i) {
		a = NULL;
		q = iflow_query_create();

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
			goto out;
		}
		
		a = iflow_transitive_flows(policy, q);
		TEST("transitive flows", a);
		i--;

	out:
		if (a)
			iflow_transitive_destroy(a);
		iflow_query_destroy(q);
	}
	free_policy(&policy);
	return 0;
}
