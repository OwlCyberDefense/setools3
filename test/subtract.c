#include "test.h"
#include "policy.h"
#include "policy-io.h"
#include "render.h"

int main(int argc, char **argv)
{
	int num_types;
	int *types;
	policy_t *policy = NULL;
	int ans;
	bool_t self;

	init_tests(argc, argv);

	TEST("loading a policy with '-'", open_policy("policy/subtract.conf", &policy) != -1);
	
	/* extract_te_rules */
	TEST("extract type from te rules with attributes",
		extract_types_from_te_rule(0, RULE_TE_ALLOW, SRC_LIST, &types, &num_types, self, policy) == 0);
	TEST("extract types from te rule result", num_types == 1 && get_type_idx("user_t", policy) == types[0]);

	TEST("extract type from te rules with attributes",
		extract_types_from_te_rule(1, RULE_TE_ALLOW, SRC_LIST, &types, &num_types, self, policy) == 0);
	TEST("extract types from te rule result", num_types == 1 && get_type_idx("sysadm_t", policy) == types[0]);

	/* match_te_rules */
	TEST("does_av_rule_idx_use_type", does_av_rule_idx_use_type(0, RULE_TE_ALLOW, get_type_idx("sysadm_t", policy), IDX_TYPE,
		SRC_LIST, TRUE, self, policy) == FALSE);
	TEST("does_av_rule_idx_use_type", does_av_rule_idx_use_type(0, RULE_TE_ALLOW, get_type_idx("user_t", policy), IDX_TYPE,
		SRC_LIST, TRUE, self, policy) == TRUE);

	return 0;
}
