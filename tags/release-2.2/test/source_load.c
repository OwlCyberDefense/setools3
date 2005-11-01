#include "test.h"
#include "policy.h"
#include "policy-io.h"

int main(int argc, char **argv)
{
	policy_t *policy = NULL;

	init_tests(argc, argv);

	TEST("loading v12 source", !open_policy("policy/default-v12-policy.conf", &policy))
	TEST("whether policy version is correct", policy->version == POL_VER_12)
	free_policy(&policy);
	TEST("loading v15 source", !open_policy("policy/small15.conf", &policy))
	TEST("whether policy version is correct", policy->version == POL_VER_15)
	free_policy(&policy);
	TEST("loading v16 source", !open_policy("policy/small16.conf", &policy))
	TEST("whether policy version is correct", policy->version == POL_VER_16)
	free_policy(&policy);
	TEST("loading v17 source", !open_policy("policy/small17.conf", &policy))
	TEST("whether policy version is correct", policy->version == POL_VER_17)
	free_policy(&policy);
	TEST("loading v18--20 source", !open_policy("policy/rbac1.conf", &policy))
	TEST("whether policy version is correct", policy->version == POL_VER_18_20)
	free_policy(&policy);
	return 0;
}
