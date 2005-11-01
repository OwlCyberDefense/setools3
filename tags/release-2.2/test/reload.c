#include "test.h"
#include "policy.h"
#include "policy-io.h"
#include "perm-map.h"

int main(int argc, char **argv)
{
	policy_t *policy = NULL;

	init_tests(argc, argv);

	TEST("loading a policy", open_policy("policy/bad-policy.conf", &policy) == 1);

	/* this used to fail even though the policy was good */
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);
	

	return 0;
}
