#include "test.h"
#include "policy.h"
#include "policy-io.h"

policy_t *policy;

int main(int argc, char **argv)
{
	int i, num_perms;
	int *perms;

	init_tests(argc, argv);
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);
	for (i = 0; i < policy->num_obj_classes; i++) {
		TEST("getting perms", get_obj_class_perms(i, &num_perms, &perms, policy) == 0);
		TEST("num perms", num_perms <= policy->num_perms);
	}

	return 0;
}
