/*
 * This tests for partial policy loading.
 *
 * Author: Don Patterson <don.patterson@tresys.com>
 *
 */
 
#include "test.h"
#include "policy.h"
#include "policy-io.h"

policy_t *policy;

int main(int argc, char **argv)
{
	/* Initialize test framework */
	init_tests(argc, argv);
	
	/* Test loading each policy option flag defined in policy.h */
	TEST("partial loading NONE of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_NONE, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading ALL of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_ALL, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TYPES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TYPES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading only CLASSES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_CLASSES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading CLASSES/PERMS in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_OBJECTS, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading EVERYTHING ELSE in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_OTHER, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading AVRULES, USERS, and ROLES", open_partial_policy("policy/default-v12-policy.conf", 
									      POLOPT_AV_RULES | POLOPT_USERS | POLOPT_ROLES, &policy) == 0);
	free_policy(&policy);
	
	/* Do the same with the binary policy */
	TEST("partial loading NONE of a policy", open_partial_policy("policy/binary_small.17", POLOPT_NONE, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading ALL of a policy", open_partial_policy("policy/binary_small.17", POLOPT_ALL, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TYPES in a policy", open_partial_policy("policy/binary_small.17", POLOPT_TYPES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading only CLASSES in a policy", open_partial_policy("policy/binary_small.17", POLOPT_CLASSES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading CLASSES/PERMS in a policy", open_partial_policy("policy/binary_small.17", POLOPT_OBJECTS, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading EVERYTHING ELSE in a policy", open_partial_policy("policy/binary_small.17", POLOPT_OTHER, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading AVRULES, USERS, and ROLES", open_partial_policy("policy/binary_small.17", 
									      POLOPT_AV_RULES | POLOPT_USERS | POLOPT_ROLES, &policy) == 0);
	free_policy(&policy);
	
	/* TODO: The following policy options need a function for re-validating the specified option flag recursively. */
	/*TEST("partial loading RBAC of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_RBAC, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_POLICY of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_POLICY, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading AV_RULES of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_AV_RULES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TYPE_RULES of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TYPE_RULES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_RULES of a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_RULES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading only PERMS in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_PERMS, &policy) == 0);
	free_policy(&policy); 
	TEST("partial loading ROLES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_ROLES, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading USERS in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_USERS, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_ALLOW RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_ALLOW, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_NEVERALLOW RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_NEVERALLOW, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_AUDIT ALLOW RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_AUDITALLOW, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_DONTAUDIT RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_DONTAUDIT, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_TRANS RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_TRANS, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_MEMBER RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_MEMBER, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading TE_CHANGE RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_TE_CHANGE, &policy) == 0);
	free_policy(&policy);
	TEST("partial loading ROLE_RULES in a policy", open_partial_policy("policy/default-v12-policy.conf", POLOPT_ROLE_RULES, &policy) == 0);
	free_policy(&policy);*/
	
	return 0;
}
