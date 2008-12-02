/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "test.h"
#include "policy.h"
#include "policy-io.h"

/* This suite is designed to work with policy/default-v12-policy.conf */
int main(int argc, char **argv)
{
	int role;
	bool_t errors; /* bool_t is typedef'd unsigned char */
	char *role_name;
	policy_t *policy;

	init_tests(argc, argv);
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);

	TEST("whether get_role_idx returns normally", (role = get_role_idx("system_r", policy)) != -1);
	get_role_name(role, &role_name, policy);
	TEST("whether get_role_name agrees", strcmp(role_name, "system_r") == 0);
	free(role_name);
	TEST("system_r's num_types", policy->roles[role].num == 30);
	TEST("object_r's num_types", policy->roles[get_role_idx("object_r", policy)].num == 0);
	TEST("sysadm_r's num_types", policy->roles[get_role_idx("sysadm_r", policy)].num == 24);
	TEST("user_r's num_types", policy->roles[get_role_idx("user_r", policy)].num == 8);
	{
		errors = 8;
		role = get_role_idx("user_r", policy);
		errors -= does_role_use_type(role, get_type_idx("user_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("user_su_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("user_chkpwd_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("user_crontab_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("user_ssh_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("user_crond_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("newrole_t", policy), policy);
		errors -= does_role_use_type(role, get_type_idx("passwd_t", policy), policy);
	}
	TEST("whether user_r has the correct types", errors == 0);
	return 0;
}
