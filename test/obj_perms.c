/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

#include "test.h"
#include "policy.h"
#include "policy-io.h"

/* This suite is designed to work with policy/default-v12-policy.conf */
int main(int argc, char **argv)
{
	int num_perms;
	int *perms;
	int filesystem_idx, lnk_file_idx, dir_idx;
	bool_t errors; /* bool_t is typedef'd unsigned char */
	char *obj_name;
	policy_t *policy;

	init_tests(argc, argv);
	TEST("loading a policy", open_policy("policy/default-v12-policy.conf", &policy) == 0);

	TEST("whether get_obj_class_name returns normally", get_obj_class_name(4, &obj_name, policy) == 0);
	TEST("whether get_obj_class_name gets the right name", strcmp(obj_name, "filesystem") == 0);
	free(obj_name);
	
	lnk_file_idx = get_obj_class_idx("lnk_file", policy);
	TEST("get_obj_class_idx", lnk_file_idx == 8);
	fprintf(stderr, "\n");
	TEST("get_num_perms_for_obj_class w/ only common perms (lnk_file)", get_num_perms_for_obj_class(lnk_file_idx, policy) == 17);
	TEST("get_obj_class_perms", get_obj_class_perms(lnk_file_idx, &num_perms, &perms, policy) == 0);
	TEST("whether num_perms makes sense", num_perms <= policy->num_perms);
	TEST("whether num_perms == get_num_perms_for_obj_class", num_perms == get_num_perms_for_obj_class(lnk_file_idx, policy));
	{
		errors = 17;
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("ioctl", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("read", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("write", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("create", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("getattr", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("setattr", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("lock", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("relabelfrom", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("relabelto", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("append", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("unlink", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("link", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("rename", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("execute", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("swapon", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("quotaon", policy), policy);
		errors -= does_class_indirectly_use_perm(lnk_file_idx, get_perm_idx("mounton", policy), policy);
	}
	TEST("whether lnk_file's perms array is correct", errors == 0);
	free(perms);
	fprintf(stderr, "\n");
	dir_idx = get_obj_class_idx("dir", policy);
	TEST("get_num_perms_for_obj_class w/ unique and common perms (dir)", get_num_perms_for_obj_class(dir_idx, policy) == 22);
	TEST("get_obj_class_perms", get_obj_class_perms(dir_idx, &num_perms, &perms, policy) == 0);
	TEST("whether num_perms makes sense", num_perms <= policy->num_perms);
	TEST("whether num_perms == get_num_perms_for_obj_class", num_perms == get_num_perms_for_obj_class(dir_idx, policy));
	{
		errors = 22;
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("ioctl", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("read", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("write", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("create", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("getattr", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("setattr", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("lock", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("relabelfrom", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("relabelto", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("append", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("unlink", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("link", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("rename", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("execute", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("swapon", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("quotaon", policy), policy);
		errors -= does_class_indirectly_use_perm(dir_idx, get_perm_idx("mounton", policy), policy);
		errors -= does_class_use_perm(dir_idx, get_perm_idx("add_name", policy), policy);
		errors -= does_class_use_perm(dir_idx, get_perm_idx("remove_name", policy), policy);
		errors -= does_class_use_perm(dir_idx, get_perm_idx("reparent", policy), policy);
		errors -= does_class_use_perm(dir_idx, get_perm_idx("search", policy), policy);
		errors -= does_class_use_perm(dir_idx, get_perm_idx("rmdir", policy), policy);
	}
	TEST("whether dir's perms array is correct", errors == 0);
	free(perms);
	fprintf(stderr, "\n");
	filesystem_idx = get_obj_class_idx("filesystem", policy);
	TEST("get_num_perms_for_obj_class w/ only unique perms(filesystem)", get_num_perms_for_obj_class(filesystem_idx, policy) == 10);
	TEST("get_obj_class_perms", get_obj_class_perms(filesystem_idx, &num_perms, &perms, policy) == 0);
	TEST("whether num_perms makes sense", num_perms <= policy->num_perms);
	TEST("whether num_perms == get_num_perms_for_obj_class", num_perms == get_num_perms_for_obj_class(filesystem_idx, policy));
	{
		errors = 10;
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("mount", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("remount", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("unmount", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("getattr", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("relabelfrom", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("relabelto", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("transition", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("associate", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("quotamod", policy), policy);
		errors -= does_class_use_perm(filesystem_idx, get_perm_idx("quotaget", policy), policy);
	}
	TEST("whether filesystem's perms array is correct", errors == 0);
	free(perms);
	fprintf(stderr, "\n");

	return 0;
}
