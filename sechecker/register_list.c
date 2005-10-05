/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: kcarr@tresys.com
 *
 */

#include "register_list.h"

static int sechk_register_num_modules=-1;
static int sechk_register_num_profiles=-1;

/* NULL terminated array of module names and register functions */
static sechk_module_name_reg_t sechk_module_register_list[] = { 
	{"find_domains",		&find_domains_register},
	{"find_file_types", 		&find_file_types_register},
	{"domain_and_file_type",	&domain_and_file_type_register},
	{"attributes_wo_types",		&attributes_wo_types_register},
	{"roles_wo_types",		&roles_wo_types_register},
	{"users_wo_roles",		&users_wo_roles_register},
	{"roles_not_in_allow",		&roles_not_in_allow_register},
	{"types_not_in_allow",		&types_not_in_allow_register},
	{"spurious_audit",		&spurious_audit_register},
	{"attributes_not_in_rules",	&attributes_not_in_rules_register},
	{"incomplete_mount",		&incomplete_mount_register},
	{"roles_not_in_users",		&roles_not_in_users_register},
	{"rules_expand_to_nothing",	&rules_expand_to_nothing_register},
	{"domains_wo_roles",		&domains_wo_roles_register},
	{"incomplete_domain_trans",	&incomplete_domain_trans_register},
	/* TODO: add additional register addresses here */

	{NULL, NULL}
};

/* NULL terminated array of profiles (name, file, description) */
static sechk_profile_name_reg_t sechk_profile_register_list[] = {
	{"development", "devel-checks.sechecker",    "common development checks"},
	{"analysis",    "analysis-checks.sechecker", "common analysis checks"},
	/* TODO: add more profiles */

	{NULL, NULL, NULL}
};

int sechk_register_list_get_num_profiles()
{
	int i;
	if (sechk_register_num_profiles != -1)
		return sechk_register_num_profiles;
	for (i=0; sechk_profile_register_list[i].name != NULL; i++);

	sechk_register_num_profiles = i;
	return sechk_register_num_profiles;
}

const sechk_profile_name_reg_t* sechk_register_list_get_profiles()
{
	return sechk_profile_register_list;
}

int sechk_register_list_get_num_modules()
{
	int i;
	if (sechk_register_num_modules != -1)
		return sechk_register_num_modules;
	for (i=0; sechk_module_register_list[i].name != NULL; i++);

	sechk_register_num_modules = i;
	return sechk_register_num_modules;
}

const sechk_module_name_reg_t* sechk_register_list_get_modules()
{
	return sechk_module_register_list;
}
