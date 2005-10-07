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
	{"attribs_wo_rules",	&attribs_wo_rules_register},
	{"attribs_wo_types",	&attribs_wo_types_register},
	{"domain_and_file",	&domain_and_file_register},
	{"domains_wo_roles",	&domains_wo_roles_register},
	{"find_domains",	&find_domains_register},
	{"find_file_types", 	&find_file_types_register},
	{"inc_dom_trans",	&inc_dom_trans_register},
	{"inc_mount",		&inc_mount_register},
	{"roles_wo_allow",	&roles_wo_allow_register},
	{"roles_wo_types",	&roles_wo_types_register},
	{"roles_wo_users",	&roles_wo_users_register},
	{"rules_exp_nothing",	&rules_exp_nothing_register},
	{"spurious_audit",	&spurious_audit_register},
	{"types_wo_allow",	&types_wo_allow_register},
	{"users_wo_roles",	&users_wo_roles_register},
	/* TODO: add additional register addresses here in alphabetical order */

	{NULL, NULL}
};

/* NULL terminated array of profiles (name, file, description) */
static sechk_profile_name_reg_t sechk_profile_register_list[] = {
	{"analysis",    "analysis-checks.sechecker", "common analysis checks"},
	{"development", "devel-checks.sechecker",    "common development checks"},
	{"all", "all-checks.sechecker", "all available checks" },
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
