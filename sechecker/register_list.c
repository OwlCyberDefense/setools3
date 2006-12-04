/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kcarr@tresys.com
 *
 */

#include "register_list.h"

static size_t sechk_register_num_modules = 0;
static size_t sechk_register_num_profiles = 0;

/* NULL terminated array of module names and register functions */
static sechk_module_name_reg_t sechk_module_register_list[] = {
	{"attribs_wo_rules", &attribs_wo_rules_register},
	{"attribs_wo_types", &attribs_wo_types_register},
	{"domain_and_file", &domain_and_file_register},
	{"domains_wo_roles", &domains_wo_roles_register},
	{"find_assoc_types", &find_assoc_types_register},
	{"find_domains", &find_domains_register},
	{"find_file_types", &find_file_types_register},
	{"find_net_domains", &find_net_domains_register},
	{"find_node_types", &find_node_types_register},
	{"find_netif_types", &find_netif_types_register},
	{"find_port_types", &find_port_types_register},
	{"imp_range_trans", &imp_range_trans_register},
	{"inc_dom_trans", &inc_dom_trans_register},
	{"inc_mount", &inc_mount_register},
	{"inc_net_access", &inc_net_access_register},
	{"roles_wo_allow", &roles_wo_allow_register},
	{"roles_wo_types", &roles_wo_types_register},
	{"roles_wo_users", &roles_wo_users_register},
	/* Deprecated *
	 * {"roles_exp_nothing",   &roles_exp_nothing_register}, 
	 */
	{"spurious_audit", &spurious_audit_register},
	{"types_wo_allow", &types_wo_allow_register},
	{"unreachable_doms", &unreachable_doms_register},
	{"users_wo_roles", &users_wo_roles_register},
	/* TODO: add additional register addresses here in alphabetical order */

	{NULL, NULL}
};

/* NULL terminated array of profiles (name, file, description) */
static sechk_profile_name_reg_t sechk_profile_register_list[] = {
	{"analysis", "analysis-checks.sechecker", "common analysis checks"},
	{"development", "devel-checks.sechecker", "common development checks"},
	{"all", "all-checks.sechecker", "all available checks"},
	/* TODO: add more profiles */

	{NULL, NULL, NULL}
};

size_t sechk_register_list_get_num_profiles()
{
	size_t i;
	if (sechk_register_num_profiles != 0)
		return sechk_register_num_profiles;
	for (i = 0; sechk_profile_register_list[i].name != NULL; i++) ;

	sechk_register_num_profiles = i;
	return sechk_register_num_profiles;
}

const sechk_profile_name_reg_t *sechk_register_list_get_profiles()
{
	return sechk_profile_register_list;
}

size_t sechk_register_list_get_num_modules()
{
	size_t i;
	if (sechk_register_num_modules != 0)
		return sechk_register_num_modules;
	for (i = 0; sechk_module_register_list[i].name != NULL; i++) ;

	sechk_register_num_modules = i;
	return sechk_register_num_modules;
}

const sechk_module_name_reg_t *sechk_register_list_get_modules()
{
	return sechk_module_register_list;
}
