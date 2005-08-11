/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: kcarr@tresys.com
 *
 */

#include "register_list.h"

static int sechk_register_num_modules=-1;

/* array of register function pointers*/
sechk_register_fn_t sechk_register_list[] = {
	&find_domains_register,
	&find_file_types_register,
	&domain_and_file_type_register,
	&attributes_wo_types_register,
	&roles_wo_types_register,
	&users_wo_roles_register,
	&roles_not_in_allow_register,
	&types_not_in_allow_register,
	&spurious_audit_register,
	&attributes_not_in_rules_register,
	/* TODO: add additional register addresses here */
	NULL
};

int sechk_register_list_get_num_modules()
{
	int i;
	if (sechk_register_num_modules != -1)
		return sechk_register_num_modules;
	for (i=0; sechk_register_list[i] != NULL; i++);

	sechk_register_num_modules = i;
	return sechk_register_num_modules;
}
