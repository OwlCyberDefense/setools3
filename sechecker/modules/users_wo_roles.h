/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef USERS_WO_ROLES
#define USERS_WO_ROLES

#include "sechecker.h"


/* The users_wo_roles_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct users_wo_roles_data {
} users_wo_roles_data_t;

int users_wo_roles_register(sechk_lib_t *lib);
int users_wo_roles_init(sechk_module_t *mod, apol_policy_t *policy);
int users_wo_roles_run(sechk_module_t *mod, apol_policy_t *policy);
void users_wo_roles_data_free(void *data);
int users_wo_roles_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *users_wo_roles_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
users_wo_roles_data_t *users_wo_roles_data_new(void);

#endif
