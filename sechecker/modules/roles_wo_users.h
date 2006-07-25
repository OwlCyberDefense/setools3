/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef ROLES_WO_USERS
#define ROLES_WO_USERS

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/user-query.h>
#include <apol/role-query.h>

/* The roles_wo_users_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct roles_wo_users_data {
} roles_wo_users_data_t;

/* Module functions:
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int roles_wo_users_register(sechk_lib_t *lib);
int roles_wo_users_init(sechk_module_t *mod, apol_policy_t *policy);
int roles_wo_users_run(sechk_module_t *mod, apol_policy_t *policy);
void roles_wo_users_data_free(void *data);
int roles_wo_users_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *roles_wo_users_get_result(sechk_module_t *mod);
int roles_wo_users_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
roles_wo_users_data_t *roles_wo_users_data_new(void);

#endif
