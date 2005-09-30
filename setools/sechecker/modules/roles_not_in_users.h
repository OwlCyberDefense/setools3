/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The roles_not_in_users_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct roles_not_in_users_data {
} roles_not_in_users_data_t;

/* Module functions:
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int roles_not_in_users_register(sechk_lib_t *lib);
int roles_not_in_users_init(sechk_module_t *mod, policy_t *policy);
int roles_not_in_users_run(sechk_module_t *mod, policy_t *policy);
void roles_not_in_users_free(sechk_module_t *mod);
int roles_not_in_users_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *roles_not_in_users_get_result(sechk_module_t *mod);
int roles_not_in_users_get_list(sechk_module_t *mod, int **array, int *size);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
roles_not_in_users_data_t *roles_not_in_users_data_new(void);

