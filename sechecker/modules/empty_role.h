/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The empty_role_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct empty_role_data {
} empty_role_data_t;

int empty_role_register(sechk_lib_t *lib);
int empty_role_init(sechk_module_t *mod, policy_t *policy);
int empty_role_run(sechk_module_t *mod, policy_t *policy);
void empty_role_free(sechk_module_t *mod);
int empty_role_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *empty_role_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
empty_role_data_t *empty_role_data_new(void);

