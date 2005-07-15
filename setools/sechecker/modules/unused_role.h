/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The unused_role_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct unused_role_data {
} unused_role_data_t;

int unused_role_register(sechk_lib_t *lib);
int unused_role_init(sechk_module_t *mod, policy_t *policy);
int unused_role_run(sechk_module_t *mod, policy_t *policy);
void unused_role_free(sechk_module_t *mod);
int unused_role_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *unused_role_get_result(sechk_module_t *mod);

int unused_role_get_unused_roles_list(sechk_module_t *mod, int **array, int *size);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
unused_role_data_t *unused_role_data_new(void);

