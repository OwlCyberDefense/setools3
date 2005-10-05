/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The roles_wo_allow_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct roles_wo_allow_data {
} roles_wo_allow_data_t;

int roles_wo_allow_register(sechk_lib_t *lib);
int roles_wo_allow_init(sechk_module_t *mod, policy_t *policy);
int roles_wo_allow_run(sechk_module_t *mod, policy_t *policy);
void roles_wo_allow_free(sechk_module_t *mod);
int roles_wo_allow_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *roles_wo_allow_get_result(sechk_module_t *mod);
int roles_wo_allow_get_list(sechk_module_t *mod, int **array, int *size);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
roles_wo_allow_data_t *roles_wo_allow_data_new(void);

