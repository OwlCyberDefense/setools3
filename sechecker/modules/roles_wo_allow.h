/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef ROLES_WO_ALLOW
#define ROLES_WO_ALLOW

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/role-query.h>
#include <apol/rbacrule-query.h>

/* The roles_wo_allow_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct roles_wo_allow_data {
} roles_wo_allow_data_t;

int roles_wo_allow_register(sechk_lib_t *lib);
int roles_wo_allow_init(sechk_module_t *mod, apol_policy_t *policy);
int roles_wo_allow_run(sechk_module_t *mod, apol_policy_t *policy);
void roles_wo_allow_data_free(void *data);
int roles_wo_allow_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *roles_wo_allow_get_result(sechk_module_t *mod);
int roles_wo_allow_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
roles_wo_allow_data_t *roles_wo_allow_data_new(void);

#endif
