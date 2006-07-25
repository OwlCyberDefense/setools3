/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef TYPES_WO_ALLOW
#define TYPES_WO_ALLOW

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/avrule-query.h>
#include <apol/type-query.h>

/* The types_wo_allow_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct types_wo_allow_data {
} types_wo_allow_data_t;

int types_wo_allow_register(sechk_lib_t *lib);
int types_wo_allow_init(sechk_module_t *mod, apol_policy_t *policy);
int types_wo_allow_run(sechk_module_t *mod, apol_policy_t *policy);
void types_wo_allow_data_free(void *data);
int types_wo_allow_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *types_wo_allow_get_result(sechk_module_t *mod);

int types_wo_allow_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
types_wo_allow_data_t *types_wo_allow_data_new(void);

#endif
