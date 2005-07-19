/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct attributes_wo_types_data {
} attributes_wo_types_data_t;

int attributes_wo_types_register(sechk_lib_t *lib);
int attributes_wo_types_init(sechk_module_t *mod, policy_t *policy);
int attributes_wo_types_run(sechk_module_t *mod, policy_t *policy);
void attributes_wo_types_free(sechk_module_t *mod);
int attributes_wo_types_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *attributes_wo_types_get_result(sechk_module_t *mod);


/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
attributes_wo_types_data_t *attributes_wo_types_data_new(void);

