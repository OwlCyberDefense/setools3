/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef ATTRIBS_WO_TYPES
#define ATTRIBS_WO_TYPES

#include "sechecker.h"
#include "policy.h"

typedef struct attribs_wo_types_data {
} attribs_wo_types_data_t;

int attribs_wo_types_register(sechk_lib_t *lib);
int attribs_wo_types_init(sechk_module_t *mod, policy_t *policy);
int attribs_wo_types_run(sechk_module_t *mod, policy_t *policy);
void attribs_wo_types_data_free(void *data);
int attribs_wo_types_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *attribs_wo_types_get_result(sechk_module_t *mod);
int attribs_wo_types_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
attribs_wo_types_data_t *attribs_wo_types_data_new(void);

#endif
