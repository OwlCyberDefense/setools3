/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef FIND_PORT_TYPES
#define FIND_PORT_TYPES

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/context-query.h>

/* The find_port_types_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_port_types_data {
} find_port_types_data_t;

int find_port_types_register(sechk_lib_t *lib);
int find_port_types_init(sechk_module_t *mod, apol_policy_t *policy);
int find_port_types_run(sechk_module_t *mod, apol_policy_t *policy);
void find_port_types_data_free(void *data);
int find_port_types_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *find_port_types_get_result(sechk_module_t *mod);
int find_port_types_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
find_port_types_data_t *find_port_types_data_new(void);

#endif
