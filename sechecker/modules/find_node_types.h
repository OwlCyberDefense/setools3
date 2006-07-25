/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef FIND_NODE_TYPES_H
#define FINE_NODE_TYPES_H

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/context-query.h>

/* The find_node_types_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_node_types_data {
} find_node_types_data_t;

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library
 * (do, however, replace the find_node_types with the module name)
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. Be sure to choose a unique name
 * for each module and to set the module name prefix find_node_types everywhere */
int find_node_types_register(sechk_lib_t *lib);
int find_node_types_init(sechk_module_t *mod, apol_policy_t *policy);
int find_node_types_run(sechk_module_t *mod, apol_policy_t *policy);
void find_node_types_data_free(void *data);
int find_node_types_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *find_node_types_get_result(sechk_module_t *mod);
int find_node_types_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
find_node_types_data_t *find_node_types_data_new(void);

#endif
