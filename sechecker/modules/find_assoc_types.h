/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef FIND_ASSOC_TYPES
#define FIND_ASSOC_TYPES

#include "sechecker.h"
#include "policy.h"

/* The find_assoc_types_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_assoc_types_data {
} find_assoc_types_data_t;

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library */
int find_assoc_types_register(sechk_lib_t *lib);
int find_assoc_types_init(sechk_module_t *mod, apol_policy_t *policy);
int find_assoc_types_run(sechk_module_t *mod, apol_policy_t *policy);
void find_assoc_types_data_free(void *data);
int find_assoc_types_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *find_assoc_types_get_result(sechk_module_t *mod);
int find_assoc_types_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
find_assoc_types_data_t *find_assoc_types_data_new(void);

#endif
