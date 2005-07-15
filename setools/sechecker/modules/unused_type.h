/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The unused_type_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct unused_type_data {
} unused_type_data_t;

int unused_type_register(sechk_lib_t *lib);
int unused_type_init(sechk_module_t *mod, policy_t *policy);
int unused_type_run(sechk_module_t *mod, policy_t *policy);
void unused_type_free(sechk_module_t *mod);
int unused_type_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *unused_type_get_result(sechk_module_t *mod);

int unused_type_get_unused_types_list(sechk_module_t *mod, int **array, int*size);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
unused_type_data_t *unused_type_data_new(void);

