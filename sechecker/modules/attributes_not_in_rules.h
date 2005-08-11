/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The attributes_not_in_rules_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct attributes_not_in_rules_data {
} attributes_not_in_rules_data_t;

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int attributes_not_in_rules_register(sechk_lib_t *lib);
int attributes_not_in_rules_init(sechk_module_t *mod, policy_t *policy);
int attributes_not_in_rules_run(sechk_module_t *mod, policy_t *policy);
void attributes_not_in_rules_free(sechk_module_t *mod);
int attributes_not_in_rules_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *attributes_not_in_rules_get_result(sechk_module_t *mod);

/* NOTE: While SEChecker is build statically, it is
 * intended that no module directly call a function
 * from another but instead use get_module_function()
 * to get the desired function from the library. */

int attributes_not_in_rules_get_list(sechk_module_t *mod, int **array, int *size);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
attributes_not_in_rules_data_t *attributes_not_in_rules_data_new(void);

