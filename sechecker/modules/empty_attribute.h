/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct empty_attribute_data {
} empty_attribute_data_t;

int empty_attribute_register(sechk_lib_t *lib);
int empty_attribute_init(sechk_module_t *mod, policy_t *policy);
int empty_attribute_run(sechk_module_t *mod, policy_t *policy);
void empty_attribute_free(sechk_module_t *mod);
int empty_attribute_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *empty_attribute_get_result(sechk_module_t *mod);


/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
empty_attribute_data_t *empty_attribute_data_new(void);

