/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The empty_user_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct empty_user_data {
} empty_user_data_t;

int empty_user_register(sechk_lib_t *lib);
int empty_user_init(sechk_module_t *mod, policy_t *policy);
int empty_user_run(sechk_module_t *mod, policy_t *policy);
void empty_user_free(sechk_module_t *mod);
int empty_user_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *empty_user_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
empty_user_data_t *empty_user_data_new(void);

