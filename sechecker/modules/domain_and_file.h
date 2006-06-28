/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef DOMAIN_AND_FILE
#define DOMAIN_AND_FILE

#include "sechecker.h"
#include "policy.h"

typedef struct domain_and_file_data {
} domain_and_file_data_t;

int domain_and_file_register(sechk_lib_t *lib);
int domain_and_file_init(sechk_module_t *mod, policy_t *policy);
int domain_and_file_run(sechk_module_t *mod, policy_t *policy);
void domain_and_file_data_free(void *data);
int domain_and_file_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *domain_and_file_get_result(sechk_module_t *mod);

domain_and_file_data_t *domain_and_file_data_new(void);

#endif
