/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef FIND_DOMAINS
#define FIND_DOMAINS

#include "sechecker.h"

#include <apol/vector.h>
typedef struct find_domains_data {
	apol_vector_t 	*domain_attribs;
	int num_domain_attribs;
} find_domains_data_t;

int find_domains_register(sechk_lib_t *lib);
int find_domains_init(sechk_module_t *mod, apol_policy_t *policy);
int find_domains_run(sechk_module_t *mod, apol_policy_t *policy);
void find_domains_data_free(void *data);
int find_domains_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *find_domains_get_result(sechk_module_t *mod);
 
int find_domains_get_list(sechk_module_t *mod, int **array, int *size);

find_domains_data_t *find_domains_data_new(void);

#endif
