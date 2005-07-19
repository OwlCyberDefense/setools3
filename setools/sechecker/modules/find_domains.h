/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct find_domians_data {
	int		*domain_attribs;
	int		num_domain_attribs;
} find_domians_data_t;

int find_domians_register(sechk_lib_t *lib);
int find_domians_init(sechk_module_t *mod, policy_t *policy);
int find_domians_run(sechk_module_t *mod, policy_t *policy);
void find_domians_data_free(sechk_module_t *mod);
int find_domians_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *find_domians_get_result(sechk_module_t *mod);
 
int find_domians_get_list(sechk_module_t *mod, int **array, int *size);

find_domians_data_t *find_domians_data_new(void);
