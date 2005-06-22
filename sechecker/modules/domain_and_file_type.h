/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct domain_and_file_type_data {
	char		*mod_header;
	char		**depend_names;
	sechk_run_fn_t	*depend_run_fns;
	sechk_module_t	**depend_mods;
	sechk_get_result_fn_t *depend_get_res_fns;
	int		num_depend;
	unsigned char	outformat;
} domain_and_file_type_data_t;

int domain_and_file_type_register(sechk_lib_t *lib);
int domain_and_file_type_init(sechk_module_t *mod, policy_t *policy);
int domain_and_file_type_run(sechk_module_t *mod, policy_t *policy);
void domain_and_file_type_free(sechk_module_t *mod);
char *domain_and_file_type_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *domain_and_file_type_get_result(sechk_module_t *mod);
 
/* TODO: declare any other functions needed by get_module_function */

domain_and_file_type_data_t *new_domain_and_file_type_data(void);
void free_domain_and_file_type_data(domain_and_file_type_data_t **datum);
