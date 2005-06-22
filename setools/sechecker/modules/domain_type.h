/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct domain_type_data {
	char		*mod_header;
	int		*domain_attribs;
	int		num_domain_attribs;
	unsigned char	outformat;
} domain_type_data_t;

int domain_type_register(sechk_lib_t *lib);
int domain_type_init(sechk_module_t *mod, policy_t *policy);
int domain_type_run(sechk_module_t *mod, policy_t *policy);
void domain_type_free(sechk_module_t *mod);
char *domain_type_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *domain_type_get_result(sechk_module_t *mod);
 
int domain_type_get_domain_list(sechk_module_t *mod, int **array, int *size);

domain_type_data_t *new_domain_type_data(void);
void free_domain_type_data(domain_type_data_t **datum);
