/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct unused_type_data {
	char		*mod_header;
	unsigned char	outformat;
} unused_type_data_t;

int unused_type_register(sechk_lib_t *lib);
int unused_type_init(sechk_module_t *mod, policy_t *policy);
int unused_type_run(sechk_module_t *mod, policy_t *policy);
void unused_type_free(sechk_module_t *mod);
char *unused_type_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *unused_type_get_result(sechk_module_t *mod);
 
int unused_type_get_unused_types_list(sechk_module_t *mod, int **array, int*size);

unused_type_data_t *new_unused_type_data(void);
void free_unused_type_data(unused_type_data_t **datum);
