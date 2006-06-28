/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef FIND_FILE_TYPES
#define FIND_FILE_TYPES

#include "sechecker.h"
#include "policy.h"

typedef struct find_file_types_data {
	int		*file_type_attribs;
	int		num_file_type_attribs;
} find_file_types_data_t;

int find_file_types_register(sechk_lib_t *lib);
int find_file_types_init(sechk_module_t *mod, policy_t *policy);
int find_file_types_run(sechk_module_t *mod, policy_t *policy);
void find_file_types_data_free(void *data);
int find_file_types_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *find_file_types_get_result(sechk_module_t *mod);
 
int find_file_types_get_list(sechk_module_t *mod, apol_vector_t **v);

find_file_types_data_t *find_file_types_data_new(void);

#endif
