/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct file_type_data {
	char		*mod_header;
	int		*file_type_attribs;
	int		num_file_type_attribs;
	unsigned char	outformat;
} file_type_data_t;

int file_type_register(sechk_lib_t *lib);
int file_type_init(sechk_module_t *mod, policy_t *policy);
int file_type_run(sechk_module_t *mod, policy_t *policy);
void file_type_free(sechk_module_t *mod);
char *file_type_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *file_type_get_result(sechk_module_t *mod);
 
int file_type_get_file_type_list(sechk_module_t *mod, int **array, int *size);

file_type_data_t *new_file_type_data(void);
void free_file_type_data(file_type_data_t **datum);
