/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct empty_role_data {
	char		*mod_header;
	unsigned char	outformat;
} empty_role_data_t;

int empty_role_register(sechk_lib_t *lib);
int empty_role_init(sechk_module_t *mod, policy_t *policy);
int empty_role_run(sechk_module_t *mod, policy_t *policy);
void empty_role_free(sechk_module_t *mod);
char *empty_role_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *empty_role_get_result(sechk_module_t *mod);

empty_role_data_t *new_empty_role_data(void);
void free_empty_role_data(empty_role_data_t **datum);
