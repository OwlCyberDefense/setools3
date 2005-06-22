/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct empty_attribute_data {
	char		*mod_header;
	unsigned char	outformat;
} empty_attribute_data_t;

int empty_attribute_register(sechk_lib_t *lib);
int empty_attribute_init(sechk_module_t *mod, policy_t *policy);
int empty_attribute_run(sechk_module_t *mod, policy_t *policy);
void empty_attribute_free(sechk_module_t *mod);
char *empty_attribute_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *empty_attribute_get_result(sechk_module_t *mod);
 
empty_attribute_data_t *new_empty_attribute_data(void);
void free_empty_attribute_data(empty_attribute_data_t **datum);
