/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

typedef struct xx_data {
	char		*mod_header;
	/* TODO: define members of this data structure for module's private data */
	unsigned char	outformat;
} xx_data_t;

int xx_register(sechk_lib_t *lib);
int xx_init(sechk_module_t *mod, policy_t *policy);
int xx_run(sechk_module_t *mod, policy_t *policy);
void xx_free(sechk_module_t *mod);
char *xx_get_output_str(sechk_module_t *mod, policy_t *policy);
sechk_result_t *xx_get_result(sechk_module_t *mod);
 
/* TODO: declare any other functions needed by get_module_function */

xx_data_t *new_xx_data(void);
void free_xx_data(xx_data_t **datum);
