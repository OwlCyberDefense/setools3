/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef FIND_NET_DOMAINS
#define FIND_NET_DOMAINS

#include "sechecker.h"
#include "policy.h"

/* The find_net_domains_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_net_domains_data {
	int *net_objs;
	int num_net_objs;
} find_net_domains_data_t;

int find_net_domains_register(sechk_lib_t *lib);
int find_net_domains_init(sechk_module_t *mod, policy_t *policy);
int find_net_domains_run(sechk_module_t *mod, policy_t *policy);
void find_net_domains_data_free(void *data);
int find_net_domains_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *find_net_domains_get_result(sechk_module_t *mod);
int find_net_domains_get_list(sechk_module_t *mod, apol_vector_t **v);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
find_net_domains_data_t *find_net_domains_data_new(void);

#endif
