/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: dwindsor@tresys.com
 *
 */

#ifndef FIND_NETIF_TYPES_H
#define FIND_NETIF_TYPES_H

#include "sechecker.h"
#include "policy.h"

/* The find_netif_types_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct find_netif_types_data {
} find_netif_types_data_t;

/* Module functions:
 * Do not change any of these prototypes or you will not be
 * able to run the module in the library */
int find_netif_types_init(sechk_module_t *mod, policy_t *policy);
int find_netif_types_run(sechk_module_t *mod, policy_t *policy);
void find_netif_types_free(sechk_module_t *mod);
int find_netif_types_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *find_netif_types_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
find_netif_types_data_t *find_netif_types_data_new(void);

#endif