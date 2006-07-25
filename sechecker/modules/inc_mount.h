/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef INC_MOUNT
#define INC_MOUNT

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/avrule-query.h>

#define SECHK_MOUNT_ONLY_MOUNT   0x01
#define SECHK_MOUNT_ONLY_MOUNTON 0x02

typedef struct inc_mount_data {
} inc_mount_data_t;

/* Module functions:
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int inc_mount_register(sechk_lib_t *lib);
int inc_mount_init(sechk_module_t *mod, apol_policy_t *policy);
int inc_mount_run(sechk_module_t *mod, apol_policy_t *policy);
void inc_mount_data_free(void *data);
int inc_mount_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *inc_mount_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
inc_mount_data_t *inc_mount_data_new(void);

#endif
