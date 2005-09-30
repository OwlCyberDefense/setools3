/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

#define SECHK_MOUNT_ONLY_MOUNT   0x01
#define SECHK_MOUNT_ONLY_MOUNTON 0x02
#define SECHK_MOUNT_INV_MOUNTON  0x04

typedef struct incomplete_mount_data {
} incomplete_mount_data_t;

/* Module functions:
 * NOTE: while using a modular format SEChecker is built
 * statically; this means that all modules and their functions
 * are in the same namespace. */
int incomplete_mount_register(sechk_lib_t *lib);
int incomplete_mount_init(sechk_module_t *mod, policy_t *policy);
int incomplete_mount_run(sechk_module_t *mod, policy_t *policy);
void incomplete_mount_free(sechk_module_t *mod);
int incomplete_mount_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *incomplete_mount_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
incomplete_mount_data_t *incomplete_mount_data_new(void);

