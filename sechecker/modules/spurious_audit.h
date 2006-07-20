/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef SPURIOUS_AUDIT
#define SPURIOUS_AUDIT

#include "sechecker.h"


/* The spurious_audit_data structure is used to hold the check specific
 *  private data of a module.*/
typedef struct spurious_audit_data {
} spurious_audit_data_t;

#define SECHK_SPUR_AU_AA_MISS 0x01
#define SECHK_SPUR_AU_AA_PART 0x02
#define SECHK_SPUR_AU_DA_FULL 0x04
#define SECHK_SPUR_AU_DA_PART 0x08

/* Module functions: */
int spurious_audit_register(sechk_lib_t *lib);
int spurious_audit_init(sechk_module_t *mod, apol_policy_t *policy);
int spurious_audit_run(sechk_module_t *mod, apol_policy_t *policy);
void spurious_audit_free(sechk_module_t *mod);
int spurious_audit_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *spurious_audit_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
spurious_audit_data_t *spurious_audit_data_new(void);

#endif
