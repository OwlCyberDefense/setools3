/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: jmowery@tresys.com
 *
 */

#ifndef RULES_EXP_NOTHING
#define RULES_EXP_NOTHING

#ifdef	__cplusplus
extern "C" {
#endif

#include "sechecker.h"

/* The rules_exp_nothing_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct rules_exp_nothing_data
{
	int num_allow;
	int num_neverallow;
	int num_auditallow;
	int num_dontaudit;
	int num_typetrans;
	int num_typechange;
	int num_typemember;
	int num_roletrans;
	int num_rangetrans;
} rules_exp_nothing_data_t;

/* Module functions: */
int rules_exp_nothing_register(sechk_lib_t * lib);
int rules_exp_nothing_init(sechk_module_t * mod, apol_policy_t * policy);
int rules_exp_nothing_run(sechk_module_t * mod, apol_policy_t * policy);
void rules_exp_nothing_data_free(void *data);
int rules_exp_nothing_print_output(sechk_module_t * mod, apol_policy_t * policy);
sechk_result_t *rules_exp_nothing_get_result(sechk_module_t * mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
rules_exp_nothing_data_t *rules_exp_nothing_data_new(void);

#ifdef	__cplusplus
}
#endif

#endif
