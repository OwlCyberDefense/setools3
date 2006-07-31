/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include <apol/policy.h>
#include <apol/role-query.h>
#include <apol/user-query.h>
#include <apol/rangetrans-query.h>
#include <apol/rbacrule-query.h>
#include <apol/domain-trans-analysis.h>
#include <apol/policy-query.h>

/* The imp_range_trans_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct imp_range_trans_data {
} imp_range_trans_data_t;

int imp_range_trans_register(sechk_lib_t *lib);
int imp_range_trans_init(sechk_module_t *mod, apol_policy_t *policy);
int imp_range_trans_run(sechk_module_t *mod, apol_policy_t *policy);
void imp_range_trans_data_free(void *data);
int imp_range_trans_print_output(sechk_module_t *mod, apol_policy_t *policy);
sechk_result_t *imp_range_trans_get_result(sechk_module_t *mod);
imp_range_trans_data_t *imp_range_trans_data_new(void);

