/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include "policy.h"

/* The imp_range_trans_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct imp_range_trans_data {
} imp_range_trans_data_t;

int imp_range_trans_register(sechk_lib_t *lib);
int imp_range_trans_init(sechk_module_t *mod, policy_t *policy);
int imp_range_trans_run(sechk_module_t *mod, policy_t *policy);
void imp_range_trans_free(sechk_module_t *mod);
int imp_range_trans_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *imp_range_trans_get_result(sechk_module_t *mod);

static char *build_no_roles_proof_str(ap_rangetrans_t *r_trans, const int type_idx, policy_t *policy);
static char *build_bad_user_mls_proof_str(ap_user_t *user, const int *valid_roles, const int valid_roles_sz, ap_rangetrans_t *r_trans, policy_t *policy);
static char *build_no_exec_proof_str(ap_rangetrans_t *r_trans, policy_t *policy);
static char *build_no_user_proof_str(const int *valid_roles, const int valid_roles_sz, policy_t *policy);
static bool_t verify_user_range(const int *valid_roles, const int valid_roles_sz, const int rtrans_idx, ap_rangetrans_t *r_trans, sechk_result_t *res, policy_t *policy);
static int get_valid_users(int **valid_users, int *valid_users_sz, const int *valid_roles, const int valid_roles_sz, bool_t *found_user, ap_mls_range_t *range, policy_t *policy);
static int get_valid_roles(int **valid_roles, int *valid_roles_sz, const int type_idx, policy_t *policy);
static bool_t has_exec_perms(ta_item_t *tgt_types, const int src_idx, const int file_idx, const int exec_idx, policy_t *policy);

imp_range_trans_data_t *imp_range_trans_data_new(void);

