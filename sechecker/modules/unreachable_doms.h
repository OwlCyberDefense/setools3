/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: David Windsor <dwindsor@tresys.com>
 *
 */

#include "sechecker.h"
#include "policy.h"
#include "dta.h"

#define SECHK_INC_DOM_TRANS_HAS_TT      0x08
#define SECHK_INC_DOM_TRANS_HAS_EXEC    0x04
#define SECHK_INC_DOM_TRANS_HAS_TRANS   0x02
#define SECHK_INC_DOM_TRANS_HAS_EP      0x01
#define SECHK_INC_DOM_TRANS_COMPLETE    (SECHK_INC_DOM_TRANS_HAS_EP|SECHK_INC_DOM_TRANS_HAS_TRANS|SECHK_INC_DOM_TRANS_HAS_EXEC)

/* The unreachable_doms_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct unreachable_doms_data {
	char *ctx_file_path;
	int *ctx_list;    /* contains domains found in default_contexts */
	int ctx_list_sz;
} unreachable_doms_data_t;

int unreachable_doms_register(sechk_lib_t *lib);
int unreachable_doms_init(sechk_module_t *mod, policy_t *policy);
int unreachable_doms_run(sechk_module_t *mod, policy_t *policy);
void unreachable_doms_free(sechk_module_t *mod);
int unreachable_doms_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *unreachable_doms_get_result(sechk_module_t *mod);

static char *build_no_trans_proof_str(void);
static char *build_invalid_trans_proof_str(dta_trans_t *trans, policy_t *policy);
static char *build_common_role_proof_str(const int src_idx, const int dst_idx, policy_t *policy);
static char *build_no_user_proof_str(const int role_idx, policy_t *policy);
static bool_t parse_default_contexts(const char *ctx_file_path, int **doms, int *ctx_list_sz, policy_t *policy);
static bool_t in_def_ctx(const int type_idx, unreachable_doms_data_t *datum);
static bool_t has_common_role(const int src_idx, const int dst_idx, policy_t *policy);
static int get_common_roles(int **common_roles, int *common_roles_sz, const int src_idx, const int dst_idx, policy_t *policy);
static int get_valid_user(const int role_idx, policy_t *policy);
static bool_t has_role_trans(const int ep_type, policy_t *policy);
static bool_t roles_have_user(ta_item_t *src_r, ta_item_t *tgt_r, policy_t *policy);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
unreachable_doms_data_t *unreachable_doms_data_new(void);

