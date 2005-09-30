/* Copyright (C) 2005 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Author: jmowery@tresys.com
 *
 */

#include "sechecker.h"
#include "policy.h"

#define SECHK_INC_DOM_TRANS_HAS_TT	0x08
#define SECHK_INC_DOM_TRANS_CAN_EXEC	0x04
#define SECHK_INC_DOM_TRANS_CAN_TRANS	0x02
#define SECHK_INC_DOM_TRANS_IS_EP	0x01
#define SECHK_INC_DOM_TRANS_COMPLETE	(SECHK_INC_DOM_TRANS_IS_EP|SECHK_INC_DOM_TRANS_CAN_TRANS|SECHK_INC_DOM_TRANS_CAN_EXEC)

/* The incomplete_domain_transition_data structure is used to hold the check specific
 *  private data of a module. */
typedef struct incomplete_domain_trans_data {
} incomplete_domain_trans_data_t;

int incomplete_domain_trans_register(sechk_lib_t *lib);
int incomplete_domain_trans_init(sechk_module_t *mod, policy_t *policy);
int incomplete_domain_trans_run(sechk_module_t *mod, policy_t *policy);
void incomplete_domain_trans_free(sechk_module_t *mod);
int incomplete_domain_trans_print_output(sechk_module_t *mod, policy_t *policy);
sechk_result_t *incomplete_domain_trans_get_result(sechk_module_t *mod);

/* The following function is used to allocate and initialize
 * the private data storage structure for this module */
incomplete_domain_trans_data_t *incomplete_domain_trans_data_new(void);

